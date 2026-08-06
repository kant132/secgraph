"""Stage 3 — audit + trace 真实，只 mock PoC（HttpClient/agent）。

audit 用真实 LLM，trace_route 用真实 codegraph DB，
verify 只 mock HttpClient + run_agent，record 真实。

即：audit 真实 → trace 真实 → verify mock(HttpClient/agent) → record 真实
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests._vuln_nodeids import VULN_NODEIDS

WEBGOAT_DB = r"D:\jar\webgoat\.codegraph\codegraph.db"
WEBGOAT_SRC = r"D:\jar\webgoat"


def build_tasks():
    """从真实 codegraph.db 构建 task — 取前 2 个 findings 以保证 5 min 内完成。"""
    from src.codegraph import CodegraphClient
    from src.state import MethodNode, FileAuditTask

    nids = VULN_NODEIDS[:2]
    cg = CodegraphClient(WEBGOAT_DB)
    tasks = []
    for nid in nids:
        row = cg._conn.execute(
            "SELECT id, qualified_name, name, signature, file_path, start_line, end_line FROM nodes WHERE id=?", (nid,)
        ).fetchone()
        m = MethodNode(id=row["id"], qualified_name=row["qualified_name"], name=row["name"],
                       signature=row["signature"], file_path=row["file_path"],
                       start_line=row["start_line"], end_line=row["end_line"])
        fields = cg.list_fields_by_nodeid(nid)
        body = cg.get_method_body(WEBGOAT_SRC, m)
        callees = cg.get_callee_bodies(WEBGOAT_SRC, nid)
        task = FileAuditTask(file_path=row["file_path"], node_id=nid,
                            fields=fields, method_bodies={nid: body}, calls=callees)
        tasks.append(task)
    cg.close()
    return tasks


@pytest.fixture
def state():
    tmpdir = tempfile.mkdtemp()
    # 限制为 2 个 findings 以保证 5 min 内完成
    nids = VULN_NODEIDS[:2]
    return {
        "mode": "dev", "codegraph_db": WEBGOAT_DB, "sources_root": WEBGOAT_SRC,
        "pkg_prefix": "org/owasp/webgoat/lessons",
        "findings_dir": f"{tmpdir}/findings", "logs_dir": f"{tmpdir}/logs",
        "file_limit": len(nids), "run_id": "stage3", "max_iterations": 3,
        "llm_model": "test", "work_list": [], "audit_index": 0,
        "findings": [], "verified": [], "reflection_notes": [], "iteration": 0,
        "agent_history": [], "next_agent": "",
    }


class TestStage3:
    """audit 真实 → trace 真实 → verify mock(HttpClient/agent) → record 真实。"""

    def test_full_pipeline(self, state):
        """完整 pipeline，只 mock PoC 执行部分。"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        tasks = build_tasks()

        # 1. audit — 真实 codegraph + 真实 LLM
        #    CodegraphClient 用真实 DB（不 mock）
        for task in tasks:
            state["work_list"] = [task]
            state["audit_index"] = 0
            from src.nodes.audit import audit_file
            state.update(audit_file(state))

        findings = state["findings"]
        print(f"\n=== audit: {len(findings)} findings ===")
        for f in findings:
            print(f"  {f.vuln_type} ({f.severity}) node={f.node_id[:30]}")
        assert len(findings) >= 1, "audit 应发现至少 1 个漏洞"

        # 2. trace_route — 真实 codegraph DB + 真实 LLM
        from src.nodes.trace_route import trace_route
        state.update(trace_route(state))

        print(f"\n=== trace_route 结果 ===")
        for f in state["findings"]:
            r = "可达" if "[路由可达性分析] 可达" in f.evidence else "不可达"
            print(f"  {f.vuln_type} → {r}")

        # 3. verify — 只 mock HttpClient + run_agent，LLM 真实
        mock_http = MagicMock()
        mock_http.login.return_value = True
        mock_http.session = MagicMock()
        mock_http.session.cookies = MagicMock()
        mock_http.session.cookies.items.return_value = [("JSESSIONID", "mock")]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"output": "101,Joe,Snow,987654321,VISA"}'
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_http.session.post.return_value = mock_resp
        mock_http.session.get.return_value = mock_resp

        with patch("src.nodes.verify.node.read_login_info", return_value={
            "target_url": "http://localhost:18080/WebGoat",
            "login_url": "http://localhost:18080/WebGoat/login",
            "login_method": "POST", "login_body": "u=admin1&p=admin1",
            "login_headers": {}, "status": "verified",
        }), patch("src.nodes.verify.node.HttpClient", return_value=mock_http), \
             patch("src.nodes.verify.node.run_agent") as ma:
            ma.return_value = (True, "PoC confirmed", "POST /x HTTP/1.1\n\na=1", [])
            from src.nodes.verify.node import verify_finding
            state.update(verify_finding(state))

        # 4. record — 真实 codegraph DB
        from src.nodes.record import record
        record(state)

        print(f"\n=== Stage 3 完整 pipeline 结果 ===")
        print(f"  findings: {len(state['findings'])}")
        for f in state["findings"]:
            print(f"  {f.vuln_type} → {f.poc_result}")
        md_files = list(Path(state["findings_dir"]).glob("*.md"))
        print(f"  .md files: {len(md_files)}")
        assert len(md_files) >= 1
