"""E2E 测试 — 真实 LLM 请求，只测 1 个明确有漏洞的 nodeid。

选 SQLi (SqlInjectionChallenge::registerNewUser) — 最可靠的漏洞类型，
LLM 几乎 100% 能发现。完整跑 audit → trace → verify → record。

运行方式：
    pytest -m e2e                    # 只跑 e2e
    pytest -m "unit or integration or e2e"  # 大改动：全跑

依赖：真实 codegraph.db + .env (LLM_API_KEY) + webgoat Docker (verify mock)
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# 选 1 个明确有漏洞的 nodeid — SQLi 最可靠
E2E_NODEID = "method:647d162fdf923cdfbc8d4343d418e51e"  # SQLi | SqlInjectionChallenge::registerNewUser

WEBGOAT_DB = r"D:\jar\webgoat\.codegraph\codegraph.db"
WEBGOAT_SRC = r"D:\jar\webgoat"


def _make_mock_cg():
    """从真实 codegraph.db 预查 1 个 nodeid 的数据，构建 mock CodegraphClient。"""
    from src.codegraph import CodegraphClient
    from src.state import MethodNode, FieldNode, FileAuditTask

    real_cg = CodegraphClient(WEBGOAT_DB)
    mock_cg = MagicMock()
    mock_cg._conn = MagicMock()
    mock_cg.init_memory_table.return_value = None
    mock_cg.save_memory.return_value = None
    mock_cg.lookup_memory.return_value = None

    nid = E2E_NODEID
    row = real_cg._conn.execute(
        "SELECT id, qualified_name, name, signature, file_path, start_line, end_line FROM nodes WHERE id=?", (nid,)
    ).fetchone()
    m = MethodNode(id=row["id"], qualified_name=row["qualified_name"], name=row["name"],
                   signature=row["signature"], file_path=row["file_path"],
                   start_line=row["start_line"], end_line=row["end_line"])
    fields = real_cg.list_fields_by_nodeid(nid)
    body = real_cg.get_method_body(WEBGOAT_SRC, m)
    callees = real_cg.get_callee_bodies(WEBGOAT_SRC, nid)
    task = FileAuditTask(file_path=row["file_path"], node_id=nid,
                         fields=fields, method_bodies={nid: body}, calls=callees)

    reachable = real_cg.is_route_reachable(nid)
    chains = real_cg.get_call_chain_to_route(nid)
    chain_bodies = {}
    if chains:
        chain_bodies = real_cg.get_chain_bodies(WEBGOAT_SRC, chains[0]["chain_ids"])

    real_cg.close()

    mock_cg.list_entry_methods.return_value = [m]
    mock_cg.list_fields_by_nodeid.return_value = fields
    mock_cg.get_method_body.return_value = body
    mock_cg.get_callee_bodies.return_value = callees
    mock_cg.is_route_reachable.return_value = reachable
    mock_cg.get_call_chain_to_route.return_value = chains
    mock_cg.get_chain_bodies.return_value = chain_bodies

    return mock_cg, task


@pytest.fixture
def state():
    tmpdir = tempfile.mkdtemp()
    return {
        "mode": "dev", "codegraph_db": WEBGOAT_DB, "sources_root": WEBGOAT_SRC,
        "pkg_prefix": "org/owasp/webgoat/lessons",
        "findings_dir": f"{tmpdir}/findings", "logs_dir": f"{tmpdir}/logs",
        "file_limit": 1, "run_id": "e2e", "max_iterations": 3,
        "llm_model": "test", "work_list": [], "audit_index": 0,
        "findings": [], "verified": [], "reflection_notes": [], "iteration": 0,
        "agent_history": [], "next_agent": "",
    }


@pytest.mark.e2e
class TestE2E:
    """完整 pipeline: 1 个 SQLi nodeid → 真实 LLM audit → trace → verify(mock HTTP) → record。"""

    def test_full_pipeline_one_vuln(self, state):
        """只发 1 个真实 LLM 请求（audit），trace 也发真实 LLM，verify mock HTTP+agent，record 真实 ORM。"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        mock_cg, task = _make_mock_cg()

        # 1. audit — 真实 LLM
        state["work_list"] = [task]
        state["audit_index"] = 0
        with patch("src.codegraph.CodegraphClient") as m:
            m.return_value.__enter__ = MagicMock(return_value=mock_cg)
            m.return_value.__exit__ = MagicMock(return_value=None)
            from src.nodes.audit import audit_file
            state.update(audit_file(state))

        findings = state["findings"]
        assert len(findings) >= 1, f"audit 应发现至少 1 个漏洞，实际 {len(findings)}"
        f = findings[0]
        print(f"\n=== E2E audit 结果: {f.vuln_type} ({f.severity}) ===")

        # 2. trace_route — 真实 LLM
        with patch("src.nodes.trace_route.CodegraphClient") as m:
            m.return_value.__enter__ = MagicMock(return_value=mock_cg)
            m.return_value.__exit__ = MagicMock(return_value=None)
            from src.nodes.trace_route import trace_route
            state.update(trace_route(state))

        print(f"=== E2E trace 结果: {findings[0].reachability or 'N/A'} ===")

        # 3. verify — mock HttpClient + run_agent（不真实发 HTTP）
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

        confirmed = [f for f in findings if f.poc_result == "confirmed"]
        print(f"=== E2E verify 结果: {len(confirmed)} confirmed ===")

        # 4. record — 真实 ORM（需要真实 codegraph.db 有业务表）
        from src.nodes.record import record
        record(state)

        md_files = list(Path(state["findings_dir"]).glob("*.md"))
        print(f"=== E2E record 结果: {len(md_files)} .md files ===")
        assert len(md_files) >= 1, f"record 应生成 .md 文件，实际 {len(md_files)}"