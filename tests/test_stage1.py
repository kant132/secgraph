"""Stage 1 — 只 mock CodegraphClient 查询，LLM 全真实跑。

5 个真实 webgoat nodeid，运行时从真实 codegraph.db 查 method/fields/callees，
mock CodegraphClient 返回这些数据，然后真实 LLM 跑 audit + trace_route + verify + record。

需要：真实 codegraph.db + .env（LLM 配置）+ webgoat Docker（verify mock）
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


def make_mock_cg_from_real():
    """从真实 codegraph.db 查数据，构建 mock CodegraphClient。预查所有数据，查完关闭。"""
    from src.codegraph import CodegraphClient
    from src.state import MethodNode, FieldNode, FileAuditTask

    real_cg = CodegraphClient(WEBGOAT_DB)
    mock_cg = MagicMock()
    mock_cg._conn = MagicMock()
    mock_cg.init_memory_table.return_value = None
    mock_cg.save_memory.return_value = None
    mock_cg.lookup_memory.return_value = None

    tasks = []
    methods = []
    reachable_map = {}
    chain_map = {}
    chain_bodies_map = {}

    for nid in VULN_NODEIDS:
        row = real_cg._conn.execute(
            "SELECT id, qualified_name, name, signature, file_path, start_line, end_line FROM nodes WHERE id=?", (nid,)
        ).fetchone()
        m = MethodNode(id=row["id"], qualified_name=row["qualified_name"], name=row["name"],
                       signature=row["signature"], file_path=row["file_path"],
                       start_line=row["start_line"], end_line=row["end_line"])
        methods.append(m)
        fields = real_cg.list_fields_by_nodeid(nid)
        body = real_cg.get_method_body(WEBGOAT_SRC, m)
        callees = real_cg.get_callee_bodies(WEBGOAT_SRC, nid)
        task = FileAuditTask(file_path=row["file_path"], node_id=nid,
                            fields=fields, method_bodies={nid: body}, calls=callees)
        tasks.append(task)
        reachable_map[nid] = real_cg.is_route_reachable(nid)
        chain_map[nid] = real_cg.get_call_chain_to_route(nid)
        if chain_map[nid]:
            chain_bodies_map[nid] = real_cg.get_chain_bodies(WEBGOAT_SRC, chain_map[nid][0]["chain_ids"])
        else:
            chain_bodies_map[nid] = {}

    real_cg.close()

    mock_cg.list_entry_methods.return_value = methods
    mock_cg.list_fields_by_nodeid.side_effect = lambda nid: next((t.fields for t in tasks if t.node_id == nid), [])
    mock_cg.get_method_body.side_effect = lambda root, m: next((t.method_bodies[m.id] for t in tasks if t.node_id == m.id), "")
    mock_cg.get_callee_bodies.side_effect = lambda root, nid: next((t.calls for t in tasks if t.node_id == nid), {})
    mock_cg.is_route_reachable.side_effect = lambda nid: reachable_map.get(nid, False)
    mock_cg.get_call_chain_to_route.side_effect = lambda nid: chain_map.get(nid, [])
    mock_cg.get_chain_bodies.side_effect = lambda root, ids: next((v for k, v in chain_bodies_map.items() if k in ids), {})

    return mock_cg, tasks


@pytest.fixture
def state():
    tmpdir = tempfile.mkdtemp()
    return {
        "mode": "dev", "codegraph_db": WEBGOAT_DB, "sources_root": WEBGOAT_SRC,
        "pkg_prefix": "org/owasp/webgoat/lessons",
        "findings_dir": f"{tmpdir}/findings", "logs_dir": f"{tmpdir}/logs",
        "file_limit": len(VULN_NODEIDS), "run_id": "stage1", "max_iterations": 3,
        "llm_model": "test", "work_list": [], "audit_index": 0,
        "findings": [], "verified": [], "reflection_notes": [], "iteration": 0,
        "agent_history": [], "next_agent": "",
    }


class TestStage1:
    """只 mock codegraph 查询，LLM 全真实。"""

    def test_audit_all_nodeids(self, state):
        """audit 5 个真实 nodeid，验证 LLM 发现漏洞。"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        mock_cg, tasks = make_mock_cg_from_real()

        all_findings = []
        for task in tasks:
            state["work_list"] = [task]
            state["audit_index"] = 0
            with patch("src.codegraph.CodegraphClient") as m:
                m.return_value.__enter__ = MagicMock(return_value=mock_cg)
                m.return_value.__exit__ = MagicMock(return_value=None)
                from src.nodes.audit import audit_file
                state.update(audit_file(state))
                all_findings = state["findings"]

        print(f"\n=== audit: {len(all_findings)} findings ===")
        for f in all_findings:
            print(f"  {f.vuln_type} ({f.severity}) node={f.node_id[:30]}")

        assert len(all_findings) >= 1, "至少应发现 1 个漏洞"

    def test_full_pipeline(self, state):
        """完整 pipeline: audit → trace → verify → record。"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        mock_cg, tasks = make_mock_cg_from_real()

        # 1. audit
        for task in tasks:
            state["work_list"] = [task]
            state["audit_index"] = 0
            with patch("src.codegraph.CodegraphClient") as m:
                m.return_value.__enter__ = MagicMock(return_value=mock_cg)
                m.return_value.__exit__ = MagicMock(return_value=None)
                from src.nodes.audit import audit_file
                state.update(audit_file(state))

        findings = state["findings"]
        assert len(findings) >= 1

        # 2. trace_route
        with patch("src.nodes.trace_route.CodegraphClient") as m:
            m.return_value.__enter__ = MagicMock(return_value=mock_cg)
            m.return_value.__exit__ = MagicMock(return_value=None)
            from src.nodes.trace_route import trace_route
            state.update(trace_route(state))

        # 3. verify (mock HttpClient)
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

        # 4. record
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_cur.lastrowid = 1
        mock_conn.execute.return_value = mock_cur
        with patch("src.nodes.record.CodegraphClient") as m:
            m.return_value.__enter__ = MagicMock(return_value=MagicMock(_conn=mock_conn))
            m.return_value.__exit__ = MagicMock(return_value=None)
            from src.nodes.record import record
            record(state)

        print(f"\n=== pipeline 结果 ===")
        print(f"  findings: {len(state['findings'])}")
        for f in state["findings"]:
            print(f"  {f.vuln_type} → {f.poc_result}")

        md_files = list(Path(state["findings_dir"]).glob("*.md"))
        print(f"  .md files: {len(md_files)}")
        assert len(md_files) >= 1
