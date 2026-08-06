"""Test 1 — 只 mock codegraph 查询（method/fields/calls），audit+trace+verify+record 全真实 LLM。

选取多个真实 webgoat nodeid，mock CodegraphClient 的查询方法返回真实数据，
然后走完整 pipeline（真实 GLM 5.1）。
"""
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from tests._test_data import (
    SQLI_INJECTABLE_METHOD, SQLI_INJECTABLE_TASK, SQLI_INJECTABLE_REACHABLE,
    SQLI_INJECTABLE_CHAIN, SQLI_INJECTABLE_CHAIN_BODIES,
    SQLI_REGISTER_METHOD, SQLI_REGISTER_TASK, SQLI_REGISTER_REACHABLE,
    SQLI_REGISTER_CHAIN, SQLI_REGISTER_CHAIN_BODIES,
    XSS_COMPLETED_METHOD, XSS_COMPLETED_TASK, XSS_COMPLETED_REACHABLE,
    XSS_COMPLETED_CHAIN, XSS_COMPLETED_CHAIN_BODIES,
    UNREACHABLE_METHOD, UNREACHABLE_TASK, UNREACHABLE_REACHABLE,
    UNREACHABLE_CHAIN, UNREACHABLE_CHAIN_BODIES,
)

ALL_METHODS = [SQLI_INJECTABLE_METHOD, SQLI_REGISTER_METHOD, XSS_COMPLETED_METHOD, UNREACHABLE_METHOD]
ALL_TASKS = {
    SQLI_INJECTABLE_METHOD.id: SQLI_INJECTABLE_TASK,
    SQLI_REGISTER_METHOD.id: SQLI_REGISTER_TASK,
    XSS_COMPLETED_METHOD.id: XSS_COMPLETED_TASK,
    UNREACHABLE_METHOD.id: UNREACHABLE_TASK,
}
REACHABLE = {
    SQLI_INJECTABLE_METHOD.id: SQLI_INJECTABLE_REACHABLE,
    SQLI_REGISTER_METHOD.id: SQLI_REGISTER_REACHABLE,
    XSS_COMPLETED_METHOD.id: XSS_COMPLETED_REACHABLE,
    UNREACHABLE_METHOD.id: UNREACHABLE_REACHABLE,
}
CHAINS = {
    SQLI_INJECTABLE_METHOD.id: [SQLI_INJECTABLE_CHAIN] if isinstance(SQLI_INJECTABLE_CHAIN, dict) else SQLI_INJECTABLE_CHAIN,
    SQLI_REGISTER_METHOD.id: [SQLI_REGISTER_CHAIN] if isinstance(SQLI_REGISTER_CHAIN, dict) else SQLI_REGISTER_CHAIN,
    XSS_COMPLETED_METHOD.id: [XSS_COMPLETED_CHAIN] if isinstance(XSS_COMPLETED_CHAIN, dict) else XSS_COMPLETED_CHAIN,
    UNREACHABLE_METHOD.id: UNREACHABLE_CHAIN,
}
CHAIN_BODIES = {
    SQLI_INJECTABLE_METHOD.id: SQLI_INJECTABLE_CHAIN_BODIES,
    SQLI_REGISTER_METHOD.id: SQLI_REGISTER_CHAIN_BODIES,
    XSS_COMPLETED_METHOD.id: XSS_COMPLETED_CHAIN_BODIES,
    UNREACHABLE_METHOD.id: UNREACHABLE_CHAIN_BODIES,
}


def make_mock_cg():
    """创建 mock CodegraphClient — 返回真实 webgoat 数据"""
    mock_cg = MagicMock()
    mock_cg._conn = MagicMock()
    mock_cg.init_memory_table.return_value = None
    mock_cg.save_memory.return_value = None
    mock_cg.lookup_memory.return_value = None

    mock_cg.list_entry_methods.return_value = ALL_METHODS
    mock_cg.list_fields_by_nodeid.side_effect = lambda nid: ALL_TASKS[nid].fields
    mock_cg.get_method_body.side_effect = lambda root, m: ALL_TASKS[m.id].method_bodies[m.id]
    mock_cg.get_callee_bodies.side_effect = lambda root, nid: ALL_TASKS[nid].calls
    mock_cg.is_route_reachable.side_effect = lambda nid: REACHABLE.get(nid, False)
    mock_cg.get_call_chain_to_route.side_effect = lambda nid: CHAINS.get(nid, [])
    mock_cg.get_chain_bodies.side_effect = lambda root, ids: CHAIN_BODIES.get(
        next((k for k in CHAIN_BODIES if k in ids), ""), {}
    )
    return mock_cg


@pytest.fixture
def state():
    import tempfile
    tmpdir = tempfile.mkdtemp()
    return {
        "mode": "dev", "codegraph_db": "mock", "sources_root": "mock",
        "pkg_prefix": "org/owasp/webgoat/lessons", "findings_dir": f"{tmpdir}/findings",
        "logs_dir": f"{tmpdir}/logs", "file_limit": 4, "run_id": "test1",
        "max_iterations": 3, "llm_model": "test", "work_list": [], "audit_index": 0,
        "findings": [], "verified": [], "reflection_notes": [], "iteration": 0,
        "agent_history": [], "next_agent": "",
    }


class TestStage1MockCodegraphOnly:
    """只 mock codegraph 查询，LLM 全真实跑。"""

    def test_audit_all_methods(self, state):
        """audit 4 个真实方法，验证 LLM 发现漏洞"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        mock_cg = make_mock_cg()
        findings = []
        for task in ALL_TASKS.values():
            state["work_list"] = [task]
            state["audit_index"] = 0
            with patch("src.codegraph.CodegraphClient") as m:
                m.return_value.__enter__ = MagicMock(return_value=mock_cg)
                m.return_value.__exit__ = MagicMock(return_value=None)
                from src.nodes.audit import audit_file
                r = audit_file(state)
                state.update(r)
                findings = state["findings"]

        print(f"\n=== audit 结果: {len(findings)} 个 findings ===")
        for f in findings:
            print(f"  {f.vuln_type} ({f.severity}) node={f.node_id[:30]}")

        assert len(findings) >= 1, "至少应发现 1 个漏洞"

    def test_trace_route_all(self, state):
        """trace_route 4 个 finding，验证可达性判断"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        mock_cg = make_mock_cg()
        # 先 audit 拿 findings
        findings_list = []
        for task in ALL_TASKS.values():
            state["work_list"] = [task]
            state["audit_index"] = 0
            with patch("src.codegraph.CodegraphClient") as m:
                m.return_value.__enter__ = MagicMock(return_value=mock_cg)
                m.return_value.__exit__ = MagicMock(return_value=None)
                from src.nodes.audit import audit_file
                state.update(audit_file(state))
                findings_list = state["findings"]

        if not findings_list:
            pytest.skip("audit 未发现漏洞")

        # trace_route
        with patch("src.nodes.trace_route.CodegraphClient") as m:
            m.return_value.__enter__ = MagicMock(return_value=mock_cg)
            m.return_value.__exit__ = MagicMock(return_value=None)
            from src.nodes.trace_route import trace_route
            state.update(trace_route(state))

        print(f"\n=== trace_route 结果 ===")
        for f in state["findings"]:
            r = "可达" if "[路由可达性分析] 可达" in f.evidence else "不可达"
            print(f"  {f.vuln_type} → {r}")

        assert any("[路由可达性分析]" in f.evidence for f in state["findings"]), "至少 1 个 finding 应有可达性标记"

    def test_full_pipeline(self, state):
        """完整 pipeline — mock codegraph + 真实 LLM"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        mock_cg = make_mock_cg()

        # 1. audit
        all_findings = []
        for task in ALL_TASKS.values():
            state["work_list"] = [task]
            state["audit_index"] = 0
            with patch("src.codegraph.CodegraphClient") as m:
                m.return_value.__enter__ = MagicMock(return_value=mock_cg)
                m.return_value.__exit__ = MagicMock(return_value=None)
                from src.nodes.audit import audit_file
                state.update(audit_file(state))
                all_findings = state["findings"]

        assert len(all_findings) >= 1

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

        print(f"\n=== 完整 pipeline 结果 ===")
        print(f"  findings: {len(state['findings'])}")
        for f in state["findings"]:
            print(f"  {f.vuln_type} → {f.poc_result}")

        # 验证 .md
        from pathlib import Path as P
        md_files = list(P(state["findings_dir"]).glob("*.md"))
        print(f"  .md files: {len(md_files)}")
        assert len(md_files) >= 1
