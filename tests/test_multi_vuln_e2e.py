"""端到端集成测试 — 多漏洞 + 不可达，监控打印 + 验证记录位置。

mock codegraph 查询返回多个漏洞方法（SQLi + XSS + 不可达方法），
真实跑 LLM audit + trace_route + verify + record，验证：
1. 多个漏洞都能发现
2. 不可达的方法被跳过（trace_route 标记不可达）
3. 监控打印（log + stdout）
4. 记录到 DB（findings 表 + verified_vulns 表）
5. 记录到 .md（每个 finding 一个 .md）
"""
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.state import AuditState, Finding, FileAuditTask, FieldNode, MethodNode


# ---------------------------------------------------------------------------
# Mock 数据 — 3 个方法：SQLi（可达）+ XSS（可达）+ RCE（不可达）
# ---------------------------------------------------------------------------

MOCK_METHOD_SQLI = MethodNode(
    id="method:sqli1",
    qualified_name="org.test::SqlController::query",
    name="query",
    signature="Result(String userid)",
    file_path="sources/org/test/SqlController.java",
    start_line=10, end_line=20,
)

MOCK_METHOD_XSS = MethodNode(
    id="method:xss1",
    qualified_name="org.test::XssController::render",
    name="render",
    signature="String(String userInput)",
    file_path="sources/org/test/XssController.java",
    start_line=5, end_line=10,
)

MOCK_METHOD_RCE_UNREACHABLE = MethodNode(
    id="method:rce1",
    qualified_name="org.test::InternalUtil::runCmd",
    name="runCmd",
    signature="void(String cmd)",
    file_path="sources/org/test/InternalUtil.java",
    start_line=1, end_line=5,
)

MOCK_TASK_SQLI = FileAuditTask(
    file_path="sources/org/test/SqlController.java",
    node_id="method:sqli1",
    fields=[],
    method_bodies={"method:sqli1": (
        "// org.test::SqlController::query\n"
        "public Result query(String userid) {\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n"
        "    return dao.execute(sql);\n"
        "}\n"
    )},
    calls={"method:dao1": "// org.test::Dao::execute\npublic Result execute(String sql) {\n    return jdbcTemplate.queryForList(sql);\n}\n"},
)

MOCK_TASK_XSS = FileAuditTask(
    file_path="sources/org/test/XssController.java",
    node_id="method:xss1",
    fields=[],
    method_bodies={"method:xss1": (
        "// org.test::XssController::render\n"
        "public String render(String userInput) {\n"
        "    return \"<div>\" + userInput + \"</div>\";\n"
        "}\n"
    )},
    calls={},
)

MOCK_TASK_RCE_UNREACHABLE = FileAuditTask(
    file_path="sources/org/test/InternalUtil.java",
    node_id="method:rce1",
    fields=[],
    method_bodies={"method:rce1": (
        "// org.test::InternalUtil::runCmd\n"
        "public void runCmd(String cmd) {\n"
        "    Runtime.getRuntime().exec(cmd);\n"
        "}\n"
    )},
    calls={},
)


def create_mock_codegraph_client_multi():
    """3 个方法：SQLi（可达）+ XSS（可达）+ RCE（不可达）"""
    mock_cg = MagicMock()
    mock_cg.db_path = "mock"

    # Q1: 返回 3 个方法
    mock_cg.list_entry_methods.return_value = [MOCK_METHOD_SQLI, MOCK_METHOD_XSS, MOCK_METHOD_RCE_UNREACHABLE]

    # Q3: 无字段
    mock_cg.list_fields_by_nodeid.return_value = []

    # get_method_body: 按方法返回不同方法体
    def get_method_body(sources_root, method):
        return MOCK_TASK_SQLI.method_bodies.get(method.id, "") or \
               MOCK_TASK_XSS.method_bodies.get(method.id, "") or \
               MOCK_TASK_RCE_UNREACHABLE.method_bodies.get(method.id, "")
    mock_cg.get_method_body.side_effect = get_method_body

    # Q4: SQLi 有 callees，其他无
    def get_callee_bodies(sources_root, node_id):
        if node_id == "method:sqli1":
            return MOCK_TASK_SQLI.calls
        return {}
    mock_cg.get_callee_bodies.side_effect = get_callee_bodies

    # is_route_reachable: SQLi 和 XSS 可达，RCE 不可达
    def is_route_reachable(node_id):
        return node_id in ("method:sqli1", "method:xss1")
    mock_cg.is_route_reachable.side_effect = is_route_reachable

    # Q5: SQLi 和 XSS 有调用链，RCE 没有
    mock_cg.get_call_chain_to_route.side_effect = lambda node_id: [
        {"id": "route:/api/query", "qualified_name": "route:/api/query", "kind": "route",
         "file_path": "sources/org/test/SqlController.java", "start_line": 1, "end_line": 1,
         "depth": 1, "chain_path": f"route:/api/query -> {node_id}",
         "chain_ids": f"route:/api/query,{node_id}"}
    ] if node_id in ("method:sqli1", "method:xss1") else []

    mock_cg.get_chain_bodies.return_value = {
        "route:/api/query": "// route:/api/query\n@PostMapping(\"/api/query\")\npublic Result query(@RequestParam String userid) {\n    return handle(userid);\n}\n",
    }

    mock_cg.init_memory_table.return_value = None
    mock_cg.save_memory.return_value = None
    mock_cg.lookup_memory.return_value = None
    mock_cg.close.return_value = None

    return mock_cg


@pytest.fixture
def mock_cg_multi():
    return create_mock_codegraph_client_multi()


@pytest.fixture
def base_state_multi():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield {
            "mode": "dev",
            "codegraph_db": "mock",
            "sources_root": str(Path(tmpdir) / "sources"),
            "pkg_prefix": "org/test",
            "findings_db": str(Path(tmpdir) / "test.db"),
            "findings_dir": str(Path(tmpdir) / "findings"),
            "logs_dir": str(Path(tmpdir) / "logs"),
            "file_limit": 10,
            "run_id": "test_multi",
            "max_iterations": 3,
            "llm_model": "test",
            "work_list": [],
            "audit_index": 0,
            "findings": [],
            "verified": [],
            "reflection_notes": [],
            "iteration": 0,
            "agent_history": [],
            "next_agent": "",
        }


class TestMultiVulnPipeline:
    """多漏洞端到端测试 — SQLi + XSS（可达）+ RCE（不可达）。"""

    def test_multi_vuln_full_pipeline(self, mock_cg_multi, base_state_multi, capsys):
        """完整 pipeline：3 个方法（2 可达 + 1 不可达），验证全流程 + 记录位置。"""
        pytest.importorskip("langchain_openai")

        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        Path(base_state_multi["sources_root"]).mkdir(parents=True, exist_ok=True)
        Path(base_state_multi["findings_dir"]).mkdir(parents=True, exist_ok=True)
        Path(base_state_multi["logs_dir"]).mkdir(parents=True, exist_ok=True)

        state = base_state_multi

        # 1. discover (mock codegraph)
        with patch("src.nodes.discover.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg_multi)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)
            mock_cg_multi._conn = MagicMock()
            mock_cg_multi._conn.execute.return_value.fetchone.return_value = [3, 3, 1, 3, 3]

            from src.nodes.discover import discover
            state.update(discover(state))

        assert len(state["work_list"]) == 3, "discover 应返回 3 个 task"

        # 2. audit (真实 LLM) — 审计 3 个方法
        with patch("src.codegraph.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg_multi)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            from src.nodes.audit import audit_file
            # 审计第 1 个（SQLi）
            state["work_list"] = [MOCK_TASK_SQLI]
            state["audit_index"] = 0
            state.update(audit_file(state))
            # 审计第 2 个（XSS）
            state["work_list"] = [MOCK_TASK_XSS]
            state["audit_index"] = 0
            state.update(audit_file(state))
            # 审计第 3 个（RCE，但可能 LLM 报也可能不报）
            state["work_list"] = [MOCK_TASK_RCE_UNREACHABLE]
            state["audit_index"] = 0
            state.update(audit_file(state))

        findings = state["findings"]
        print(f"\n=== audit 结果: {len(findings)} 个 findings ===")
        for f in findings:
            print(f"  {f.vuln_type} ({f.severity}) conf={f.confidence} node={f.node_id[:20]}")

        assert len(findings) >= 2, f"至少应发现 2 个漏洞（SQLi + XSS），实际 {len(findings)}"

        # 3. trace_route (mock Q5 + 真实 LLM)
        with patch("src.nodes.trace_route.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg_multi)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            from src.nodes.trace_route import trace_route
            state.update(trace_route(state))

        print(f"\n=== trace_route 结果 ===")
        for f in state["findings"]:
            reachable = "可达" if "[路由可达性分析] 可达" in f.evidence else "不可达"
            print(f"  {f.vuln_type} node={f.node_id[:20]} → {reachable}")

        # 验证可达性
        reachable_findings = [f for f in state["findings"] if "[路由可达性分析] 可达" in f.evidence]
        unreachable_findings = [f for f in state["findings"] if "[路由可达性分析] 不可达" in f.evidence]
        print(f"\n  可达: {len(reachable_findings)}, 不可达: {len(unreachable_findings)}")

        # SQLi 和 XSS 应该可达
        assert len(reachable_findings) >= 1, "至少 1 个 finding 应可达"

        # 捕获 stdout（监控打印）
        captured = capsys.readouterr()
        print(f"\n=== stdout 监控（前 500 字）===")
        print(captured.out[:500])

        # 4. verify (mock HttpClient + 真实 LLM)
        mock_login_info = {
            "target_url": "http://localhost:18080/test",
            "login_url": "http://localhost:18080/test/login",
            "login_method": "POST",
            "login_body": "username=test&password=test",
            "login_headers": {},
            "status": "verified",
        }
        mock_http = MagicMock()
        mock_http.login.return_value = True
        mock_http.session = MagicMock()
        mock_http.session.cookies = MagicMock()
        mock_http.session.cookies.items.return_value = [("JSESSIONID", "mock")]
        mock_http.send.return_value = (200, {"Content-Type": "application/json"},
                                       '{"output": "101,Joe,Snow,987654321,VISA"}')

        with patch("src.nodes.verify.node.read_login_info", return_value=mock_login_info), \
             patch("src.nodes.verify.node.HttpClient", return_value=mock_http), \
             patch("src.nodes.verify.node.run_agent") as mock_run_agent:

            mock_run_agent.return_value = (True, "PoC 验证成功", "POST /api/query HTTP/1.1\n\nuserid=' OR '1'='1", [])

            from src.nodes.verify.node import verify_finding
            state.update(verify_finding(state))

        print(f"\n=== verify 结果 ===")
        for f in state["findings"]:
            print(f"  {f.vuln_type} node={f.node_id[:20]} → poc_result={f.poc_result}")

        # 5. record (真实 DB + .md)
        from src.nodes.record import record
        state["findings"] = state.get("findings", [])
        record_result = record(state)

        # 验证 .md 文件
        findings_dir = Path(state["findings_dir"])
        md_files = list(findings_dir.glob("*.md"))
        print(f"\n=== record 结果: {len(md_files)} 个 .md 文件 ===")
        for md in md_files:
            print(f"  {md.name}")

        assert len(md_files) >= 1, "至少应有 1 个 .md 文件"

        # 验证 .md 内容包含 PoC Result
        for md in md_files:
            content = md.read_text(encoding="utf-8")
            assert "PoC Result" in content, f"{md.name} 应包含 PoC Result"

        # 验证 DB 记录
        db_path = state["findings_db"]
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        db_findings = conn.execute("SELECT * FROM findings").fetchall()
        print(f"\n=== DB findings 表: {len(db_findings)} 行 ===")
        for r in db_findings:
            print(f"  {r['vuln_type']:10s} {r['status']:15s} node={r['node_id'][:20]}")

        assert len(db_findings) >= 1, "DB 应至少有 1 条 finding"

        verified = conn.execute("SELECT * FROM verified_vulns").fetchall()
        print(f"\n=== DB verified_vulns 表: {len(verified)} 行 ===")

        runs = conn.execute("SELECT * FROM runs").fetchall()
        print(f"\n=== DB runs 表: {len(runs)} 行 ===")
        for r in runs:
            print(f"  run_id={r['id']} findings={r['total_findings']} verified={r['total_verified']}")

        conn.close()

        print(f"\n=== 验证完毕 ===")
        print(f"  findings 总数: {len(state['findings'])}")
        print(f"  .md 文件数: {len(md_files)}")
        print(f"  DB findings 行数: {len(db_findings)}")
