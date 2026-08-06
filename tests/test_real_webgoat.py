"""真实 webgoat 漏洞 nodeid 的端到端测试。

用 webgoat codegraph.db 真实数据（不 mock codegraph 查询），
LLM 真实跑，验证完整 pipeline。

3 个真实漏洞 nodeid：
  1. SQLi — SqlInjectionLesson6a::injectableQuery (method:997b7879a35fb0d978b1dec266c18e63)
  2. SQLi — SqlInjectionChallenge::registerNewUser (method:647d162fdf923cdfbc8d4343d418e51e)
  3. XSS — CrossSiteScriptingLesson1::completed (method:7ee6991165334a5b9998084beba380b5)

1 个不可达 nodeid：
  4. SqlInjectionLesson6a 构造函数 (method:1a6f33df415e87274a6d8b8b3c777423) — 不在 route_reachable
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.state import AuditState, Finding, FileAuditTask, FieldNode, MethodNode

# ---------------------------------------------------------------------------
# 真实 webgoat 数据
# ---------------------------------------------------------------------------

WEBGOAT_DB = r"D:\jar\webgoat\.codegraph\codegraph.db"
WEBGOAT_SOURCES = r"D:\jar\webgoat"

# 真实 nodeid
NODEID_SQLI_INJECTABLE = "method:997b7879a35fb0d978b1dec266c18e63"
NODEID_SQLI_REGISTER = "method:647d162fdf923cdfbc8d4343d418e51e"
NODEID_XSS_COMPLETED = "method:7ee6991165334a5b9998084beba380b5"
NODEID_UNREACHABLE = "method:1a6f33df415e87274a6d8b8b3c777423"

# 真实方法元数据
METHOD_SQLI_INJECTABLE = MethodNode(
    id=NODEID_SQLI_INJECTABLE,
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery",
    name="injectableQuery",
    signature="AttackResult (String accountName)",
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    start_line=36, end_line=53,
)

METHOD_SQLI_REGISTER = MethodNode(
    id=NODEID_SQLI_REGISTER,
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionChallenge::registerNewUser",
    name="registerNewUser",
    signature='AttackResult (@RequestParam("username_reg") String username, @RequestParam("email_reg") String email, @RequestParam("password_reg") String password)',
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java",
    start_line=35, end_line=66,
)

METHOD_XSS_COMPLETED = MethodNode(
    id=NODEID_XSS_COMPLETED,
    qualified_name="org.owasp.webgoat.lessons.xss::CrossSiteScriptingLesson1::completed",
    name="completed",
    signature="AttackResult (@RequestParam String userid_6a)",
    file_path="sources/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java",
    start_line=1, end_line=20,
)

METHOD_UNREACHABLE = MethodNode(
    id=NODEID_UNREACHABLE,
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::SqlInjectionLesson6a",
    name="SqlInjectionLesson6a",
    signature="SqlInjectionLesson6a (LessonDataSource dataSource)",
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    start_line=22, end_line=25,
)


@pytest.fixture
def real_db():
    """检查 webgoat DB 是否存在"""
    if not os.path.exists(WEBGOAT_DB):
        pytest.skip(f"webgoat DB 不存在: {WEBGOAT_DB}")
    return WEBGOAT_DB


@pytest.fixture
def real_state():
    """真实 state — 用 webgoat 项目路径"""
    tmpdir = str(Path(__file__).parent / "test_output")
    Path(tmpdir, "findings").mkdir(parents=True, exist_ok=True)
    Path(tmpdir, "logs").mkdir(parents=True, exist_ok=True)
    return {
        "mode": "dev",
        "codegraph_db": WEBGOAT_DB,
        "sources_root": WEBGOAT_SOURCES,
        "pkg_prefix": "org/owasp/webgoat/lessons/sqlinjection",
        "findings_dir": str(Path(tmpdir) / "findings"),
        "logs_dir": str(Path(tmpdir) / "logs"),
        "file_limit": 10,
        "run_id": "test_real",
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


class TestRealWebgoatNodeIDs:
    """用真实 webgoat nodeid 测试完整 pipeline。"""

    def test_sqli_injectable_query(self, real_db, real_state):
        """测试 SqlInjectionLesson6a::injectableQuery — SQL 注入（真实代码）"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        # 用真实 codegraph 构建 work_list
        from src.codegraph import CodegraphClient
        with CodegraphClient(real_db) as cg:
            method = METHOD_SQLI_INJECTABLE
            fields = cg.list_fields_by_nodeid(method.id)
            method_body = cg.get_method_body(WEBGOAT_SOURCES, method)
            calls = cg.get_callee_bodies(WEBGOAT_SOURCES, method.id)

            print(f"\n=== 真实方法体 ===")
            print(f"  fqn: {method.qualified_name}")
            print(f"  file: {method.file_path}")
            print(f"  lines: {method.start_line}-{method.end_line}")
            print(f"  body (前 300 字): {method_body[:300]}")
            print(f"  callees: {list(calls.keys())}")

        task = FileAuditTask(
            file_path=method.file_path,
            node_id=method.id,
            fields=fields,
            method_bodies={method.id: method_body},
            calls=calls,
        )
        real_state["work_list"] = [task]
        real_state["audit_index"] = 0

        # audit (真实 LLM)
        from src.nodes.audit import audit_file
        with patch("src.codegraph.CodegraphClient") as mock_cg_class:
            mock_cg = MagicMock()
            mock_cg._conn = MagicMock()
            mock_cg.init_memory_table.return_value = None
            mock_cg.save_memory.return_value = None
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)
            result = audit_file(real_state)

        findings = result.get("findings", [])
        print(f"\n=== audit 结果: {len(findings)} 个 findings ===")
        for f in findings:
            print(f"  {f.vuln_type} ({f.severity}) conf={f.confidence}")
            print(f"  evidence: {f.evidence[:100]}")

        assert len(findings) >= 1, "injectableQuery 应发现 SQLi"
        assert any(f.vuln_type == "SQLi" for f in findings), "应发现 SQLi 类型"

    def test_route_reachable_check(self, real_db):
        """测试 route 可达性判断 — 真实 nodeid"""
        from src.codegraph import CodegraphClient
        with CodegraphClient(real_db) as cg:
            # SQLi injectableQuery — 应可达
            assert cg.is_route_reachable(NODEID_SQLI_INJECTABLE), "injectableQuery 应 route 可达"

            # SQLi registerNewUser — 应可达
            assert cg.is_route_reachable(NODEID_SQLI_REGISTER), "registerNewUser 应 route 可达"

            # XSS completed — 应可达
            assert cg.is_route_reachable(NODEID_XSS_COMPLETED), "XSS completed 应 route 可达"

            # 构造函数 — 不应可达
            assert not cg.is_route_reachable(NODEID_UNREACHABLE), "构造函数不应 route 可达"

    def test_full_pipeline_real_sqli(self, real_db, real_state):
        """完整 pipeline — 用真实 SqlInjectionLesson6a::injectableQuery"""
        pytest.importorskip("langchain_openai")
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置")

        # 1. discover — 用真实 codegraph 构建 task
        from src.codegraph import CodegraphClient
        with CodegraphClient(real_db) as cg:
            method = METHOD_SQLI_INJECTABLE
            fields = cg.list_fields_by_nodeid(method.id)
            method_body = cg.get_method_body(WEBGOAT_SOURCES, method)
            calls = cg.get_callee_bodies(WEBGOAT_SOURCES, method.id)

        task = FileAuditTask(
            file_path=method.file_path,
            node_id=method.id,
            fields=fields,
            method_bodies={method.id: method_body},
            calls=calls,
        )
        real_state["work_list"] = [task]
        real_state["audit_index"] = 0

        # 2. audit (真实 LLM)
        from src.nodes.audit import audit_file
        with patch("src.codegraph.CodegraphClient") as mock_cg_class:
            mock_cg = MagicMock()
            mock_cg._conn = MagicMock()
            mock_cg.init_memory_table.return_value = None
            mock_cg.save_memory.return_value = None
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)
            real_state.update(audit_file(real_state))

        findings = real_state["findings"]
        print(f"\n=== audit: {len(findings)} findings ===")
        for f in findings:
            print(f"  {f.vuln_type} ({f.severity}) conf={f.confidence}")
        assert len(findings) >= 1, "应发现至少 1 个漏洞"

        # 3. trace_route (真实 Q5 + 真实 LLM)
        from src.nodes.trace_route import trace_route
        real_state.update(trace_route(real_state))

        print(f"\n=== trace_route 结果 ===")
        for f in real_state["findings"]:
            reachable = "可达" if "[路由可达性分析] 可达" in f.evidence else "不可达"
            print(f"  {f.vuln_type} → {reachable}")
            if f.payload:
                print(f"  payload: {f.payload[:80]}")

        assert any("[路由可达性分析] 可达" in f.evidence for f in real_state["findings"]), \
            "至少 1 个 finding 应可达"

        # 4. verify (mock HttpClient + 真实 LLM)
        mock_login_info = {
            "target_url": "http://localhost:18080/WebGoat",
            "login_url": "http://localhost:18080/WebGoat/login",
            "login_method": "POST",
            "login_body": "username=admin1&password=admin1",
            "login_headers": {},
            "status": "verified",
        }
        mock_http = MagicMock()
        mock_http.login.return_value = True
        mock_http.session = MagicMock()
        mock_http.session.cookies = MagicMock()
        mock_http.session.cookies.items.return_value = [("JSESSIONID", "mock")]
        # send 返回的真实类型 (status:int, headers:dict, body:str)
        mock_http.send.return_value = (200, {"Content-Type": "application/json"},
                                       '{"output": "101,Joe,Snow,987654321,VISA"}')
        # session.post/get 返回的 resp 也 mock
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"output": "101,Joe,Snow,987654321,VISA"}'
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_http.session.post.return_value = mock_resp
        mock_http.session.get.return_value = mock_resp

        with patch("src.nodes.verify.node.read_login_info", return_value=mock_login_info), \
             patch("src.nodes.verify.node.HttpClient", return_value=mock_http), \
             patch("src.nodes.verify.node.run_agent") as mock_run_agent:
            mock_run_agent.return_value = (True, "PoC 验证成功，响应包含数据库数据",
                                           "POST /SqlInjectionAdvanced/attack6a HTTP/1.1\n\nuserid_6a=' OR '1'='1",
                                           [])
            from src.nodes.verify.node import verify_finding
            real_state.update(verify_finding(real_state))

        print(f"\n=== verify 结果 ===")
        for f in real_state["findings"]:
            print(f"  {f.vuln_type} → poc_result={f.poc_result}")

        # 5. record (mock CodegraphClient + .md)
        mock_conn_rec = MagicMock()
        mock_cursor_rec = MagicMock()
        mock_cursor_rec.lastrowid = 1
        mock_conn_rec.execute.return_value = mock_cursor_rec
        with patch("src.nodes.record.CodegraphClient") as mock_cg_class_rec:
            mock_cg_rec = MagicMock()
            mock_cg_rec._conn = mock_conn_rec
            mock_cg_class_rec.return_value.__enter__ = MagicMock(return_value=mock_cg_rec)
            mock_cg_class_rec.return_value.__exit__ = MagicMock(return_value=None)
            from src.nodes.record import record
            record(real_state)

        # 验证 .md
        findings_dir = Path(real_state["findings_dir"])
        md_files = list(findings_dir.glob("*.md"))
        print(f"\n=== record: {len(md_files)} 个 .md ===")
        for md in md_files:
            print(f"  {md.name}")
        assert len(md_files) >= 1, "至少 1 个 .md"

        print(f"\n=== 完整 pipeline 验证通过 ===")
