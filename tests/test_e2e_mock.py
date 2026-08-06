"""端到端集成测试 — mock codegraph + mock LLM，测试完整 pipeline 流程。

用 pytest + unittest.mock 测试 discovery→trace→verify→record 全流程。
不依赖真实 codegraph.db / 不调真实 LLM。
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.state import (
    AuditState, Finding, FileAuditTask, FieldNode, MethodNode,
    VulnDetail, AuditResult, ReachabilityResult, PoCVerificationResult,
    SupervisorDecision,
)


# ---------------------------------------------------------------------------
# Mock 数据
# ---------------------------------------------------------------------------

MOCK_METHOD = MethodNode(
    id="method:997b7879a35fb0d978b1dec266c18e63",
    qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery",
    name="injectableQuery",
    signature="AttackResult (String accountName)",
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    start_line=36,
    end_line=53,
)

MOCK_TASK = FileAuditTask(
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    node_id="method:997b7879a35fb0d978b1dec266c18e63",
    fields=[FieldNode(id="field:1", qualified_name="org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::dataSource", name="dataSource", start_line=23, end_line=23)],
    method_bodies={"method:997b7879a35fb0d978b1dec266c18e63": (
        "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery\n"
        "public AttackResult injectableQuery(String accountName) {\n"
        "    String query = \"\";\n"
        "    try {\n"
        "        Connection connection = this.dataSource.getConnection();\n"
        "        try {\n"
        "            boolean usedUnion = unionQueryChecker(accountName);\n"
        "            query = \"SELECT * FROM user_data WHERE last_name = '\" + accountName + \"'\";\n"
        "            AttackResult attackResultExecuteSqlInjection = executeSqlInjection(connection, query, usedUnion);\n"
        "            if (connection != null) { connection.close(); }\n"
        "            return attackResultExecuteSqlInjection;\n"
        "        } finally {}\n"
        "    } catch (Exception e) {\n"
        "        return AttackResultBuilder.failed(this).output(...).build();\n"
        "    }\n"
        "}\n"
    )},
    calls={
        "method:6132b9dafbe4e0a343bbcf84c0e33021": (
            "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::unionQueryChecker\n"
            "private boolean unionQueryChecker(String accountName) {\n"
            "    return accountName.matches(\"(?i)(^[^-/*;)]*)(\\\\s*)UNION(.*$)\");\n"
            "}\n"
        ),
        "method:20df665d446bd71e644585b43acf7832": (
            "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::executeSqlInjection\n"
            "private AttackResult executeSqlInjection(Connection connection, String query, boolean usedUnion) {\n"
            "    Statement statement = connection.createStatement(1004, 1007);\n"
            "    ResultSet results = statement.executeQuery(query);\n"
            "    ...\n"
            "}\n"
        ),
    },
)

MOCK_FINDING = Finding(
    file_path="sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    node_id="method:997b7879a35fb0d978b1dec266c18e63",
    vuln_type="SQLi",
    severity="critical",
    evidence="accountName 直接拼接到 SQL 语句 query = \"SELECT * FROM user_data WHERE last_name = '\" + accountName + \"'\"，无参数化查询，无消毒",
    payload="POST /SqlInjectionAdvanced/attack6a HTTP/1.1\n\nuserid_6a=' OR '1'='1",
    confidence=0.9,
)

MOCK_CHAIN = [{
    "id": "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java::route:/SqlInjectionAdvanced/attack6a",
    "qualified_name": "route:/SqlInjectionAdvanced/attack6a",
    "kind": "route",
    "file_path": "sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java",
    "start_line": 30,
    "end_line": 34,
    "depth": 1,
    "chain_path": "route:/SqlInjectionAdvanced/attack6a -> org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::completed -> org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery",
    "chain_ids": "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java::route:/SqlInjectionAdvanced/attack6a,method:0d187d9ac1aa8a2efc9d66e1b0077f5d,method:997b7879a35fb0d978b1dec266c18e63",
}]

MOCK_CHAIN_BODIES = {
    "route:sources/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java::route:/SqlInjectionAdvanced/attack6a": (
        "// route:/SqlInjectionAdvanced/attack6a\n"
        "@PostMapping({\"/SqlInjectionAdvanced/attack6a\"})\n"
        "public AttackResult completed(@RequestParam(\"userid_6a\") String userId) {\n"
        "    return injectableQuery(userId);\n"
        "}\n"
    ),
    "method:0d187d9ac1aa8a2efc9d66e1b0077f5d": (
        "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::completed\n"
        "public AttackResult completed(@RequestParam(\"userid_6a\") String userId) {\n"
        "    return injectableQuery(userId);\n"
        "}\n"
    ),
    "method:997b7879a35fb0d978b1dec266c18e63": (
        "// org.owasp.webgoat.lessons.sqlinjection.advanced::SqlInjectionLesson6a::injectableQuery\n"
        "public AttackResult injectableQuery(String accountName) {\n"
        "    query = \"SELECT * FROM user_data WHERE last_name = '\" + accountName + \"'\";\n"
        "    return executeSqlInjection(connection, query, usedUnion);\n"
        "}\n"
    ),
}

MOCK_AUDIT_RESULT = AuditResult.model_validate({
    "method:997b7879a35fb0d978b1dec266c18e63": {
        "vuln_type": "SQLi",
        "severity": "critical",
        "evidence": "accountName 直接拼接到 SQL 语句，无参数化查询，无消毒",
        "payload": "' OR '1'='1",
        "confidence": 0.9,
        "input_validation": "unionQueryChecker 仅检查 UNION 关键字，不做输入过滤",
        "output_limitation": "无",
        "called_methods": "executeSqlInjection, unionQueryChecker",
        "security_risk": "SQL注入：accountName 未消毒直接拼接 SQL",
    }
})

MOCK_REACHABILITY_RESULT = ReachabilityResult(
    reachable=True,
    updated_payload="POST /SqlInjectionAdvanced/attack6a HTTP/1.1\n\nuserid_6a=' OR '1'='1",
    conditions="需要 POST 到 /SqlInjectionAdvanced/attack6a，提供 userid_6a 参数",
    confidence=0.9,
)

MOCK_POC_RESULT = PoCVerificationResult(
    verified=True,
    cvss_score="9.8 Critical",
    cia_proof="C: PoC 返回了 user_data 表数据（id, name, password）",
    reasoning="响应 body 包含数据库数据，SQL注入成功",
    second_payload="",
)


class TestEndToEnd:
    """端到端测试 — mock codegraph + mock LLM，完整 pipeline。"""

    def test_discovery_finds_vuln(self):
        """测试 discovery → audit 发现漏洞。"""
        from src.nodes.agents.discovery import discovery_agent

        state: AuditState = {
            "mode": "dev",
            "codegraph_db": "mock",
            "sources_root": "mock",
            "pkg_prefix": "org/owasp/webgoat/lessons",
            "findings_dir": "/tmp/test_findings",
            "logs_dir": "/tmp/test_logs",
            "file_limit": 10,
            "run_id": "test1",
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

        with patch("src.nodes.agents.discovery.discover") as mock_discover, \
             patch("src.nodes.agents.discovery.audit_file") as mock_audit, \
             patch("src.nodes.agents.discovery.CodegraphClient") as mock_cg_class:

            mock_discover.return_value = {
                "work_list": [MOCK_TASK],
                "audit_index": 0,
            }
            mock_audit.return_value = {
                "findings": [MOCK_FINDING],
                "audit_index": 1,
            }
            mock_cg = MagicMock()
            mock_cg.lookup_memory.return_value = None
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            result = discovery_agent(state)

            assert len(result["findings"]) == 1
            assert result["findings"][0].vuln_type == "SQLi"
            assert result["audit_index"] == 1
            assert result["work_list"] == [MOCK_TASK]

    def test_trace_route_finds_chain(self):
        """测试 trace_route 找到调用链 + AI 判断可达。"""
        from src.nodes.trace_route import trace_route

        state: AuditState = {
            "mode": "dev",
            "codegraph_db": "mock",
            "sources_root": "mock",
            "pkg_prefix": "org/owasp/webgoat/lessons",
            "findings_dir": "/tmp/test",
            "logs_dir": "/tmp/test",
            "file_limit": 10,
            "run_id": "test2",
            "max_iterations": 3,
            "llm_model": "test",
            "findings": [MOCK_FINDING],
            "verified": [],
            "work_list": [MOCK_TASK],
            "audit_index": 1,
            "reflection_notes": [],
            "iteration": 0,
            "agent_history": [],
            "next_agent": "",
        }

        with patch("src.nodes.trace_route.CodegraphClient") as mock_cg_class, \
             patch("src.nodes.trace_route.call_reachability_llm") as mock_llm:

            mock_cg = MagicMock()
            mock_cg.is_route_reachable.return_value = True
            mock_cg.get_call_chain_to_route.return_value = MOCK_CHAIN
            mock_cg.get_chain_bodies.return_value = MOCK_CHAIN_BODIES
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            mock_llm.return_value = MOCK_REACHABILITY_RESULT

            result = trace_route(state)

            findings = result["findings"]
            assert len(findings) == 1
            assert "POST /SqlInjectionAdvanced/attack6a" in findings[0].payload
            assert "[路由可达性分析] 可达" in findings[0].evidence
            mock_llm.assert_called_once()

    def test_record_writes_all_findings(self):
        """测试 record 为所有 finding 写 .md（不论 confirmed/denied）。"""
        import tempfile
        from src.nodes.record import record

        with tempfile.TemporaryDirectory() as tmpdir:
            # mock CodegraphClient + _conn
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_cursor.lastrowid = 1
            mock_conn.execute.return_value = mock_cursor

            mock_cg = MagicMock()
            mock_cg._conn = mock_conn

            with patch("src.nodes.record.CodegraphClient") as mock_cg_class:
                mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
                mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

                state = {
                    "mode": "dev",
                    "codegraph_db": "mock",
                    "sources_root": "mock",
                    "pkg_prefix": "org/owasp/webgoat/lessons",
                    "findings_dir": str(Path(tmpdir) / "findings"),
                    "logs_dir": str(Path(tmpdir) / "logs"),
                    "file_limit": 10,
                    "run_id": "test3",
                    "max_iterations": 3,
                    "llm_model": "test",
                    "findings": [
                        Finding(
                            file_path="Test.java", node_id="method:1", vuln_type="SQLi",
                            severity="high", evidence="test", payload="POST /x HTTP/1.1\n\na=1",
                            confidence=0.9, poc_result="confirmed", poc="curl test",
                            poc_output="200 OK",
                        ),
                        Finding(
                            file_path="Test.java", node_id="method:2", vuln_type="XSS",
                            severity="medium", evidence="test2", payload="",
                            confidence=0.5, poc_result="denied",
                        ),
                        Finding(
                            file_path="Test.java", node_id="method:3", vuln_type="SSRF",
                            severity="low", evidence="test3", payload="",
                            confidence=0.3, poc_result="inconclusive",
                        ),
                    ],
                    "verified": [],
                    "work_list": [],
                    "audit_index": 3,
                    "reflection_notes": [],
                    "iteration": 0,
                    "agent_history": [],
                    "next_agent": "",
                }

                result = record(state)

                # 验证 3 个 finding 都写了 .md
                findings_dir = Path(tmpdir) / "findings"
                md_files = list(findings_dir.glob("*.md"))
                assert len(md_files) == 3

                # 验证文件名包含验证结果
                filenames = [f.name for f in md_files]
                assert any("confirmed" in name for name in filenames)
                assert any("denied" in name for name in filenames)
                assert any("inconclusive" in name for name in filenames)

                # 验证 verified 列表
                assert len(result["verified"]) == 1
                assert result["verified"][0].poc_result == "confirmed"

    def test_graph_compiles(self):
        """测试 graph 编译。"""
        from src.graph import build_graph
        app = build_graph()
        assert app is not None

    def test_audit_result_schema(self):
        """测试 AuditResult Pydantic schema 序列化正确。"""
        schema = AuditResult.model_json_schema()
        assert "VulnDetail" in schema.get("$defs", {})

    def test_vuln_detail_fields(self):
        """测试 VulnDetail 所有字段。"""
        v = VulnDetail(
            vuln_type="SQLi", severity="high", evidence="test",
            payload="a=1", confidence=0.8,
            input_validation="无", output_limitation="无",
            called_methods="dao.execute", security_risk="SQL注入",
        )
        data = v.model_dump()
        assert data["vuln_type"] == "SQLi"
        assert data["input_validation"] == "无"
        assert data["security_risk"] == "SQL注入"
