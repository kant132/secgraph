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
    id="method:abc123",
    qualified_name="org.test::SqlController::query",
    name="query",
    signature="Result(String userid)",
    file_path="sources/org/test/SqlController.java",
    start_line=10,
    end_line=20,
)

MOCK_TASK = FileAuditTask(
    file_path="sources/org/test/SqlController.java",
    node_id="method:abc123",
    fields=[FieldNode(id="field:1", qualified_name="org.test::SqlController::dao", name="dao", start_line=5, end_line=5)],
    method_bodies={"method:abc123": "// org.test::SqlController::query\npublic Result query(String userid) {\n    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n    return dao.execute(sql);\n}"},
    calls={"method:dao1": "// org.test::Dao::execute\npublic Result execute(String sql) {\n    return jdbcTemplate.queryForList(sql);\n}"},
)

MOCK_FINDING = Finding(
    file_path="sources/org/test/SqlController.java",
    node_id="method:abc123",
    vuln_type="SQLi",
    severity="high",
    evidence="line 12: userid 拼接到 SQL，无消毒",
    payload="POST /api/query HTTP/1.1\n\nuserid=' OR '1'='1",
    confidence=0.8,
)

MOCK_CHAIN = [{
    "id": "route:/api/query",
    "qualified_name": "route:/api/query",
    "kind": "route",
    "file_path": "sources/org/test/SqlController.java",
    "start_line": 1,
    "end_line": 1,
    "depth": 1,
    "chain_path": "route:/api/query -> org.test::SqlController::query",
    "chain_ids": "route:/api/query,method:abc123",
}]

MOCK_CHAIN_BODIES = {
    "route:/api/query": "// route:/api/query\n@PostMapping(\"/api/query\")\npublic Result query(@RequestParam String userid) {\n    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n    return dao.execute(sql);\n}",
    "method:abc123": "// org.test::SqlController::query\npublic Result query(String userid) {\n    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n    return dao.execute(sql);\n}",
}

MOCK_AUDIT_RESULT = AuditResult.model_validate({
    "method:abc123": {
        "vuln_type": "SQLi",
        "severity": "high",
        "evidence": "line 12: userid 拼接到 SQL，无消毒",
        "payload": "userid=' OR '1'='1",
        "confidence": 0.8,
        "input_validation": "无",
        "output_limitation": "无",
        "called_methods": "dao.execute",
        "security_risk": "SQL注入：userid 直接拼接 SQL 无消毒",
    }
})

MOCK_REACHABILITY_RESULT = ReachabilityResult(
    reachable=True,
    updated_payload="POST /api/query HTTP/1.1\n\nuserid=' OR '1'='1",
    conditions="需要 POST 到 /api/query，提供 userid 参数",
    confidence=0.9,
)

MOCK_POC_RESULT = PoCVerificationResult(
    verified=True,
    cvss_score="9.8 Critical",
    cia_proof="C: PoC 返回了 users 表数据（id, name, password）",
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
            "pkg_prefix": "org/test",
            "findings_db": "mock",
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
            "pkg_prefix": "org/test",
            "findings_db": "mock",
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
            assert "POST /api/query" in findings[0].payload
            assert "[路由可达性分析] 可达" in findings[0].evidence
            mock_llm.assert_called_once()

    def test_record_writes_all_findings(self):
        """测试 record 为所有 finding 写 .md（不论 confirmed/denied）。"""
        import tempfile
        from src.nodes.record import record

        with tempfile.TemporaryDirectory() as tmpdir:
            state: AuditState = {
                "mode": "dev",
                "codegraph_db": "mock",
                "sources_root": "mock",
                "pkg_prefix": "org/test",
                "findings_db": str(Path(tmpdir) / "test.db"),
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
