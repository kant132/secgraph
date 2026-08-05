"""测试 — LangGraph pipeline 结构 + state schema。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestGraphStructure:
    """pipeline 拓扑结构。"""

    def test_graph_compiles(self):
        from src.graph import build_graph
        app = build_graph()
        assert app is not None

    def test_nodes(self):
        from src.graph import build_graph
        app = build_graph()
        nodes = list(app.get_graph().nodes.keys())
        assert "__start__" in nodes
        assert "discover" in nodes
        assert "audit_file" in nodes
        assert "trace_route" in nodes
        assert "verify_finding" in nodes
        assert "record" in nodes
        assert "__end__" in nodes
        # reflect 不在 graph 里
        assert "reflect" not in nodes

    def test_edges(self):
        from src.graph import build_graph
        app = build_graph()
        edges = app.get_graph().edges
        edge_pairs = [(e.source, e.target) for e in edges]
        assert ("__start__", "discover") in edge_pairs
        assert ("discover", "audit_file") in edge_pairs
        assert ("trace_route", "verify_finding") in edge_pairs
        assert ("verify_finding", "record") in edge_pairs
        assert ("record", "__end__") in edge_pairs


class TestStateSchema:
    """AuditState 字段。"""

    def test_required_keys(self):
        from src.state import AuditState
        annotations = AuditState.__annotations__
        # 核心决策字段
        assert "findings" in annotations
        assert "work_list" in annotations
        assert "audit_index" in annotations
        # explore_messages / agent_messages 已移除（写文件）
        assert "explore_messages" not in annotations
        assert "agent_messages" not in annotations

    def test_no_reflect_fields(self):
        from src.state import AuditState
        annotations = AuditState.__annotations__
        # reflect 已摘除
        assert "reflection_notes" in annotations  # 字段保留但不连 graph


class TestPydanticModels:
    """LLM 结构化输出 schema。"""

    def test_vuln_detail(self):
        from src.state import VulnDetail
        v = VulnDetail(
            vuln_type="SQLi", severity="high",
            evidence="line 42", payload="", confidence=0.8,
        )
        assert v.vuln_type == "SQLi"

    def test_audit_result(self):
        from src.state import AuditResult
        schema = AuditResult.model_json_schema()
        assert "VulnDetail" in schema.get("$defs", {})

    def test_poc_verification(self):
        from src.state import PoCVerificationResult
        fields = PoCVerificationResult.model_fields
        assert "verified" in fields
        assert "cvss_score" in fields
        assert "cia_proof" in fields
        assert "second_payload" in fields

    def test_reachability_result(self):
        from src.state import ReachabilityResult
        fields = ReachabilityResult.model_fields
        assert "reachable" in fields
        assert "updated_payload" in fields

    def test_login_exploration(self):
        from src.state import LoginExplorationResult
        fields = LoginExplorationResult.model_fields
        assert "steps" in fields
        assert "login_url" in fields
