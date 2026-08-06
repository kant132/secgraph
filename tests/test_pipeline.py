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
        assert "supervisor" in nodes
        assert "discovery" in nodes
        assert "trace" in nodes
        assert "verify" in nodes
        assert "record" in nodes
        assert "__end__" in nodes

    def test_edges(self):
        from src.graph import build_graph
        app = build_graph()
        edges = app.get_graph().edges
        edge_pairs = [(e.source, e.target) for e in edges]
        assert ("__start__", "supervisor") in edge_pairs
        assert ("supervisor", "discovery") in edge_pairs
        assert ("record", "__end__") in edge_pairs


class TestStateSchema:
    """AuditState 字段。"""

    def test_required_keys(self):
        from src.state import AuditState
        annotations = AuditState.__annotations__
        assert "findings" in annotations
        assert "work_list" in annotations
        assert "audit_index" in annotations
        assert "next_agent" in annotations
        assert "agent_history" in annotations
        assert "findings_db" not in annotations  # 已删 — 用 codegraph_db

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

    def test_supervisor_decision(self):
        from src.state import SupervisorDecision
        fields = SupervisorDecision.model_fields
        assert "next_agent" in fields
        assert "reasoning" in fields
