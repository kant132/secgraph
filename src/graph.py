"""LangGraph StateGraph — 审计 pipeline 编排。

拓扑：
  START -> discover -> audit_file
  audit_file --(还有文件)--> audit_file   （按文件循环）
  audit_file --(审完)-----> trace_route -> verify_finding -> record -> END

路由：
  _after_audit: audit_index < len(work_list) ? "next" : "done"
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes import audit_file, discover, record, trace_route, verify_finding
from .state import AuditState


def _after_audit(state: AuditState) -> str:
    """audit_file 后路由：还有文件则继续，否则进入路由追溯。"""
    idx = state.get("audit_index", 0)
    work_list = state.get("work_list", [])
    return "next" if idx < len(work_list) else "done"


def build_graph():
    """编译并返回可运行的 LangGraph。"""
    g: StateGraph = StateGraph(AuditState)
    g.add_node("discover", discover)
    g.add_node("audit_file", audit_file)
    g.add_node("trace_route", trace_route)
    g.add_node("verify_finding", verify_finding)
    g.add_node("record", record)

    g.add_edge(START, "discover")
    g.add_edge("discover", "audit_file")
    g.add_conditional_edges("audit_file", _after_audit, {"next": "audit_file", "done": "trace_route"})
    g.add_edge("trace_route", "verify_finding")
    g.add_edge("verify_finding", "record")
    g.add_edge("record", END)

    return g.compile()
