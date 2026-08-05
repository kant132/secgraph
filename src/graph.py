"""LangGraph Supervisor 模式 — 主管调度子agent。

拓扑：
  START → supervisor → [discovery | trace | verify | record]
                          ↑_______________↓
                       子agent 完成后回 supervisor
  supervisor 返回 FINISH → record → END

Supervisor 用 LLM 决定下一步派给哪个子agent（不是硬编码 if/else）。
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes.agents.discovery import discovery_agent
from .nodes.agents.trace import trace_agent
from .nodes.agents.verify import verify_agent
from .nodes.record import record
from .nodes.supervisor import supervisor
from .state import AuditState


def build_graph():
    """编译并返回 Supervisor 模式的 LangGraph。"""
    g: StateGraph = StateGraph(AuditState)

    # 节点
    g.add_node("supervisor", supervisor)
    g.add_node("discovery", discovery_agent)
    g.add_node("trace", trace_agent)
    g.add_node("verify", verify_agent)
    g.add_node("record", record)

    # 边：supervisor 根据 next_agent 路由
    g.add_edge(START, "supervisor")
    g.add_conditional_edges(
        "supervisor",
        lambda s: s.get("next_agent", "discovery"),
        {
            "discovery": "discovery",
            "trace": "trace",
            "verify": "verify",
            "FINISH": "record",
        },
    )

    # 子agent 完成后回 supervisor
    g.add_edge("discovery", "supervisor")
    g.add_edge("trace", "supervisor")
    g.add_edge("verify", "supervisor")
    g.add_edge("record", END)

    return g.compile()
