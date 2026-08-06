"""LangGraph — agent 之间直接流转，不经 supervisor 中转。

拓扑：
  START → supervisor（初始决策）
  supervisor → discovery
  discovery → 有 finding 未分析 → trace（直接，不回 supervisor）
  discovery → 无 finding 有剩余 → discovery（继续审下一个）
  discovery → 无剩余 → record → END
  trace → 可达且未验证 → verify（直接）
  trace → 不可达 → discovery（继续审下一个）
  verify → 有剩余 → discovery（继续审下一个）
  verify → 无剩余 → record → END

supervisor 只参与初始路由和复杂决策，常见流程 discovery→trace→verify 直接流转。
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes.agents.discovery import discovery_agent
from .nodes.agents.trace import trace_agent
from .nodes.agents.verify import verify_agent
from .nodes.record import record
from .nodes.supervisor import supervisor
from .state import EVIDENCE_TRACE_TAG, AuditState


def _remaining(state: AuditState) -> int:
    """work_list 中尚未审计的方法数。"""
    work_list = state.get("work_list", [])
    audit_index = state.get("audit_index", 0)
    return max(0, len(work_list) - audit_index)


def _has_tag(f, tag: str) -> bool:
    """finding.evidence 是否包含路由可达性分析标记。"""
    return tag in (f.evidence or "")


def _after_discovery(state: AuditState) -> str:
    """discovery 完成后直接路由：有 finding 未分析 → trace；剩余方法 → discovery；否则 record。"""
    findings = state.get("findings", [])

    # 有未分析调用链的 finding → 直接 trace
    if any(not _has_tag(f, EVIDENCE_TRACE_TAG) for f in findings):
        return "trace"

    # 还有剩余方法 → 继续审
    if _remaining(state) > 0:
        return "discovery"

    return "record"


def _after_trace(state: AuditState) -> str:
    """trace 完成后直接路由：可达未验证 → verify；剩余方法 → discovery；否则 record。"""
    findings = state.get("findings", [])

    # 有已分析调用链但未验证的 finding → verify
    if any(_has_tag(f, EVIDENCE_TRACE_TAG) and not f.poc_result for f in findings):
        return "verify"

    # 还有剩余方法 → 继续审
    if _remaining(state) > 0:
        return "discovery"

    return "record"


def _after_verify(state: AuditState) -> str:
    """verify 完成后直接路由：剩余方法 → discovery；否则 record。"""
    if _remaining(state) > 0:
        return "discovery"
    return "record"


def build_graph():
    """编译 agent 直接流转的 LangGraph。"""
    g: StateGraph = StateGraph(AuditState)

    # 节点
    g.add_node("supervisor", supervisor)
    g.add_node("discovery", discovery_agent)
    g.add_node("trace", trace_agent)
    g.add_node("verify", verify_agent)
    g.add_node("record", record)

    # supervisor 初始路由 → discovery
    g.add_edge(START, "supervisor")
    g.add_edge("supervisor", "discovery")

    # discovery 直接路由（不回 supervisor）
    g.add_conditional_edges("discovery", _after_discovery, {
        "trace": "trace",
        "discovery": "discovery",
        "record": "record",
    })

    # trace 直接路由
    g.add_conditional_edges("trace", _after_trace, {
        "verify": "verify",
        "discovery": "discovery",
        "record": "record",
    })

    # verify 直接路由
    g.add_conditional_edges("verify", _after_verify, {
        "discovery": "discovery",
        "record": "record",
    })

    g.add_edge("record", END)

    return g.compile()