"""LangGraph — agent 之间直接流转，不经 supervisor 中转。

拓扑：
  START → discovery（直接，不经 supervisor）
  discovery → 有 finding 未分析 → trace（直接）
  discovery → 无 finding 有剩余 → discovery（继续审下一个）
  discovery → 无剩余 → record → END
  trace → 可达且未验证 → verify（直接）
  trace → 不可达 → discovery（继续审下一个）
  verify → 有剩余 → discovery（继续审下一个）
  verify → 无剩余 → record → END

路由依据：Finding.reachability 结构化字段（不靠 evidence 子串匹配）。
"""
from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from .nodes.agents.discovery import discovery_agent
from .nodes.agents.trace import trace_agent
from .nodes.agents.verify import verify_agent
from .nodes.record import record
from .state import AuditState


def _remaining(state: AuditState) -> int:
    """work_list 中尚未审计的方法数。"""
    work_list = state.get("work_list", [])
    audit_index = state.get("audit_index", 0)
    return max(0, len(work_list) - audit_index)


def _after_discovery(state: AuditState) -> str:
    """discovery 完成后：有 finding 未 trace → trace；有剩余 → discovery；否则 record。

    路由依据：finding.reachability is None 表示还没跑 trace_route。
    """
    findings = state.get("findings", [])

    # 有未分析调用链的 finding（reachability 为 None）→ trace
    if any(f.reachability is None for f in findings):
        return "trace"

    if _remaining(state) > 0:
        return "discovery"

    return "record"


def _after_trace(state: AuditState) -> str:
    """trace 完成后：可达未验证 → verify；有剩余 → discovery；否则 record。

    路由依据：reachability != None 且无 poc_result → 需要 verify。
    """
    findings = state.get("findings", [])

    # 已 trace 但未验证 → verify
    if any(f.reachability is not None and not f.poc_result for f in findings):
        return "verify"

    if _remaining(state) > 0:
        return "discovery"

    return "record"


def _after_verify(state: AuditState) -> str:
    """verify 完成后：有剩余 → discovery；否则 record。"""
    if _remaining(state) > 0:
        return "discovery"
    return "record"


def build_graph():
    """编译 LangGraph（5 节点直接流转，无 supervisor）。"""
    g: StateGraph = StateGraph(AuditState)

    g.add_node("discovery", discovery_agent)
    g.add_node("trace", trace_agent)
    g.add_node("verify", verify_agent)
    g.add_node("record", record)

    # START → discovery（直接，不经 supervisor）
    g.add_edge(START, "discovery")

    g.add_conditional_edges("discovery", _after_discovery, {
        "trace": "trace",
        "discovery": "discovery",
        "record": "record",
    })

    g.add_conditional_edges("trace", _after_trace, {
        "verify": "verify",
        "discovery": "discovery",
        "record": "record",
    })

    g.add_conditional_edges("verify", _after_verify, {
        "discovery": "discovery",
        "record": "record",
    })

    g.add_edge("record", END)

    return g.compile()