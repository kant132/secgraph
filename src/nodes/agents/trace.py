"""调用链分析子agent — 封装 trace_route。

trace_route 完成后返回更新后的 findings（含可达性标记 + 更新的 payload）。
不修改输入 state — 只返回 partial update dict。
"""
from __future__ import annotations

import logging

from ..trace_route import trace_route
from ...state import AuditState

log = logging.getLogger("secgraph.agents.trace")


def trace_agent(state: AuditState) -> dict:
    """调用链分析：trace_route → 返回更新后的 findings。"""
    log.info("trace: === TRACE AGENT START ===")

    result = trace_route(state)

    findings = result.get("findings", [])
    traced = sum(1 for f in findings if f.reachability is not None)
    log.info("trace: === TRACE AGENT END → %d traced ===", traced)

    return {
        **result,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "trace",
            "result": f"{traced} 个 findings 已分析可达性",
        }],
    }