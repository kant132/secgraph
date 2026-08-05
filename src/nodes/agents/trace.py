"""调用链分析子agent — 封装 trace_route。

Supervisor 分配 trace 任务后，本 agent 执行：
1. 对每个 finding 反向追溯 route 调用链（Q5 递归 CTE）
2. AI 判断可达性 + 更新 payload
执行完返回 state 给 supervisor。
"""
from __future__ import annotations

import logging

from ..trace_route import trace_route
from ...state import AuditState

log = logging.getLogger("secgraph.agents.trace")


def trace_agent(state: AuditState) -> dict:
    """调用链分析：trace_route → 返回更新后的 findings（含可达 payload）。"""
    log.info("[trace] 开始调用链分析...")

    result = trace_route(state)
    state.update(result)

    findings = state.get("findings", [])
    traced = sum(1 for f in findings if f.payload)
    log.info("[trace] 完成: %d 个 findings 有 payload", traced)

    return {
        "findings": findings,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "trace",
            "result": f"{traced} 个 findings 有可达 payload",
        }],
    }
