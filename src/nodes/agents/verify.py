"""PoC 验证子agent — 封装 verify_finding。

verify_finding 完成后返回更新后的 findings（含 poc_result）。
不修改输入 state — 只返回 partial update dict。
"""
from __future__ import annotations

import logging

from ..verify.node import verify_finding
from ...state import AuditState

log = logging.getLogger("secgraph.agents.verify")


def verify_agent(state: AuditState) -> dict:
    """PoC 验证：verify_finding → 返回验证结果。"""
    log.info("verify: === VERIFY AGENT START ===")

    result = verify_finding(state)

    findings = result.get("findings", state.get("findings", []))
    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")

    log.info("verify: === VERIFY AGENT END → %d confirmed, %d denied ===", confirmed, denied)

    return {
        **result,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "verify",
            "result": f"{confirmed} confirmed, {denied} denied",
        }],
    }