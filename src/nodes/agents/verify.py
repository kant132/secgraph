"""PoC 验证子agent — 封装 verify。

Supervisor 分配 verify 任务后，本 agent 执行：
1. 登录探索（Playwright CDP + login_info.json 缓存）
2. 发初始 payload + AI 验证（含 second_payload 循环）
3. 失败 → agent 循环（create_react_agent + 工具）
4. 更新 findings 的 poc_result
执行完返回 state 给 supervisor。
"""
from __future__ import annotations

import logging

from ..verify.node import verify_finding
from ...state import AuditState

log = logging.getLogger("secgraph.agents.verify")


def verify_agent(state: AuditState) -> dict:
    """PoC 验证：verify_finding → 返回验证结果。"""
    log.info("[verify] 开始 PoC 验证...")

    result = verify_finding(state)
    state.update(result)

    findings = state.get("findings", [])
    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")
    inconclusive = sum(1 for f in findings if f.poc_result == "inconclusive")
    pending = sum(1 for f in findings if not f.poc_result)

    log.info("[verify] 完成: %d confirmed, %d denied, %d inconclusive, %d pending",
              confirmed, denied, inconclusive, pending)

    return {
        "findings": findings,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "verify",
            "result": f"{confirmed} confirmed, {denied} denied, {inconclusive} inconclusive, {pending} pending",
        }],
    }
