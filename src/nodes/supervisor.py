"""Supervisor（主管）— 看当前 state，用 LLM 决定下一步派给哪个子agent。

调度逻辑由 LLM 决定（不是硬编码 if/else）：
- 输入：当前 state 摘要（findings 数量、哪些已验证、哪些待处理）
- 输出：{"next_agent": "discovery|trace|verify|FINISH", "reasoning": "..."}

Supervisor → 子agent → Supervisor → 子agent → ... → FINISH → record → END
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..llm import call_supervisor_llm
from ..state import AuditState

log = logging.getLogger("secgraph.supervisor")

_SUPERVISOR_PROMPT = Path(__file__).parent.parent / "prompts" / "supervisor_prompt.md"
_SUPERVISOR_PROMPT = _SUPERVISOR_PROMPT.resolve()


def _build_state_summary(state: AuditState) -> str:
    """从 state 提取摘要，发给 supervisor LLM 做路由决策。"""
    findings = state.get("findings", [])
    work_list = state.get("work_list", [])
    audit_index = state.get("audit_index", 0)

    if not findings:
        if not work_list:
            return "初始状态：无 findings，无 work_list。需要 discover 入口方法。"
        return f"已 discover {len(work_list)} 个方法，audit_index={audit_index}，但无 findings。"

    has_payload = sum(1 for f in findings if f.payload)
    has_poc = sum(1 for f in findings if f.poc_result)
    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")
    pending = sum(1 for f in findings if not f.poc_result)

    return (
        f"findings: {len(findings)} 个\n"
        f"  有 payload（已分析调用链）: {has_payload}\n"
        f"  有 poc_result（已验证）: {has_poc}\n"
        f"  confirmed: {confirmed}\n"
        f"  denied: {denied}\n"
        f"  pending（无 poc_result）: {pending}\n"
        f"  需要进一步验证或有 second_payload: {pending}"
    )


def supervisor(state: AuditState) -> dict:
    """Supervisor 路由：看 state → LLM 决定下一步 → 返回 next_agent。"""
    state_summary = _build_state_summary(state)
    log.info("[supervisor] state:\n%s", state_summary)

    tmpl = _SUPERVISOR_PROMPT.read_text(encoding="utf-8")
    prompt = tmpl.replace("{state_summary}", state_summary)

    print(f"\n{'='*60}")
    print(f"[Supervisor] 分析当前状态...")
    print(f"  状态摘要:\n{state_summary}")

    try:
        decision = call_supervisor_llm(prompt)
        next_agent = decision.next_agent
        reasoning = decision.reasoning
    except Exception as e:
        log.warning("[supervisor] LLM 调用失败 → %s，降级为规则路由", e)
        # 降级：硬编码规则
        findings = state.get("findings", [])
        if not findings:
            next_agent = "discovery"
        elif all(f.poc_result for f in findings):
            next_agent = "FINISH"
        elif all(f.payload for f in findings) and not all(f.poc_result for f in findings):
            next_agent = "verify"
        else:
            next_agent = "trace"
        reasoning = f"降级路由 → {next_agent}"

    print(f"  → 决定: {next_agent}")
    print(f"  → 理由: {reasoning}")
    print(f"{'='*60}")

    log.info("[supervisor] → %s (%s)", next_agent, reasoning[:80])

    history = list(state.get("agent_history", []))
    history.append({"agent": "supervisor", "decision": next_agent, "reasoning": reasoning})

    return {"next_agent": next_agent, "agent_history": history}
