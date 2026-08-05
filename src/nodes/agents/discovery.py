"""漏洞发现子agent — 封装 discover + audit 循环。

Supervisor 分配 discovery 任务后，本 agent 执行：
1. discover — codegraph 查入口方法 + callees + fields
2. audit — 每个方法一个 task，LLM 结构化输出 findings
执行完返回 state 给 supervisor。
"""
from __future__ import annotations

import logging

from ..discover import discover
from ..audit import audit_file
from ...state import AuditState

log = logging.getLogger("secgraph.agents.discovery")


def discovery_agent(state: AuditState) -> dict:
    """漏洞发现：discover → audit 循环 → 返回 findings。"""
    log.info("[discovery] 开始漏洞发现...")

    # 1. discover
    discover_result = discover(state)
    state.update(discover_result)
    work_list = state.get("work_list", [])
    log.info("[discovery] discover 完成: %d 个方法", len(work_list))

    # 2. audit 循环
    findings = list(state.get("findings", []))
    audit_index = state.get("audit_index", 0)

    while audit_index < len(work_list):
        log.info("[discovery] audit [%d/%d]", audit_index + 1, len(work_list))
        audit_result = audit_file(state)
        state.update(audit_result)
        audit_index = state.get("audit_index", audit_index)
        findings = state.get("findings", findings)

    log.info("[discovery] 完成: %d 个 findings", len(findings))
    return {
        "findings": findings,
        "audit_index": audit_index,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "discovery",
            "result": f"发现 {len(findings)} 个漏洞",
        }],
    }
