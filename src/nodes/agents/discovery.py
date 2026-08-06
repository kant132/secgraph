"""漏洞发现子agent — 封装 discover + audit 循环。

Supervisor 分配 discovery 任务后，本 agent 执行：
1. discover — codegraph 查入口方法 + callees + fields
2. 对每个方法先查 audit_memory — 置信度 >= 0.9 直接复用，跳过 LLM 审计
3. audit — 未命中 memory 的方法，LLM 结构化输出 findings
执行完返回 state 给 supervisor。
"""
from __future__ import annotations

import logging

from ..discover import discover
from ..audit import audit_file
from ...db import FindingsDB
from ...state import AuditState, Finding

log = logging.getLogger("secgraph.agents.discovery")

MEMORY_CONFIDENCE_THRESHOLD = 0.9


def discovery_agent(state: AuditState) -> dict:
    """漏洞发现：discover → memory 查询 → audit 循环 → 返回 findings。"""
    log.info("[discovery] 开始漏洞发现...")

    # 1. discover
    discover_result = discover(state)
    state.update(discover_result)
    work_list = state.get("work_list", [])
    log.info("[discovery] discover 完成: %d 个方法", len(work_list))

    # 2. 查 memory — 置信度 >= 0.9 的直接复用，不调 LLM
    findings_db_path = state.get("findings_db", "")
    cached_findings: list[Finding] = []
    tasks_to_audit: list = []

    if findings_db_path:
        with FindingsDB(findings_db_path) as db:
            for task in work_list:
                # task.method_bodies 的 key 就是 nodeid
                for node_id in task.method_bodies:
                    memory = db.lookup_memory(node_id, MEMORY_CONFIDENCE_THRESHOLD)
                    if memory:
                        log.info("[discovery] memory 命中: %s (confidence=%.2f) → 跳过审计",
                                 node_id[:30], memory["confidence"])
                        cached_findings.append(Finding(
                            file_path=task.file_path,
                            node_id=node_id,
                            vuln_type=memory["vuln_type"],
                            severity=memory.get("status", "pending"),
                            evidence=memory["security_risk"],
                            payload="",
                            confidence=memory["confidence"],
                        ))
                    else:
                        tasks_to_audit.append(task)
                        break  # 一个 task 只需一个 node_id 没命中就审
                else:
                    # 所有 node_id 都命中 memory → 整个 task 跳过
                    pass
    else:
        tasks_to_audit = work_list

    log.info("[discovery] memory 命中 %d 个，待审计 %d 个",
             len(cached_findings), len(tasks_to_audit))

    # 3. audit 未命中 memory 的方法
    # 重建 work_list 只含待审计的 task
    if tasks_to_audit and tasks_to_audit != work_list:
        state["work_list"] = tasks_to_audit
        state["audit_index"] = 0

    audit_index = state.get("audit_index", 0)
    current_work_list = state.get("work_list", work_list)

    while audit_index < len(current_work_list):
        log.info("[discovery] audit [%d/%d]", audit_index + 1, len(current_work_list))
        audit_result = audit_file(state)
        state.update(audit_result)
        audit_index = state.get("audit_index", audit_index)

    # 合并 memory 命中的 + 新审计的 findings
    all_findings = cached_findings + list(state.get("findings", []))

    log.info("[discovery] 完成: %d 个 findings (%d from memory, %d new)",
             len(all_findings), len(cached_findings), len(all_findings) - len(cached_findings))
    return {
        "findings": all_findings,
        "audit_index": audit_index,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "discovery",
            "result": f"发现 {len(all_findings)} 个漏洞 ({len(cached_findings)} from memory)",
        }],
    }

