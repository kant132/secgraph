"""漏洞发现子agent — 封装 discover + 批量 audit。

Supervisor 分配 discovery 任务后，本 agent 执行：
1. discover — codegraph 查入口方法 + callees + fields
2. 对每个方法先查 audit_memory — 置信度 >= 0.9 直接复用，跳过 LLM 审计
3. audit — 未命中 memory 的方法，LLM 结构化输出 findings
4. 每批审计 file_limit 个方法就返回 supervisor（让 supervisor 决定是否先 trace/verify）
执行完返回 state 给 supervisor。
"""
from __future__ import annotations

import logging

from ..discover import discover
from ..audit import audit_file
from ...codegraph import CodegraphClient
from ...state import AuditState, Finding

log = logging.getLogger("secgraph.agents.discovery")

MEMORY_CONFIDENCE_THRESHOLD = 0.9
DEFAULT_BATCH_SIZE = 10  # runtime 模式默认每批审计 10 个


def discovery_agent(state: AuditState) -> dict:
    """漏洞发现：discover → memory 查询 → 批量 audit → 返回 findings。
    每批审 file_limit 个方法就返回，让 supervisor 决定下一步（trace/verify/discovery）。"""
    log.info("[discovery] 开始漏洞发现...")

    # 1. discover（首次调用时执行，后续 supervisor 回来时 work_list 已有）
    work_list = state.get("work_list", [])
    audit_index = state.get("audit_index", 0)

    if not work_list or audit_index >= len(work_list):
        discover_result = discover(state)
        state.update(discover_result)
        work_list = state.get("work_list", [])
        audit_index = 0
        log.info("[discovery] discover 完成: %d 个方法", len(work_list))
    else:
        log.info("[discovery] 继续审计，当前 %d/%d", audit_index, len(work_list))

    # 2. 查 memory（从 codegraph.db）— 置信度 >= 0.9 直接复用
    codegraph_db_path = state.get("codegraph_db", "")
    cached_findings: list[Finding] = []
    tasks_to_audit: list = []

    if codegraph_db_path:
        with CodegraphClient(codegraph_db_path) as cg:
            cg.init_memory_table()
            for task in work_list:
                for node_id in task.method_bodies:
                    memory = cg.lookup_memory(node_id, MEMORY_CONFIDENCE_THRESHOLD)
                    if memory:
                        log.info("[discovery] memory 命中: %s (confidence=%.2f) → 跳过",
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
                        break
                else:
                    pass
    else:
        tasks_to_audit = work_list

    log.info("[discovery] memory 命中 %d 个，待审计 %d 个",
             len(cached_findings), len(tasks_to_audit))

    # 3. 重建 work_list 只含待审计的 task
    if tasks_to_audit and tasks_to_audit != work_list:
        state["work_list"] = tasks_to_audit
        state["audit_index"] = 0
        work_list = tasks_to_audit
        audit_index = 0

    # 4. 批量审计 — 每批 file_limit 个就返回
    file_limit = state.get("file_limit") or DEFAULT_BATCH_SIZE
    batch_end = min(audit_index + file_limit, len(work_list))

    log.info("[discovery] 审计批次: %d → %d (共 %d, 每批 %d)",
             audit_index, batch_end, len(work_list), file_limit)

    while audit_index < batch_end:
        log.info("[discovery] audit [%d/%d]", audit_index + 1, len(work_list))
        audit_result = audit_file(state)
        state.update(audit_result)
        audit_index = state.get("audit_index", audit_index)

    # 合并 memory 命中的 + 新审计的 findings
    all_findings = cached_findings + list(state.get("findings", []))

    remaining = len(work_list) - audit_index
    log.info("[discovery] 完成: %d 个 findings (%d from memory), 剩余 %d 个待审",
             len(all_findings), len(cached_findings), remaining)

    return {
        "findings": all_findings,
        "audit_index": audit_index,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "discovery",
            "result": f"发现 {len(all_findings)} 个漏洞 ({len(cached_findings)} from memory), 剩余 {remaining} 待审",
        }],
    }

