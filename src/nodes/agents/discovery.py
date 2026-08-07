"""漏洞发现子agent — 封装 discover + audit。

流程：
1. discover — codegraph 查入口方法 + callees + fields
2. 对每个方法先查 audit_memory — 置信度 >= 0.9 直接复用，跳过 LLM 审计
3. audit — 逐个方法审计

不修改输入 state — 用 local_state 传递给子调用，只返回 partial update dict。
"""
from __future__ import annotations

import logging

from ..discover import discover
from ..audit import audit_file
from ...codegraph import CodegraphClient
from ...state import AuditState, Finding

log = logging.getLogger("secgraph.agents.discovery")

MEMORY_CONFIDENCE_THRESHOLD = 0.9


def discovery_agent(state: AuditState) -> dict:
    """漏洞发现：discover → memory 查询 → audit（逐个）。"""
    work_list = state.get("work_list", [])
    audit_index = state.get("audit_index", 0)
    existing_findings = list(state.get("findings", []))

    # 1. discover（首次调用时执行）
    if not work_list or audit_index >= len(work_list):
        log.info("discovery: 开始 discover 入口方法...")
        discover_result = discover(state)
        work_list = discover_result.get("work_list", [])
        audit_index = discover_result.get("audit_index", 0)
        log.info("discovery: discover 完成 → %d 个方法待审", len(work_list))
    else:
        log.debug("discovery: 继续 audit [%d/%d]", audit_index, len(work_list))

    # 2. 查 memory（从 codegraph.db）— 置信度 >= 0.9 直接复用
    codegraph_db_path = state.get("codegraph_db", "")
    cached_findings: list[Finding] = []

    if codegraph_db_path and audit_index < len(work_list):
        with CodegraphClient(codegraph_db_path) as cg:
            cg.init_memory_table()
            task = work_list[audit_index]
            node_id = next(iter(task.method_bodies))
            memory = cg.lookup_memory(node_id, MEMORY_CONFIDENCE_THRESHOLD)
            if memory:
                log.info("discovery: memory 命中: %s (confidence=%.2f) → 跳过",
                         node_id[:30], memory["confidence"])
                cached_findings.append(Finding(
                    file_path=task.file_path,
                    node_id=node_id,
                    vuln_type=memory["vuln_type"],
                    severity=memory.get("severity", "unknown"),
                    evidence=memory["security_risk"],
                    payload="",
                    confidence=memory["confidence"],
                ))
                audit_index += 1

    log.info("discovery: memory 命中 %d 个", len(cached_findings))

    # 3. 审计当前方法（只审 1 个）
    #    构建局部 state 传给 audit_file（不修改输入 state）
    new_audit_findings: list[Finding] = []
    if audit_index < len(work_list):
        log.info("discovery: audit [%d/%d]", audit_index + 1, len(work_list))
        local_state = {**state, "work_list": work_list, "audit_index": audit_index}
        audit_result = audit_file(local_state)
        new_audit_findings = audit_result.get("findings", [])
        audit_index = audit_result.get("audit_index", audit_index)

    # 合并 memory 命中的 + 新审计的 + 已有的 findings
    all_findings = existing_findings + cached_findings + [
        f for f in new_audit_findings if f not in existing_findings
    ]

    remaining = len(work_list) - audit_index
    log.info("discovery: 完成 → %d 个 findings, 剩余 %d 个待审",
             len(all_findings), remaining)

    return {
        "findings": all_findings,
        "audit_index": audit_index,
        "work_list": work_list,
        "agent_history": state.get("agent_history", []) + [{
            "agent": "discovery",
            "result": f"审计到 {audit_index}/{len(work_list)}, {len(all_findings)} findings, 剩余 {remaining}",
        }],
    }