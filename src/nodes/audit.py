"""audit_file node — renders the prompt template + calls structured LLM.

Uses langchain with_structured_output(dict[str, VulnDetail]) — no manual
JSON parsing. LangChain auto-retries on schema violations.

Consumes one FileAuditTask from work_list[audit_index]. Produces Finding[]
appended to state['findings'].
"""
from __future__ import annotations

import json
import logging

from ..llm import call_audit_llm
from ..prompts import render
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.audit")


def _render_template(task) -> str:
    """Fill the audit prompt template with one FileAuditTask's data."""
    fields_text = "\n".join(
        f"  {f.qualified_name}  (line {f.start_line})" for f in task.fields
    ) or "  (none)"

    methods_json = json.dumps(task.method_bodies, indent=2, ensure_ascii=False) if task.method_bodies else "{}"
    calls_json = json.dumps(task.calls, indent=2, ensure_ascii=False) if task.calls else "{}"

    return render("audit",
                  fields=fields_text,
                  methods=methods_json,
                  calls=calls_json)


def audit_file(state: AuditState) -> dict:
    """Audit work_list[audit_index] via structured LLM. Appends findings."""
    work_list: list = state.get("work_list", [])
    idx: int = state.get("audit_index", 0)
    if idx >= len(work_list):
        return {}  # loop done; router sends to record

    task = work_list[idx]
    log.info("audit: [%d/%d] %s", idx + 1, len(work_list), task.file_path)

    prompt = _render_template(task)
    log.debug("audit: prompt=\n%s", prompt)
    result = call_audit_llm(prompt)  # AuditResult (RootModel[dict[str, VulnDetail]])
    log.debug("audit: llm result=%s", result.root)

    # 保存审计记忆到 codegraph.db（和代码索引同库）
    codegraph_db_path = state.get("codegraph_db", "")
    if codegraph_db_path:
        from ..codegraph import CodegraphClient
        with CodegraphClient(codegraph_db_path) as cg:
            cg.init_memory_table()
            for nid, detail in (result.root or {}).items():
                cg.save_memory(
                    node_id=nid,
                    signature=f"{nid}:{detail.vuln_type}",
                    vuln_type=detail.vuln_type,
                    security_risk=detail.security_risk or detail.evidence[:200],
                    confidence=detail.confidence,
                    status="pending",
                    input_validation=detail.input_validation,
                    output_limitation=detail.output_limitation,
                    called_methods=detail.called_methods,
                )
        log.info("audit: 审计记忆已保存到 codegraph.db → %d 条", len(result.root or {}))

    new_findings: list[Finding] = [
        Finding(
            file_path=task.file_path,
            node_id=node_id,
            vuln_type=detail.vuln_type,
            severity=detail.severity,
            evidence=detail.evidence,
            payload=detail.payload,
            confidence=detail.confidence,
        )
        for node_id, detail in result.root.items()
    ]

    log.info("audit: %s -> %d findings", task.file_path, len(new_findings))
    findings = state.get("findings", []) + new_findings
    return {"findings": findings, "audit_index": idx + 1}
