"""audit_file node — renders the prompt template + calls structured LLM.

Uses langchain with_structured_output(Dict[str, VulnDetail]) — no manual
JSON parsing. LangChain auto-retries on schema violations.

Consumes one FileAuditTask from work_list[audit_index]. Produces Finding[]
appended to state['findings'].
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..llm import call_audit_llm
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.audit")

_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "audit_template.md"
_TEMPLATE = _TEMPLATE.resolve()


def _render_template(task) -> str:
    """Fill the audit prompt template with one FileAuditTask's data.
    Uses str.replace (not str.format) to avoid collision with literal {} in the
    JSON output section of the template."""
    fields_text = "\n".join(
        f"  {f.id}: {f.qualified_name}  (line {f.start_line})" for f in task.fields
    ) or "  (none)"

    methods_json = json.dumps(task.method_bodies, indent=2, ensure_ascii=False) if task.method_bodies else "{}"
    calls_json = json.dumps(task.calls, indent=2, ensure_ascii=False) if task.calls else "{}"

    tmpl = _TEMPLATE.read_text(encoding="utf-8")
    out = tmpl.replace("{fields}", fields_text)
    out = out.replace("{methods}", methods_json)
    out = out.replace("{calls}", calls_json)
    return out


def audit_file(state: AuditState) -> dict:
    """Audit work_list[audit_index] via structured LLM. Appends findings."""
    work_list: list = state.get("work_list", [])
    idx: int = state.get("audit_index", 0)
    if idx >= len(work_list):
        return {}  # loop done; router will send to reflect

    task = work_list[idx]
    log.info("audit: [%d/%d] %s", idx + 1, len(work_list), task.file_path)

    prompt = _render_template(task)
    log.info("audit: ===== prompt 发送给 LLM =====")
    print(prompt)
    log.info("audit: ===== prompt 结束 =====")
    result = call_audit_llm(prompt)  # AuditResult (RootModel[Dict[str, VulnDetail]])
    log.info("audit: ===== LLM 返回结构化结果 =====")
    for nid, detail in (result.root or {}).items():
        print(f"  [{nid}]")
        print(f"    vuln_type:  {detail.vuln_type}")
        print(f"    severity:   {detail.severity}")
        print(f"    confidence: {detail.confidence}")
        print(f"    payload:    {detail.payload}")
        print(f"    evidence:   {detail.evidence}")
        if detail.input_validation:
            print(f"    input_validation: {detail.input_validation}")
        if detail.output_limitation:
            print(f"    output_limitation: {detail.output_limitation}")
        if detail.called_methods:
            print(f"    called_methods: {detail.called_methods}")
        if detail.security_risk:
            print(f"    security_risk: {detail.security_risk}")
    log.info("audit: ===== LLM 返回结束 =====")

    # 保存审计记忆到 DB
    from ..db import FindingsDB
    findings_db_path = state.get("findings_db", "")
    if findings_db_path:
        with FindingsDB(findings_db_path) as db:
            for nid, detail in (result.root or {}).items():
                signature = f"{nid}:{detail.vuln_type}"
                db.save_memory(
                    node_id=nid,
                    signature=signature,
                    vuln_type=detail.vuln_type,
                    security_risk=detail.security_risk or detail.evidence[:200],
                    confidence=detail.confidence,
                    status="pending",
                    input_validation=detail.input_validation,
                    output_limitation=detail.output_limitation,
                    called_methods=detail.called_methods,
                )
        log.info("audit: 审计记忆已保存 → %d 条", len(result.root or {}))

    new_findings: list[Finding] = []
    for node_id, detail in result.root.items():
        new_findings.append(Finding(
            file_path=task.file_path,
            node_id=node_id,
            vuln_type=detail.vuln_type,
            severity=detail.severity,
            evidence=detail.evidence,
            payload=detail.payload,
            confidence=detail.confidence,
        ))

    log.info("audit: %s -> %d findings", task.file_path, len(new_findings))
    findings = list(state.get("findings", [])) + new_findings
    return {"findings": findings, "audit_index": idx + 1}
