"""verify_finding node — PoC self-verification of pending findings.

Runs AFTER the file-audit loop completes (all files audited, findings accumulated).
For each pending finding:
  - runtime mode: generate a PoC (HTTP curl for web endpoints / Arthas OGNL for
    non-web), execute against the running target, record confirmed/denied/inconclusive.
  - dev mode: skip execution (target may not be running), mark as 'inconclusive'
    with a static-only note — keeps the pipeline runnable without a live target.

TODO: wire real PoC generation + execution. Reference: D:\\back-skill\\java-poc-verify.
"""
from __future__ import annotations

import logging

from ..state import AuditState, Finding

log = logging.getLogger("secgraph.verify")


def verify_finding(state: AuditState) -> dict:
    """Verify all pending findings. Updates status + poc_result on each."""
    findings: list[Finding] = list(state.get("findings", []))
    mode = state.get("mode", "dev")

    if mode == "dev":
        log.info("verify: dev mode — skipping PoC execution, marking inconclusive")
        for f in findings:
            if f.status == "pending":
                f.poc_result = "inconclusive"
                f.poc_output = "[dev mode] PoC execution skipped — static-only analysis"
                # keep status='pending' so record() inserts as-is;
                # verified .md only written when poc_result=='confirmed'
        return {"findings": findings}

    # runtime mode — TODO: real PoC generation + execution
    log.info("verify: runtime mode — %d pending findings to PoC-verify", len(findings))
    for f in findings:
        if f.status != "pending":
            continue
        # TODO:
        #   1. LLM generates PoC from f.evidence + f.sink + call chain
        #   2. execute against running target (curl / Arthas)
        #   3. f.poc = <command>; f.poc_output = <output>
        #   4. f.poc_result = 'confirmed' | 'denied' | 'inconclusive'
        #   5. if confirmed: f.status = 'verified'
        #      if denied: f.status = 'false_positive'
        f.poc_result = "inconclusive"
        f.poc_output = "[TODO] PoC execution not implemented"

    return {"findings": findings}
