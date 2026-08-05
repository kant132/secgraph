"""reflect node — LLM self-reflection on false positives / false negatives.

After one full pass (discover -> audit -> verify -> record), reflect():
  1. Summarize FP rate (denied / total) and coverage gaps.
  2. Asks LLM: "Which SQL filters / prompt sections / sink patterns should change?"
  3. Writes reflection_notes[].
  4. If iteration < max_iterations AND notes suggest improvement -> router loops
     back to discover() with adjusted params. Otherwise -> END.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..llm import call_llm
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.reflect")

_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "reflect_template.md"
_TEMPLATE = _TEMPLATE.resolve()


def reflect(state: AuditState) -> dict:
    """LLM reflection -> notes. Router decides loop-back vs END."""
    iteration = state.get("iteration", 0)
    max_iter = state.get("max_iterations", 3)
    if iteration >= max_iter:
        log.info("reflect: max_iterations reached (%d), stopping", max_iter)
        return {"reflection_notes": ["max_iterations reached"]}

    findings: list[Finding] = list(state.get("findings", []))
    confirmed = [f for f in findings if f.poc_result == "confirmed"]
    denied = [f for f in findings if f.poc_result == "denied"]
    inconclusive = [f for f in findings if f.poc_result == "inconclusive"]

    fp_samples = "\n".join(
        f"  - {f.file_path}:{f.node_id} ({f.vuln_type})" for f in denied[:5]
    ) or "  (none)"
    inc_samples = "\n".join(
        f"  - {f.file_path}:{f.node_id} ({f.vuln_type})" for f in inconclusive[:5]
    ) or "  (none)"

    tmpl = _TEMPLATE.read_text(encoding="utf-8")
    prompt = tmpl \
        .replace("{files_audited}", str(state.get("audit_index", 0))) \
        .replace("{total}", str(len(findings))) \
        .replace("{confirmed}", str(len(confirmed))) \
        .replace("{denied}", str(len(denied))) \
        .replace("{inconclusive}", str(len(inconclusive))) \
        .replace("{fp_samples}", fp_samples) \
        .replace("{inconclusive_samples}", inc_samples)

    try:
        raw = call_llm(prompt)
        log.info("reflect: iteration %d -> LLM response %.200s", iteration, raw)
        notes = [raw]
    except Exception as e:
        log.warning("reflect: LLM call failed (%s), skipping reflection", e)
        notes = [f"LLM call failed: {e}"]

    return {
        "reflection_notes": notes,
        "iteration": iteration + 1,
    }
