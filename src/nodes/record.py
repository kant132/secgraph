"""record node — persist findings to DB + write standalone .md for verified vulns.

Runs ONCE after verify_finding completes. Idempotent per run_id.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..db import FindingsDB
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.record")


def _write_vuln_md(findings_dir: str, run_id: str, f: Finding) -> str:
    """Write a standalone .md writeup for one verified vuln. Returns the path."""
    stem = Path(f.file_path).stem
    # sanitize node_id for filename (may contain non-path chars)
    safe_node = f.node_id.replace(":", "_").replace("/", "_")[:40]
    name = f"{stem}_{safe_node}_{f.vuln_type}.md"
    out = Path(findings_dir) / name
    out.parent.mkdir(parents=True, exist_ok=True)
    body = f"""# {f.vuln_type} — {f.severity}

- **file**: `{f.file_path}`
- **node_id**: `{f.node_id}`
- **confidence**: {f.confidence}
- **run_id**: {run_id}

## Evidence
{f.evidence}

## Payload (static)
{f.payload or '(none)'}

## PoC (executed)
```
{f.poc or '(none)'}
```

## PoC Result
{f.poc_result or 'inconclusive'}

## Output
```
{f.poc_output or '(none)'}
```
"""
    out.write_text(body, encoding="utf-8")
    return str(out)


def record(state: AuditState) -> dict:
    """Insert all findings to DB; write .md for verified (poc_result=='confirmed')."""
    db_path = state["findings_db"]
    run_id = state["run_id"]
    findings_dir = state["findings_dir"]
    findings: list[Finding] = list(state.get("findings", []))

    verified_count = 0
    with FindingsDB(db_path) as db:
        for f in findings:
            fid = db.insert_finding(run_id, f)
            if f.poc_result == "confirmed":
                md_path = _write_vuln_md(findings_dir, run_id, f)
                db.mark_verified(fid, run_id, f, md_path)
                verified_count += 1
                log.info("record: VERIFIED -> %s", md_path)
            elif f.poc_result == "denied":
                db.mark_false_positive(fid)
                log.info("record: FALSE POSITIVE -> %s:%s", f.file_path, f.node_id)

        db.finish_run(run_id, files_audited=state.get("audit_index", 0),
                      total_findings=len(findings), total_verified=verified_count)

    log.info("record: %d findings, %d verified -> %s", len(findings), verified_count, db_path)
    return {"verified": [f for f in findings if f.poc_result == "confirmed"]}
