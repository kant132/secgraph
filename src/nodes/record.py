"""record node — 持久化所有 findings 到 DB + 为每个 finding 写 .md（不论验证结果）。

verify 完成后记录验证过程和结果，包括：
- confirmed: 漏洞已验证 → verified_vulns 表 + .md
- denied: 漏洞被否认 → findings 表 + .md（记录为什么否认）
- inconclusive: 无法确定 → findings 表 + .md（记录缺少什么信息）
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..db import FindingsDB
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.record")


def _write_finding_md(findings_dir: str, run_id: str, f: Finding) -> str:
    """为每个 finding 写 .md（不论验证结果），记录完整验证过程。"""
    stem = Path(f.file_path).stem
    safe_node = f.node_id.replace(":", "_").replace("/", "_")[:40]
    # 文件名标记验证结果
    result_tag = f.poc_result or "pending"
    name = f"{stem}_{safe_node}_{f.vuln_type}_{result_tag}.md"
    out = Path(findings_dir) / name
    out.parent.mkdir(parents=True, exist_ok=True)

    body = f"""# {f.vuln_type} — {f.severity} — {f.poc_result or 'pending'}

- **file**: `{f.file_path}`
- **node_id**: `{f.node_id}`
- **confidence**: {f.confidence}
- **run_id**: {run_id}
- **验证结果**: {f.poc_result or 'pending'}

## Evidence
{f.evidence}

## Payload（发送的 PoC）
```
{f.payload or '(none)'}
```

## PoC（执行的命令）
```
{f.poc or '(none)'}
```

## PoC Result
{f.poc_result or 'inconclusive'}

## PoC Output（验证响应）
```
{f.poc_output or '(none)'}
```
"""
    out.write_text(body, encoding="utf-8")
    return str(out)


def record(state: AuditState) -> dict:
    """持久化所有 findings 到 DB + 为每个 finding 写 .md（不论验证结果）。"""
    db_path = state["findings_db"]
    run_id = state["run_id"]
    findings_dir = state["findings_dir"]
    findings: list[Finding] = list(state.get("findings", []))

    verified_count = 0
    with FindingsDB(db_path) as db:
        for f in findings:
            fid = db.insert_finding(run_id, f)

            # 每个 finding 都写 .md（记录完整验证过程和结果）
            md_path = _write_finding_md(findings_dir, run_id, f)

            if f.poc_result == "confirmed":
                db.mark_verified(fid, run_id, f, md_path)
                verified_count += 1
                log.info("record: CONFIRMED → %s", md_path)
            elif f.poc_result == "denied":
                db.mark_false_positive(fid)
                log.info("record: DENIED → %s", md_path)
            elif f.poc_result == "inconclusive":
                log.info("record: INCONCLUSIVE → %s", md_path)
            else:
                log.info("record: PENDING（未验证）→ %s", md_path)

        db.finish_run(run_id, files_audited=state.get("audit_index", 0),
                      total_findings=len(findings), total_verified=verified_count)

    log.info("record: %d findings (%d confirmed, %d denied, rest inconclusive/pending) → %s",
             len(findings), verified_count,
             sum(1 for f in findings if f.poc_result == "denied"), db_path)
    return {"verified": [f for f in findings if f.poc_result == "confirmed"]}
