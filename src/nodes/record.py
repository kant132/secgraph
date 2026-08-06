"""record node — 持久化所有 findings 到 codegraph.db + 为每个 finding 写 .md。

findings/verified_vulns/runs 表直接在 codegraph.db 里建（和代码索引同库）。
.md 报告写到输入项目的 secgraph_findings/ 目录下。
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..codegraph import CodegraphClient
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.record")

# 建 runs / findings / verified_vulns 表（直接写在 codegraph.db）。
# 表结构必须和 discovery/save_memory 用同一库时的 queries 一致。
_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS runs (
    id              TEXT PRIMARY KEY,
    mode            TEXT NOT NULL,
    pkg_prefix      TEXT NOT NULL,
    file_limit      INTEGER,
    iteration       INTEGER DEFAULT 0,
    files_audited   INTEGER DEFAULT 0,
    total_findings  INTEGER DEFAULT 0,
    total_verified  INTEGER DEFAULT 0,
    started_at      TEXT DEFAULT (datetime('now')),
    finished_at     TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    node_id     TEXT NOT NULL,
    vuln_type   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    evidence    TEXT,
    payload     TEXT,
    confidence  REAL,
    status      TEXT DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_node_id ON findings(node_id);
CREATE TABLE IF NOT EXISTS verified_vulns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id  INTEGER NOT NULL,
    run_id      TEXT NOT NULL,
    file_path   TEXT NOT NULL,
    node_id     TEXT NOT NULL,
    vuln_type   TEXT NOT NULL,
    severity    TEXT NOT NULL,
    evidence    TEXT,
    payload     TEXT,
    poc         TEXT,
    poc_result  TEXT,
    poc_output  TEXT,
    md_path     TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_verified_run_id ON verified_vulns(run_id);
"""


def _write_finding_md(findings_dir: str, run_id: str, f: Finding) -> str:
    """为每个 finding 写 .md（不论验证结果），记录完整验证过程。"""
    stem = Path(f.file_path).stem
    safe_node = f.node_id.replace(":", "_").replace("/", "_")[:40]
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
    """持久化所有 findings 到 codegraph.db + 为每个 finding 写 .md。"""
    codegraph_db = state["codegraph_db"]
    run_id = state["run_id"]
    findings_dir = state["findings_dir"]
    findings: list[Finding] = list(state.get("findings", []))

    verified_count = 0
    with CodegraphClient(codegraph_db) as cg:
        cg._conn.executescript(_SCHEMA_DDL)
        cg._conn.commit()

        # 记录 run
        cg._conn.execute(
            "INSERT OR REPLACE INTO runs(id, mode, pkg_prefix, file_limit, iteration) VALUES (?, ?, ?, ?, ?)",
            (run_id, state.get("mode", "dev"), state.get("pkg_prefix", ""),
             state.get("file_limit"), state.get("iteration", 0)),
        )
        cg._conn.commit()

        for f in findings:
            # 插入 finding
            cur = cg._conn.execute(
                "INSERT INTO findings(run_id, file_path, node_id, vuln_type, severity, evidence, payload, confidence, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (run_id, f.file_path, f.node_id, f.vuln_type, f.severity,
                 f.evidence, f.payload, f.confidence, f.status),
            )
            fid = cur.lastrowid if cur.lastrowid else 0

            # 每个 finding 都写 .md
            md_path = _write_finding_md(findings_dir, run_id, f)

            if f.poc_result == "confirmed":
                cg._conn.execute(
                    "INSERT INTO verified_vulns(finding_id, run_id, file_path, node_id, vuln_type, severity, evidence, payload, poc, poc_result, poc_output, md_path) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (fid, run_id, f.file_path, f.node_id, f.vuln_type, f.severity,
                     f.evidence, f.payload, f.poc or "", f.poc_result or "inconclusive",
                     f.poc_output or "", md_path),
                )
                cg._conn.execute("UPDATE findings SET status='verified' WHERE id=?", (fid,))
                verified_count += 1
                log.info("record: CONFIRMED → %s", md_path)
            elif f.poc_result == "denied":
                cg._conn.execute("UPDATE findings SET status='false_positive' WHERE id=?", (fid,))
                log.info("record: DENIED → %s", md_path)
            else:
                log.info("record: INCONCLUSIVE → %s", md_path)

        # 更新 run 统计
        cg._conn.execute(
            "UPDATE runs SET finished_at=datetime('now'), files_audited=?, total_findings=?, total_verified=? WHERE id=?",
            (state.get("audit_index", 0), len(findings), verified_count, run_id),
        )
        cg._conn.commit()

    log.info("record: %d findings (%d confirmed) → codegraph.db + %s",
             len(findings), verified_count, findings_dir)
    return {"verified": [f for f in findings if f.poc_result == "confirmed"]}