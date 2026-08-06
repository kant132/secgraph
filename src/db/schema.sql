-- secgraph 业务表 schema — 直接建在 codegraph.db 里（和 nodes/edges 同库）
-- audit_memory 由 CodegraphClient.init_memory_table() 单独建
-- 这里只建 runs / findings / verified_vulns

CREATE TABLE IF NOT EXISTS runs (
    id            TEXT PRIMARY KEY,
    mode          TEXT NOT NULL,
    pkg_prefix    TEXT NOT NULL,
    file_limit    INTEGER,
    files_audited  INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_verified INTEGER DEFAULT 0,
    iteration     INTEGER DEFAULT 0,
    started_at    TEXT DEFAULT (datetime('now')),
    finished_at   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    payload       TEXT DEFAULT '',
    confidence    REAL NOT NULL,
    status        TEXT NOT NULL DEFAULT 'pending',
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS verified_vulns (
    finding_id    INTEGER PRIMARY KEY,
    run_id        TEXT NOT NULL,
    file_path     TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    payload       TEXT DEFAULT '',
    poc           TEXT NOT NULL,
    poc_result    TEXT NOT NULL,
    poc_output    TEXT,
    md_path       TEXT,
    verified_at   TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_run       ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_verified_run       ON verified_vulns(run_id);
