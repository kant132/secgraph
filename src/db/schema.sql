-- secgraph findings DB schema
-- All suspected findings go to `findings`; only verified vulns go to `verified_vulns`.
-- `runs` tracks one pipeline execution (one ralph/loop iteration).

CREATE TABLE IF NOT EXISTS runs (
    id            TEXT PRIMARY KEY,           -- uuid
    mode          TEXT NOT NULL,              -- dev | runtime
    pkg_prefix    TEXT NOT NULL,
    file_limit    INTEGER,                     -- NULL = unlimited (runtime mode)
    files_audited  INTEGER DEFAULT 0,
    total_findings INTEGER DEFAULT 0,
    total_verified INTEGER DEFAULT 0,
    iteration     INTEGER DEFAULT 0,
    started_at    TEXT DEFAULT (datetime('now')),
    finished_at   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        TEXT NOT NULL REFERENCES runs(id),
    file_path     TEXT NOT NULL,
    node_id       TEXT NOT NULL,              -- codegraph nodeid of the method/callee
    vuln_type     TEXT NOT NULL,              -- SQLi / SSRF / deser / path-traversal / ... / unknown
    severity      TEXT NOT NULL,             -- critical / high / medium / low / unknown
    evidence      TEXT NOT NULL,             -- line refs + taint/logic + sanitization + reachability
    payload       TEXT DEFAULT '',            -- PoC payload from static analysis
    confidence    REAL NOT NULL,             -- 0.0-1.0
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending / verified / false_positive
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS verified_vulns (
    finding_id    INTEGER PRIMARY KEY REFERENCES findings(id),
    run_id        TEXT NOT NULL REFERENCES runs(id),
    file_path     TEXT NOT NULL,
    node_id       TEXT NOT NULL,
    vuln_type     TEXT NOT NULL,
    severity      TEXT NOT NULL,
    evidence      TEXT NOT NULL,
    payload       TEXT DEFAULT '',
    poc           TEXT NOT NULL,             -- the executed PoC command / payload
    poc_result    TEXT NOT NULL,             -- confirmed / denied / inconclusive
    poc_output    TEXT,                       -- raw execution output
    md_path       TEXT,                       -- path to the standalone .md writeup
    verified_at   TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_findings_run       ON findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_status    ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_vuln_type ON findings(vuln_type);
CREATE INDEX IF NOT EXISTS idx_verified_run       ON verified_vulns(run_id);
