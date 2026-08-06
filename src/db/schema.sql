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

CREATE TABLE IF NOT EXISTS audit_memory (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id       TEXT NOT NULL,              -- codegraph nodeid（方法签名唯一标识）
    signature     TEXT NOT NULL,              -- 方法签名（qualified_name + signature 拼接）
    input_validation TEXT DEFAULT '',         -- 输入校验：参数注解/类型/约束
    output_limitation TEXT DEFAULT '',        -- 输出限制：返回值约束/编码/过滤
    called_methods TEXT DEFAULT '',           -- 调用的方法（callee qualified_names 逗号分隔）
    security_risk TEXT NOT NULL,              -- 存在的安全风险（vuln_type + evidence）
    vuln_type     TEXT NOT NULL,              -- 漏洞类型
    confidence    REAL NOT NULL,             -- 置信度 0.0-1.0
    status        TEXT NOT NULL DEFAULT 'pending',  -- pending / verified / false_positive
    created_at    TEXT DEFAULT (datetime('now')),
    updated_at    TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_memory_node_id   ON audit_memory(node_id);
CREATE INDEX IF NOT EXISTS idx_memory_signature ON audit_memory(signature);
CREATE INDEX IF NOT EXISTS idx_memory_confidence ON audit_memory(confidence);
