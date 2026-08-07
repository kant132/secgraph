"""record node — 持久化所有 findings 到 codegraph.db + 为每个 finding 写 .md。

所有 DB 操作走 SQLAlchemy ORM（src/db/models.py 的 Run/FindingORM/VerifiedVuln）。
.md 报告写到输入项目的 secgraph_findings/ 目录下。

为什么用 ORM 而非裸 SQL
------------------------
1. 类型安全：Python 端字段名拼错会立即 AttributeError，不用等跑 SQL 才发现。
2. UPSERT 语义清晰：SQLite 方言的 `insert().on_conflict_do_update()` 比
   `INSERT ... ON CONFLICT ... DO UPDATE SET` 字符串更易读。
3. 表结构单一来源：models.py 的 `Mapped[...]` 声明既是 DDL 又是类型注解，
   不用维护两份 schema（DDL 字符串 + Python 类型）。
4. 索引/约束随模型声明：`__table_args__` 里 Index 声明和列定义在一起，
   不用单独维护 `CREATE INDEX` 语句。

codegraph.db 双连接
-------------------
codegraph.db 同时被：
- CodegraphClient（裸 sqlite3 连接，跑 codegraph 索引查询 Q1-Q5 + ROUTE_REACHABLE_INIT）
- 本模块的 ORM session（SQLAlchemy engine，跑业务表 CRUD）
访问。SQLite 支持多连接并发读；写事务加库级锁。业务表写只在 record/audit 两个节点，
不会并发写。
"""
from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from ..db import FindingORM, Run, VerifiedVuln, get_session, init_business_tables
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.record")


def _write_finding_md(findings_dir: str, run_id: str, f: Finding) -> str:
    """为每个 finding 写 .md（不论验证结果），记录完整验证过程。

    .md 文件名格式：{文件名}_{node_id 前 40 字符}_{vuln_type}_{poc_result}.md
    例：SqlInjection_method_abc123_Sqli_confirmed.md

    内容包括：漏洞类型/严重度/验证结果、源码路径、node_id、置信度、
    完整 evidence（含可达性分析 + CIA 证明）、payload、PoC 命令、PoC 输出。
    """
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
    """持久化所有 findings 到 codegraph.db（ORM）+ 为每个 finding 写 .md。

    流程
    ----
    1. `init_business_tables` 建 runs/findings/verified_vulns/audit_memory 表（IF NOT EXISTS）
    2. INSERT OR REPLACE run（run_id 唯一，重复跑覆盖）
    3. 遍历 findings：
       - INSERT finding（自增 PK，flush 后拿回 id 作为 fid）
       - 写 .md 报告
       - confirmed → INSERT verified_vuln（PK=finding_id，1:1）+ UPDATE finding.status='verified'
       - denied    → UPDATE finding.status='false_positive'
       - 其他       → 不更新 status（保持 pending）
    4. UPDATE run 统计（finished_at / files_audited / total_findings / total_verified）
    """
    codegraph_db = state["codegraph_db"]
    run_id = state["run_id"]
    findings_dir = state["findings_dir"]
    findings: list[Finding] = list(state.get("findings", []))

    # 1. 建业务表（ORM Base.metadata.create_all，IF NOT EXISTS）
    init_business_tables(codegraph_db)

    verified_count = 0
    with get_session(codegraph_db) as session:
        # 2. 记录 run（INSERT OR REPLACE 语义 — run_id 已存在则覆盖）
        #    SQLite 方言的 on_conflict_do_update 等价于 INSERT OR REPLACE
        run_stmt = sqlite_insert(Run).values(
            id=run_id,
            mode=state.get("mode", "dev"),
            pkg_prefix=state.get("pkg_prefix", ""),
            file_limit=state.get("file_limit"),
            iteration=state.get("iteration", 0),
        )
        run_stmt = run_stmt.on_conflict_do_update(
            index_elements=["id"],
            set_={
                "mode": run_stmt.excluded.mode,
                "pkg_prefix": run_stmt.excluded.pkg_prefix,
                "file_limit": run_stmt.excluded.file_limit,
                "iteration": run_stmt.excluded.iteration,
            },
        )
        session.execute(run_stmt)
        session.commit()

        # 3. 遍历 findings
        for f in findings:
            # 3a. INSERT finding（ORM 对象）
            finding_row = FindingORM(
                run_id=run_id,
                file_path=f.file_path,
                node_id=f.node_id,
                vuln_type=f.vuln_type,
                severity=f.severity,
                evidence=f.evidence,
                payload=f.payload or "",
                confidence=f.confidence,
                status=f.status,
            )
            session.add(finding_row)
            session.flush()  # flush 拿回自增 PK（finding_row.id）
            fid = finding_row.id

            # 3b. 每个 finding 都写 .md
            md_path = _write_finding_md(findings_dir, run_id, f)

            # 3c. 根据验证结果写 verified_vuln / 更新 status
            if f.poc_result == "confirmed":
                # INSERT verified_vuln（PK=finding_id，1:1 关系）
                verified_row = VerifiedVuln(
                    finding_id=fid,
                    run_id=run_id,
                    file_path=f.file_path,
                    node_id=f.node_id,
                    vuln_type=f.vuln_type,
                    severity=f.severity,
                    evidence=f.evidence,
                    payload=f.payload or "",
                    poc=f.poc or "",
                    poc_result=f.poc_result or "inconclusive",
                    poc_output=f.poc_output or "",
                    md_path=md_path,
                )
                session.add(verified_row)
                # UPDATE finding.status='verified'（ORM 风格：改属性 + commit 时自动 UPDATE）
                finding_row.status = "verified"
                verified_count += 1
                log.info("record: CONFIRMED → %s", md_path)
            elif f.poc_result == "denied":
                finding_row.status = "false_positive"
                log.info("record: DENIED → %s", md_path)
            else:
                log.info("record: INCONCLUSIVE → %s", md_path)

        # 4. UPDATE run 统计
        #    ORM 风格：查回 run 行，改属性，commit 时自动 UPDATE
        run_row = session.get(Run, run_id)
        if run_row:
            run_row.finished_at = datetime.now().isoformat()
            run_row.files_audited = state.get("audit_index", 0)
            run_row.total_findings = len(findings)
            run_row.total_verified = verified_count

        session.commit()

    log.info("record: %d findings (%d confirmed) → codegraph.db + %s",
             len(findings), verified_count, findings_dir)
    return {"verified": [f for f in findings if f.poc_result == "confirmed"]}