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

from ..db import ChainResultORM, FindingORM, Run, VerifiedVuln, get_session, init_business_tables
from ..prompts import render
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.record")


def _write_finding_md(findings_dir: str, run_id: str, f: Finding) -> str:
    """为每个 finding 写 .md（不论验证结果），记录完整验证过程。

    模板文件：src/prompts/finding_report_template.md
    文件名格式：{文件名}_{node_id 前 40 字符}_{vuln_type}_{poc_result}.md
    """
    stem = Path(f.file_path).stem
    safe_node = f.node_id.replace(":", "_").replace("/", "_")[:40]
    result_tag = f.poc_result or "pending"
    name = f"{stem}_{safe_node}_{f.vuln_type}_{result_tag}.md"
    out = Path(findings_dir) / name
    out.parent.mkdir(parents=True, exist_ok=True)

    # 用模板渲染，默认值在 Python 端算好再传入
    body = render("finding_report",
                  vuln_type=f.vuln_type,
                  severity=f.severity,
                  poc_result=f.poc_result or "pending",
                  file_path=f.file_path,
                  node_id=f.node_id,
                  confidence=f.confidence,
                  run_id=run_id,
                  evidence=f.evidence,
                  payload=f.payload or "(none)",
                  poc=f.poc or "(none)",
                  poc_result_inconclusive=f.poc_result or "inconclusive",
                  poc_output=f.poc_output or "(none)")
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

    log.info("record: === RECORD START %d 个 finding ===", len(findings))

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
            session.flush()
            fid = finding_row.id

            # 3b. 每个 finding 都写 .md
            md_path = _write_finding_md(findings_dir, run_id, f)

            # 3c. 每条链独立写 chain_results + verified_vuln（confirmed 链才写 verified_vuln）
            for cr in f.chains:
                # 写 chain_results（所有链都写，不论 reachable/poc_result）
                chain_row = ChainResultORM(
                    finding_id=fid,
                    run_id=run_id,
                    node_id=f.node_id,
                    chain_path=cr.chain_path,
                    chain_ids=cr.chain_ids,
                    reachable=cr.reachable,
                    payload=cr.payload or "",
                    conditions=cr.conditions or "",
                    confidence=cr.confidence,
                    poc_result=cr.poc_result,
                    poc_output=cr.poc_output,
                )
                session.add(chain_row)

                if cr.poc_result == "confirmed":
                    verified_row = VerifiedVuln(
                        finding_id=fid,
                        run_id=run_id,
                        file_path=f.file_path,
                        node_id=f.node_id,
                        vuln_type=f.vuln_type,
                        severity=f.severity,
                        evidence=f.evidence,
                        payload=cr.payload or "",
                        poc=cr.payload or "",
                        poc_result=cr.poc_result or "inconclusive",
                        poc_output=cr.poc_output or "",
                        md_path=md_path,
                    )
                    session.add(verified_row)
                    verified_count += 1
                    log.info("record: CONFIRMED 链 %s → %s", cr.chain_path[:50], md_path)

            # 3d. 更新 finding.status
            if f.poc_result == "confirmed":
                finding_row.status = "verified"
            elif f.poc_result == "denied":
                finding_row.status = "false_positive"
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

    log.info("record: === RECORD END → %d findings (%d confirmed) ===",
             len(findings), verified_count)
    return {"verified": [f for f in findings if f.poc_result == "confirmed"]}