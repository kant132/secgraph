"""ORM 模型 — secgraph 业务表（runs / findings / verified_vulns / audit_memory）。

所有表都直接建在 codegraph.db 里（和 codegraph CLI 索引的 nodes / edges / route_reachable
同库）。nodes / edges / route_reachable 由 codegraph CLI 外部维护，本模块不管。

设计原则
--------
1. **业务表全部 ORM**：runs / findings / verified_vulns / audit_memory 四张表
   的 DDL、INSERT、UPDATE、SELECT 都走 SQLAlchemy 2.0 ORM，不再用裸 sqlite3。
2. **codegraph 索引表保留裸 SQL**：nodes / edges / route_reachable 由 codegraph CLI
   建表 + 写入，且 Q1-Q5 查询含递归 CTE（WITH RECURSIVE），ORM 表达力不够，
   继续用 src/codegraph/queries.py 里的裸 SQL。
3. **同库双连接**：codegraph.db 同时被 CodegraphClient（裸 sqlite3 连接，跑 Q1-Q5）
   和本模块的 ORM session（SQLAlchemy 引擎，跑业务表 CRUD）访问。SQLite 支持多连接
   并发读，写事务会加库级锁 — 业务表写只在 record / audit 两个节点，不会并发。

时间字段
--------
SQLite 没有原生 DATETIME 类型，所有时间用 TEXT 存 ISO 字符串。Python 端读回是 str，
需要 datetime 时在调用处自行 `datetime.fromisoformat()`。本层不做类型转换，保持
SQL 原生行为，避免 ORM 类型映射引入隐性 bug。

UPSERT
------
SQLAlchemy 2.0 没有跨方言的 UPSERT 抽象（PostgreSQL 有 ON CONFLICT，MySQL 有
ON DUPLICATE KEY UPDATE，SQLite 3.24+ 有 ON CONFLICT）。我们用 SQLite 专用的
`from sqlalchemy.dialects.sqlite import insert` 来做 UPSERT，避免 dialect 漂移。
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Index, Integer, String, Text, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

log = logging.getLogger("secgraph.db.models")


class Base(DeclarativeBase):
    """所有 ORM 模型的基类。`Base.metadata.create_all(engine)` 一次性建全部业务表。"""
    pass


# ---------------------------------------------------------------------------
# runs — 一次 pipeline 执行（一个 run_id = 一次 main.py 调用）
# ---------------------------------------------------------------------------

class Run(Base):
    """一次 pipeline 执行的元数据。

    用途
    ----
    每次跑 `python main.py --project ... --group-id ...` 会生成一个 8 位 hex
    run_id（main.py:43 `uuid.uuid4().hex[:8]`），record 节点用 INSERT OR REPLACE
    写入本表。run 结束时更新 finished_at + 统计字段。

    字段
    ----
    id           : 8 位 hex run_id（PK）。由 main.py 生成，全 pipeline 共享。
    mode         : 'dev' 或 'runtime'。dev 限制 file_limit=20 + debug 日志；runtime 全量扫。
    pkg_prefix   : 业务包前缀，如 'org/owasp/webgoat'（group_id 把 '.' 换成 '/'）。
                   用于 codegraph Q1 过滤入口方法。
    file_limit   : dev 模式限制审计的方法数（20）；runtime 模式为 None（不限）。
    files_audited : 实际审计的方法数（audit_index 最终值）。
    total_findings : 本次 run 发现的 findings 总数。
    total_verified : 本次 run 确认（poc_result='confirmed'）的漏洞数。
    iteration    : self-reflection 循环迭代次数（reflect 节点已摘除，字段保留但不再用）。
    started_at   : record 节点写入时由 SQLite `datetime('now')` 自动填。
    finished_at  : record 节点结束前手动 UPDATE 填当前时间。
    """

    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, comment="8 位 hex run_id")
    mode: Mapped[str] = mapped_column(String, nullable=False, comment="dev | runtime")
    pkg_prefix: Mapped[str] = mapped_column(String, nullable=False, comment="业务包前缀，如 org/owasp/webgoat")
    file_limit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, comment="dev=20, runtime=None（不限）")
    files_audited: Mapped[int] = mapped_column(Integer, default=0, server_default="0", comment="实际审计的方法数")
    total_findings: Mapped[int] = mapped_column(Integer, default=0, server_default="0", comment="本次 run 发现的 findings 总数")
    total_verified: Mapped[int] = mapped_column(Integer, default=0, server_default="0", comment="本次 run 确认的漏洞数")
    iteration: Mapped[int] = mapped_column(Integer, default=0, server_default="0", comment="self-reflection 迭代次数（已摘除，保留字段）")
    started_at: Mapped[Optional[str]] = mapped_column(Text, server_default=text("datetime('now')"), comment="run 开始时间（ISO 字符串）")
    finished_at: Mapped[Optional[str]] = mapped_column(Text, nullable=True, comment="run 结束时间（ISO 字符串，record 节点结束时填）")


# ---------------------------------------------------------------------------
# findings — 所有疑似漏洞（不论是否验证成功）
# ---------------------------------------------------------------------------

class FindingORM(Base):
    """一条疑似漏洞记录。

    用途
    ----
    audit 节点每发现一个漏洞就产生一个 Finding（state.py 的 dataclass），record 节点
    把它写入本表。verify 节点验证后回写 status 字段（pending → verified / false_positive）。

    字段
    ----
    id          : 自增主键（SQLite INTEGER PRIMARY KEY AUTOINCREMENT）。
    run_id      : 外键到 runs.id。同一次 run 的所有 findings 共享 run_id。
    file_path   : 漏洞所在的 Java 源码相对路径（如 'src/main/java/.../SqlInjection.java'）。
    node_id     : codegraph 节点 ID（如 'method:abc123'），是 codegraph.db nodes 表的 id。
                  audit 阶段从 FileAuditTask.node_id 取，trace 阶段用它查调用链。
    vuln_type   : 漏洞类型枚举：SQLi | SSRF | deser | path-traversal | XXE |
                  expression-injection | RCE | XSS | JNDI | LDAP-injection | XPath-injection | unknown
    severity    : 严重等级：critical | high | medium | low | unknown
                  （memory cache 命中时用 "unknown" 占位，因为 audit_memory 表不存 severity）
    evidence    : 审计证据文本。包含行号、污点分析、消毒情况、可达性分析标记
                  （[路由可达性分析] 可达/不可达）。trace_route 节点会追加可达性结论。
    payload     : PoC 攻击载荷。audit 阶段可能给一个静态 payload；trace_route 阶段
                  根据 HTTP 路由更新为完整 HTTP 请求；verify 阶段 second_payload 循环可能改写。
    confidence  : 置信度 0.0-1.0。audit 阶段 LLM 给初值；trace 阶段可达则用 LLM 更新值，
                  不可达则 × 0.3 衰减；verify 阶段失败也 × 0.3 衰减。
    status      : 生命周期状态：pending（audit 后）→ verified（verify confirmed）
                  或 false_positive（verify denied）。inconclusive 的不更新 status。
    created_at  : INSERT 时由 SQLite `datetime('now')` 自动填。
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="自增主键")
    run_id: Mapped[str] = mapped_column(String, nullable=False, comment="外键到 runs.id")
    file_path: Mapped[str] = mapped_column(String, nullable=False, comment="漏洞所在 Java 源码相对路径")
    node_id: Mapped[str] = mapped_column(String, nullable=False, comment="codegraph 节点 ID（nodes.id）")
    vuln_type: Mapped[str] = mapped_column(String, nullable=False, comment="漏洞类型：SQLi|SSRF|deser|path-traversal|XXE|RCE|XSS|...")
    severity: Mapped[str] = mapped_column(String, nullable=False, comment="严重等级：critical|high|medium|low|unknown")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, comment="审计证据（行号+污点+消毒+可达性标记）")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="", comment="PoC 攻击载荷")
    confidence: Mapped[float] = mapped_column(nullable=False, comment="置信度 0.0-1.0")
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending", server_default="pending", comment="生命周期：pending→verified|false_positive")
    created_at: Mapped[Optional[str]] = mapped_column(Text, server_default=text("datetime('now')"), comment="INSERT 时间（ISO 字符串）")

    __table_args__ = (
        # run_id 索引：record 节点按 run_id 查统计 + 跨 run 对比
        Index("idx_findings_run", "run_id"),
        # status 索引：按状态过滤（只看 verified / 只看 pending）
        Index("idx_findings_status", "status"),
        # vuln_type 索引：按漏洞类型统计
        Index("idx_findings_vuln_type", "vuln_type"),
    )


# ---------------------------------------------------------------------------
# verified_vulns — 已确认漏洞（poc_result='confirmed' 才写入）
# ---------------------------------------------------------------------------

class VerifiedVuln(Base):
    """一条已确认漏洞的完整 PoC 记录。

    用途
    ----
    verify 节点确认（poc_result='confirmed'）的 finding 才写入本表。包含 PoC 执行细节
    （发送的 payload、执行的命令、响应、.md 报告路径）。用于事后审计 + 漏洞复盘。

    设计：finding_id 是 PK（1:1 到 findings.id），不是 AUTOINCREMENT —
    一个 finding 最多对应一条 verified_vuln 记录。

    字段
    ----
    finding_id  : 主键，外键到 findings.id（1:1 关系）。
    run_id      : 外键到 runs.id（冗余存储，方便按 run 查已确认漏洞，不用 JOIN findings）。
    file_path   : 漏洞源码路径（冗余自 findings，方便不 JOIN 直接看）。
    node_id     : codegraph 节点 ID（冗余自 findings）。
    vuln_type   : 漏洞类型（冗余自 findings）。
    severity    : 严重等级（冗余自 findings）。
    evidence    : 证据全文（含 trace 阶段追加的可达性分析 + verify 阶段追加的 CIA 证明）。
    payload     : 最终确认生效的 PoC payload（可能是 second_payload 改写后的版本）。
    poc         : 执行的命令/请求（目前和 payload 基本相同，保留字段供未来扩展为 shell 命令 PoC）。
    poc_result  : 永远是 'confirmed'（写入条件）。保留字段以支持未来 'partially_confirmed' 等中间态。
    poc_output  : verify 阶段的 AI 推理文本（包含 CIA 证明 + reasoning）。
    md_path     : .md 报告文件的绝对路径（secgraph_findings/<file>_<node>_<vuln>_confirmed.md）。
    verified_at : INSERT 时由 SQLite `datetime('now')` 自动填。
    """

    __tablename__ = "verified_vulns"

    finding_id: Mapped[int] = mapped_column(
        Integer, primary_key=True, comment="主键+外键到 findings.id（1:1 关系）",
    )
    run_id: Mapped[str] = mapped_column(String, nullable=False, comment="外键到 runs.id（冗余存储）")
    file_path: Mapped[str] = mapped_column(String, nullable=False, comment="漏洞源码路径（冗余自 findings）")
    node_id: Mapped[str] = mapped_column(String, nullable=False, comment="codegraph 节点 ID（冗余自 findings）")
    vuln_type: Mapped[str] = mapped_column(String, nullable=False, comment="漏洞类型（冗余自 findings）")
    severity: Mapped[str] = mapped_column(String, nullable=False, comment="严重等级（冗余自 findings）")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, comment="证据全文（含可达性+CIA 证明）")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="", comment="最终生效的 PoC payload")
    poc: Mapped[str] = mapped_column(Text, nullable=False, comment="执行的命令/请求")
    poc_result: Mapped[str] = mapped_column(String, nullable=False, comment="验证结果（写入时永远='confirmed'）")
    poc_output: Mapped[Optional[str]] = mapped_column(Text, nullable=True, comment="verify AI 推理文本（CIA 证明 + reasoning）")
    md_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True, comment=".md 报告文件绝对路径")
    verified_at: Mapped[Optional[str]] = mapped_column(Text, server_default=text("datetime('now')"), comment="确认时间（ISO 字符串）")

    __table_args__ = (
        # run_id 索引：按 run 查已确认漏洞
        Index("idx_verified_run", "run_id"),
    )


# ---------------------------------------------------------------------------
# audit_memory — 审计记忆缓存（避免重复 LLM 审计同一方法）
# ---------------------------------------------------------------------------

class AuditMemory(Base):
    """审计记忆缓存 — 已审过的方法的结构化结论。

    用途
    ----
    audit 节点审完一个方法后，把 LLM 给出的结构化结论（vuln_type / confidence /
    input_validation / output_limitation / called_methods / security_risk）存入本表。
    下次再审同一 node_id 时，discovery_agent 先查本表：confidence >= 0.9 直接复用，
    跳过 LLM 调用（省 token + 时间）。

    UPSERT 语义
    -----------
    按 node_id 唯一约束 UPSERT（SQLite ON CONFLICT(node_id) DO UPDATE）。
    同一方法多次审计，后写覆盖前写，updated_at 刷新。

    字段
    ----
    id               : 自增主键。
    node_id          : codegraph 节点 ID（UNIQUE 约束，UPSERT 的冲突判定列）。
    signature        : 签名摘要，格式 '{node_id}:{vuln_type}'，用于快速识别。
    input_validation : 输入校验情况（参数注解 @NotNull/@Pattern/@Size、类型约束、手动校验逻辑）。
    output_limitation: 输出限制（返回值编码/过滤/转义/长度限制）。
    called_methods   : 被调方法列表（callee qualified_names 逗号分隔）。
    security_risk    : 安全风险摘要（vuln_type + evidence 摘要）。lookup_memory 时作为 evidence 返回。
    vuln_type        : 漏洞类型（同 findings.vuln_type 枚举）。
    confidence       : 置信度 0.0-1.0。discovery_agent 的 MEMORY_CONFIDENCE_THRESHOLD=0.9
                       是 lookup_memory 的默认阈值 — 低于 0.9 的记忆不缓存命中。
    status           : 生命周期状态（pending/verified/false_positive），和 findings.status 同语义。
    created_at       : 首次 INSERT 时间。
    updated_at       : 最近 UPSERT 时间（每次覆盖都刷新）。
    """

    __tablename__ = "audit_memory"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True, comment="自增主键")
    node_id: Mapped[str] = mapped_column(String, nullable=False, unique=True, comment="codegraph 节点 ID（UNIQUE，UPSERT 冲突列）")
    signature: Mapped[str] = mapped_column(String, nullable=False, comment="签名摘要 '{node_id}:{vuln_type}'")
    input_validation: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="", comment="输入校验情况（注解/类型/约束）")
    output_limitation: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="", comment="输出限制（编码/过滤/转义/长度）")
    called_methods: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="", comment="被调方法列表（逗号分隔）")
    security_risk: Mapped[str] = mapped_column(Text, nullable=False, comment="安全风险摘要（lookup_memory 时作为 evidence 返回）")
    vuln_type: Mapped[str] = mapped_column(String, nullable=False, comment="漏洞类型（同 findings.vuln_type 枚举）")
    confidence: Mapped[float] = mapped_column(nullable=False, comment="置信度 0.0-1.0（>=0.9 才缓存命中）")
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending", server_default="pending", comment="生命周期：pending|verified|false_positive")
    created_at: Mapped[Optional[str]] = mapped_column(Text, server_default=text("datetime('now')"), comment="首次 INSERT 时间")
    updated_at: Mapped[Optional[str]] = mapped_column(Text, server_default=text("datetime('now')"), comment="最近 UPSERT 时间")

    __table_args__ = (
        # node_id 索引：lookup_memory 按 node_id 查（已有 UNIQUE 约束自动建索引，
        # 但显式声明让意图更清晰）
        Index("idx_memory_node_id", "node_id"),
        # confidence 索引：按置信度过滤（如查所有 >= 0.9 的高置信记忆）
        Index("idx_memory_confidence", "confidence"),
    )


__all__ = ["Base", "Run", "FindingORM", "VerifiedVuln", "AuditMemory"]