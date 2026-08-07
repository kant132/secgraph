"""codegraph 客户端 — 通过 sqlite3 查询 codegraph.db，返回类型化数据。

每条方法对应 Q1/Q3-Q5 查询，返回 state.py 中的 dataclass。
用可写连接（非 mode=ro）确保 SQLite 能读 WAL 数据 — 只读模式会跳过 WAL 返回 0 行。
所有查询以 node_id 为键（不再用 file_path）。
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from sqlalchemy import text

from ..state import FieldNode, MethodNode
from .queries import (
    Q1_ENTRY_METHODS, Q3_FIELDS_BY_NODE, Q4_CALLEE_META, Q5_REVERSE_CHAIN,
    ROUTE_REACHABLE_INIT, IS_ROUTE_REACHABLE,
)

log = logging.getLogger("secgraph.codegraph")


class CodegraphClient:
    """codegraph SQLite 索引的薄类型化封装。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        # 进程级缓存：{(sources_root, file_path): list[str]}，避免同一文件多次 read_text+splitlines
        self._file_lines: dict[tuple[str, str], list[str]] = {}
        # 建临时表（调用一次，后续全部 JOIN）
        self._conn.executescript(ROUTE_REACHABLE_INIT)
        self._conn.commit()
        count = self._conn.execute("SELECT COUNT(*) FROM route_reachable").fetchone()[0]
        log.info("codegraph: route_reachable 表已建，%d 个可达 node", count)

    def is_route_reachable(self, node_id: str) -> bool:
        """快速判断 node_id 是否在 route 可达集中。"""
        row = self._conn.execute(IS_ROUTE_REACHABLE, {"node_id": node_id}).fetchone()
        return row is not None

    # ---- Q1: 入口方法发现 -----------------------------------------------

    def list_entry_methods(self, pkg_prefix: str, limit: int | None = None) -> list[MethodNode]:
        """Q1 — route 可达的入口方法（JOIN route_reachable 直接过滤）。"""
        pattern = f"%{pkg_prefix}%"
        rows = self._conn.execute(Q1_ENTRY_METHODS, {"pkg_pattern": pattern}).fetchall()
        methods = [
            MethodNode(
                id=r["id"],
                qualified_name=r["qualified_name"],
                name=r["name"],
                signature=r["signature"],
                file_path=r["file_path"],
                start_line=r["start_line"],
                end_line=r["end_line"],
            )
            for r in rows
        ]
        log.info("codegraph: route 可达入口方法 %d 个", len(methods))

        if limit is not None:
            methods = methods[:limit]
        return methods

    # ---- Q3: 成员字段（按 nodeid 查同文件） ------------------------------

    def list_fields_by_nodeid(self, node_id: str) -> list[FieldNode]:
        """Q3 — 给定任一方法 nodeid，返回同文件的成员字段（子查询取 file_path）。"""
        rows = self._conn.execute(Q3_FIELDS_BY_NODE, {"node_id": node_id}).fetchall()
        return [
            FieldNode(
                id=r["id"],
                qualified_name=r["qualified_name"],
                name=r["name"],
                start_line=r["start_line"],
                end_line=r["end_line"],
            )
            for r in rows
        ]

    # ---- Q4 + 方法体读取 -----------------------------------------------

    def _read_lines(self, sources_root: str, file_path: str) -> list[str] | None:
        """读源码行列表（进程内缓存）。文件不存在返回 None。"""
        key = (sources_root, file_path)
        if key not in self._file_lines:
            full = Path(sources_root) / file_path
            if not full.exists():
                self._file_lines[key] = []
                return None
            self._file_lines[key] = full.read_text(encoding="utf-8", errors="replace").splitlines()
        lines = self._file_lines[key]
        return lines if lines else None

    def _read_method_body(self, sources_root: str, file_path: str,
                          start_line: int, end_line: int, qualified_name: str) -> str:
        """读源码 [start_line, end_line]，首行加 // qualified_name 注释。不加行号。"""
        lines = self._read_lines(sources_root, file_path)
        if lines is None:
            return f"// {qualified_name}\n[source not found: {Path(sources_root) / file_path}]"
        snippet = lines[start_line - 1:end_line]
        body = "".join(f"{line}\n" for line in snippet)
        return f"// {qualified_name}\n{body}"

    def get_method_body(self, sources_root: str, method: MethodNode) -> str:
        """取一个入口方法的方法体（带行号 + qualified_name 注释）。"""
        return self._read_method_body(
            sources_root, method.file_path, method.start_line, method.end_line, method.qualified_name)

    def get_callee_bodies(self, sources_root: str, node_id: str) -> dict[str, str]:
        """Q4 — 入口方法的被调方法体 {callee_nodeid: '// fqn\nbody'}。
        仅 kind=calls 的边，distinct 去重。"""
        rows = self._conn.execute(Q4_CALLEE_META, {"node_id": node_id}).fetchall()
        return {
            r["callee_id"]: self._read_method_body(
                sources_root, r["callee_file"],
                r["callee_start_line"], r["callee_end_line"], r["callee_qualified"])
            for r in rows
        }

    # ---- Q5: 反向调用链追溯 ---------------------------------------------

    def get_call_chain_to_route(self, node_id: str) -> list[dict]:
        """Q5 — 从 vuln 方法反向追溯到 kind='route' 的 HTTP 入口。
        返回每条路径的元数据（route 节点 + chain_path + chain_ids）。"""
        rows = self._conn.execute(Q5_REVERSE_CHAIN, {"node_id": node_id}).fetchall()
        return [dict(r) for r in rows]

    def get_chain_bodies(self, sources_root: str, chain_ids: str) -> dict[str, str]:
        """按逗号分隔的 nodeid 列表，单条 SQL IN (...) 取所有方法体。
        用于构建调用链方法体，发给 AI 做可达性分析。"""
        nids = [nid.strip() for nid in chain_ids.split(",") if nid.strip()]
        if not nids:
            return {}
        placeholders = ",".join("?" for _ in nids)
        rows = self._conn.execute(
            f"SELECT id, qualified_name, file_path, start_line, end_line FROM nodes WHERE id IN ({placeholders})",
            nids,
        ).fetchall()
        return {
            r["id"]: self._read_method_body(
                sources_root, r["file_path"], r["start_line"], r["end_line"], r["qualified_name"])
            for r in rows
        }

    # ---- 审计记忆（ORM，和代码索引同库）---------------------------------
    # audit_memory 表的 DDL + CRUD 走 SQLAlchemy ORM（src/db/models.py 的 AuditMemory）。
    # CodegraphClient 本身保留裸 sqlite3 连接跑 Q1-Q5（递归 CTE 不适合 ORM），
    # 但 audit_memory 的 init/save/lookup 用独立 ORM session。

    def init_memory_table(self) -> None:
        """建 audit_memory 表（如果不存在）。走 ORM Base.metadata.create_all。

        等价于原 `CREATE TABLE IF NOT EXISTS audit_memory (...)`。
        ORM 模型定义在 src/db/models.py 的 AuditMemory 类。
        """
        from ..db import init_business_tables
        init_business_tables(self.db_path)

    def save_memory(self, node_id: str, signature: str, vuln_type: str,
                    security_risk: str, confidence: float, status: str = "pending",
                    input_validation: str = "", output_limitation: str = "",
                    called_methods: str = "") -> None:
        """保存/更新审计记忆。按 node_id UPSERT。

        ORM 实现：用 SQLite 方言的 `insert().on_conflict_do_update()`
        （等价于 `INSERT ... ON CONFLICT(node_id) DO UPDATE SET ...`）。
        """
        from sqlalchemy.dialects.sqlite import insert as sqlite_insert
        from sqlalchemy import text
        from ..db import AuditMemory, get_session

        stmt = sqlite_insert(AuditMemory).values(
            node_id=node_id,
            signature=signature,
            input_validation=input_validation,
            output_limitation=output_limitation,
            called_methods=called_methods,
            security_risk=security_risk,
            vuln_type=vuln_type,
            confidence=confidence,
            status=status,
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["node_id"],
            set_={
                "signature": stmt.excluded.signature,
                "input_validation": stmt.excluded.input_validation,
                "output_limitation": stmt.excluded.output_limitation,
                "called_methods": stmt.excluded.called_methods,
                "security_risk": stmt.excluded.security_risk,
                "vuln_type": stmt.excluded.vuln_type,
                "confidence": stmt.excluded.confidence,
                "status": stmt.excluded.status,
                "updated_at": text("datetime('now')"),
            },
        )

        with get_session(self.db_path) as session:
            session.execute(stmt)
            session.commit()

    def lookup_memory(self, node_id: str, min_confidence: float = 0.9) -> dict | None:
        """查审计记忆。置信度 >= min_confidence 才返回（直接复用，不再审）。

        ORM 实现：`select(AuditMemory).where(node_id=..., confidence>=...)`。
        返回 ORM 对象的 `__dict__`（去掉 SQLAlchemy 内部字段）。
        """
        from sqlalchemy import select
        from ..db import AuditMemory, get_session

        with get_session(self.db_path) as session:
            row = session.execute(
                select(AuditMemory).where(
                    AuditMemory.node_id == node_id,
                    AuditMemory.confidence >= min_confidence,
                )
            ).scalar_one_or_none()

            if row is None:
                return None
            # 返回 plain dict（兼容原 sqlite3.Row 行为 — 调用方按 dict 取键）
            return {
                "id": row.id,
                "node_id": row.node_id,
                "signature": row.signature,
                "input_validation": row.input_validation,
                "output_limitation": row.output_limitation,
                "called_methods": row.called_methods,
                "security_risk": row.security_risk,
                "vuln_type": row.vuln_type,
                "confidence": row.confidence,
                "status": row.status,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }

    # ---- 生命周期 --------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CodegraphClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()