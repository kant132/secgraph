"""codegraph 客户端 — 通过 sqlite3 查询 codegraph.db，返回类型化数据。

每条方法对应 Q1/Q3-Q5 查询，返回 state.py 中的 dataclass。
用可写连接（非 mode=ro）确保 SQLite 能读 WAL 数据 — 只读模式会跳过 WAL 返回 0 行。
所有查询以 node_id 为键（不再用 file_path）。
"""
from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

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

    # ---- 审计记忆（直接存 codegraph.db，和代码索引同库）-------------------

    def init_memory_table(self) -> None:
        """在 codegraph.db 里建 audit_memory 表（如果不存在）。"""
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS audit_memory (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            node_id         TEXT NOT NULL,
            signature       TEXT NOT NULL,
            input_validation TEXT DEFAULT '',
            output_limitation TEXT DEFAULT '',
            called_methods  TEXT DEFAULT '',
            security_risk   TEXT NOT NULL,
            vuln_type       TEXT NOT NULL,
            confidence      REAL NOT NULL,
            status          TEXT NOT NULL DEFAULT 'pending',
            created_at      TEXT DEFAULT (datetime('now')),
            updated_at      TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_memory_node_id ON audit_memory(node_id);
        CREATE INDEX IF NOT EXISTS idx_memory_confidence ON audit_memory(confidence);
        """)
        self._conn.commit()

    def save_memory(self, node_id: str, signature: str, vuln_type: str,
                    security_risk: str, confidence: float, status: str = "pending",
                    input_validation: str = "", output_limitation: str = "",
                    called_methods: str = "") -> None:
        """保存/更新审计记忆。按 node_id UPSERT（SQLite 3.24+）。"""
        self._conn.execute("""
            INSERT INTO audit_memory
                (node_id, signature, input_validation, output_limitation,
                 called_methods, security_risk, vuln_type, confidence, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(node_id) DO UPDATE SET
                signature = excluded.signature,
                input_validation = excluded.input_validation,
                output_limitation = excluded.output_limitation,
                called_methods = excluded.called_methods,
                security_risk = excluded.security_risk,
                vuln_type = excluded.vuln_type,
                confidence = excluded.confidence,
                status = excluded.status,
                updated_at = datetime('now')
        """, (node_id, signature, input_validation, output_limitation,
              called_methods, security_risk, vuln_type,
              confidence, status))
        self._conn.commit()

    def lookup_memory(self, node_id: str, min_confidence: float = 0.9) -> dict | None:
        """查审计记忆。置信度 >= min_confidence 才返回（直接复用，不再审）。"""
        row = self._conn.execute(
            "SELECT * FROM audit_memory WHERE node_id = ? AND confidence >= ?",
            (node_id, min_confidence)
        ).fetchone()
        if row:
            return dict(row)
        return None

    # ---- 生命周期 --------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "CodegraphClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()