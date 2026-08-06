"""codegraph 客户端 — 通过 sqlite3 查询 codegraph.db，返回类型化数据。

每条方法对应 Q1-Q4 查询，返回 state.py 中的 dataclass。
用可写连接（非 mode=ro）确保 SQLite 能读 WAL 数据 — 只读模式会跳过 WAL 返回 0 行。
所有查询以 node_id 为键（不再用 file_path）。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from ..state import CallEdge, FieldNode, MethodNode
from .queries import (
    Q1_ENTRY_METHODS, Q2_CALL_EDGES, Q3_FIELDS_BY_NODE, Q4_CALLEE_META, Q5_REVERSE_CHAIN,
)


class CodegraphClient:
    """codegraph SQLite 索引的薄类型化封装。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        # 可写连接：必须才能读 WAL（只读会跳过 WAL 返回 0 行）
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row

    # ---- Q1: 入口方法发现 -----------------------------------------------

    def list_entry_methods(self, pkg_prefix: str, limit: int | None = None) -> list[MethodNode]:
        """Q1 — 业务包内的 public 带参方法（入口方法），返回 nodeid 列表。
        limit 按 method 数切片（dev 态限 10 个方法）。"""
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
        if limit is not None:
            methods = methods[:limit]
        return methods

    # ---- Q2: 调用边（按 nodeid，多行） -----------------------------------

    def list_call_edges(self, node_id: str) -> list[CallEdge]:
        """Q2 — 入口方法的调用边（e.source = :node_id）。多行返回，需聚合。"""
        rows = self._conn.execute(Q2_CALL_EDGES, {"node_id": node_id}).fetchall()
        return [
            CallEdge(
                caller_qualified="",
                caller_name="",
                caller_line=0,
                callee_qualified=r["callee_qualified"],
                callee_name=r["callee_name"],
                callee_file=r["callee_file"],
                callee_line=r["callee_line"],
                edge_kind=r["edge_kind"],
            )
            for r in rows
        ]

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

    def list_sink_candidates(self, node_id: str) -> list[str]:
        """Q4 — 入口方法的 distinct callee qualified_name（仅 kind=calls）。"""
        rows = self._conn.execute(Q4_CALLEE_META, {"node_id": node_id}).fetchall()
        return [r["callee_qualified"] for r in rows]

    @staticmethod
    def _read_method_body(sources_root: str, file_path: str,
                          start_line: int, end_line: int, qualified_name: str) -> str:
        """读源码 [start_line, end_line]，首行加 // qualified_name 注释。不加行号。"""
        full = Path(sources_root) / file_path
        if not full.exists():
            return f"// {qualified_name}\n[source not found: {full}]"
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
        snippet = lines[start_line - 1:end_line]  # 0-indexed 切片
        body = "".join(f"{line}\n" for line in snippet)
        return f"// {qualified_name}\n{body}"

    def get_method_body(self, sources_root: str, method: MethodNode) -> str:
        """取一个入口方法的方法体（带行号 + qualified_name 注释）。"""
        return self._read_method_body(
            sources_root, method.file_path, method.start_line, method.end_line, method.qualified_name)

    def get_callee_bodies(self, sources_root: str, node_id: str) -> dict[str, str]:
        """Q4 — 入口方法的被调方法体 {callee_nodeid: '// fqn\\nbody'}。
        仅 kind=calls 的边，distinct 去重。"""
        rows = self._conn.execute(Q4_CALLEE_META, {"node_id": node_id}).fetchall()
        return {
            r["callee_id"]: self._read_method_body(
                sources_root, r["callee_file"],
                r["callee_start_line"], r["callee_end_line"], r["callee_qualified"])
            for r in rows
        }

    @staticmethod
    def read_source(sources_root: str, file_path: str) -> str:
        """读完整 .java 源码（带行号），保留兼容。"""
        full = Path(sources_root) / file_path
        if not full.exists():
            return f"[source not found: {full}]"
        text = full.read_text(encoding="utf-8", errors="replace")
        return "".join(f"{i + 1}: {line}\n" for i, line in enumerate(text.splitlines()))

    # ---- Q5: 反向调用链追溯 ---------------------------------------------

    def get_call_chain_to_route(self, node_id: str) -> list[dict]:
        """Q5 — 从 vuln 方法反向追溯到 kind='route' 的 HTTP 入口。
        返回每条路径的元数据（route 节点 + chain_path + chain_ids）。"""
        rows = self._conn.execute(Q5_REVERSE_CHAIN, {"node_id": node_id}).fetchall()
        return [dict(r) for r in rows]

    def get_chain_bodies(self, sources_root: str, chain_ids: str) -> dict[str, str]:
        """按逗号分隔的 nodeid 列表，逐个取方法体，返回 {nodeid: body}。
        用于构建调用链方法体，发给 AI 做可达性分析。"""
        result: dict[str, str] = {}
        for nid in chain_ids.split(","):
            nid = nid.strip()
            if not nid:
                continue
            row = self._conn.execute(
                "SELECT qualified_name, file_path, start_line, end_line FROM nodes WHERE id = ?",
                (nid,),
            ).fetchone()
            if row:
                result[nid] = self._read_method_body(
                    sources_root, row["file_path"],
                    row["start_line"], row["end_line"], row["qualified_name"])
        return result

    def get_node_body(self, sources_root: str, node_id: str) -> str:
        """按 nodeid 取单个节点的源码体。"""
        row = self._conn.execute(
            "SELECT qualified_name, file_path, start_line, end_line FROM nodes WHERE id = ?",
            (node_id,),
        ).fetchone()
        if row:
            return self._read_method_body(
                sources_root, row["file_path"],
                row["start_line"], row["end_line"], row["qualified_name"])
        return f"[node not found: {node_id}]"

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
        """保存/更新审计记忆。按 node_id upsert。"""
        existing = self._conn.execute(
            "SELECT id FROM audit_memory WHERE node_id = ?", (node_id,)
        ).fetchone()
        if existing:
            self._conn.execute("""
                UPDATE audit_memory SET
                    signature = ?, input_validation = ?, output_limitation = ?,
                    called_methods = ?, security_risk = ?, vuln_type = ?,
                    confidence = ?, status = ?, updated_at = datetime('now')
                WHERE node_id = ?
            """, (signature, input_validation, output_limitation,
                  called_methods, security_risk, vuln_type,
                  confidence, status, node_id))
        else:
            self._conn.execute("""
                INSERT INTO audit_memory
                    (node_id, signature, input_validation, output_limitation,
                     called_methods, security_risk, vuln_type, confidence, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (node_id, signature, input_validation, output_limitation,
                  called_methods, security_risk, vuln_type, confidence, status))
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
