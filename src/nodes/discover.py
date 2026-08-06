"""discover 节点 — "codegraph 节点"。

将 SQL 查询转为工作列表，每个 task 对应一个入口方法 + 其所有被调方法。
下游节点使用预取的方法体 + 被调方法体 + 字段列表。
所有查询以 node_id 为键，一次审计一个 method 对应的所有 calls。
"""
from __future__ import annotations

import logging

from ..codegraph import CodegraphClient
from ..state import AuditState, FileAuditTask

log = logging.getLogger("secgraph.discover")


def discover(state: AuditState) -> dict:
    """Q1-Q7 -> work_list[FileAuditTask]。dev 态切片到 limit。"""
    codegraph_db = state["codegraph_db"]
    sources_root = state["sources_root"]
    pkg_prefix = state["pkg_prefix"]
    file_limit = state.get("file_limit")

    with CodegraphClient(codegraph_db) as cg:
        # 统计 DB 基础信息
        total_nodes = cg._conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        total_methods = cg._conn.execute("SELECT COUNT(*) FROM nodes WHERE kind='method'").fetchone()[0]
        total_routes = cg._conn.execute("SELECT COUNT(*) FROM nodes WHERE kind='route'").fetchone()[0]
        total_edges = cg._conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        total_calls_edges = cg._conn.execute("SELECT COUNT(*) FROM edges WHERE kind='calls'").fetchone()[0]
        log.info("discover: codegraph.db 基础统计 → nodes=%d, methods=%d, routes=%d, edges=%d, calls_edges=%d",
                 total_nodes, total_methods, total_routes, total_edges, total_calls_edges)

        # Q7: route 可达的入口方法（与 Q1 取交集，只审 route 能到达的）
        # Q7 无结果时回退到 Q1 全量
        methods = cg.list_entry_methods(pkg_prefix, limit=file_limit)
        log.info("discover: %d 个入口方法（limit=%s, prefix=%s, route过滤=%s）",
                 len(methods), file_limit, pkg_prefix,
                 "Q7" if total_routes > 0 else "Q1回退")

        work_list: list[FileAuditTask] = []
        for m in methods:
            # Q3: 字段（按 nodeid 查同文件）
            fields = cg.list_fields_by_nodeid(m.id)

            # Q1: 入口方法体（仅此一个方法）
            method_bodies = {m.id: cg.get_method_body(sources_root, m)}

            # Q4: 该方法的所有被调方法体
            calls = cg.get_callee_bodies(sources_root, m.id)

            task = FileAuditTask(
                file_path=m.file_path,
                node_id=m.id,
                fields=fields,
                method_bodies=method_bodies,
                calls=calls,
            )
            work_list.append(task)
            log.debug("discover: %s::%s — %d 字段, %d callees",
                      m.file_path.split("/")[-1], m.name, len(fields), len(calls))

        log.info("discover: work_list 构建完成 → %d 个 task（待审计）", len(work_list))

    return {"work_list": work_list, "audit_index": 0}
