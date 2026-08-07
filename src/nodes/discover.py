"""discover 节点 — codegraph 查询入口方法 + callees + fields，构建 work_list。

将 SQL 查询转为工作列表，每个 task 对应一个入口方法 + 其所有被调方法。
下游节点使用预取的方法体 + 被调方法体 + 字段列表。
所有查询以 node_id 为键，一次审计一个 method 对应的所有 calls。
"""
from __future__ import annotations

import logging
from collections import Counter

from ..codegraph import CodegraphClient
from ..state import AuditState, FileAuditTask

log = logging.getLogger("secgraph.discover")


def discover(state: AuditState) -> dict:
    """Q1-Q7 -> work_list[FileAuditTask]。dev 态切片到 limit。

    统计输出
    --------
    - codegraph.db 基础统计（nodes / methods / routes / edges / calls_edges）
    - route HTTP 方法分布（GET / POST / PUT / DELETE / ANY / 其他）
    - route 涉及的文件数
    - work_list 方法涉及的文件数
    """
    codegraph_db = state["codegraph_db"]
    sources_root = state["sources_root"]
    pkg_prefix = state["pkg_prefix"]
    file_limit = state.get("file_limit")

    with CodegraphClient(codegraph_db) as cg:
        # ---- codegraph.db 基础统计 ----
        total_nodes = cg._conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        total_methods = cg._conn.execute("SELECT COUNT(*) FROM nodes WHERE kind='method'").fetchone()[0]
        total_routes = cg._conn.execute("SELECT COUNT(*) FROM nodes WHERE kind='route'").fetchone()[0]
        total_edges = cg._conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        total_calls_edges = cg._conn.execute("SELECT COUNT(*) FROM edges WHERE kind='calls'").fetchone()[0]
        route_files = cg._conn.execute(
            "SELECT COUNT(DISTINCT file_path) FROM nodes WHERE kind='route'"
        ).fetchone()[0]

        log.info("discover: codegraph.db 基础统计 → nodes=%d, methods=%d, routes=%d, edges=%d, calls_edges=%d",
                 total_nodes, total_methods, total_routes, total_edges, total_calls_edges)
        log.info("discover: route 涉及 %d 个不同文件", route_files)

        # ---- route HTTP 方法分布 ----
        # route 节点的 name 格式: "POST /path" / "GET /path" / "ANY /path" / "DELETE /path" 等
        # 取第一个空格前的词作为 HTTP 方法
        route_names = [r[0] for r in cg._conn.execute(
            "SELECT name FROM nodes WHERE kind='route'"
        ).fetchall()]
        method_counter: Counter[str] = Counter()
        for name in route_names:
            method = name.split(" ")[0].upper() if name else "UNKNOWN"
            method_counter[method] += 1

        method_summary = ", ".join(f"{m}={c}" for m, c in method_counter.most_common())
        log.info("discover: route HTTP 方法分布 (共 %d 条) → %s", total_routes, method_summary)

        # ---- Q7: route 可达的入口方法（与 Q1 取交集，只审 route 能到达的）----
        methods = cg.list_entry_methods(pkg_prefix, limit=file_limit)
        log.info("discover: %d 个入口方法（limit=%s, prefix=%s, route过滤=%s）",
                 len(methods), file_limit, pkg_prefix,
                 "Q1+route_reachable" if total_routes > 0 else "Q1回退(无route)")

        # ---- work_list 构建 + 文件统计 ----
        work_list: list[FileAuditTask] = []
        work_files: set[str] = set()
        for m in methods:
            fields = cg.list_fields_by_nodeid(m.id)
            method_bodies = {m.id: cg.get_method_body(sources_root, m)}
            calls = cg.get_callee_bodies(sources_root, m.id)

            task = FileAuditTask(
                file_path=m.file_path,
                node_id=m.id,
                fields=fields,
                method_bodies=method_bodies,
                calls=calls,
            )
            work_list.append(task)
            work_files.add(m.file_path)
            log.debug("discover: %s::%s — %d 字段, %d callees",
                      m.file_path.split("/")[-1], m.name, len(fields), len(calls))

        log.info("discover: work_list 构建完成 → %d 个 task, 涉及 %d 个不同文件（待审计）",
                 len(work_list), len(work_files))

    return {"work_list": work_list, "audit_index": 0}