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
    """Q1-Q4 -> work_list[FileAuditTask]。每方法一个 task。dev 态切片到 limit。"""
    codegraph_db = state["codegraph_db"]
    sources_root = state["sources_root"]
    pkg_prefix = state["pkg_prefix"]
    file_limit = state.get("file_limit")

    with CodegraphClient(codegraph_db) as cg:
        # Q1: 获取所有入口方法（含 nodeid）
        methods = cg.list_entry_methods(pkg_prefix, limit=file_limit)
        log.info("discover: %d 个入口方法（limit=%s, prefix=%s）",
                 len(methods), file_limit, pkg_prefix)

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

    return {"work_list": work_list, "audit_index": 0}
