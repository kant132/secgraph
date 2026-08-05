"""discover 节点 — "codegraph 节点"。

将 4 条 SQL 查询（Q1-Q4）转为 FileAuditTask 工作列表。
这是唯一访问 codegraph.db 的节点；下游节点使用预取的方法体 + 被调方法体 + 字段列表。
所有查询以 node_id 为键，按 file_path 分组后构建每个文件的审计任务。
"""
from __future__ import annotations

import logging
from collections import defaultdict

from ..codegraph import CodegraphClient
from ..state import AuditState, FileAuditTask

log = logging.getLogger("secgraph.discover")


def discover(state: AuditState) -> dict:
    """Q1-Q4 -> work_list[FileAuditTask]。dev 态按文件数切片（limit=10）。"""
    codegraph_db = state["codegraph_db"]
    sources_root = state["sources_root"]
    pkg_prefix = state["pkg_prefix"]
    file_limit = state.get("file_limit")

    with CodegraphClient(codegraph_db) as cg:
        # Q1: 获取所有入口方法（含 nodeid）
        methods = cg.list_entry_methods(pkg_prefix, limit=file_limit)
        log.info("discover: %d 个入口方法（limit=%s, prefix=%s）",
                 len(methods), file_limit, pkg_prefix)

        # 按 file_path 分组（按文件维度审计）
        files_map: dict[str, list] = defaultdict(list)
        for m in methods:
            files_map[m.file_path].append(m)

        work_list: list[FileAuditTask] = []
        for fp, file_methods in files_map.items():
            # Q1: 入口方法体 {nodeid: body}
            method_bodies = {
                m.id: cg.get_method_body(sources_root, m) for m in file_methods
            }

            # Q3: 字段（用任一方法 nodeid 查同文件字段）
            fields = cg.list_fields_by_nodeid(file_methods[0].id)

            # Q4: 被调方法体（聚合本文件所有入口方法的 callees）
            calls: dict[str, str] = {}
            for m in file_methods:
                callees = cg.get_callee_bodies(sources_root, m.id)
                calls.update(callees)

            task = FileAuditTask(
                file_path=fp,
                fields=fields,
                method_bodies=method_bodies,
                calls=calls,
            )
            work_list.append(task)
            log.debug("discover: %s — %d 字段, %d 入口方法, %d 被调方法",
                      fp, len(fields), len(method_bodies), len(calls))

    return {"work_list": work_list, "audit_index": 0}
