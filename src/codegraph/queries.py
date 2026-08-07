"""codegraph SQL 查询 — 以 nodeid 为查询键。

查询策略
--------
  Q1: 业务包内的带参方法（JOIN route_reachable，只返回 route 可达的）
  Q3: 成员字段（按 nodeid 查同文件）
  Q4: 被调方法体（按 nodeid 查 callees）
  Q5: 反向追溯 route 入口（18 层递归 CTE，JOIN route_reachable）
  ROUTE_REACHABLE_INIT: 建临时表（调用一次，后续全部 JOIN）
  IS_ROUTE_REACHABLE: 单行查 node_id 是否在 route_reachable 表

为什么这些查询保留裸 SQL 而不 ORM 化
------------------------------------
1. **递归 CTE**：Q5 和 ROUTE_REACHABLE_INIT 使用 `WITH RECURSIVE` 遍历调用图，
   ORM 没有等价抽象。SQLAlchemy 的 `cte()` + `select()` 可以写但极不自然，
   可读性远差于原生 SQL。
2. **codegraph CLI 外部建表**：nodes / edges / route_reachable 表由 codegraph CLI
   建表和写入，不在 src/db/models.py 的 ORM 模型里。ORM session 只管业务表
   （runs / findings / verified_vulns / audit_memory）。
3. **性能**：Q1-Q5 每次跑 pipeline 都执行数十到数百次，ORM 的对象映射开销不划算。
   裸 SQL + sqlite3.Row 性能更好。
4. **IS_ROUTE_REACHABLE**：单行查 + 返回 bool，ORM 查询的开销大于裸 SQL。

Q2 已删除（list_call_edges 是死代码），Q3-Q5 继续使用。
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Q1 — 入口方法发现（业务包前缀过滤，JOIN route_reachable 只返回可达的）
# ---------------------------------------------------------------------------

Q1_ENTRY_METHODS = """
SELECT n.id, n.qualified_name, n.name, n.signature, n.file_path, n.start_line, n.end_line
FROM nodes n
INNER JOIN route_reachable rr ON n.id = rr.id
WHERE n.kind = 'method'
  AND n.language = 'java'
  AND n.signature NOT GLOB '*()'
  AND n.file_path LIKE :pkg_pattern
  AND n.file_path NOT LIKE '%/bean/%'
  AND n.file_path NOT LIKE '%/entity/%'
  AND n.file_path NOT LIKE '%/foundation/%'
  AND n.file_path NOT LIKE '%/it/%'
  AND n.file_path NOT LIKE '%/opengaussdb/%'
  AND n.file_path NOT LIKE '%/huawei/his/%'
  AND n.file_path NOT LIKE '%/test/%'
ORDER BY n.file_path, n.start_line
"""

# ---------------------------------------------------------------------------
# Q2 — 调用边（按入口方法 nodeid 查询，多行）
# ---------------------------------------------------------------------------

Q2_CALL_EDGES = """
SELECT
  n2.qualified_name AS callee_qualified,
  n2.name           AS callee_name,
  n2.file_path      AS callee_file,
  n2.start_line     AS callee_line,
  e.kind            AS edge_kind
FROM edges e
INNER JOIN nodes n2 ON e.target = n2.id
WHERE e.source = :node_id
ORDER BY n2.start_line
"""

# ---------------------------------------------------------------------------
# Q3 — 成员字段（按 nodeid 查同文件字段）
# ---------------------------------------------------------------------------

Q3_FIELDS_BY_NODE = """
SELECT id, qualified_name, name, start_line, end_line
FROM nodes
WHERE kind = 'field'
  AND file_path = (SELECT file_path FROM nodes WHERE id = :node_id)
ORDER BY qualified_name
"""

# ---------------------------------------------------------------------------
# Q4 — 被调方法元数据（按入口方法 nodeid 查 callees，仅 kind='calls'）
# ---------------------------------------------------------------------------

Q4_CALLEE_META = """
SELECT DISTINCT
  n2.id            AS callee_id,
  n2.qualified_name AS callee_qualified,
  n2.file_path      AS callee_file,
  n2.start_line     AS callee_start_line,
  n2.end_line       AS callee_end_line
FROM edges e
INNER JOIN nodes n2 ON e.target = n2.id
WHERE e.source = :node_id
  AND e.kind = 'calls'
"""

# ---------------------------------------------------------------------------
# Q5 — 反向调用链追溯（从方法往上找 route，18 层递归）
# 递归时 INNER JOIN route_reachable，只遍历可达的节点，不遍历全图
# ---------------------------------------------------------------------------

Q5_REVERSE_CHAIN = """
WITH RECURSIVE chain AS (
  SELECT id, qualified_name, kind, file_path, start_line, end_line,
         0 AS depth,
         qualified_name AS chain_path,
         id AS chain_ids
  FROM nodes WHERE id = :node_id
  UNION
  SELECT n1.id, n1.qualified_name, n1.kind, n1.file_path, n1.start_line, n1.end_line,
         c.depth + 1,
         n1.qualified_name || ' -> ' || c.chain_path,
         n1.id || ',' || c.chain_ids
  FROM chain c
  INNER JOIN edges e ON e.target = c.id AND e.kind IN ('calls', 'references')
  INNER JOIN nodes n1 ON e.source = n1.id
  INNER JOIN route_reachable rr ON n1.id = rr.id
  WHERE c.depth < 18
)
SELECT id, qualified_name, kind, file_path, start_line, end_line, depth, chain_path, chain_ids
FROM chain
WHERE kind = 'route'
ORDER BY depth ASC
LIMIT 3
"""

# ---------------------------------------------------------------------------
# ROUTE_REACHABLE_INIT — 建临时表（调用一次，后续全部 JOIN）
# ---------------------------------------------------------------------------

ROUTE_REACHABLE_INIT = """
DROP TABLE IF EXISTS route_reachable;
CREATE TABLE route_reachable AS
WITH RECURSIVE reachable AS (
  SELECT id, 0 AS depth
  FROM nodes WHERE kind = 'route'
  UNION
  SELECT n2.id, r.depth + 1
  FROM reachable r
  INNER JOIN edges e ON e.source = r.id AND e.kind IN ('calls', 'references')
  INNER JOIN nodes n2 ON e.target = n2.id
  WHERE r.depth < 18
)
SELECT DISTINCT id FROM reachable;
CREATE INDEX IF NOT EXISTS idx_route_reachable ON route_reachable(id);
"""

# ---------------------------------------------------------------------------
# IS_ROUTE_REACHABLE — 单行查 node_id 是否在 route_reachable 表
# ---------------------------------------------------------------------------

IS_ROUTE_REACHABLE = """
SELECT 1 FROM route_reachable WHERE id = :node_id LIMIT 1
"""
