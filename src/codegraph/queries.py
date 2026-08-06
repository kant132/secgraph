"""codegraph SQL 查询 — 以 nodeid 为查询键。

查询策略：
  Q1: 业务包内的 public 带参方法
  Q2: 调用边
  Q3: 成员字段
  Q4: 被调方法体
  Q5: 反向追溯 route 入口（18 层递归）
  Q6: 正向从所有 route 节点向下 18 层遍历，找到所有关联 nodeid
  Q7: Q6 结果与 Q1 结果取交集（只审 route 可达的方法）
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Q1 — 入口方法发现（业务包前缀过滤）
# ---------------------------------------------------------------------------

Q1_ENTRY_METHODS = """
SELECT id, qualified_name, name, signature, file_path, start_line, end_line
FROM nodes
WHERE kind = 'method'
  AND language = 'java'
  AND signature NOT GLOB '*()'
  AND file_path LIKE :pkg_pattern
  AND file_path NOT LIKE '%/bean/%'
  AND file_path NOT LIKE '%/entity/%'
  AND file_path NOT LIKE '%/foundation/%'
  AND file_path NOT LIKE '%/it/%'
  AND file_path NOT LIKE '%/opengaussdb/%'
  AND file_path NOT LIKE '%/huawei/his/%'
ORDER BY file_path, start_line
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
# 递归 CTE：沿 edges 反向走（e.target = 当前节点, e.kind IN ('calls','references')），
# 逐层往上找调用方，直到找到 kind='route' 或达到深度上限 18。
# 返回每条路径的 route 节点 + chain_path + chain_ids。
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
# Q6 — 正向遍历：从所有 route 节点向下 18 层，找所有关联 nodeid
# 递归 CTE：从 kind='route' 出发，沿 e.kind='calls' 向下走，
# 收集所有可达的 node id。
# ---------------------------------------------------------------------------

Q6_ROUTE_REACHABLE_NODES = """
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
SELECT DISTINCT id FROM reachable
"""

# ---------------------------------------------------------------------------
# Q7 — route 可达方法与 Q1 入口方法取交集
# 只审计 route 能到达的 public 带参方法（过滤掉不可达的，减少审计量）
# ---------------------------------------------------------------------------

Q7_ROUTE_REACHABLE_ENTRY_METHODS = """
SELECT n.id, n.qualified_name, n.name, n.signature, n.file_path, n.start_line, n.end_line
FROM nodes n
WHERE n.kind = 'method'
  AND n.language = 'java'
  AND n.signature NOT GLOB '*()'
  AND n.file_path LIKE :pkg_pattern
  AND n.id IN (
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
    SELECT DISTINCT id FROM reachable
  )
ORDER BY n.file_path, n.start_line
"""
