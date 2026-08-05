"""codegraph 的 4 条 SQL 查询 — 修正后参数化，以 nodeid 为查询键。

相对 init_req.md 原版的修正：
  1. Q1 补了 language='java'（原版漏了，会捞出 JS/TS 方法）
  2. signature NOT GLOB '.*\\(\\)' 改成 NOT GLOB '*()'。
     GLOB 用 shell-glob 语义：'.' 是字面量不是"任意字符"。
     "签名以 () 结尾（无参方法）"的正确写法是 '*()'。
  3. REGEXP 在原生 SQLite 不可用（无扩展）— 只用 GLOB。
  4. 包前缀参数化为 :pkg_pattern（不硬编码 com/huawei）。
  5. 所有按 file_path 过滤的查询改为按 node_id 过滤：
     - Q1 直接返回入口方法 nodeid 列表（不再先查 file_path 再查方法）
     - Q2/Q4 用 e.source = :node_id 直接查调用边（不再 join n1 + filter file_path）
     - Q3 用子查询从 node_id 取 file_path 再查同文件字段
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Q1 — 入口方法发现（直接返回 nodeid 列表，不再先查 file_path）
# 业务包前缀过滤，返回 public 带参方法的完整元数据。
# ---------------------------------------------------------------------------

Q1_ENTRY_METHODS = """
SELECT id, qualified_name, name, signature, file_path, start_line, end_line
FROM nodes
WHERE kind = 'method'
  AND visibility = 'public'
  AND language = 'java'
  AND signature NOT GLOB '*()'
  AND file_path LIKE :pkg_pattern
  and  qualified_name like '%injectableQuery%'
ORDER BY file_path, start_line
"""

# ---------------------------------------------------------------------------
# Q2 — 调用边（按入口方法 nodeid 查询，多行）
# 用 e.source = :node_id 直接查，不再 join n1 + filter file_path。
# 多行返回，调用方需聚合。
# ---------------------------------------------------------------------------

Q2_CALL_EDGES = """
SELECT
  n2.qualified_name AS callee_qualified,
  n2.name           AS callee_name,
  n2.file_path      AS callee_file,
  n2.start_line     AS callee_line,
  e.kind            AS edge_kind
FROM edges e
JOIN nodes n2 ON e.target = n2.id
WHERE e.source = :node_id
ORDER BY n2.start_line
"""

# ---------------------------------------------------------------------------
# Q3 — 成员字段（按 nodeid 查同文件字段）
# 用子查询从 node_id 取 file_path，再查同文件的 field 节点。
# 用于构建 field 段（数据流源 / state 上下文）。
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
# 用 e.source = :node_id 直接查，不再 join n1 + filter file_path。
# 返回 callee 的 nodeid + 行范围，客户端据此取方法体构建 {nodeid: body} 字典。
# 过滤 e.kind='calls'，排除 references/decorates/instantiates 噪声。
# ---------------------------------------------------------------------------

Q4_CALLEE_META = """
SELECT DISTINCT
  n2.id            AS callee_id,
  n2.qualified_name AS callee_qualified,
  n2.file_path      AS callee_file,
  n2.start_line     AS callee_start_line,
  n2.end_line       AS callee_end_line
FROM edges e
JOIN nodes n2 ON e.target = n2.id
WHERE e.source = :node_id
  AND e.kind = 'calls'
"""

# ---------------------------------------------------------------------------
# Q5 — 反向调用链追溯（从 vuln 方法往上找 kind='route' 的 HTTP 入口）
# 递归 CTE：沿 edges 反向走（e.target = 当前节点, e.kind='calls'），
# 逐层往上找调用方，直到找到 kind='route' 或达到深度上限。
# 返回每条路径的 route 节点 + chain_path（人类可读）+ chain_ids（机器取方法体用）。
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
  JOIN edges e ON e.target = c.id AND e.kind IN ('calls', 'references')
  JOIN nodes n1 ON e.source = n1.id
  WHERE c.depth < 10
)
SELECT id, qualified_name, kind, file_path, start_line, end_line, depth, chain_path, chain_ids
FROM chain
WHERE kind = 'route'
ORDER BY depth ASC
LIMIT 3
"""
