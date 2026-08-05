"""codegraph 查询层 — 将 SQL 查询转为类型化客户端调用。"""
from .queries import Q1_ENTRY_METHODS, Q2_CALL_EDGES, Q3_FIELDS_BY_NODE, Q4_CALLEE_META, Q5_REVERSE_CHAIN
from .client import CodegraphClient

__all__ = [
    "Q1_ENTRY_METHODS", "Q2_CALL_EDGES", "Q3_FIELDS_BY_NODE", "Q4_CALLEE_META", "Q5_REVERSE_CHAIN",
    "CodegraphClient",
]
