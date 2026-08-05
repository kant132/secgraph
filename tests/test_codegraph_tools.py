"""测试 — codegraph SQL 查询 + HttpClient 工具。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.codegraph.queries import (
    Q1_ENTRY_METHODS, Q2_CALL_EDGES, Q3_FIELDS_BY_NODE,
    Q4_CALLEE_META, Q5_REVERSE_CHAIN,
)


class TestQueriesSyntax:
    """SQL 查询语法 + 参数绑定。"""

    def test_q1_has_nodeid(self):
        assert "id" in Q1_ENTRY_METHODS
        assert ":pkg_pattern" in Q1_ENTRY_METHODS

    def test_q2_uses_node_id(self):
        assert "e.source = :node_id" in Q2_CALL_EDGES

    def test_q3_subquery(self):
        assert "SELECT file_path FROM nodes WHERE id = :node_id" in Q3_FIELDS_BY_NODE

    def test_q4_calls_only(self):
        assert "e.kind = 'calls'" in Q4_CALLEE_META
        assert ":node_id" in Q4_CALLEE_META

    def test_q5_recursive(self):
        assert "WITH RECURSIVE" in Q5_REVERSE_CHAIN
        assert "kind = 'route'" in Q5_REVERSE_CHAIN
        assert ":node_id" in Q5_REVERSE_CHAIN


class TestHttpClientImport:
    """HttpClient 工具导入 + 基本结构。"""

    def test_import(self):
        from src.tools.http_client import HttpClient, SKIP_HEADERS
        assert HttpClient is not None
        assert "cookie" in SKIP_HEADERS
        assert "host" in SKIP_HEADERS

    def test_file_tool_import(self):
        from src.tools.file_tool import FileTool
        assert hasattr(FileTool, "read")
        assert hasattr(FileTool, "write")
        assert hasattr(FileTool, "read_json")
        assert hasattr(FileTool, "write_json")

    def test_codegraph_explore_import(self):
        from src.tools.codegraph_explore import codegraph_explore
        assert callable(codegraph_explore)
