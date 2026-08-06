"""端到端集成测试 — 只 mock codegraph 查询（discover 阶段），LLM 和其他步骤真实跑。

mock CodegraphClient 的查询方法返回构造的漏洞数据，
然后真实跑 audit（LLM 结构化输出）、trace_route（Q5 + LLM）、record（写 DB + .md）。

需要真实的 LLM 配置（.env）和 codegraph.db（用于 route_reachable 表初始化）。
"""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.state import AuditState, Finding, FileAuditTask, FieldNode, MethodNode


# ---------------------------------------------------------------------------
# Mock CodegraphClient — 只 mock 查询方法，其他逻辑真实跑
# ---------------------------------------------------------------------------

def create_mock_codegraph_client():
    """创建 mock CodegraphClient，返回构造的 SQL 注入漏洞数据。"""

    mock_cg = MagicMock()
    mock_cg.db_path = "mock"

    # Q1: 返回 1 个有漏洞的入口方法
    mock_method = MethodNode(
        id="method:abc123",
        qualified_name="org.test::SqlController::query",
        name="query",
        signature="Result(String userid)",
        file_path="sources/org/test/SqlController.java",
        start_line=10,
        end_line=20,
    )
    mock_cg.list_entry_methods.return_value = [mock_method]

    # Q3: 返回 1 个字段
    mock_cg.list_fields_by_nodeid.return_value = [
        FieldNode(id="field:1", qualified_name="org.test::SqlController::dao", name="dao", start_line=5, end_line=5),
    ]

    # get_method_body: 返回有漏洞的方法体
    mock_cg.get_method_body.return_value = (
        "// org.test::SqlController::query\n"
        "public Result query(String userid) {\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n"
        "    return dao.execute(sql);\n"
        "}\n"
    )

    # Q4: 返回被调方法体
    mock_cg.get_callee_bodies.return_value = {
        "method:dao1": "// org.test::Dao::execute\n"
        "public Result execute(String sql) {\n"
        "    return jdbcTemplate.queryForList(sql);\n"
        "}\n",
    }

    # is_route_reachable: 返回 True
    mock_cg.is_route_reachable.return_value = True

    # Q5: 返回调用链
    mock_cg.get_call_chain_to_route.return_value = [{
        "id": "route:/api/query",
        "qualified_name": "route:/api/query",
        "kind": "route",
        "file_path": "sources/org/test/SqlController.java",
        "start_line": 1,
        "end_line": 1,
        "depth": 1,
        "chain_path": "route:/api/query -> org.test::SqlController::query",
        "chain_ids": "route:/api/query,method:abc123",
    }]

    # get_chain_bodies: 返回调用链方法体
    mock_cg.get_chain_bodies.return_value = {
        "route:/api/query": "// route:/api/query\n"
        "@PostMapping(\"/api/query\")\n"
        "public Result query(@RequestParam String userid) {\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n"
        "    return dao.execute(sql);\n"
        "}\n",
        "method:abc123": "// org.test::SqlController::query\n"
        "public Result query(String userid) {\n"
        "    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n"
        "    return dao.execute(sql);\n"
        "}\n",
    }

    # init_memory_table / save_memory / lookup_memory
    mock_cg.init_memory_table.return_value = None
    mock_cg.save_memory.return_value = None
    mock_cg.lookup_memory.return_value = None

    # context manager
    mock_cg.close.return_value = None

    return mock_cg


@pytest.fixture
def mock_cg():
    """fixture: mock CodegraphClient"""
    return create_mock_codegraph_client()


@pytest.fixture
def base_state():
    """fixture: 基础 state"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield {
            "mode": "dev",
            "codegraph_db": "mock",
            "sources_root": str(Path(tmpdir) / "sources"),
            "pkg_prefix": "org/test",
            "findings_db": str(Path(tmpdir) / "test.db"),
            "findings_dir": str(Path(tmpdir) / "findings"),
            "logs_dir": str(Path(tmpdir) / "logs"),
            "file_limit": 10,
            "run_id": "test_mock",
            "max_iterations": 3,
            "llm_model": "test",
            "work_list": [],
            "audit_index": 0,
            "findings": [],
            "verified": [],
            "reflection_notes": [],
            "iteration": 0,
            "agent_history": [],
            "next_agent": "",
        }


class TestDiscoverWithMockCodegraph:
    """只 mock codegraph 查询，LLM 和其他逻辑真实跑。"""

    def test_discover_builds_work_list(self, mock_cg, base_state):
        """测试 discover 用 mock codegraph 构建 work_list。"""
        # 创建 mock sources 目录
        Path(base_state["sources_root"]).mkdir(parents=True, exist_ok=True)

        with patch("src.nodes.discover.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)
            mock_cg._conn = MagicMock()
            mock_cg._conn.execute.return_value.fetchone.return_value = [1, 1, 1, 1, 1]

            from src.nodes.discover import discover
            result = discover(base_state)

            # 验证 work_list 有 1 个 task
            assert len(result["work_list"]) == 1
            task = result["work_list"][0]
            assert task.node_id == "method:abc123"
            assert task.file_path == "sources/org/test/SqlController.java"

            # 验证 method_bodies 有方法体
            assert len(task.method_bodies) == 1
            assert "query" in list(task.method_bodies.values())[0]

            # 验证 calls 有被调方法
            assert len(task.calls) == 1

            # 验证 audit_index = 0
            assert result["audit_index"] == 0

    def test_audit_finds_sqli(self, mock_cg, base_state):
        """测试 audit 用 mock work_list 发现 SQLi（真实 LLM）。

        需要 .env 配置。如果 LLM 不可用则跳过。
        """
        pytest.importorskip("langchain_openai")

        import os
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置，跳过 LLM 测试")

        task = FileAuditTask(
            file_path="sources/org/test/SqlController.java",
            node_id="method:abc123",
            fields=[FieldNode(id="field:1", qualified_name="org.test::SqlController::dao", name="dao", start_line=5, end_line=5)],
            method_bodies={"method:abc123": (
                "// org.test::SqlController::query\n"
                "public Result query(String userid) {\n"
                "    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n"
                "    return dao.execute(sql);\n"
                "}\n"
            )},
            calls={"method:dao1": (
                "// org.test::Dao::execute\n"
                "public Result execute(String sql) {\n"
                "    return jdbcTemplate.queryForList(sql);\n"
                "}\n"
            )},
        )
        base_state["work_list"] = [task]
        base_state["audit_index"] = 0

        with patch("src.codegraph.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            from src.nodes.audit import audit_file
            result = audit_file(base_state)

        findings = result.get("findings", [])
        assert len(findings) >= 1, "LLM 应该发现至少 1 个漏洞"
        vuln_types = [f.vuln_type for f in findings]
        assert "SQLi" in vuln_types, f"应发现 SQLi，实际: {vuln_types}"
        assert result["audit_index"] == 1

    def test_full_pipeline_with_mock_codegraph(self, mock_cg, base_state):
        """完整 pipeline：mock codegraph + 真实 LLM。

        discover(mock) → audit(真实LLM) → trace_route(mock Q5 + 真实LLM) → record(真实DB)
        """
        pytest.importorskip("langchain_openai")

        import os
        from dotenv import load_dotenv
        load_dotenv(Path(__file__).parent.parent / ".env")
        if not os.getenv("LLM_API_KEY"):
            pytest.skip("LLM_API_KEY 未配置，跳过 LLM 测试")

        Path(base_state["sources_root"]).mkdir(parents=True, exist_ok=True)
        Path(base_state["findings_dir"]).mkdir(parents=True, exist_ok=True)
        Path(base_state["logs_dir"]).mkdir(parents=True, exist_ok=True)

        # 1. discover (mock codegraph)
        with patch("src.nodes.discover.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)
            mock_cg._conn = MagicMock()
            mock_cg._conn.execute.return_value.fetchone.return_value = [1, 1, 1, 1, 1]

            from src.nodes.discover import discover
            discover_result = discover(base_state)
            base_state.update(discover_result)

        assert len(base_state["work_list"]) == 1, "discover 应返回 1 个 task"

        # 2. audit (真实 LLM, mock CodegraphClient for memory save)
        with patch("src.codegraph.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            from src.nodes.audit import audit_file
            audit_result = audit_file(base_state)
            base_state.update(audit_result)

        findings = base_state["findings"]
        assert len(findings) >= 1, "audit 应发现至少 1 个漏洞"

        # 3. trace_route (mock Q5 + 真实 LLM)
        with patch("src.nodes.trace_route.CodegraphClient") as mock_cg_class:
            mock_cg_class.return_value.__enter__ = MagicMock(return_value=mock_cg)
            mock_cg_class.return_value.__exit__ = MagicMock(return_value=None)

            from src.nodes.trace_route import trace_route
            trace_result = trace_route(base_state)
            base_state.update(trace_result)

        # 验证 trace_route 给 finding 加了 evidence 标记
        for f in base_state["findings"]:
            assert "[路由可达性分析]" in f.evidence, "trace_route 应标记可达性"

        # 4. verify (mock HttpClient + 真实 LLM)
        mock_login_info = {
            "target_url": "http://localhost:18080/test",
            "login_url": "http://localhost:18080/test/login",
            "login_method": "POST",
            "login_body": "username=test&password=test",
            "login_headers": {},
            "status": "verified",
        }
        mock_http = MagicMock()
        mock_http.login.return_value = True
        mock_http.session = MagicMock()
        mock_http.session.cookies = MagicMock()
        mock_http.session.cookies.items.return_value = [("JSESSIONID", "mock-session-id")]
        mock_http.send.return_value = (200, {"Content-Type": "application/json"}, '{"lessonCompleted": false, "output": "101,Joe,Snow,987654321,VISA"}')

        with patch("src.nodes.verify.node.read_login_info", return_value=mock_login_info), \
             patch("src.nodes.verify.node.HttpClient", return_value=mock_http), \
             patch("src.nodes.verify.node.run_agent") as mock_run_agent:

            mock_run_agent.return_value = (True, "PoC 验证成功，响应包含数据库数据", "POST /api/query HTTP/1.1\n\nuserid=' OR '1'='1", [{"iter": 1, "tool": "send_http", "result": "200 OK"}])

            from src.nodes.verify.node import verify_finding
            verify_result = verify_finding(base_state)
            base_state.update(verify_result)

        # 验证 finding 有 poc_result
        for f in base_state["findings"]:
            assert f.poc_result is not None, "verify 应设置 poc_result"
            assert f.poc_result in ("confirmed", "denied", "inconclusive"), \
                f"poc_result 应是 confirmed/denied/inconclusive，实际: {f.poc_result}"

        # 5. record (真实 DB + .md)
        from src.nodes.record import record
        record_result = record(base_state)

        # 验证写了 .md 文件
        findings_dir = Path(base_state["findings_dir"])
        md_files = list(findings_dir.glob("*.md"))
        assert len(md_files) >= 1, "record 应为每个 finding 写 .md"

        # 验证 .md 包含 PoC 验证结果
        for md_file in md_files:
            content = md_file.read_text(encoding="utf-8")
            assert "PoC Result" in content, ".md 应包含 PoC 验证结果"
