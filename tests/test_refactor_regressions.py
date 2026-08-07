"""Regression tests for the critical fixes applied in the refactor.

Catches:
1. record() works without mocking CodegraphClient — protects against future
   schema.sql-style deletions that break the persistence path.
2. LLM cache collision — call_exploration_llm and call_verification_llm can
   both run in one process without one poisoning the other's structured LLM.
3. record() writes to runs/findings/verified_vulns tables correctly when
   findings have various poc_result values.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.state import Finding


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        file_path="src/main/java/Foo.java",
        node_id="method:abc123",
        vuln_type="SQLi",
        severity="high",
        evidence="evidence text",
        payload="POST /api HTTP/1.1\n\nfoo=1",
        confidence=0.8,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _state(codegraph_db: str, findings_dir: str, findings, **extra) -> dict:
    return {
        "codegraph_db": codegraph_db,
        "findings_dir": findings_dir,
        "run_id": "test-run",
        "mode": "dev",
        "pkg_prefix": "com.example",
        "file_limit": 10,
        "iteration": 0,
        "audit_index": 1,
        "findings": findings,
        **extra,
    }


def _fake_codegraph_db(db_path: str) -> None:
    """给空 SQLite DB 补上 codegraph 必需的 nodes/edges 表。
    audit_memory 表由 ORM init_business_tables 自动建（含 severity 列），不在这里手动建。
    """
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            qualified_name TEXT,
            name TEXT,
            kind TEXT,
            signature TEXT,
            file_path TEXT,
            start_line INT,
            end_line INT
        );
        CREATE TABLE IF NOT EXISTS edges (
            source TEXT,
            target TEXT,
            kind TEXT,
            callee_name TEXT,
            caller_name TEXT,
            caller_line INT,
            callee_qualified TEXT,
            callee_file TEXT,
            callee_line INT,
            callee_id TEXT,
            callee_start_line INT,
            callee_end_line INT
        );
        """)
        conn.commit()
    finally:
        conn.close()


class TestRecordSchemaInline:
    """record() 必须能跑通完整持久化路径，不依赖外部 schema.sql 文件。"""

    def test_record_creates_runs_findings_verified_vulns_tables(self, tmp_path):
        from src.nodes.record import record

        db_path = str(tmp_path / "codegraph.db")
        _fake_codegraph_db(db_path)
        findings_dir = str(tmp_path / "findings")

        state = _state(db_path, findings_dir, [_make_finding()])
        result = record(state)

        conn = sqlite3.connect(db_path)
        try:
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()}
            assert "runs" in tables
            assert "findings" in tables
            assert "verified_vulns" in tables
        finally:
            conn.close()

        assert result["verified"] == []

    def test_record_writes_confirmed_finding_to_verified_vulns(self, tmp_path):
        from src.nodes.record import record

        db_path = str(tmp_path / "codegraph.db")
        _fake_codegraph_db(db_path)
        findings_dir = str(tmp_path / "findings")

        f = _make_finding(node_id="method:conf1", poc_result="confirmed",
                          poc="POST /x HTTP/1.1", poc_output="response")
        result = record(_state(db_path, findings_dir, [f]))

        conn = sqlite3.connect(db_path)
        try:
            v = conn.execute("SELECT node_id, vuln_type, poc_result, md_path FROM verified_vulns").fetchone()
            assert v is not None
            assert v[0] == "method:conf1"
            assert v[1] == "SQLi"
            assert v[2] == "confirmed"
            assert v[3].endswith(".md")
        finally:
            conn.close()

        assert len(result["verified"]) == 1
        assert result["verified"][0].node_id == "method:conf1"

    def test_record_marks_denied_as_false_positive(self, tmp_path):
        from src.nodes.record import record

        db_path = str(tmp_path / "codegraph.db")
        _fake_codegraph_db(db_path)
        findings_dir = str(tmp_path / "findings")

        f = _make_finding(node_id="method:deny1", poc_result="denied")
        record(_state(db_path, findings_dir, [f]))

        conn = sqlite3.connect(db_path)
        try:
            status = conn.execute("SELECT status FROM findings WHERE node_id='method:deny1'").fetchone()[0]
            assert status == "false_positive"
        finally:
            conn.close()

    def test_record_writes_md_file_for_each_finding(self, tmp_path):
        from src.nodes.record import record

        db_path = str(tmp_path / "codegraph.db")
        _fake_codegraph_db(db_path)
        findings_dir = str(tmp_path / "findings")

        findings = [
            _make_finding(node_id=f"method:n{i}", vuln_type=t)
            for i, t in enumerate(["SQLi", "RCE", "SSRF"])
        ]
        record(_state(db_path, findings_dir, findings))

        md_files = list(Path(findings_dir).glob("*.md"))
        assert len(md_files) == 3


class TestLLMRoleCacheCollision:
    """同 role 不同 model_cls 不能互相串号。"""

    def test_cache_keys_by_role_and_model_cls(self):
        """_STRUCTURED_CACHE 用 (role, model_cls) 二元组 key — 同 role 不同 model 独立缓存。"""
        from src.llm import _STRUCTURED_CACHE
        from src.state import LoginExplorationResult, PoCVerificationResult

        _STRUCTURED_CACHE.clear()

        # mock _create_llm 避免真去构造 ChatOpenAI
        with patch("src.llm._create_llm", return_value=MagicMock()):
            from src.llm import _get_structured
            _get_structured("verify", LoginExplorationResult)
            _get_structured("verify", PoCVerificationResult)

        # 关键：cache 应该有 2 个 entry（按 (role, model_cls)），不能只 1 个
        assert len(_STRUCTURED_CACHE) == 2, (
            f"cache should have 2 entries (one per model_cls), got {len(_STRUCTURED_CACHE)}: "
            f"{list(_STRUCTURED_CACHE.keys())}"
        )
        keys = list(_STRUCTURED_CACHE.keys())
        assert any(k[1] is LoginExplorationResult for k in keys)
        assert any(k[1] is PoCVerificationResult for k in keys)


class TestTraceRouteFallbackTag:
    """trace_route LLM 失败时必须给 finding 打 fallback tag，避免 routing 反复 re-trace。"""

    def test_fallback_tag_written_on_llm_failure_pattern(self):
        """验证 fallback 写入逻辑：模拟 except 分支写入 EVIDENCE_TRACE_TAG + 降 confidence。"""
        from src.state import EVIDENCE_TRACE_TAG, Finding

        f = Finding(
            file_path="Foo.java", node_id="method:test2", vuln_type="SQLi",
            severity="high", evidence="no tag", payload="", confidence=0.8,
        )

        # 模拟 trace_route 里的 except 分支：
        try:
            raise RuntimeError("LLM down")
        except Exception as e:
            f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达（LLM 分析失败: {str(e)[:80]}）"
            f.confidence *= 0.3

        assert EVIDENCE_TRACE_TAG in f.evidence
        assert "LLM 分析失败" in f.evidence
        assert f.confidence == pytest.approx(0.24)

    def test_trace_route_invocation_writes_tag_when_llm_fails(self, tmp_path):
        """集成测试：实际跑 trace_route()，mock LLM 抛异常，断言 finding 被正确标记。
        比 pattern-based 版本更紧 — refactor 改 except 分支文案时这个测试会跟动。
        """
        from src.codegraph import CodegraphClient
        from src.nodes.trace_route import trace_route
        from src.state import EVIDENCE_TRACE_TAG, Finding

        db_path = str(tmp_path / "codegraph.db")

        # 构造 route_reachable 可达的 DB：route 节点 → method 节点（反向链 method→route）
        conn = sqlite3.connect(db_path)
        conn.executescript("""
        CREATE TABLE nodes (
            id TEXT PRIMARY KEY, qualified_name TEXT, name TEXT,
            kind TEXT, signature TEXT, file_path TEXT,
            start_line INT, end_line INT
        );
        CREATE TABLE edges (
            source TEXT, target TEXT, kind TEXT,
            caller_name TEXT, caller_line INT,
            callee_qualified TEXT, callee_name TEXT,
            callee_file TEXT, callee_line INT,
            callee_id TEXT, callee_start_line INT, callee_end_line INT
        );
        INSERT INTO nodes VALUES
            ('route:login', 'r.LoginController', 'LoginController', 'route', 'sig', 'LoginController.java', 1, 50),
            ('method:victim', 'com.x.Victim.foo', 'foo', 'method', 'sig', 'Victim.java', 10, 20);
        -- route:login 调 method:victim（正向：route → victim）
        -- ROUTE_REACHABLE_INIT 沿 edges FROM route 走，所以 victim 会被加入 route_reachable
        INSERT INTO edges VALUES
            ('route:login', 'method:victim', 'calls', 'LoginController', 30,
             'com.x.Victim.foo', 'foo', 'Victim.java', 10,
             'method:victim', 10, 20);
        """)
        conn.commit()
        conn.close()

        f = Finding(
            file_path="Victim.java", node_id="method:victim", vuln_type="SQLi",
            severity="high", evidence="audit evidence", payload="", confidence=0.8,
        )
        state = {
            "codegraph_db": db_path,
            "sources_root": ".",  # 源码路径不存在也无妨 — get_chain_bodies 会返回 source-not-found 占位
            "findings": [f],
        }

        # mock LLM 抛异常 — 触发 trace_route 的 except 分支
        with patch("src.nodes.trace_route.call_reachability_llm",
                   side_effect=RuntimeError("LLM rate limit")):
            result = trace_route(state)

        # fallback tag 必须写入；confidence 必须衰减
        out = result["findings"][0]
        assert EVIDENCE_TRACE_TAG in out.evidence
        assert "LLM 分析失败" in out.evidence
        assert "LLM rate limit" in out.evidence
        assert out.confidence == pytest.approx(0.24), (
            f"confidence should be 0.8 * 0.3 = 0.24, got {out.confidence}"
        )


class TestPromptsRender:
    """prompts.render() 基础行为 — 防止回归。"""

    def test_render_replaces_provided_keywords(self):
        from src.prompts import render
        out = render("audit", fields="X", methods="{}", calls="{}")
        assert "X" in out
        assert "{methods}" not in out
        assert "{calls}" not in out
        assert "{fields}" not in out

    def test_render_preserves_unfilled_keywords(self):
        """未提供的 keyword 占位符保留为字面 {key} 文本。"""
        from src.prompts import render
        out = render("audit", fields="X")  # 只填 fields
        assert "X" in out
        assert "{methods}" in out  # 未填的保留
        assert "{calls}" in out

    def test_load_caches_result(self):
        """load() 用 lru_cache — 第二次读不到文件也能返回。"""
        from src.prompts import load, _TEMPLATE_DIR
        a = load("audit")
        target = _TEMPLATE_DIR / "audit_template.md"
        original = target.read_bytes()
        try:
            target.unlink()
            b = load("audit")
            assert a == b  # 缓存命中
        finally:
            target.write_bytes(original)


class TestDiscoveryMemorySeverity:
    """discovery.py 从 memory 还原 finding 时 severity 必须从 audit_memory 恢复，不是用占位符。"""

    def test_memory_cached_finding_recovers_severity(self, tmp_path):
        """直接验证 discovery_agent 的 memory-hit 路径：存 severity=high → 命中后恢复 high。"""
        from src.codegraph import CodegraphClient
        from src.nodes.agents.discovery import discovery_agent
        from src.state import FileAuditTask, FieldNode

        db_path = str(tmp_path / "codegraph.db")
        _fake_codegraph_db(db_path)

        # 先写入一条 memory 记录（带 severity=high）
        with CodegraphClient(db_path) as cg:
            cg.init_memory_table()
            cg.save_memory(
                node_id="method:cached1",
                signature="sig",
                vuln_type="SQLi",
                severity="high",
                security_risk="test risk",
                confidence=0.95,
                status="pending",
            )

        # 构造 state，让 discovery 命中这条 memory
        task = FileAuditTask(
            file_path="Foo.java",
            node_id="method:cached1",
            fields=[FieldNode(id="f1", qualified_name="Foo.bar", name="bar",
                              start_line=1, end_line=1)],
            method_bodies={"method:cached1": "// fqn\nbody"},
            calls={},
        )
        state = {
            "codegraph_db": db_path,
            "sources_root": ".",
            "pkg_prefix": "com.example",
            "work_list": [task],
            "audit_index": 0,
            "findings": [],
            "agent_history": [],
        }
        result = discovery_agent(state)

        cached = next((f for f in result["findings"] if f.node_id == "method:cached1"), None)
        assert cached is not None, f"expected memory-hit finding, got findings={[f.node_id for f in result['findings']]}"
        # severity 必须从 audit_memory 恢复为 "high"，不是 "unknown" 占位
        assert cached.severity == "high", f"expected severity=high from memory, got {cached.severity}"
        assert cached.severity not in ("pending", "verified", "false_positive")