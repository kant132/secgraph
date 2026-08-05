"""测试 — Config 参数化 + CLI 参数。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.config import Config


class TestConfig:
    """Config 参数化。"""

    def test_from_args(self):
        cfg = Config.from_args("D:/jar/webgoat", "org.owasp.webgoat")
        assert cfg.project_path == "D:/jar/webgoat"
        assert cfg.group_id == "org.owasp.webgoat"

    def test_codegraph_db_derived(self):
        cfg = Config.from_args("D:/jar/webgoat", "org.owasp.webgoat")
        assert "codegraph.db" in cfg.codegraph_db
        # Windows path separator normalization
        assert "jar" in cfg.codegraph_db and "webgoat" in cfg.codegraph_db

    def test_sources_root_derived(self):
        cfg = Config.from_args("D:/jar/webgoat", "org.owasp.webgoat")
        assert cfg.sources_root == "D:/jar/webgoat"

    def test_pkg_prefix_converts_dots(self):
        cfg = Config.from_args("D:/jar/webgoat", "org.owasp.webgoat")
        assert cfg.pkg_prefix == "org/owasp/webgoat"

    def test_file_limit_dev(self):
        cfg = Config.from_args("D:/test", "com.test", mode="dev")
        assert cfg.file_limit is not None  # dev=非None, runtime=None

    def test_file_limit_runtime(self):
        cfg = Config.from_args("D:/test", "com.test", mode="runtime")
        assert cfg.file_limit is None

    def test_to_state(self):
        cfg = Config.from_args("D:/jar/webgoat", "org.owasp.webgoat")
        state = cfg.to_state()
        assert state["codegraph_db"] == cfg.codegraph_db
        assert state["pkg_prefix"] == cfg.pkg_prefix
        assert state["llm_model"] == cfg.llm_model
