"""测试 trace_route 的 prompt 填充 — 调用链合并为一段，含 FQN + 方法体。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.nodes.trace_route import _render_prompt
from src.state import Finding


class TestRenderPrompt:
    """测试 _render_prompt — 调用链合并 + FQN + 方法体。"""

    def test_basic(self):
        """基本测试：2 层调用链，验证 FQN + body + → 分隔。"""
        f = Finding(
            file_path="sources/Test.java",
            node_id="method:abc",
            vuln_type="SQLi",
            severity="high",
            evidence="line 10: executeQuery",
            payload="POST /attack HTTP/1.1\n\nuserid=1' OR '1'='1",
            confidence=0.8,
        )
        chain_path = "route:/api/attack → com.example::Controller::attack → com.example::Dao::query"
        chain_bodies = {
            "route:/api/attack": "// route:/api/attack\n@PostMapping(\"/api/attack\")\npublic Result attack(@RequestParam String userid) {\n    return dao.query(userid);\n}",
            "method:abc": "// com.example::Dao::query\npublic Result query(String userid) {\n    String sql = \"SELECT * FROM users WHERE id='\" + userid + \"'\";\n    return execute(sql);\n}",
        }

        prompt = _render_prompt(f, chain_path, chain_bodies)

        # 验证合并为一段
        assert "## 调用链（" not in prompt  # 旧的两段标题不存在
        assert "## 调用链方法体" not in prompt
        assert "## 完整调用链" in prompt

        # 验证 FQN + body 内联
        assert "// route:/api/attack" in prompt
        assert "com.example::Controller::attack" not in chain_bodies.get("route:/api/attack", "")
        assert "@PostMapping" in prompt
        assert "com.example::Dao::query" in prompt
        assert "SELECT * FROM users" in prompt

        # 验证 → 分隔
        assert "\n→\n" in prompt

        # 验证漏洞信息填充
        assert "SQLi" in prompt
        assert "high" in prompt
        assert "executeQuery" in prompt
        assert "userid=1' OR '1'='1" in prompt

    def test_single_method(self):
        """单层调用链（route 直接到漏洞方法）。"""
        f = Finding(
            file_path="Test.java",
            node_id="method:abc",
            vuln_type="XSS",
            severity="medium",
            evidence="line 5: unescaped output",
            payload="",
            confidence=0.5,
        )
        chain_bodies = {
            "method:abc": "// com.example::Handler::handle\npublic void handle(String input) {\n    response.getWriter().write(input);\n}",
        }

        prompt = _render_prompt(f, "", chain_bodies)

        assert "## 完整调用链" in prompt
        assert "// com.example::Handler::handle" in prompt
        assert "response.getWriter().write" in prompt
        assert "XSS" in prompt
        assert "\n→\n" not in prompt  # 单层没有 → 分隔

    def test_empty_chain(self):
        """空调用链（chain_bodies 为空）。"""
        f = Finding(
            file_path="Test.java",
            node_id="method:abc",
            vuln_type="SQLi",
            severity="high",
            evidence="test",
            payload="",
            confidence=0.5,
        )

        prompt = _render_prompt(f, "", {})

        assert "(无方法体)" in prompt
        assert "SQLi" in prompt

    def test_three_layer_chain(self):
        """三层调用链：route → service → dao。"""
        f = Finding(
            file_path="Test.java",
            node_id="method:dao",
            vuln_type="SQLi",
            severity="critical",
            evidence="line 20: string concat in SQL",
            payload="POST /api/search HTTP/1.1\n\nkeyword=test'",
            confidence=0.9,
        )
        chain_bodies = {
            "route:/api/search": "// route:/api/search\n@PostMapping(\"/api/search\")\npublic Result search(@RequestParam String keyword) {\n    return service.search(keyword);\n}",
            "method:service": "// com.example::Service::search\npublic Result search(String keyword) {\n    return dao.find(keyword);\n}",
            "method:dao": "// com.example::Dao::find\npublic Result find(String keyword) {\n    String sql = \"SELECT * FROM t WHERE name LIKE '%\" + keyword + \"%'\";\n    return execute(sql);\n}",
        }

        prompt = _render_prompt(f, "route:/api/search → Service::search → Dao::find", chain_bodies)

        # 三层都有 body
        assert "route:/api/search" in prompt
        assert "com.example::Service::search" in prompt
        assert "com.example::Dao::find" in prompt
        assert "@PostMapping" in prompt
        assert "SELECT * FROM t WHERE name LIKE" in prompt

        # 两个 → 分隔符
        assert prompt.count("\n→\n") == 2

        # 漏洞信息
        assert "critical" in prompt
        assert "keyword=test'" in prompt

    def test_special_chars_in_body(self):
        """方法体含特殊字符（引号、换行、大括号）。"""
        f = Finding(
            file_path="Test.java",
            node_id="method:abc",
            vuln_type="RCE",
            severity="critical",
            evidence="line 1: Runtime.exec",
            payload="",
            confidence=0.9,
        )
        chain_bodies = {
            "method:abc": '// com.example::Cmd::run\npublic void run(String cmd) {\n    Runtime.getRuntime().exec(cmd + " && " + "ls");\n}',
        }

        prompt = _render_prompt(f, "", chain_bodies)

        assert "Runtime.getRuntime().exec" in prompt
        assert "ls" in prompt
        assert "RCE" in prompt
