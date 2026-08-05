"""测试 — login_info.json 读写 + env.txt 解析。"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.nodes.verify._login import read_env, read_login_info, write_login_info, _identify_login_request


class TestReadEnv:
    """read_env — 解析 env.txt。"""

    def test_basic(self, tmp_path):
        env_file = tmp_path / "env.txt"
        env_file.write_text(
            "# comment\n"
            "target_url=http://localhost:18080/WebGoat\n"
            "username=admin1\n"
            "password=admin1\n"
            "cdp_url=http://127.0.0.1:9222\n"
        )
        env = read_env(str(tmp_path))
        assert env is not None
        assert env["target_url"] == "http://localhost:18080/WebGoat"
        assert env["username"] == "admin1"
        assert env["cdp_url"] == "http://127.0.0.1:9222"

    def test_not_exist(self, tmp_path):
        assert read_env(str(tmp_path)) is None

    def test_skip_comments(self, tmp_path):
        (tmp_path / "env.txt").write_text("# only comment\n")
        env = read_env(str(tmp_path))
        assert env == {}


class TestLoginInfoCache:
    """read_login_info / write_login_info — JSON 缓存。"""

    def test_write_read(self, tmp_path):
        info = {
            "login_url": "http://localhost/login",
            "login_method": "POST",
            "login_body": "username=admin1&password=admin1",
            "login_headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "status": "verified",
        }
        write_login_info(str(tmp_path), info)
        result = read_login_info(str(tmp_path))
        assert result is not None
        assert result["login_url"] == "http://localhost/login"
        assert result["login_body"] == "username=admin1&password=admin1"

    def test_not_verified(self, tmp_path):
        write_login_info(str(tmp_path), {"status": "unverified"})
        assert read_login_info(str(tmp_path)) is None

    def test_not_exist(self, tmp_path):
        assert read_login_info(str(tmp_path)) is None


class TestIdentifyLoginRequest:
    """_identify_login_request — 从捕获请求中识别登录请求。"""

    requests = [
        {"url": "http://localhost/static/css/main.css", "method": "POST", "body": "", "headers": {}},
        {"url": "http://localhost/WebGoat/login", "method": "POST", "body": "username=a&password=b", "headers": {}},
        {"url": "http://localhost/api/data", "method": "POST", "body": "data=1", "headers": {}},
    ]

    def test_url_login_keyword(self):
        result = _identify_login_request(self.requests)
        assert "login" in result["url"]

    def test_body_password_fallback(self):
        requests = [
            {"url": "http://localhost/submit", "method": "POST", "body": "password=secret", "headers": {}},
        ]
        result = _identify_login_request(requests)
        assert "password" in result["body"]

    def test_first_post_fallback(self):
        requests = [
            {"url": "http://localhost/api", "method": "POST", "body": "data=1", "headers": {}},
        ]
        result = _identify_login_request(requests)
        assert result["url"] == "http://localhost/api"

    def test_empty(self):
        assert _identify_login_request([]) == {}
