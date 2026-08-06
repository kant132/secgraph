"""测试 — payload 解析（7种格式）。

_parse_payload 是 verify 的入口，支持 curl/raw HTTP/URL/路径 4 种格式。
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.nodes.verify._payload import parse_payload, format_request_detail, format_response_detail
from src.state import Finding


class TestParsePayload:
    """parse_payload 7 种解析路径。"""

    def test_empty(self):
        assert parse_payload("") == {}

    def test_raw_http_post(self):
        result = parse_payload("POST /attack6a HTTP/1.1\nContent-Type: application/x-www-form-urlencoded\n\nuserid_6a=' OR '1'='1")
        assert result["method"] == "POST"
        assert result["path"] == "/attack6a"
        assert "userid_6a" in result["body"]
        assert result["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

    def test_raw_http_get(self):
        result = parse_payload("GET /api/users?id=1 HTTP/1.1")
        assert result["method"] == "GET"
        assert "/api/users" in result["path"]

    def test_curl_post(self):
        result = parse_payload("curl -X POST http://localhost:8080/attack?userid=test -d 'data=1'")
        assert result["method"] == "POST"
        assert "/attack" in result["path"]

    def test_curl_get(self):
        result = parse_payload("curl http://localhost:8080/api/users?id=1")
        assert result["method"] == "GET"

    def test_pure_url(self):
        result = parse_payload("http://localhost:8080/attack6a?userid_6a=test")
        assert result["method"] == "GET"
        assert result["path"] == "/attack6a"
        assert "userid_6a=test" in result["body"]

    def test_pure_path(self):
        result = parse_payload("/attack6a")
        assert result["method"] == "GET"
        assert result["path"] == "/attack6a"


class TestFormatRequestDetail:
    """format_request_detail — 发 AI 判断用的请求详情。"""

    def test_basic(self):
        text = format_request_detail("POST", "http://localhost/attack", {"Content-Type": "application/x-www-form-urlencoded"}, "userid=1")
        assert "POST http://localhost/attack" in text
        assert "Content-Type" in text
        assert "userid=1" in text

    def test_no_headers(self):
        text = format_request_detail("GET", "http://localhost/api", {}, None)
        assert "GET http://localhost/api" in text
        assert "Headers" not in text


class TestFormatResponseDetail:
    """format_response_detail — 发 AI 判断用的响应详情。"""

    def test_basic(self):
        text = format_response_detail(200, {"Content-Type": "application/json"}, '{"lessonCompleted": false}')
        assert "HTTP 200" in text
        assert "application/json" in text
        assert "lessonCompleted" in text

    def test_empty_body(self):
        text = format_response_detail(404, {}, "")
        assert "HTTP 404" in text


class TestFinding:
    """Finding dataclass 基本行为。"""

    def test_create(self):
        f = Finding(
            file_path="sources/Test.java",
            node_id="method:997b7879a35fb0d978b1dec266c18e63",
            vuln_type="SQLi",
            severity="high",
            evidence="line 42: executeQuery",
            payload="POST /attack HTTP/1.1\n\ntest=1",
            confidence=0.8,
        )
        assert f.vuln_type == "SQLi"
        assert f.status == "pending"
        assert f.poc is None
        assert f.poc_result is None

    def test_severity_update(self):
        f = Finding(
            file_path="t.java", node_id="n1", vuln_type="XSS",
            severity="medium", evidence="e", payload="p", confidence=0.5,
        )
        f.severity = "9.8 Critical"
        assert f.severity == "9.8 Critical"
