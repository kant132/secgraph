"""HTTP 工具 — 封装登录 + 请求发送，支持 http/https，自动带 session cookies + headers。

用法：
    tool = HttpClient(login_info)
    tool.login()                          # 登录，拿新 session
    status, headers, body = tool.send(    # 发请求
        method="POST",
        url="http://localhost:18080/WebGoat/attack6a",
        body="userid_6a=' OR '1'='1",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

每次调用都打印完整的请求 + 响应。
"""
from __future__ import annotations

import logging
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except ImportError:
    Retry = None  # urllib3 版本兼容

log = logging.getLogger("secgraph.http")

# session 应该自动处理的 headers（不从 payload 传，避免占位符覆盖真值）
SKIP_HEADERS = {
    "cookie", "host", "content-length", "connection",
    "accept-encoding", "content-encoding", "transfer-encoding",
}


class HttpClient:
    """HTTP 工具：登录拿 session，后续请求自动带 cookies + headers。"""

    def __init__(self, login_info: dict, verify_tls: bool = False):
        self.login_info = login_info
        self.session: requests.Session | None = None
        self._verify_tls = verify_tls

    # ---- 登录 ----

    def login(self) -> bool:
        """按 login_info 的登录方法 POST，获取新 session（不缓存 cookies）。"""
        login_url = self.login_info.get("login_url", "")
        method = self.login_info.get("login_method", "POST").upper()
        body = self.login_info.get("login_body", "")
        headers = self.login_info.get("login_headers", {})

        if not login_url:
            log.warning("http: login_info 无 login_url")
            return False

        self.session = self._new_session()

        # 打印登录请求
        print(f"\n{'='*60}")
        print(f"[工具调用] login()")
        print(f"  {method} {login_url}")
        print(f"  Headers:")
        for k, v in headers.items():
            print(f"    {k}: {v}")
        print(f"  Body: {body}")
        print(f"{'='*60}")

        try:
            if method == "POST":
                resp = self.session.post(
                    login_url, data=body, headers=headers,
                    timeout=15, allow_redirects=True, verify=self._verify_tls,
                )
            else:
                resp = self.session.get(
                    login_url, params=body, headers=headers,
                    timeout=15, allow_redirects=True, verify=self._verify_tls,
                )

            cookies = "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())
            print(f"\n  → HTTP {resp.status_code}")
            print(f"  → Cookies: {cookies}")
            print(f"  → Body (前200): {resp.text[:200]}")
            print(f"{'='*60}")

            log.info("http: 登录 → %s %s → status=%d cookies=%d",
                     method, login_url, resp.status_code, len(self.session.cookies))
            return resp.status_code in (200, 302)

        except Exception as e:
            log.warning("http: 登录失败 → %s", e)
            print(f"  → ERROR: {e}")
            return False

    # ---- 发请求 ----

    def send(self, method: str, url: str, body: str | None = None,
             headers: dict | None = None) -> tuple[int, dict, str] | None:
        """发 HTTP 请求，自动带 session cookies + 过滤后的 headers。
        返回 (status, resp_headers, resp_body)。"""
        if not self.session:
            log.warning("http: 未登录，先调 login()")
            if not self.login():
                return None
        assert self.session is not None

        # 过滤掉 session 自动管理的 headers
        clean_headers = {k: v for k, v in (headers or {}).items()
                         if k.lower() not in SKIP_HEADERS}
        # 补 Content-Type
        if not any(k.lower() == "content-type" for k in clean_headers):
            clean_headers["Content-Type"] = "application/x-www-form-urlencoded"

        # session 的真实 cookies
        session_cookies = "; ".join(f"{k}={v}" for k, v in self.session.cookies.items())

        # 打印请求
        print(f"\n{'='*60}")
        print(f"[工具调用] send()")
        print(f"  {method} {url}")
        print(f"  Headers:")
        for k, v in clean_headers.items():
            print(f"    {k}: {v}")
        if session_cookies:
            print(f"    Cookie: {session_cookies}")
        if body:
            print(f"  Body: {body}")
        print(f"{'='*60}")

        log.info("http: send → %s %s", method, url)
        try:
            if method.upper() == "POST":
                resp = self.session.post(
                    url, data=body, headers=clean_headers,
                    timeout=30, allow_redirects=True, verify=self._verify_tls,
                )
            else:
                resp = self.session.get(
                    url, params=body, headers=clean_headers,
                    timeout=30, allow_redirects=True, verify=self._verify_tls,
                )

            resp_headers = dict(resp.headers)

            # 打印响应
            print(f"\n  → HTTP {resp.status_code}")
            print(f"  Headers:")
            for k, v in resp_headers.items():
                print(f"    {k}: {v}")
            print(f"  Body (前500字):")
            print(f"    {resp.text[:500]}")
            print(f"{'='*60}")

            log.info("http: 响应 → status=%d len=%d", resp.status_code, len(resp.text))
            return resp.status_code, resp_headers, resp.text

        except Exception as e:
            log.warning("http: 请求失败 → %s", e)
            print(f"  → ERROR: {e}")
            print(f"{'='*60}")
            return None

    # ---- 内部 ----

    def _new_session(self) -> requests.Session:
        """创建带重试策略的 session。"""
        s = requests.Session()
        s.headers.update({"User-Agent": "secgraph-poc/1.0"})
        # 重试策略（urllib3 版本兼容）
        if Retry is not None:
            retry = Retry(total=2, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry)
            s.mount("https://", adapter)
            s.mount("http://", adapter)
        return s
