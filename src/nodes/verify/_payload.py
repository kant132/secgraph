"""HTTP payload 解析/发送/格式化 + AI 验证判断。

完整请求/响应格式化（发 AI 时用）+ PoC 验证（带 CVSS/CIA/second_payload）。
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from ...state import Finding
from ...tools.http_client import SKIP_HEADERS

log = logging.getLogger("secgraph.verify.payload")

_VERIFY_TEMPLATE_PATH = (Path(__file__).parent.parent.parent / "prompts" / "poc_verification_template.md").resolve()
_VERIFY_TEMPLATE_TEXT = _VERIFY_TEMPLATE_PATH.read_text(encoding="utf-8")

_CURL_URL_RE = re.compile(r"https?://\S+")


# ---------------------------------------------------------------------------
# Payload 解析
# ---------------------------------------------------------------------------

def parse_payload(payload: str) -> dict:
    """解析 AI 给的 payload，提取 method/path/body/headers。

    支持：curl / raw HTTP / 纯 URL / 纯路径。
    """
    payload = payload.strip()
    if not payload:
        return {}
    method = "GET"
    path = ""
    body = None
    headers = {}
    if payload.startswith("curl"):
        url_match = _CURL_URL_RE.search(payload)
        if url_match:
            parsed = urlparse(url_match.group())
            path = parsed.path
            if parsed.query:
                body = parsed.query
        if "-X POST" in payload or "--data" in payload or "-d " in payload:
            method = "POST"
    elif payload.startswith(("POST ", "GET ", "PUT ", "DELETE ")):
        lines = payload.split("\n")
        first = lines[0].split()
        method = first[0]
        path = first[1] if len(first) > 1 else "/"
        in_body = False
        body_lines = []
        for line in lines[1:]:
            if in_body:
                body_lines.append(line)
            elif line.strip() == "":
                in_body = True
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        if body_lines:
            body = "\n".join(body_lines)
    elif payload.startswith("http"):
        parsed = urlparse(payload)
        path = parsed.path
        if parsed.query:
            body = parsed.query
    else:
        path = payload
    return {"method": method, "path": path, "body": body, "headers": headers}


# ---------------------------------------------------------------------------
# 请求/响应格式化（发 AI 时用）
# ---------------------------------------------------------------------------

def format_request_detail(method: str, url: str, headers: dict, body: str | None) -> str:
    """格式化请求详情（发给 AI 判断用）。"""
    lines = [f"{method} {url}"]
    if headers:
        lines.append("Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
    if body:
        lines.append(f"Body: {body}")
    return "\n".join(lines)


def format_response_detail(status: int, headers: dict, body: str) -> str:
    """格式化响应详情（发给 AI 判断用）。"""
    lines = [f"HTTP {status}"]
    if headers:
        lines.append("Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
    if body:
        lines.append(f"Body:")
        lines.append(body)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 发送 payload
# ---------------------------------------------------------------------------

def send_payload(http_client, target_url: str, finding: Finding) -> tuple | None:
    """发 payload HTTP 请求，打印完整请求+响应。
    返回 (status, resp_headers, resp_body, req_method, req_url, req_body, req_headers, session_cookies_str)。
    过滤掉 Cookie/Host/Content-Length — 让 session 自动带真 JSESSIONID。
    http_client: HttpClient 实例（用 .session 发请求）。"""
    session = http_client.session
    parsed = parse_payload(finding.payload or "")
    if not parsed.get("path"):
        return None
    # 通用 URL 去重：如果 payload path 已含 target_url 的 context path，不重复拼接
    # 例如 target_url=http://localhost/WebGoat, path=/WebGoat/attack → 不变成 /WebGoat/WebGoat/attack
    raw_path = parsed["path"].lstrip("/")
    target_parsed = urlparse(target_url)
    target_path = target_parsed.path.strip("/")
    if target_path and raw_path.startswith(target_path + "/"):
        raw_path = raw_path[len(target_path) + 1:]
    url = urljoin(target_url + "/", raw_path)
    method = parsed["method"]
    body = parsed.get("body")
    headers = {k: v for k, v in (parsed.get("headers") or {}).items()
               if k.lower() not in SKIP_HEADERS}
    if not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    session_cookies = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
    print(f"\n{'='*60}")
    print(f"发送请求:")
    print(f"  {method} {url}")
    print(f"  Headers:")
    for k, v in headers.items():
        print(f"    {k}: {v}")
    if session_cookies:
        print(f"    Cookie: {session_cookies}")
    if body:
        print(f"  Body: {body}")
    print(f"{'='*60}")

    log.info("verify: 发送 %s %s", method, url)
    try:
        if method == "POST":
            resp = session.post(url, data=body, headers=headers, timeout=15, allow_redirects=True)
        else:
            resp = session.get(url, params=body, headers=headers, timeout=15, allow_redirects=True)

        resp_headers = dict(resp.headers)

        print(f"\n{'='*60}")
        print(f"响应:")
        print(f"  HTTP {resp.status_code}")
        print(f"  Headers:")
        for k, v in resp_headers.items():
            print(f"    {k}: {v}")
        print(f"  Body:")
        print(f"    {resp.text}")
        print(f"{'='*60}")

        log.info("verify: 响应 → status=%d len=%d", resp.status_code, len(resp.text))
        return resp.status_code, resp_headers, resp.text, method, url, body or "", headers, session_cookies
    except Exception as e:
        log.warning("verify: 请求失败 → %s", e)
        return None


# ---------------------------------------------------------------------------
# AI 验证判断（结构化输出：verified/cvss/cia_proof/second_payload）
# ---------------------------------------------------------------------------

def ai_verify(finding: Finding, req_method: str, req_url: str,
              req_headers: dict, req_body: str,
              status: int, resp_headers: dict, resp_body: str) -> tuple[bool, str, str, str]:
    """发请求+响应给 AI 判断漏洞是否验证成功。
    返回 (verified, reasoning, cvss_score, second_payload)。
    同时更新 finding.severity=CVSS，finding.evidence+=CIA 证明。"""
    from ...llm import call_verification_llm

    req_detail = format_request_detail(req_method, req_url, req_headers, req_body)
    resp_detail = format_response_detail(status, resp_headers, resp_body)

    tmpl = _VERIFY_TEMPLATE_TEXT
    prompt = (
        tmpl
        .replace("{vuln_type}", finding.vuln_type)
        .replace("{severity}", finding.severity)
        .replace("{evidence}", finding.evidence)
        .replace("{request_detail}", req_detail)
        .replace("{response_detail}", resp_detail)
    )

    print(f"\n{'='*60}")
    print(f"发送 AI 验证判断...")
    result = call_verification_llm(prompt)
    print(f"  verified: {result.verified}")
    print(f"  CVSS: {result.cvss_score}")
    print(f"  CIA证明: {result.cia_proof}")
    print(f"  reasoning: {result.reasoning}")
    if result.second_payload:
        print(f"  second_payload: {result.second_payload[:120]}")
    print(f"{'='*60}")

    # 更新 finding
    finding.severity = result.cvss_score
    if result.cia_proof:
        finding.evidence += f"\n\n[CIA 证明] {result.cia_proof}"

    return result.verified, result.reasoning, result.cvss_score, result.second_payload
