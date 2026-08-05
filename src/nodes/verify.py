"""verify 节点 — 动态 PoC 验证。

流程：
1. 读 {project_path}/env.txt（目标 URL、凭据）
2. 检查 {project_path}/login_info.json 缓存
   - 有缓存 → 直接读，跳过 Playwright 探索
   - 无缓存 → Playwright CDP 连 127.0.0.1:9222，AI 分析页面表单，
     执行登录步骤，网络拦截捕获登录 HTTP 请求，回写 login_info.json
3. Python requests 按登录信息发 HTTP 登录请求，拿 session cookies
4. 对每个 finding：解析 payload → 发 HTTP 请求 → 判断响应
5. 更新 finding 的 poc / poc_result / poc_output
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

from ..codegraph import CodegraphClient
from ..llm import call_exploration_llm, call_retry_llm, call_verification_llm
from ..state import AuditState, Finding
from ..tools.http_client import HttpClient, SKIP_HEADERS

log = logging.getLogger("secgraph.verify")

_LOGIN_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "login_exploration_template.md"
_LOGIN_TEMPLATE = _LOGIN_TEMPLATE.resolve()
_VERIFY_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "poc_verification_template.md"
_VERIFY_TEMPLATE = _VERIFY_TEMPLATE.resolve()
_RETRY_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "payload_retry_template.md"
_RETRY_TEMPLATE = _RETRY_TEMPLATE.resolve()

MAX_RETRIES = 3


# ---------------------------------------------------------------------------
# env.txt + login_info.json 读写
# ---------------------------------------------------------------------------

def _read_env(project_path: str) -> dict[str, str] | None:
    """读 {project_path}/env.txt。"""
    env_file = Path(project_path) / "env.txt"
    if not env_file.exists():
        log.warning("verify: env.txt 不存在 → %s", env_file)
        return None
    env: dict[str, str] = {}
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def _read_login_info(project_path: str) -> dict | None:
    """读 {project_path}/login_info.json 缓存。"""
    f = Path(project_path) / "login_info.json"
    if not f.exists():
        return None
    info = json.loads(f.read_text(encoding="utf-8"))
    if info.get("status") == "verified":
        log.info("verify: login_info.json 缓存命中，跳过 Playwright 探索")
        return info
    return None


def _write_login_info(project_path: str, info: dict) -> None:
    """回写 login_info.json。"""
    f = Path(project_path) / "login_info.json"
    f.write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("verify: login_info.json 已回写 → %s", f)


# ---------------------------------------------------------------------------
# Playwright CDP + AI 探索
# ---------------------------------------------------------------------------

def _extract_forms_text(page) -> str:
    """提取页面所有表单元素，格式化为 AI 可读文本。"""
    forms = page.eval_on_selector_all("form", """els => els.map(f => {
        let inputs = Array.from(f.querySelectorAll('input, button, select, textarea')).map(i => ({
            tag: i.tagName, type: i.type || '', name: i.name || '',
            value: (i.value||'').substring(0,50), text: (i.textContent||'').trim().substring(0,50)
        }));
        return {action: f.action || '', method: (f.method||'get').toUpperCase(), inputs: inputs};
    })""")
    if not forms:
        return "(无表单)"
    lines = []
    for i, form in enumerate(forms):
        lines.append(f"Form {i+1}: action={form.get('action','')} method={form.get('method','GET')}")
        for inp in form.get("inputs", []):
            parts = [f"tag={inp['tag']}", f"type={inp['type']}", f"name={inp['name']}"]
            if inp["text"]:
                parts.append(f"text={inp['text']}")
            lines.append(f"  {' '.join(parts)}")
    return "\n".join(lines)


def _render_exploration_prompt(target_url: str, forms_text: str, username: str, password: str) -> str:
    tmpl = _LOGIN_TEMPLATE.read_text(encoding="utf-8")
    return (
        tmpl
        .replace("{target_url}", target_url)
        .replace("{forms_text}", forms_text)
        .replace("{username}", username)
        .replace("{password}", password)
    )


def _explore_login(target_url: str, username: str, password: str) -> dict | None:
    """Playwright CDP 连接 → AI 分析页面 → 执行登录步骤 → 捕获登录 HTTP 请求 → 返回登录信息。

    网络拦截捕获所有 POST 请求（不只 login 关键词），执行完步骤后从所有捕获请求中
    识别登录请求（URL 含 login/auth，或第一个含 password 的 body）。
    记录完整的 url + method + 所有 headers + body。
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.warning("verify: playwright 未安装")
        return None

    all_post_requests: list[dict] = []   # 捕获所有 POST 请求

    log.info("verify: Playwright CDP → 127.0.0.1:9222")
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.new_page()

            # 网络拦截：捕获所有请求（POST + GET），记录完整 header + body
            def on_request(request):
                if request.method in ("POST", "PUT"):
                    req_data = {
                        "url": request.url,
                        "method": request.method,
                        "body": request.post_data or "",
                        "headers": dict(request.headers),
                    }
                    all_post_requests.append(req_data)
                    log.info("verify: 捕获 %s %s", request.method, request.url)

            page.on("request", on_request)

            # 1. 访问登录页（直接访问 /login 确保看到表单）
            login_page_url = target_url.rstrip("/") + "/login"
            page.goto(login_page_url, wait_until="networkidle", timeout=15000)
            log.info("verify: 页面标题 → %s", page.title())

            # 2. 提取表单 → AI 分析
            forms_text = _extract_forms_text(page)
            log.info("verify: 提取到 %d 个表单", forms_text.count("Form "))

            prompt = _render_exploration_prompt(target_url, forms_text, username, password)
            print(f"\n===== 登录探索 prompt =====\n{prompt[:800]}\n===== 结束 =====\n")

            result = call_exploration_llm(prompt)

            print(f"\n===== AI 登录步骤 =====")
            for i, step in enumerate(result.steps):
                print(f"  {i+1}. {step.action} selector={step.selector} value={step.value[:30]}")
            print(f"  login_url: {result.login_url}")
            print(f"===== 结束 =====\n")

            # 3. 执行 AI 返回的步骤
            for step in result.steps:
                try:
                    if step.action == "fill" and step.selector:
                        page.fill(step.selector, step.value)
                        log.info("verify: fill %s = %s", step.selector, step.value[:30])
                    elif step.action == "click" and step.selector:
                        page.click(step.selector)
                        log.info("verify: click %s", step.selector)
                    elif step.action == "navigate" and step.value:
                        page.goto(step.value, wait_until="networkidle", timeout=10000)
                    elif step.action == "wait":
                        page.wait_for_timeout(2000)
                except Exception as e:
                    log.warning("verify: 步骤 %s 失败 → %s", step.action, e)

            page.wait_for_load_state("networkidle", timeout=10000)

            # 4. 从所有捕获的 POST 请求中识别登录请求
            captured: dict = {}
            # 优先匹配 URL 含 login/auth 的
            for req in all_post_requests:
                if any(kw in req["url"].lower() for kw in ("login", "auth", "signin")):
                    captured = req
                    break
            # 其次匹配 body 含 password 的
            if not captured:
                for req in all_post_requests:
                    if "password" in (req.get("body") or "").lower():
                        captured = req
                        break
            # 最后取第一个 POST
            if not captured and all_post_requests:
                captured = all_post_requests[0]

            if captured:
                log.info("verify: 识别到登录请求 → %s %s（headers=%d, body=%d chars）",
                         captured["method"], captured["url"],
                         len(captured["headers"]), len(captured.get("body", "")))

            # 5. 构建登录信息（只存登录方法，不存 cookies）
            login_url = captured.get("url", result.login_url)
            login_method = captured.get("method", result.login_method)
            login_body = captured.get("body", result.login_body)
            login_headers = captured.get("headers", {})

            # 如果没捕获到 headers，补默认值
            if not login_headers:
                login_headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "secgraph-poc/1.0",
                }

            if login_url:
                info = {
                    "project": target_url,
                    "target_url": target_url,
                    "login_url": login_url,
                    "login_method": login_method,
                    "login_body": login_body,
                    "login_headers": login_headers,
                    "status": "verified",
                }
                log.info("verify: 登录探索成功")
                return info
            else:
                log.warning("verify: 未捕获到登录请求，AI 分析结果: %s", result.description)
                return None

    except Exception as e:
        log.warning("verify: Playwright CDP 连接失败 → %s", e)
        return None


# ---------------------------------------------------------------------------
# Python requests 登录 + payload
# ---------------------------------------------------------------------------

def _http_login(login_info: dict) -> object | None:
    """用 login_info 中的登录方法发 HTTP 请求，获取新的 session（不缓存 cookies）。"""
    import requests

    login_url = login_info.get("login_url", "")
    method = login_info.get("login_method", "POST").upper()
    body = login_info.get("login_body", "")
    headers = login_info.get("login_headers", {})

    if not login_url:
        return None

    session = requests.Session()
    session.headers.update({"User-Agent": "secgraph-poc/1.0"})

    log.info("verify: HTTP 登录 → %s %s", method, login_url)
    try:
        if method == "POST":
            resp = session.post(login_url, data=body, headers=headers, timeout=15, allow_redirects=True)
        else:
            resp = session.get(login_url, params=body, headers=headers, timeout=15, allow_redirects=True)
        log.info("verify: 登录响应 → status=%d cookies=%d（新 session）", resp.status_code, len(session.cookies))
        return session
    except Exception as e:
        log.warning("verify: HTTP 登录失败 → %s", e)
        return None


def _parse_payload(payload: str) -> dict:
    """解析 AI 给的 payload，提取 method/path/body/headers。"""
    payload = payload.strip()
    if not payload:
        return {}
    method = "GET"
    path = ""
    body = None
    headers = {}
    if payload.startswith("curl"):
        url_match = re.search(r"https?://\S+", payload)
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


def _format_request_detail(method: str, url: str, headers: dict, body: str | None) -> str:
    """格式化请求详情（发给 AI 判断用）。"""
    lines = [f"{method} {url}"]
    if headers:
        lines.append("Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
    if body:
        lines.append(f"Body: {body}")
    return "\n".join(lines)


def _format_response_detail(status: int, headers: dict, body: str) -> str:
    """格式化响应详情（发给 AI 判断用）。"""
    lines = [f"HTTP {status}"]
    if headers:
        lines.append("Headers:")
        for k, v in headers.items():
            lines.append(f"  {k}: {v}")
    if body:
        lines.append(f"Body (前1000字):")
        lines.append(body[:1000])
    return "\n".join(lines)


def _send_payload(session, target_url: str, finding: Finding) -> tuple | None:
    """发 payload HTTP 请求，打印完整请求+响应。
    返回 (status, resp_headers, resp_body, req_method, req_url, req_body)。
    过滤掉 Cookie/Host/Content-Length — 让 session 自动带真 JSESSIONID。"""
    parsed = _parse_payload(finding.payload or "")
    if not parsed.get("path"):
        return None
    url = urljoin(target_url + "/", parsed["path"].lstrip("/"))
    method = parsed["method"]
    body = parsed.get("body")
    # 过滤掉 session 应该自动处理的 headers（Cookie/Host/Content-Length 等）
    # AI 的 payload 里的 Cookie 是占位符，真的 JSESSIONID 在 session.cookies 里
    SKIP_HEADERS = {"cookie", "host", "content-length", "connection", "accept-encoding",
                    "content-encoding", "transfer-encoding"}
    headers = {k: v for k, v in (parsed.get("headers") or {}).items()
               if k.lower() not in SKIP_HEADERS}
    # 补 Content-Type（如果 AI 没给）
    if not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    # 打印完整请求（含 session 的真实 Cookie）
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

        # 打印完整响应
        print(f"\n{'='*60}")
        print(f"响应:")
        print(f"  HTTP {resp.status_code}")
        print(f"  Headers:")
        for k, v in resp_headers.items():
            print(f"    {k}: {v}")
        print(f"  Body (前500字):")
        print(f"    {resp.text[:500]}")
        print(f"{'='*60}")

        log.info("verify: 响应 → status=%d len=%d", resp.status_code, len(resp.text))
        return resp.status_code, resp_headers, resp.text, method, url, body or "", headers, session_cookies
    except Exception as e:
        log.warning("verify: 请求失败 → %s", e)
        return None


def _ai_verify(finding: Finding, req_method: str, req_url: str,
               req_headers: dict, req_body: str,
               status: int, resp_headers: dict, resp_body: str) -> tuple[bool, str]:
    """发请求+响应给 AI 判断漏洞是否验证成功。"""
    req_detail = _format_request_detail(req_method, req_url, req_headers, req_body)
    resp_detail = _format_response_detail(status, resp_headers, resp_body)

    tmpl = _VERIFY_TEMPLATE.read_text(encoding="utf-8")
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
    print(f"  reasoning: {result.reasoning}")
    print(f"{'='*60}")

    return result.verified, result.reasoning


def _ai_retry_payload(finding: Finding, response_detail: str, failure_reason: str,
                      method_source: str, callees_source: dict[str, str]) -> tuple[str, str]:
    """根据 codegraph 源码 + 失败响应，让 AI 重构 payload。"""
    callees_text = "\n\n".join(
        f"// {nid}\n{body}" for nid, body in callees_source.items()
    ) if callees_source else "(无)"

    tmpl = _RETRY_TEMPLATE.read_text(encoding="utf-8")
    prompt = (
        tmpl
        .replace("{vuln_type}", finding.vuln_type)
        .replace("{original_payload}", finding.payload or "")
        .replace("{response_detail}", response_detail)
        .replace("{failure_reason}", failure_reason)
        .replace("{method_source}", method_source)
        .replace("{callees_source}", callees_text)
    )

    print(f"\n{'='*60}")
    print(f"发送 AI payload 重构（查 codegraph 源码）...")
    result = call_retry_llm(prompt)
    print(f"  corrected_payload: {result.corrected_payload[:120]}")
    print(f"  reasoning: {result.reasoning}")
    print(f"{'='*60}")

    return result.corrected_payload, result.reasoning
    if status in (401, 403):
        return "inconclusive"
    return "inconclusive"


# ---------------------------------------------------------------------------
# 主节点
# ---------------------------------------------------------------------------

def verify_finding(state: AuditState) -> dict:
    """动态 PoC 验证：env.txt → 登录探索(缓存) → requests 登录 → 发 payload → 判断。"""
    findings: list[Finding] = list(state.get("findings", []))
    if not findings:
        return {}

    project_path = state.get("sources_root", "")

    # 1. 读 env.txt
    env = _read_env(project_path)
    if not env:
        for f in findings:
            f.poc_result = "inconclusive"
            f.poc_output = "[no env.txt]"
        return {"findings": findings}

    target_url = env.get("target_url", "").rstrip("/")
    username = env.get("username", "")
    password = env.get("password", "")
    cdp_url = env.get("cdp_url", "http://127.0.0.1:9222")

    # 2. 检查 login_info.json 缓存
    login_info = _read_login_info(project_path)
    if not login_info:
        # 3. Playwright CDP + AI 探索
        login_info = _explore_login(target_url, username, password)
        if login_info:
            _write_login_info(project_path, login_info)

    if not login_info:
        log.warning("verify: 登录探索失败，所有 finding 标记 inconclusive")
        for f in findings:
            f.poc_result = "inconclusive"
            f.poc_output = "[login exploration failed]"
        return {"findings": findings}

    # 4. HttpClient 工具：先登录，再发 payload
    tool = HttpClient(login_info)
    if not tool.login():
        log.warning("verify: 登录失败")
        for f in findings:
            f.poc_result = "inconclusive"
            f.poc_output = "[login failed]"
        return {"findings": findings}

    # 5. 发 payload（用 HttpClient.send，自动带 session cookies）+ 重试循环
    log.info("verify: 开始发送 %d 个 payload", len(findings))
    codegraph_db = state.get("codegraph_db", "")
    sources_root = state.get("sources_root", "")

    for f in findings:
        if not f.payload:
            f.poc_result = "inconclusive"
            f.poc_output = "[no payload]"
            continue

        print(f"\n{'#'*60}")
        print(f"# PoC: {f.vuln_type} — {f.node_id[:30]}")
        print(f"{'#'*60}")

        verified = False
        last_reasoning = ""
        status = 0
        resp_body = ""

        for attempt in range(MAX_RETRIES):
            print(f"\n--- 尝试 {attempt+1}/{MAX_RETRIES} ---")

            # 解析 payload
            parsed = _parse_payload(f.payload or "")
            if not parsed.get("path"):
                f.poc_result = "inconclusive"
                f.poc_output = "[payload parse failed]"
                break

            url = urljoin(target_url + "/", parsed["path"].lstrip("/"))
            method = parsed["method"]
            body = parsed.get("body")
            headers = parsed.get("headers", {})

            # 发请求
            result = tool.send(method=method, url=url, body=body, headers=headers)
            if result is None:
                f.poc_result = "inconclusive"
                f.poc_output = "[request failed]"
                break

            status, resp_headers, resp_body = result

            # AI 验证
            actual_headers = {k: v for k, v in headers.items() if k.lower() not in SKIP_HEADERS}
            if tool.session and tool.session.cookies:
                actual_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in tool.session.cookies.items())

            verified, last_reasoning = _ai_verify(
                f, method, url, actual_headers, body or "",
                status, resp_headers, resp_body,
            )

            if verified:
                break  # 验证成功

            # 验证失败 + 还有重试次数 → 查 codegraph 源码 + 重构 payload
            if attempt < MAX_RETRIES - 1:
                log.info("verify: payload 验证失败，查 codegraph 源码重构...")
                print(f"\n--- 查 codegraph 源码重构 payload ---")

                resp_detail = _format_response_detail(status, resp_headers, resp_body)

                with CodegraphClient(codegraph_db) as cg:
                    method_source = cg.get_node_body(sources_root, f.node_id)
                    callees_source = cg.get_callee_bodies(sources_root, f.node_id)

                corrected_payload, retry_reason = _ai_retry_payload(
                    f, resp_detail, last_reasoning,
                    method_source, callees_source,
                )
                f.payload = corrected_payload
                log.info("verify: payload 已重构，重试...")

        # 更新 finding
        verdict = "confirmed" if verified else "denied"
        f.poc = f.payload[:200]
        f.poc_result = verdict
        f.poc_output = f"HTTP {status}\nAI: {last_reasoning}\n\n{resp_body[:300]}"
        log.info("verify: %s → %s (%s)", f.node_id[:30], verdict.upper(), last_reasoning[:80])

    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")
    log.info("verify: 完成 → %d confirmed, %d denied, %d inconclusive",
             confirmed, denied, len(findings) - confirmed - denied)
    return {"findings": findings}
