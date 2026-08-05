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

from ..llm import call_exploration_llm, call_verification_llm
from ..state import AuditState, Finding
from ..tools.agent_tools import create_agent_tools
from ..tools.codegraph_explore import codegraph_explore
from ..tools.http_client import HttpClient, SKIP_HEADERS

log = logging.getLogger("secgraph.verify")

_LOGIN_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "login_exploration_template.md"
_LOGIN_TEMPLATE = _LOGIN_TEMPLATE.resolve()
_VERIFY_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "poc_verification_template.md"
_VERIFY_TEMPLATE = _VERIFY_TEMPLATE.resolve()
_RETRY_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "payload_retry_template.md"
_RETRY_TEMPLATE = _RETRY_TEMPLATE.resolve()
_AGENT_PROMPT = Path(__file__).with_name("..") / "prompts" / "agent_system_prompt.md"
_AGENT_PROMPT = _AGENT_PROMPT.resolve()

MAX_RETRIES = 3
MAX_AGENT_ITERS = 10


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
               status: int, resp_headers: dict, resp_body: str) -> tuple[bool, str, str, str]:
    """发请求+响应给 AI 判断漏洞是否验证成功。
    返回 (verified, reasoning, cvss_score, second_payload)。"""
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
    print(f"  CVSS: {result.cvss_score}")
    print(f"  CIA证明: {result.cia_proof}")
    print(f"  reasoning: {result.reasoning}")
    if result.second_payload:
        print(f"  second_payload: {result.second_payload[:120]}")
    print(f"{'='*60}")

    # 更新 finding 的严重等级为 CVSS 打分
    finding.severity = result.cvss_score

    # CIA 证明追加到 evidence
    if result.cia_proof:
        finding.evidence += f"\n\n[CIA 证明] {result.cia_proof}"

    return result.verified, result.reasoning, result.cvss_score, result.second_payload


def _run_agent(finding: Finding, project_path: str, http_client: HttpClient,
               target_url: str, explore_msgs: list[str]) -> tuple[bool, str, str, list[dict]]:
    """AI agent 循环：自由调用 explore_code + send_http + read_file + write_file。

    AI 自己决定：探索什么、构造什么 payload、怎么测试、什么时候停。
    返回 (verified, reasoning, updated_payload, agent_messages)。
    """
    from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
    from ..llm import _get_raw_llm

    # 创建工具（绑定到当前项目 + session）
    tools = create_agent_tools(project_path, http_client)
    tool_map = {t.name: t for t in tools}

    # 绑定工具到 LLM
    llm = _get_raw_llm().bind_tools(tools)

    # 系统提示
    system_prompt = _AGENT_PROMPT.read_text(encoding="utf-8")

    # 用户消息
    user_msg = (
        f"## 漏洞信息\n"
        f"- 类型: {finding.vuln_type}\n"
        f"- 文件: {finding.file_path}\n"
        f"- node_id: {finding.node_id}\n"
        f"- 证据: {finding.evidence}\n"
        f"- 初始 payload: {finding.payload}\n"
        f"- 目标 URL: {target_url}\n\n"
        f"请验证这个漏洞是否可利用。先用 explore_code 探索代码理解业务逻辑和成功条件，"
        f"然后构造能真正成功的 payload 用 send_http 测试。"
    )

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=user_msg),
    ]

    agent_msgs: list[dict] = []
    final_text = ""
    updated_payload = finding.payload

    for i in range(MAX_AGENT_ITERS):
        print(f"\n--- Agent 迭代 {i+1}/{MAX_AGENT_ITERS} ---")
        response = llm.invoke(messages)
        messages.append(response)

        if not response.tool_calls:
            final_text = response.content or ""
            print(f"  → Agent 完成: {final_text[:200]}")
            agent_msgs.append({"iter": i + 1, "type": "final", "content": final_text[:500]})
            break

        # 执行工具调用
        for call in response.tool_calls:
            tool_name = call["name"]
            tool_args = call["args"]
            tool_id = call["id"]

            print(f"  → 调工具: {tool_name}({str(tool_args)[:120]})")

            # 保存探索消息
            if tool_name == "explore_code":
                explore_msgs.append(f"[agent iter {i+1}] query={tool_args.get('query','')}")

            tool = tool_map.get(tool_name)
            if tool:
                result = tool.invoke(tool_args)
            else:
                result = f"[未知工具: {tool_name}]"

            result_str = str(result)
            print(f"  → 结果({len(result_str)}字): {result_str[:200]}")

            # 记录最后一次 send_http 的 payload
            if tool_name == "send_http":
                body = tool_args.get("body", "")
                url = tool_args.get("url", "")
                method = tool_args.get("method", "POST")
                if body:
                    updated_payload = f"{method} {url}\n\n{body}"

            messages.append(ToolMessage(content=result_str, tool_call_id=tool_id))
            agent_msgs.append({
                "iter": i + 1,
                "tool": tool_name,
                "args": str(tool_args)[:300],
                "result": result_str[:500],
            })
    else:
        final_text = "达到最大迭代数，未能确认"
        agent_msgs.append({"iter": MAX_AGENT_ITERS, "type": "max_iters"})

    # 判断是否 confirmed
    verified = any(kw in final_text.lower() for kw in ("confirmed", "可利用", "已确认", "verified", "成功"))
    if not verified:
        verified = any(kw in final_text.lower() for kw in ("数据泄露", "数据返回", "成功执行", "绕过"))

    return verified, final_text, updated_payload, agent_msgs


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

    # 5. 第一轮：顺序发初始 payload + AI 验证
    log.info("verify: 第一轮 — 发送 %d 个初始 payload", len(findings))
    explore_msgs: list[str] = list(state.get("explore_messages", []))
    agent_msgs_all: list[dict] = []
    need_agent: list[Finding] = []  # 初始验证失败的，需要 agent 进一步探索

    for f in findings:
        if not f.payload:
            f.poc_result = "inconclusive"
            f.poc_output = "[no payload]"
            continue

        print(f"\n{'#'*60}")
        print(f"# 初始 PoC: {f.vuln_type} — {f.node_id[:30]}")
        print(f"{'#'*60}")

        parsed = _parse_payload(f.payload or "")
        if not parsed.get("path"):
            f.poc_result = "inconclusive"
            f.poc_output = "[payload parse failed]"
            continue

        url = urljoin(target_url + "/", parsed["path"].lstrip("/"))
        method = parsed["method"]
        body = parsed.get("body")
        headers = parsed.get("headers", {})

        result = tool.send(method=method, url=url, body=body, headers=headers)
        if result is None:
            f.poc_result = "inconclusive"
            f.poc_output = "[request failed]"
            continue

        status, resp_headers, resp_body = result

        actual_headers = {k: v for k, v in headers.items() if k.lower() not in SKIP_HEADERS}
        if tool.session and tool.session.cookies:
            actual_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in tool.session.cookies.items())

        verified, reasoning, cvss_score, second_payload = _ai_verify(
            f, method, url, actual_headers, body or "",
            status, resp_headers, resp_body,
        )

        if second_payload:
            print(f"\n--- AI 生成 second_payload，更新 ---")
            f.payload = second_payload

        if verified and not second_payload:
            f.poc_result = "confirmed"
            f.poc_output = f"AI: {reasoning}"
            log.info("verify: %s → CONFIRMED（初始 payload）", f.node_id[:30])
        else:
            log.info("verify: %s → 初始失败，待 agent 循环", f.node_id[:30])
            need_agent.append(f)

    # 6. 第二轮：并发 agent 循环（并发度=3，每个 agent 独立 session）
    if need_agent:
        log.info("verify: 第二轮 — %d 个 finding 启动 agent 循环（并发度=3）", len(need_agent))

        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run_one_agent(f: Finding) -> tuple[str, bool, str, str, list[str], list[dict]]:
            """单个 finding 的 agent 循环（独立 session，线程安全）。"""
            # 每个 agent 独立登录（避免 session 共享）
            agent_tool = HttpClient(login_info)
            agent_tool.login()
            agent_explore_msgs: list[str] = []

            verified, agent_reasoning, updated_payload, agent_msgs = _run_agent(
                f, project_path, agent_tool, target_url, agent_explore_msgs,
            )
            return f.node_id, verified, agent_reasoning, updated_payload, agent_explore_msgs, agent_msgs

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(_run_one_agent, f): f for f in need_agent}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    nid, verified, reasoning, updated_payload, a_explore_msgs, a_agent_msgs = future.result()
                except Exception as e:
                    log.warning("verify: agent %s 异常 → %s", f.node_id[:30], e)
                    f.poc_result = "inconclusive"
                    f.poc_output = f"[agent error: {e}]"
                    continue

                if updated_payload and updated_payload != f.payload:
                    f.payload = updated_payload
                f.poc_result = "confirmed" if verified else "denied"
                f.poc_output = f"AI: {reasoning}"
                explore_msgs.extend(a_explore_msgs)
                agent_msgs_all.extend(a_agent_msgs)
                log.info("verify: %s → %s (agent)", nid[:30], f.poc_result.upper())

    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")
    log.info("verify: 完成 → %d confirmed, %d denied, %d inconclusive",
             confirmed, denied, len(findings) - confirmed - denied)
    return {"findings": findings, "explore_messages": explore_msgs, "agent_messages": agent_msgs_all}
