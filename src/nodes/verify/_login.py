"""env.txt 读取 + login_info.json 缓存。

两个 adapter（HTTP 登录 / Playwright 探索）是 real seam：
- `_read_env` / `_read_login_info` / `_write_login_info` — 文件 I/O
- `_explore_login` — Playwright CDP + AI 探索
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("secgraph.verify.login")

# ---------------------------------------------------------------------------
# env.txt
# ---------------------------------------------------------------------------

def read_env(project_path: str) -> dict[str, str] | None:
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


# ---------------------------------------------------------------------------
# login_info.json 缓存（只存登录方法，不存 cookies）
# ---------------------------------------------------------------------------

def read_login_info(project_path: str) -> dict | None:
    """读 {project_path}/login_info.json 缓存。status='verified' 才有效。"""
    f = Path(project_path) / "login_info.json"
    if not f.exists():
        return None
    info = json.loads(f.read_text(encoding="utf-8"))
    if info.get("status") == "verified":
        log.info("verify: login_info.json 缓存命中，跳过 Playwright 探索")
        return info
    return None


def write_login_info(project_path: str, info: dict) -> None:
    """回写 login_info.json。"""
    f = Path(project_path) / "login_info.json"
    f.write_text(json.dumps(info, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("verify: login_info.json 已回写 → %s", f)


# ---------------------------------------------------------------------------
# Playwright CDP + AI 探索（一个 adapter）
# ---------------------------------------------------------------------------

_LOGIN_TEMPLATE = Path(__file__).with_name("..").parent.parent / "prompts" / "login_exploration_template.md"
_LOGIN_TEMPLATE = _LOGIN_TEMPLATE.resolve()


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


def explore_login(target_url: str, username: str, password: str) -> dict | None:
    """Playwright CDP 连接 → AI 分析页面 → 执行登录步骤 → 捕获登录 HTTP 请求 → 返回登录信息。

    网络拦截捕获所有 POST 请求（不只 login 关键词），执行完步骤后从所有捕获请求中
    识别登录请求（URL 含 login/auth，或第一个含 password 的 body）。
    记录完整的 url + method + 所有 headers + body。
    """
    # 懒加载 playwright（避免硬依赖）
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.warning("verify: playwright 未安装")
        return None

    from ..llm import call_exploration_llm

    all_post_requests: list[dict] = []

    log.info("verify: Playwright CDP → 127.0.0.1:9222")
    try:
        with sync_playwright() as p:
            browser = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
            context = browser.contexts[0] if browser.contexts else browser.new_context()
            page = context.new_page()

            # 网络拦截：捕获所有请求
            def on_request(request):
                if request.method in ("POST", "PUT"):
                    all_post_requests.append({
                        "url": request.url,
                        "method": request.method,
                        "body": request.post_data or "",
                        "headers": dict(request.headers),
                    })
                    log.info("verify: 捕获 %s %s", request.method, request.url)

            page.on("request", on_request)

            # 1. 访问登录页
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

            # 3. 执行步骤
            for step in result.steps:
                try:
                    if step.action == "fill" and step.selector:
                        page.fill(step.selector, step.value)
                    elif step.action == "click" and step.selector:
                        page.click(step.selector)
                    elif step.action == "navigate" and step.value:
                        page.goto(step.value, wait_until="networkidle", timeout=10000)
                    elif step.action == "wait":
                        page.wait_for_timeout(2000)
                except Exception as e:
                    log.warning("verify: 步骤 %s 失败 → %s", step.action, e)

            page.wait_for_load_state("networkidle", timeout=10000)

            # 4. 识别登录请求（priority: URL 含 login > body 含 password > 第一个 POST）
            captured = _identify_login_request(all_post_requests)

            if captured:
                log.info("verify: 识别到登录请求 → %s %s（headers=%d, body=%d chars）",
                         captured["method"], captured["url"],
                         len(captured["headers"]), len(captured.get("body", "")))

            # 5. 构建登录信息
            login_url = captured.get("url", result.login_url)
            login_method = captured.get("method", result.login_method)
            login_body = captured.get("body", result.login_body)
            login_headers = captured.get("headers", {})
            if not login_headers:
                login_headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "secgraph-poc/1.0",
                }

            if login_url:
                return {
                    "project": target_url,
                    "target_url": target_url,
                    "login_url": login_url,
                    "login_method": login_method,
                    "login_body": login_body,
                    "login_headers": login_headers,
                    "status": "verified",
                }
            return None

    except Exception as e:
        log.warning("verify: Playwright CDP 连接失败 → %s", e)
        return None


def _identify_login_request(requests: list[dict]) -> dict:
    """从所有捕获的请求中识别登录请求。优先级: URL 关键词 > body 含 password > 第一个 POST。"""
    for req in requests:
        if any(kw in req["url"].lower() for kw in ("login", "auth", "signin")):
            return req
    for req in requests:
        if "password" in (req.get("body") or "").lower():
            return req
    return requests[0] if requests else {}


# ---------------------------------------------------------------------------
# HTTP 登录（另一个 adapter — 备选，不依赖 Playwright）
# ---------------------------------------------------------------------------

def http_login(login_info: dict) -> object | None:
    """用 login_info 的登录方法发 HTTP 请求，获取新 session（不缓存 cookies）。"""
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
        log.info("verify: 登录响应 → status=%d cookies=%d", resp.status_code, len(session.cookies))
        return session
    except Exception as e:
        log.warning("verify: HTTP 登录失败 → %s", e)
        return None
