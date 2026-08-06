"""Chrome DevTools MCP 工具 — 通过 chrome-devtools-mcp 连接 Chrome 实例。

用 --autoConnect 自动连接用户正在运行的 Chrome（需 Chrome 144+ 开启 chrome://inspect/#remote-debugging）。
或用 --browserUrl http://127.0.0.1:9222 连接命令行启动的 Chrome。

提供的工具（MCP 标准工具）：
- navigate_page(url) — 导航到 URL
- take_screenshot() — 截图
- execute_script(js) — 执行 JS
- click_element(selector) — 点击元素
- fill_element(selector, value) — 填写表单
- get_page_content() — 获取页面内容
- ... 等 MCP 标准工具
"""
from __future__ import annotations

import json
import logging
import subprocess
import shutil
from typing import Optional

log = logging.getLogger("secgraph.chrome_devtools")

# chrome-devtools-mcp 启动命令
_MCP_COMMAND = ["npx", "chrome-devtools-mcp@latest"]
_AUTO_CONNECT_ARGS = ["--autoConnect", "--channel=stable"]
_BROWSER_URL_ARGS = ["--browserUrl", "http://127.0.0.1:9222"]


class ChromeDevToolsMCP:
    """连接 chrome-devtools-mcp 服务器，提供浏览器自动化工具。

    两种连接方式：
    1. autoConnect — Chrome 144+ 用户在 chrome://inspect/#remote-debugging 开启
    2. browserUrl — Chrome 命令行 --remote-debugging-port=9222 启动
    """

    def __init__(self, use_auto_connect: bool = True, browser_url: str = "") -> None:
        self._process: subprocess.Popen | None = None
        self._use_auto_connect = use_auto_connect
        self._browser_url = browser_url

    def start(self) -> bool:
        """启动 chrome-devtools-mcp 服务器进程。"""
        cmd = list(_MCP_COMMAND)
        if self._use_auto_connect:
            cmd.extend(_AUTO_CONNECT_ARGS)
        elif self._browser_url:
            cmd.extend(["--browserUrl", self._browser_url])
        else:
            cmd.extend(_BROWSER_URL_ARGS)

        log.info("chrome_devtools: 启动 MCP → %s", " ".join(cmd))
        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                encoding="utf-8",
            )
            log.info("chrome_devtools: MCP 进程启动 (PID=%d)", self._process.pid)
            return True
        except Exception as e:
            log.warning("chrome_devtools: 启动失败 → %s", e)
            return False

    def stop(self) -> None:
        """停止 MCP 服务器进程。"""
        if self._process:
            self._process.terminate()
            self._process.wait(timeout=5)
            self._process = None
            log.info("chrome_devtools: MCP 进程已停止")

    def is_running(self) -> bool:
        """MCP 服务器是否在运行。"""
        return self._process is not None and self._process.poll() is None

    def send_request(self, method: str, params: dict) -> dict | None:
        """通过 stdio 发送 MCP JSON-RPC 请求，等待响应。"""
        if not self._process or not self.is_running():
            log.warning("chrome_devtools: MCP 未运行")
            return None

        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }
        try:
            msg = json.dumps(request) + "\n"
            assert self._process.stdin is not None
            self._process.stdin.write(msg)
            self._process.stdin.flush()

            # 读取响应（按行）
            assert self._process.stdout is not None
            line = self._process.stdout.readline()
            if line:
                return json.loads(line)
        except Exception as e:
            log.warning("chrome_devtools: 请求失败 → %s", e)
        return None


def register_chrome_devtools_tools(registry, use_auto_connect: bool = True,
                                    browser_url: str = "") -> ChromeDevToolsMCP:
    """注册 Chrome DevTools MCP 工具到 ToolRegistry。

    注册的工具：
    - navigate_page(url) — 导航到 URL
    - take_screenshot() — 截图
    - execute_script(js) — 执行 JavaScript
    - get_page_content() — 获取页面内容
    - click_element(selector) — 点击元素
    - fill_element(selector, value) — 填写表单
    """
    mcp = ChromeDevToolsMCP(use_auto_connect=use_auto_connect, browser_url=browser_url)

    def _navigate_page(url: str) -> str:
        """导航到指定 URL"""
        result = mcp.send_request("tools/call", {"name": "navigate_page", "arguments": {"url": url}})
        if result and "result" in result:
            return str(result["result"])
        return f"[导航失败: {url}]"

    def _take_screenshot() -> str:
        """截图当前页面"""
        result = mcp.send_request("tools/call", {"name": "take_screenshot", "arguments": {}})
        if result and "result" in result:
            return str(result["result"])[:500] + "..."
        return "[截图失败]"

    def _execute_script(script: str) -> str:
        """执行 JavaScript 并返回结果"""
        result = mcp.send_request("tools/call", {"name": "execute_script", "arguments": {"script": script}})
        if result and "result" in result:
            return str(result["result"])
        return "[执行失败]"

    def _get_page_content() -> str:
        """获取当前页面内容"""
        result = mcp.send_request("tools/call", {"name": "get_page_content", "arguments": {}})
        if result and "result" in result:
            return str(result["result"])
        return "[获取失败]"

    def _click_element(selector: str) -> str:
        """点击页面元素"""
        result = mcp.send_request("tools/call", {"name": "click_element", "arguments": {"selector": selector}})
        if result and "result" in result:
            return str(result["result"])
        return f"[点击失败: {selector}]"

    def _fill_element(selector: str, value: str) -> str:
        """填写表单元素"""
        result = mcp.send_request("tools/call", {"name": "fill_element", "arguments": {"selector": selector, "value": value}})
        if result and "result" in result:
            return str(result["result"])
        return f"[填写失败: {selector}]"

    registry.add(
        "navigate_page",
        "导航浏览器到指定 URL",
        _navigate_page,
        url="目标 URL",
    )
    registry.add(
        "take_screenshot",
        "截图当前页面（用于查看页面状态）",
        _take_screenshot,
    )
    registry.add(
        "execute_script",
        "执行 JavaScript 并返回结果（用于获取页面数据、操作 DOM）",
        _execute_script,
        script="JavaScript 代码",
    )
    registry.add(
        "get_page_content",
        "获取当前页面的 HTML 内容",
        _get_page_content,
    )
    registry.add(
        "click_element",
        "点击页面元素（CSS 选择器）",
        _click_element,
        selector="CSS 选择器",
    )
    registry.add(
        "fill_element",
        "填写表单元素（CSS 选择器 + 值）",
        _fill_element,
        selector="CSS 选择器",
        value="填写值",
    )

    return mcp
