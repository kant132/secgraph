"""Agent 工具 — 用注册器模式注册给 AI 自由调用的工具集。

运行时可以动态添加工具，不局限于固定的 4 个。
"""
from __future__ import annotations

import json
import logging

from .codegraph_explore import codegraph_explore
from .file_tool import FileTool
from .http_client import HttpClient
from .tool_registry import ToolRegistry

log = logging.getLogger("secgraph.agent_tools")


def create_agent_tools(project_path: str, http_client: HttpClient) -> list:
    """创建绑定到当前项目 + session 的工具集，返回 LangChain tool 列表。
    用 ToolRegistry 注册，运行时可继续 add。"""
    registry = ToolRegistry()

    def _explore_code(query: str) -> str:
        result = codegraph_explore(query, project_path)
        if len(result) > 6000:
            result = result[:6000] + "\n...(截断，如需更多请再次 explore)"
        return result

    def _send_http(method: str, url: str, body: str = "", headers: str = "") -> str:
        hdrs = {}
        if headers:
            try:
                hdrs = json.loads(headers)
            except json.JSONDecodeError:
                hdrs = {}
        result = http_client.send(method=method, url=url, body=body or None, headers=hdrs)
        if result is None:
            return "[请求失败]"
        status, resp_headers, resp_body = result
        return (
            f"HTTP {status}\n"
            f"Headers: {json.dumps(resp_headers, ensure_ascii=False)}\n"
            f"Body: {resp_body}"
        )

    def _read_file(path: str) -> str:
        return FileTool.read(path) or "[文件不存在]"

    def _write_file(path: str, content: str) -> str:
        FileTool.write(path, content)
        return "写入成功"

    registry.add(
        "explore_code",
        "探索代码库，返回调用链+源代码+关系图+blast radius。可以多次调用，每次探索不同的问题。",
        _explore_code,
        query="符号名、类名或文件名，如 SqlInjectionLesson6a verifySqlInjection",
    )
    registry.add(
        "send_http",
        "发送 HTTP 请求（自动带登录 session cookies）。如果返回登录页说明 session 失效。",
        _send_http,
        method="GET 或 POST",
        url="完整 URL 或相对路径（如 /SqlInjectionAdvanced/attack6a）",
        body="请求体（表单数据，如 userid_6a=Smith' UNION SELECT...）",
        headers='JSON 格式的额外 headers（可空，如 {"Content-Type": "application/x-www-form-urlencoded"}）',
    )
    registry.add(
        "read_file",
        "读文件内容。",
        _read_file,
        path="文件路径",
    )
    registry.add(
        "write_file",
        "写文件（覆盖，自动创建目录）。",
        _write_file,
        path="文件路径",
        content="文件内容",
    )

    return registry.build()