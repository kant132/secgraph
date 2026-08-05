"""Agent 工具 — 注册给 AI 自由调用的工具集。

AI agent 拿到这些工具后自己决定：
1. 调 explore_code 探索代码（理解 SQL 结构、成功条件等）
2. 调 send_http 测试 payload
3. 调 read_file / write_file 读写文件
4. 循环直到确认漏洞可利用或放弃
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from langchain_core.tools import tool

from .codegraph_explore import codegraph_explore
from .file_tool import FileTool
from .http_client import HttpClient

log = logging.getLogger("secgraph.agent_tools")


def create_agent_tools(project_path: str, http_client: HttpClient):
    """创建绑定到当前项目 + session 的工具集，返回 LangChain tool 列表。"""

    @tool
    def explore_code(query: str) -> str:
        """探索代码库，返回调用链+源码+关系图+blast radius。
        query 用符号名、类名或文件名，如 "SqlInjectionLesson6a verifySqlInjection"。
        可以多次调用，每次探索不同的问题。"""
        result = codegraph_explore(query, project_path)
        # 截断太长的输出（避免 token 爆炸）
        if len(result) > 6000:
            result = result[:6000] + "\n...(截断，如需更多请再次 explore)"
        return result

    @tool
    def send_http(method: str, url: str, body: str = "", headers: str = "") -> str:
        """发送 HTTP 请求（自动带登录 session cookies）。
        method: GET 或 POST
        url: 完整 URL
        body: 请求体（表单数据，如 userid_6a=Smith' UNION SELECT...）
        headers: JSON 格式的额外 headers（可选，如 {"Content-Type": "application/x-www-form-urlencoded"}）
        返回：HTTP 状态码 + 响应头 + 响应体（前2000字）。"""
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

    @tool
    def read_file(path: str) -> str:
        """读文件内容。path: 文件路径。返回文件内容或文件不存在。"""
        return FileTool.read(path) or "[文件不存在]"

    @tool
    def write_file(path: str, content: str) -> str:
        """写文件（覆盖，自动创建目录）。path: 文件路径。content: 文件内容。"""
        FileTool.write(path, content)
        return "写入成功"

    return [explore_code, send_http, read_file, write_file]
