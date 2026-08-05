"""AI agent 循环 — 用 LangGraph create_react_agent 替代手写 tool loop。

之前是 100 行手写 SystemMessage/HumanMessage/ToolMessage 循环。
现在用 LangGraph 标准模式 create_react_agent — 自动 tool 调用 + state 管理 + checkpointing。

子图设计：
  START → agent (ReAct) → tool_node? → agent (循环) → END
  agent 决定调什么工具，tool_node 执行工具，结果回到 agent 直到决定结束。

返回：从子图 state 提取最终判断 + 对话历史。
"""
from __future__ import annotations

import logging
from pathlib import Path

from ...state import Finding
from ...tools.agent_tools import create_agent_tools
from ...tools.http_client import HttpClient

log = logging.getLogger("secgraph.verify.agent")

_AGENT_PROMPT = Path(__file__).parent.parent.parent / "prompts" / "agent_system_prompt.md"
_AGENT_PROMPT = _AGENT_PROMPT.resolve()

MAX_AGENT_ITERS = 10


def run_agent(finding: Finding, project_path: str, http_client: HttpClient,
              target_url: str, explore_msgs: list[str]) -> tuple[bool, str, str, list[dict]]:
    """AI agent 子图：自由调用 explore_code + send_http + read_file + write_file。

    返回 (verified, reasoning, updated_payload, agent_messages)。
    """
    from langgraph.prebuilt import create_react_agent
    from langchain_core.messages import HumanMessage
    from ...llm import _get_raw_llm

    # 1. 创建工具（绑定到当前项目 + session）
    tools = create_agent_tools(project_path, http_client)
    log.info("agent: 创建 %d 个工具", len(tools))

    # 2. 创建 LangGraph ReAct agent
    llm = _get_raw_llm()
    agent_graph = create_react_agent(llm, tools, version="v2")
    log.info("agent: LangGraph create_react_agent 创建完成（version=v2, recursion_limit=25）")

    # 3. 系统提示
    system_prompt = _AGENT_PROMPT.read_text(encoding="utf-8")

    # 4. 用户消息
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
        f"如果 send_http 返回登录页（session 失效），不要重复登录，"
        f"说明 session 失效并结束分析。"
    )

    # 5. 调用 agent 子图（显式 recursion_limit 防死循环）
    print(f"\n{'='*60}")
    print(f"启动 LangGraph ReAct agent 子图...")
    print(f"{'='*60}")

    try:
        result = agent_graph.invoke(
            {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_msg},
                ]
            },
            {"recursion_limit": 25},
        )
    except Exception as e:
        log.warning("agent: 子图执行失败 → %s", e)
        return False, f"agent error: {e}", finding.payload, []

    # 6. 提取结果
    messages = result.get("messages", [])
    agent_msgs: list[dict] = []
    final_text = ""
    updated_payload = finding.payload

    for i, msg in enumerate(messages):
        if isinstance(msg, HumanMessage):
            continue
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for call in msg.tool_calls:
                tool_name = call["name"]
                tool_args = call["args"]
                if tool_name == "explore_code":
                    explore_msgs.append(f"[agent iter {i}] query={tool_args.get('query','')}")
                if tool_name == "send_http":
                    body = tool_args.get("body", "")
                    url = tool_args.get("url", "")
                    method = tool_args.get("method", "POST")
                    if body:
                        updated_payload = f"{method} {url}\n\n{body}"
                agent_msgs.append({
                    "iter": i,
                    "tool": tool_name,
                    "args": str(tool_args)[:300],
                })
        elif hasattr(msg, "content") and msg.content:
            final_text = msg.content if isinstance(msg.content, str) else str(msg.content)
            agent_msgs.append({"iter": i, "type": "final", "content": final_text[:500]})

    # 7. 用 AI 结构化输出判断 verified（基于最后一次 send_http 的响应 body）
    verified, reasoning = _ai_judge_from_last_response(
        finding, messages, updated_payload, target_url
    )

    log.info("agent: 完成 → verified=%s, %d 条对话", verified, len(messages))
    return verified, reasoning, updated_payload, agent_msgs


def _ai_judge_from_last_response(finding: Finding, messages: list,
                                  updated_payload: str, target_url: str) -> tuple[bool, str]:
    """从 agent 对话历史中找最后一次 send_http 的响应，调 ai_verify 结构化判断。

    不再靠关键词匹配 agent 的 final_text — 而是让 AI 分析实际 HTTP 响应 body，
    根据漏洞类型理解返回值是否能证明利用成功。
    """
    from langchain_core.messages import ToolMessage
    from ._payload import ai_verify, parse_payload

    # 从对话历史倒序找最后一次 send_http 的 ToolMessage（响应）
    last_http_response: str | None = None
    last_http_request: dict = {}

    for msg in reversed(messages):
        if not isinstance(msg, ToolMessage):
            continue
        # ToolMessage 的 content 是工具返回值
        # send_http 工具返回格式：'HTTP {status}\nHeaders: {...}\nBody: {body}'
        content = str(msg.content) if not isinstance(msg.content, str) else msg.content
        if content.startswith("HTTP ") or "Headers:" in content:
            last_http_response = content
            break

    # 找最后一次 send_http 的 AIMessage 里的 tool_call args
    for msg in reversed(messages):
        if hasattr(msg, "tool_calls") and msg.tool_calls:
            for call in reversed(msg.tool_calls):
                if call["name"] == "send_http":
                    last_http_request = call["args"]
                    break
            if last_http_request:
                break

    if not last_http_response:
        return False, "agent 未发送任何 HTTP 请求"

    # 解析 send_http 工具返回的响应文本
    # 格式: 'HTTP {status}\nHeaders: {json}\nBody: {body}'
    import json
    lines = last_http_response.split("\n", 2)
    status = 0
    resp_headers = {}
    resp_body = ""

    if lines and lines[0].startswith("HTTP "):
        try:
            status = int(lines[0].replace("HTTP ", ""))
        except ValueError:
            pass

    for line in lines[1:] if len(lines) > 1 else []:
        if line.startswith("Headers: "):
            try:
                resp_headers = json.loads(line.replace("Headers: ", ""))
            except json.JSONDecodeError:
                pass
        elif line.startswith("Body: "):
            resp_body = line.replace("Body: ", "")

    # 构造请求详情（从最后一次 send_http 的 args）
    method = last_http_request.get("method", "POST")
    url = last_http_request.get("url", "")
    body = last_http_request.get("body", "")
    headers = {}
    hdr_str = last_http_request.get("headers", "")
    if hdr_str:
        try:
            headers = json.loads(hdr_str)
        except json.JSONDecodeError:
            pass

    # 调 ai_verify（结构化输出：verified/cvss/cia_proof/second_payload）
    verified, reasoning, _cvss, _second = ai_verify(
        finding, method, url, headers, body,
        status, resp_headers, resp_body,
    )

    return verified, reasoning

