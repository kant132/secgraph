"""AI agent 循环 — 自由调用 explore_code + send_http + read_file + write_file。

AI 自己决定：探索什么、构造什么 payload、怎么测试、什么时候停。

注意：当前仍是手写 tool loop（SystemMessage/HumanMessage/ToolMessage）。
后续 #2 重构会改用 LangGraph ToolNode + MessagesState sub-graph。
"""
from __future__ import annotations

import logging
from pathlib import Path

from ...state import Finding
from ...tools.agent_tools import create_agent_tools
from ...tools.http_client import HttpClient

log = logging.getLogger("secgraph.verify.agent")

_AGENT_PROMPT = Path(__file__).with_name("..").parent.parent / "prompts" / "agent_system_prompt.md"
_AGENT_PROMPT = _AGENT_PROMPT.resolve()

MAX_AGENT_ITERS = 10


def run_agent(finding: Finding, project_path: str, http_client: HttpClient,
              target_url: str, explore_msgs: list[str]) -> tuple[bool, str, str, list[dict]]:
    """AI agent 循环：自由调用 explore_code + send_http + read_file + write_file。

    返回 (verified, reasoning, updated_payload, agent_messages)。
    """
    from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
    from ...llm import _get_raw_llm

    # 创建工具（绑定到当前项目 + session）
    tools = create_agent_tools(project_path, http_client)
    tool_map = {t.name: t for t in tools}

    # 绑定工具到 LLM
    llm = _get_raw_llm().bind_tools(tools)

    system_prompt = _AGENT_PROMPT.read_text(encoding="utf-8")
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

        for call in response.tool_calls:
            tool_name = call["name"]
            tool_args = call["args"]
            tool_id = call["id"]

            print(f"  → 调工具: {tool_name}({str(tool_args)[:120]})")

            if tool_name == "explore_code":
                explore_msgs.append(f"[agent iter {i+1}] query={tool_args.get('query','')}")

            tool = tool_map.get(tool_name)
            result = tool.invoke(tool_args) if tool else f"[未知工具: {tool_name}]"

            result_str = str(result)
            print(f"  → 结果({len(result_str)}字): {result_str[:200]}")

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

    verified = any(kw in final_text.lower() for kw in ("confirmed", "可利用", "已确认", "verified", "成功"))
    if not verified:
        verified = any(kw in final_text.lower() for kw in ("数据泄露", "数据返回", "成功执行", "绕过"))

    return verified, final_text, updated_payload, agent_msgs
