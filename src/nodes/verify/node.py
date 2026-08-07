"""verify 节点 — 薄编排层。

把复杂逻辑委托给三个子模块：
- `_login` — env.txt + login_info.json + Playwright CDP
- `_payload` — HTTP payload 解析/发送/格式化 + AI 验证
- `_agent` — AI agent 循环（带 tools）

本文件只做：登录 → 顺序发初始 payload + AI 验证（含 second_payload 循环）→ 并发 agent 循环。
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from ...state import AuditState, Finding
from ...tools.http_client import HttpClient
from ._agent import run_agent
from ._login import explore_login, read_env, read_login_info, write_login_info
from ._payload import ai_verify, send_payload

log = logging.getLogger("secgraph.verify.node")

MAX_PAYLOAD_ROUNDS = 3  # second_payload 最多循环次数
AGENT_CONCURRENCY = 3    # agent 循环并发度


def verify_finding(state: AuditState) -> dict:
    """动态 PoC 验证：env.txt → 登录探索(缓存) → 顺序发初始 payload + AI 验证 → 并发 agent 循环。"""
    findings: list[Finding] = list(state.get("findings", []))
    if not findings:
        return {}

    log.info("verify: === VERIFY START %d 个 finding ===", len(findings))

    project_path = state.get("sources_root", "")

    # 1. 读 env.txt
    env = read_env(project_path)
    if not env:
        for f in findings:
            f.poc_result = "inconclusive"
            f.poc_output = "[no env.txt]"
        return {"findings": findings}

    target_url = env.get("target_url", "").rstrip("/")
    username = env.get("username", "")
    password = env.get("password", "")

    # 2. 登录探索（缓存优先）
    login_info = read_login_info(project_path)
    if not login_info:
        login_info = explore_login(target_url, username, password)
        if login_info:
            write_login_info(project_path, login_info)

    if not login_info:
        for f in findings:
            f.poc_result = "inconclusive"
            f.poc_output = "[login exploration failed]"
        return {"findings": findings}

    # 3. HttpClient 登录
    tool = HttpClient(login_info)
    if not tool.login():
        for f in findings:
            f.poc_result = "inconclusive"
            f.poc_output = "[login failed]"
        return {"findings": findings}

    # 4. 第一轮：顺序发初始 payload + AI 验证（含 second_payload 循环）
    explore_msgs: list[str] = []
    agent_msgs_all: list[dict] = []
    need_agent: list[Finding] = []

    for f in findings:
        if not f.payload:
            f.poc_result = "inconclusive"
            f.poc_output = "[no payload]"
            continue

        log.info("verify: 初始 PoC — %s — %s", f.vuln_type, f.node_id[:30])

        verified = False
        reasoning = ""
        second_payload = ""

        for round_num in range(MAX_PAYLOAD_ROUNDS):
            label = "初始" if round_num == 0 else f"second_payload({round_num})"
            log.info("verify: %s — round %d (%s)", f.node_id[:30], round_num, label)

            parsed_result = send_payload(tool, target_url, f)
            if parsed_result is None:
                break
            status, resp_headers, resp_body, method, url, body, headers, _ = parsed_result

            verified, reasoning, _cvss, second_payload = ai_verify(
                f, method, url, headers, body,
                status, resp_headers, resp_body,
            )

            # 已确认就不浪费 round 发 second_payload
            if second_payload and not verified:
                log.info("verify: AI 生成 second_payload，重试")
                f.payload = second_payload
                continue
            break

        # 所有 finding 都进 agent 循环（不只是失败的）
        # confirmed 的也进 agent 做深度验证（CIA 证明 + PoC 确认）
        log.info("verify: %s → 第一轮 %s，进入 agent 深度验证",
                 f.node_id[:30], "confirmed" if verified else "未确认")
        need_agent.append(f)

    # 5. 第二轮：并发 agent 循环
    if need_agent:
        log.info("verify: 第二轮 — %d 个 finding 启动 agent 循环（并发度=%d）",
                 len(need_agent), AGENT_CONCURRENCY)

        def _run_one_agent(f: Finding) -> tuple[str, bool, str, str, list[str], list[dict]]:
            agent_tool = HttpClient(login_info)
            agent_tool.login()
            agent_explore: list[str] = []
            verified, reasoning, payload, msgs = run_agent(
                f, project_path, agent_tool, target_url, agent_explore,
            )
            return f.node_id, verified, reasoning, payload, agent_explore, msgs

        with ThreadPoolExecutor(max_workers=AGENT_CONCURRENCY) as pool:
            futures = {pool.submit(_run_one_agent, f): f for f in need_agent}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    nid, verified, reasoning, updated_payload, a_explore, a_msgs = future.result()
                except Exception as e:
                    log.warning("verify: agent %s 异常 → %s", f.node_id[:30], e)
                    f.poc_result = "inconclusive"
                    f.poc_output = f"[agent error: {e}]"
                    continue

                if updated_payload and updated_payload != f.payload:
                    f.payload = updated_payload
                f.poc_result = "confirmed" if verified else "denied"
                f.poc_output = f"AI: {reasoning}"
                explore_msgs.extend(a_explore)
                agent_msgs_all.extend(a_msgs)
                log.info("verify: %s → %s (agent)", nid[:30], f.poc_result.upper())

    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")
    log.info("verify: === VERIFY END → %d confirmed, %d denied ===", confirmed, denied)

    # 写运行历史到文件（不进 state — state 是决策，不是日志）
    _write_history(project_path, state.get("run_id", ""),
                   explore_msgs, agent_msgs_all)

    return {"findings": findings}


def _write_history(project_path: str, run_id: str,
                   explore_msgs: list[str], agent_msgs: list[dict]) -> None:
    """把 explore_msgs + agent_msgs 追加到 {project_path}/verify_history.json。
    与 DB 分离 — DB 存 findings（决策），文件存历史（日志）。"""
    if not explore_msgs and not agent_msgs:
        return
    f = Path(project_path) / "verify_history.json"
    entry = {
        "timestamp": datetime.now().isoformat(),
        "run_id": run_id,
        "explore_messages": explore_msgs,
        "agent_messages": agent_msgs,
    }
    # 追加（不是覆盖 — 多次跑累积历史）
    if f.exists():
        try:
            history = json.loads(f.read_text(encoding="utf-8"))
            if not isinstance(history, list):
                history = [history]
        except json.JSONDecodeError:
            history = []
    else:
        history = []
    history.append(entry)
    f.write_text(json.dumps(history, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("verify: 历史已写入 → %s（%d explore, %d agent）",
             f, len(explore_msgs), len(agent_msgs))