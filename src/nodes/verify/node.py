"""verify 节点 — 薄编排层。

把复杂逻辑委托给三个子模块：
- `_login` — env.txt + login_info.json + Playwright CDP
- `_payload` — HTTP payload 解析/发送/格式化 + AI 验证
- `_agent` — AI agent 循环（带 tools）

本文件只做：登录 → 遍历每条可达链顺序发 payload + AI 验证 → 并发 agent 循环。
每个 finding 可能有多条到达链（finding.chains），每条链独立验证。
"""
from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from ...state import AuditState, ChainResult, Finding
from ...tools.http_client import HttpClient
from ._agent import run_agent
from ._login import explore_login, read_env, read_login_info, write_login_info
from ._payload import ai_verify, send_payload

log = logging.getLogger("secgraph.verify.node")

MAX_PAYLOAD_ROUNDS = 3
AGENT_CONCURRENCY = 3


def verify_finding(state: AuditState) -> dict:
    """动态 PoC 验证：遍历每条可达链，独立发 payload + AI 验证 → agent 深度验证。"""
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

    explore_msgs: list[str] = []
    agent_msgs_all: list[dict] = []
    need_agent: list[tuple[Finding, ChainResult]] = []

    # 4. 遍历每个 finding 的每条可达链，独立验证
    for f in findings:
        reachable_chains = [c for c in f.chains if c.reachable == "reachable" and c.payload]
        if not reachable_chains:
            f.poc_result = "inconclusive"
            f.poc_output = "[no reachable chain or payload]"
            continue

        for cr in reachable_chains:
            log.info("verify: %s 链 %s — 初始 PoC", f.node_id[:30], cr.chain_path[:50])

            # 临时把链的 payload 设到 finding 上给 send_payload 用
            f.payload = cr.payload

            verified = False
            reasoning = ""
            second_payload = ""

            for round_num in range(MAX_PAYLOAD_ROUNDS):
                log.info("verify: %s 链 %s — round %d", f.node_id[:30], cr.chain_path[:50], round_num)

                parsed_result = send_payload(tool, target_url, f)
                if parsed_result is None:
                    break
                status, resp_headers, resp_body, method, url, body, headers, _ = parsed_result

                verified, reasoning, _cvss, second_payload = ai_verify(
                    f, method, url, headers, body,
                    status, resp_headers, resp_body,
                )

                if second_payload and not verified:
                    log.info("verify: AI 生成 second_payload，重试")
                    f.payload = second_payload
                    cr.payload = second_payload
                    continue
                break

            cr.poc_output = f"AI: {reasoning}"
            log.info("verify: %s 链 %s → 第一轮 %s",
                     f.node_id[:30], cr.chain_path[:50],
                     "confirmed" if verified else "未确认")
            need_agent.append((f, cr))

    # 5. 并发 agent 循环（每条链独立）
    if need_agent:
        log.info("verify: 第二轮 — %d 条链启动 agent 循环（并发度=%d）",
                 len(need_agent), AGENT_CONCURRENCY)

        def _run_one_agent(f: Finding, cr: ChainResult) -> tuple[str, bool, str, str, list[str], list[dict]]:
            agent_tool = HttpClient(login_info)
            agent_tool.login()
            agent_explore: list[str] = []
            f.payload = cr.payload
            verified, reasoning, payload, msgs = run_agent(
                f, project_path, agent_tool, target_url, agent_explore,
            )
            return f.node_id, verified, reasoning, payload, agent_explore, msgs

        with ThreadPoolExecutor(max_workers=AGENT_CONCURRENCY) as pool:
            futures = {pool.submit(_run_one_agent, f, cr): (f, cr) for f, cr in need_agent}
            for future in as_completed(futures):
                f, cr = futures[future]
                try:
                    nid, verified, reasoning, updated_payload, a_explore, a_msgs = future.result()
                except Exception as e:
                    log.warning("verify: agent %s 链 %s 异常 → %s",
                               f.node_id[:30], cr.chain_path[:50], e)
                    cr.poc_result = "inconclusive"
                    cr.poc_output = f"[agent error: {e}]"
                    continue

                if updated_payload and updated_payload != f.payload:
                    cr.payload = updated_payload
                cr.poc_result = "confirmed" if verified else "denied"
                cr.poc_output = f"AI: {reasoning}"
                explore_msgs.extend(a_explore)
                agent_msgs_all.extend(a_msgs)
                log.info("verify: %s 链 %s → %s (agent)",
                         nid[:30], cr.chain_path[:50], cr.poc_result.upper())

    # 6. 汇总：finding 的 poc_result = 任一链 confirmed → confirmed；全 denied → denied；否则 inconclusive
    for f in findings:
        chain_results = [c.poc_result for c in f.chains if c.poc_result]
        if "confirmed" in chain_results:
            f.poc_result = "confirmed"
        elif chain_results and all(r == "denied" for r in chain_results):
            f.poc_result = "denied"
        else:
            f.poc_result = "inconclusive"

        # 取 confirmed 链的 poc_output 作为 finding 的 poc_output
        confirmed_chains = [c for c in f.chains if c.poc_result == "confirmed"]
        if confirmed_chains:
            f.poc_output = confirmed_chains[0].poc_output
            f.payload = confirmed_chains[0].payload

    confirmed = sum(1 for f in findings if f.poc_result == "confirmed")
    denied = sum(1 for f in findings if f.poc_result == "denied")
    log.info("verify: === VERIFY END → %d confirmed, %d denied ===", confirmed, denied)

    _write_history(project_path, state.get("run_id", ""),
                   explore_msgs, agent_msgs_all)

    return {"findings": findings}


def _write_history(project_path: str, run_id: str,
                   explore_msgs: list[str], agent_msgs: list[dict]) -> None:
    """把 explore_msgs + agent_msgs 追加到 {project_path}/verify_history.json。"""
    if not explore_msgs and not agent_msgs:
        return
    f = Path(project_path) / "verify_history.json"
    entry = {
        "timestamp": datetime.now().isoformat(),
        "run_id": run_id,
        "explore_messages": explore_msgs,
        "agent_messages": agent_msgs,
    }
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