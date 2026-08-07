"""trace_route 节点 — 对每个 finding 反向追溯调用链到 kind='route'，发 AI 判断可达性。

流程：
  1. 取所有 findings（audit 阶段产出的漏洞）
  2. 对每个 finding 的 node_id，跑 Q5（递归反向追溯）找 kind='route' 的 HTTP 入口
  3. 取最短链，拉取链上每个方法的方法体
  4. 渲染可达性分析 prompt，调 AI 判断：漏洞是否可从路由到达？更新 payload
     （LLM 调用并行）
  5. 更新 finding 的 payload / evidence / confidence
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor

from ..codegraph import CodegraphClient
from ..llm import call_reachability_llm
from ..prompts import render
from ..state import EVIDENCE_TRACE_TAG, AuditState, Finding

log = logging.getLogger("secgraph.trace_route")

_ROUTE_PATH_RE = re.compile(r"route:(/[^\s]+)")
LLM_CONCURRENCY = 3  # 并发跑 LLM 调用，避免 Q5 SQL 串行 + LLM 网络阻塞


def _render_prompt(f, chain_path: str, chain_bodies: dict[str, str]) -> str:
    """渲染可达性分析 prompt（测试 + _prepare 共用）。"""
    chain_text = "\n→\n".join(chain_bodies.values()) if chain_bodies else "(无方法体)"
    return render("route_reachability",
                  vuln_type=f.vuln_type,
                  severity=f.severity,
                  evidence=f.evidence,
                  payload=f.payload or "",
                  call_chain=chain_text)


def _prepare(f: Finding, cg: CodegraphClient, sources_root: str):
    """阶段 1：抓 chain + bodies → 渲染 prompt（串行，SQLite 连接不线程安全）。

    返回 (finding, prompt, chain_path) 三元组，或 None 表示该 finding 不需要 LLM 调用。"""
    if not cg.is_route_reachable(f.node_id):
        log.info("trace_route: %s — 不在 route 可达集中，跳过", f.node_id[:30])
        f.confidence = f.confidence * 0.3
        f.reachability = "unreachable"
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达（不在 route 可达集中）"
        return None

    chains = cg.get_call_chain_to_route(f.node_id)
    if not chains:
        log.info("trace_route: %s — Q5 未找到 route，Q6 确认可达", f.node_id[:30])
        f.reachability = "reachable"
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 可达（调用链超过 18 层）"
        f.confidence = max(f.confidence, 0.6)
        return None

    chain = chains[0]
    chain_path = chain["chain_path"]
    chain_ids = chain["chain_ids"]
    log.info("trace_route: %s — 找到路由链 (depth=%d): %s",
             f.node_id[:30], chain["depth"], chain_path[:100])

    chain_bodies = cg.get_chain_bodies(sources_root, chain_ids)
    prompt = _render_prompt(f, chain_path, chain_bodies)
    return f, prompt, chain_path


def _apply(f, result, chain_path: str) -> None:
    """阶段 3：把 LLM 结果写回 finding。"""
    if result.reachable:
        payload = result.updated_payload.strip()
        if payload and not payload.startswith(("POST ", "GET ", "PUT ", "DELETE ", "curl", "http")):
            route_match = _ROUTE_PATH_RE.search(chain_path)
            route_path = route_match.group(1) if route_match else "/"
            payload = f"POST {route_path} HTTP/1.1\n\n{payload}"
            log.info("trace_route: payload 不是 HTTP 格式，已包裹为 POST %s", route_path)
        f.payload = payload
        f.confidence = result.confidence
        f.reachability = "reachable"
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 可达。条件: {result.conditions}"
        log.info("trace_route: %s — 可达，payload 已更新", f.node_id[:30])
    else:
        f.confidence = result.confidence * 0.3
        f.reachability = "unreachable"
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达。原因: {result.conditions}"
        log.info("trace_route: %s — 不可达，置信度降至 %.2f", f.node_id[:30], f.confidence)


def trace_route(state: AuditState) -> dict:
    """对每个 finding 反向追溯调用链到 route，并行发 AI 判断可达性。"""
    findings: list[Finding] = list(state.get("findings", []))
    if not findings:
        return {}

    sources_root = state["sources_root"]
    codegraph_db = state["codegraph_db"]
    log.info("trace_route: === TRACE START %d 个 finding ===", len(findings))

    # 阶段 1：SQLite 串行抓数据 + 渲染 prompt
    prepped = []
    with CodegraphClient(codegraph_db) as cg:
        for f in findings:
            out = _prepare(f, cg, sources_root)
            if out is not None:
                prepped.append(out)

    # 阶段 2：LLM 并发调用（每条独立，互不依赖）
    if prepped:
        log.info("trace_route: 并发 %d 个 LLM 调用（并发度=%d）",
                 len(prepped), LLM_CONCURRENCY)
        with ThreadPoolExecutor(max_workers=LLM_CONCURRENCY) as pool:
            futures = {
                pool.submit(call_reachability_llm, prompt): (f, chain_path)
                for f, prompt, chain_path in prepped
            }
            for future in futures:
                f, chain_path = futures[future]
                try:
                    result = future.result()
                    log.info("trace_route: AI 返回: reachable=%s confidence=%.2f",
                             result.reachable, result.confidence)
                    _apply(f, result, chain_path)
                except Exception as e:
                    # LLM 失败：写 fallback tag，避免后续 _after_discovery 反复 re-trace 这个 finding
                    log.warning("trace_route: %s LLM 失败 → %s", f.node_id[:30], e)
                    f.reachability = "uncertain"
                    f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达（LLM 分析失败: {str(e)[:80]}）"
                    f.confidence *= 0.3

    log.info("trace_route: === TRACE END ===")
    return {"findings": findings}