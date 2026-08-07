"""trace_route 节点 — 对每个 finding 反向追溯调用链到 kind='route'，发 AI 判断可达性。

流程：
  1. 取所有 findings（audit 阶段产出的漏洞）
  2. 对每个 finding 的 node_id，跑 Q5（递归反向追溯）找所有 kind='route' 的 HTTP 入口
  3. 每条链独立拉取方法体、独立渲染 prompt、独立调 LLM
  4. 每条链的结论写入 finding.chains[i]，汇总写入 finding.reachability
"""
from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor

from ..codegraph import CodegraphClient
from ..llm import call_reachability_llm
from ..prompts import render
from ..state import EVIDENCE_TRACE_TAG, AuditState, ChainResult, Finding

log = logging.getLogger("secgraph.trace_route")

_ROUTE_PATH_RE = re.compile(r"route:(/[^\s]+)")
LLM_CONCURRENCY = 3


def _render_prompt(f: Finding, chain_path: str, chain_bodies: dict[str, str]) -> str:
    """渲染可达性分析 prompt（测试 + _prepare 共用）。"""
    chain_text = "\n→\n".join(chain_bodies.values()) if chain_bodies else "(无方法体)"
    return render("route_reachability",
                  vuln_type=f.vuln_type,
                  severity=f.severity,
                  evidence=f.evidence,
                  payload=f.payload or "",
                  call_chain=chain_text)


def _prepare_chains(f: Finding, cg: CodegraphClient, sources_root: str) -> list[tuple]:
    """阶段 1：对 finding 的所有链，拉方法体 + 渲染 prompt（串行，SQLite 不线程安全）。

    返回 [(finding, chain_result, prompt, chain_path), ...] 列表。
    如果 finding 不可达（不在 route_reachable 集），直接标记并返回空列表。
    """
    if not cg.is_route_reachable(f.node_id):
        log.info("trace_route: %s — 不在 route 可达集中，跳过", f.node_id[:30])
        f.confidence = f.confidence * 0.3
        f.reachability = "unreachable"
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达（不在 route 可达集中）"
        return []

    chains = cg.get_call_chain_to_route(f.node_id)
    if not chains:
        log.info("trace_route: %s — Q5 未找到 route，Q6 确认可达", f.node_id[:30])
        f.reachability = "reachable"
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 可达（调用链超过 18 层）"
        f.confidence = max(f.confidence, 0.6)
        return []

    prepped = []
    for chain in chains:
        chain_path = chain["chain_path"]
        chain_ids = chain["chain_ids"]
        log.info("trace_route: %s — 链 %d/%d (depth=%d): %s",
                 f.node_id[:30], len(prepped) + 1, len(chains),
                 chain["depth"], chain_path[:100])

        chain_bodies = cg.get_chain_bodies(sources_root, chain_ids)
        prompt = _render_prompt(f, chain_path, chain_bodies)

        # 创建 ChainResult 占位，LLM 返回后填充
        cr = ChainResult(
            chain_path=chain_path,
            chain_ids=chain_ids,
            reachable="pending",
        )
        f.chains.append(cr)
        prepped.append((f, cr, prompt, chain_path))

    return prepped


def _apply_chain(f: Finding, cr: ChainResult, result, chain_path: str) -> None:
    """阶段 3：把 LLM 结果写回 ChainResult + 汇总到 finding。"""
    if result.reachable:
        payload = result.updated_payload.strip()
        if payload and not payload.startswith(("POST ", "GET ", "PUT ", "DELETE ", "curl", "http")):
            route_match = _ROUTE_PATH_RE.search(chain_path)
            route_path = route_match.group(1) if route_match else "/"
            payload = f"POST {route_path} HTTP/1.1\n\n{payload}"
        cr.payload = payload
        cr.confidence = result.confidence
        cr.reachable = "reachable"
        cr.conditions = result.conditions
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 可达 [{cr.chain_path[:60]}]。条件: {result.conditions}"
        log.info("trace_route: %s — 链可达，payload 已更新", f.node_id[:30])
    else:
        cr.confidence = result.confidence * 0.3
        cr.reachable = "unreachable"
        cr.conditions = result.conditions
        f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达 [{cr.chain_path[:60]}]。原因: {result.conditions}"
        log.info("trace_route: %s — 链不可达", f.node_id[:30])


def _summarize(f: Finding) -> None:
    """汇总所有链的结论到 finding.reachability + finding.payload + finding.confidence。"""
    if not f.chains:
        return

    reachable_chains = [c for c in f.chains if c.reachable == "reachable"]
    if reachable_chains:
        f.reachability = "reachable"
        # 取置信度最高的可达链作为 finding 的主 payload
        best = max(reachable_chains, key=lambda c: c.confidence)
        f.payload = best.payload
        f.confidence = max(c.confidence for c in reachable_chains)
    elif all(c.reachable == "unreachable" for c in f.chains):
        f.reachability = "unreachable"
        f.confidence = max(c.confidence for c in f.chains)
    else:
        f.reachability = "uncertain"
        f.confidence = max(c.confidence for c in f.chains) if f.chains else f.confidence


def trace_route(state: AuditState) -> dict:
    """对每个 finding 反向追溯调用链到 route，每条链独立调 AI 判断可达性。"""
    findings: list[Finding] = list(state.get("findings", []))
    if not findings:
        return {}

    sources_root = state["sources_root"]
    codegraph_db = state["codegraph_db"]
    log.info("trace_route: === TRACE START %d 个 finding ===", len(findings))

    # 阶段 1：SQLite 串行抓数据 + 渲染 prompt（每个 finding 的每条链）
    prepped = []
    with CodegraphClient(codegraph_db) as cg:
        for f in findings:
            prepped.extend(_prepare_chains(f, cg, sources_root))

    # 阶段 2：LLM 并发调用（每条链独立）
    if prepped:
        log.info("trace_route: 并发 %d 个 LLM 调用（并发度=%d, %d 条链）",
                 len(prepped), LLM_CONCURRENCY, len(prepped))
        with ThreadPoolExecutor(max_workers=LLM_CONCURRENCY) as pool:
            futures = {
                pool.submit(call_reachability_llm, prompt): (f, cr, chain_path)
                for f, cr, prompt, chain_path in prepped
            }
            for future in futures:
                f, cr, chain_path = futures[future]
                try:
                    result = future.result()
                    log.info("trace_route: AI 返回: reachable=%s confidence=%.2f [%s]",
                             result.reachable, result.confidence, chain_path[:60])
                    _apply_chain(f, cr, result, chain_path)
                except Exception as e:
                    log.warning("trace_route: %s 链 LLM 失败 → %s", f.node_id[:30], e)
                    cr.reachable = "uncertain"
                    cr.conditions = f"LLM 分析失败: {str(e)[:80]}"
                    f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不确定 [{cr.chain_path[:60]}]（LLM 失败: {str(e)[:60]}）"
                    cr.confidence = f.confidence * 0.3

    # 阶段 3：汇总每个 finding 的多链结论
    for f in findings:
        _summarize(f)

    log.info("trace_route: === TRACE END ===")
    return {"findings": findings}