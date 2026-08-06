"""trace_route 节点 — 对每个 finding 反向追溯调用链到 kind='route'，发 AI 判断可达性。

流程：
  1. 取所有 findings（audit 阶段产出的漏洞）
  2. 对每个 finding 的 node_id，跑 Q5（递归反向追溯）找 kind='route' 的 HTTP 入口
  3. 取最短链，拉取链上每个方法的方法体
  4. 渲染可达性分析 prompt，调 AI 判断：漏洞是否可从路由到达？更新 payload
  5. 更新 finding 的 payload / evidence / confidence
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..codegraph import CodegraphClient
from ..llm import call_reachability_llm
from ..state import EVIDENCE_TRACE_TAG, AuditState, Finding

log = logging.getLogger("secgraph.trace_route")

_TEMPLATE_PATH = (Path(__file__).with_name("..") / "prompts" / "route_reachability_template.md").resolve()
_TEMPLATE_TEXT = _TEMPLATE_PATH.read_text(encoding="utf-8")

_ROUTE_PATH_RE = re.compile(r"route:(/[^\s]+)")


def _render_prompt(f: Finding, chain_path: str, chain_bodies: dict[str, str]) -> str:
    """填充路由可达性分析 prompt 模板。
    把调用链路径 + 方法体合并成一个完整调用链文本，不拆成两部分。"""
    chain_text = "\n→\n".join(chain_bodies.values()) if chain_bodies else "(无方法体)"
    return (
        _TEMPLATE_TEXT
        .replace("{vuln_type}", f.vuln_type)
        .replace("{severity}", f.severity)
        .replace("{evidence}", f.evidence)
        .replace("{payload}", f.payload or "")
        .replace("{call_chain}", chain_text)
    )


def trace_route(state: AuditState) -> dict:
    """对每个 finding 反向追溯调用链到 route，发 AI 判断可达性并更新 payload。"""
    findings: list[Finding] = list(state.get("findings", []))
    if not findings:
        return {}

    sources_root = state["sources_root"]
    codegraph_db = state["codegraph_db"]

    log.info("trace_route: %d 个 finding 待追溯", len(findings))

    with CodegraphClient(codegraph_db) as cg:
        for f in findings:
            # 快速判断是否 route 可达（查 route_reachable 表，不跑递归 CTE）
            if not cg.is_route_reachable(f.node_id):
                log.info("trace_route: %s — 不在 route 可达集中，跳过", f.node_id[:30])
                f.confidence = f.confidence * 0.3
                f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达（不在 route 可达集中）"
                continue

            # Q5：反向追溯调用链（18 层，只保留 kind=route）
            chains = cg.get_call_chain_to_route(f.node_id)
            if not chains:
                # Q5 没找到 route，但 Q6 确认可达 → 标记为可达但链太深
                log.info("trace_route: %s — Q5 未找到 route，Q6 确认可达", f.node_id[:30])
                f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 可达（调用链超过 18 层）"
                f.confidence = max(f.confidence, 0.6)
                continue

            # 取最短链
            chain = chains[0]
            chain_path = chain["chain_path"]
            chain_ids = chain["chain_ids"]
            log.info("trace_route: %s — 找到路由链 (depth=%d): %s",
                     f.node_id[:30], chain["depth"], chain_path[:100])

            # 拉取链上每个方法的方法体
            chain_bodies = cg.get_chain_bodies(sources_root, chain_ids)
            log.info("trace_route: 方法体拉取完成，%d 个，总 %d 字符",
                     len(chain_bodies), sum(len(v) for v in chain_bodies.values()))

            # 渲染 prompt + 调 AI
            prompt = _render_prompt(f, chain_path, chain_bodies)
            log.info("trace_route: prompt 渲染完成，%d 字符，发送 AI...", len(prompt))
            result = call_reachability_llm(prompt)
            log.info("trace_route: AI 返回: reachable=%s confidence=%.2f",
                     result.reachable, result.confidence)

            # 更新 finding
            if result.reachable:
                payload = result.updated_payload.strip()
                if payload and not payload.startswith(("POST ", "GET ", "PUT ", "DELETE ", "curl", "http")):
                    route_match = _ROUTE_PATH_RE.search(chain_path)
                    route_path = route_match.group(1) if route_match else "/"
                    payload = f"POST {route_path} HTTP/1.1\n\n{payload}"
                    log.info("trace_route: payload 不是 HTTP 格式，已包裹为 POST %s", route_path)
                f.payload = payload
                f.confidence = result.confidence
                f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 可达。条件: {result.conditions}"
                log.info("trace_route: %s — 可达，payload 已更新", f.node_id[:30])
            else:
                f.confidence = result.confidence * 0.3
                f.evidence += f"\n\n{EVIDENCE_TRACE_TAG} 不可达。原因: {result.conditions}"
                log.info("trace_route: %s — 不可达，置信度降至 %.2f", f.node_id[:30], f.confidence)

    return {"findings": findings}