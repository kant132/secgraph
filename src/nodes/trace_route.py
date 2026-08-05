"""trace_route 节点 — 对每个 finding 反向追溯调用链到 kind='route'，发 AI 判断可达性。

流程：
  1. 取所有 findings（audit 阶段产出的漏洞）
  2. 对每个 finding 的 node_id，跑 Q5（递归反向追溯）找 kind='route' 的 HTTP 入口
  3. 取最短链，拉取链上每个方法的方法体
  4. 渲染可达性分析 prompt，调 AI 判断：漏洞是否可从路由到达？更新 payload。
  5. 更新 finding 的 payload / evidence / confidence
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..codegraph import CodegraphClient
from ..llm import call_reachability_llm
from ..state import AuditState, Finding

log = logging.getLogger("secgraph.trace_route")

_TEMPLATE = Path(__file__).with_name("..") / "prompts" / "route_reachability_template.md"
_TEMPLATE = _TEMPLATE.resolve()


def _render_prompt(f: Finding, chain_path: str, chain_bodies: dict[str, str]) -> str:
    """填充路由可达性分析 prompt 模板。"""
    bodies_json = json.dumps(chain_bodies, indent=2, ensure_ascii=False) if chain_bodies else "{}"
    tmpl = _TEMPLATE.read_text(encoding="utf-8")
    return (
        tmpl
        .replace("{vuln_type}", f.vuln_type)
        .replace("{severity}", f.severity)
        .replace("{evidence}", f.evidence)
        .replace("{payload}", f.payload or "")
        .replace("{chain_path}", chain_path)
        .replace("{chain_bodies}", bodies_json)
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
            # Q5：反向追溯调用链
            chains = cg.get_call_chain_to_route(f.node_id)
            if not chains:
                log.info("trace_route: %s — 无 route 可达链（可能不是路由入口方法）", f.node_id[:30])
                continue

            # 取最短链（depth 最小 = 最直接路径）
            chain = chains[0]
            chain_path = chain["chain_path"]
            chain_ids = chain["chain_ids"]
            log.info("trace_route: %s — 找到路由链 (depth=%d): %s", f.node_id[:30], chain["depth"], chain_path)

            # 拉取链上每个方法的方法体
            chain_bodies = cg.get_chain_bodies(sources_root, chain_ids)

            # 渲染 prompt 并调 AI
            prompt = _render_prompt(f, chain_path, chain_bodies)
            log.info("trace_route: 发送 AI 可达性分析（链 %d 层）", len(chain_bodies))
            print(f"\n===== 可达性分析 prompt =====\n{prompt[:1500]}\n===== 结束 =====\n")

            result = call_reachability_llm(prompt)

            print(f"\n===== AI 可达性结果 =====")
            print(f"  reachable:   {result.reachable}")
            print(f"  confidence:  {result.confidence}")
            print(f"  conditions:  {result.conditions}")
            print(f"  payload:     {result.updated_payload}")
            print(f"===== 结束 =====\n")

            # 更新 finding
            if result.reachable:
                f.payload = result.updated_payload
                f.confidence = result.confidence
                f.evidence += f"\n\n[路由可达性分析] 可达。条件: {result.conditions}"
                log.info("trace_route: %s — 可达，payload 已更新", f.node_id[:30])
            else:
                f.confidence = result.confidence * 0.3
                f.evidence += f"\n\n[路由可达性分析] 不可达。原因: {result.conditions}"
                log.info("trace_route: %s — 不可达，置信度降至 %.2f", f.node_id[:30], f.confidence)

    return {"findings": findings}
