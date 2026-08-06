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
    """填充路由可达性分析 prompt 模板。
    把调用链路径 + 方法体合并成一个完整调用链文本，不拆成两部分。"""
    # 合并：chain_ids 按顺序从 route → vuln，每个 body 已经是 "// fqn\n<body>" 格式
    # 拼成：// fqn\n<body>\n→\n// fqn\n<body>\n→\n...
    chain_text = "\n→\n".join(
        body for body in chain_bodies.values()
    ) if chain_bodies else "(无方法体)"

    tmpl = _TEMPLATE.read_text(encoding="utf-8")
    return (
        tmpl
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
        # 预计算 Q6 route 可达集（一次性，后续查每个 finding 都用）
        from ..codegraph.queries import Q6_ROUTE_REACHABLE_NODES
        route_rows = cg._conn.execute(Q6_ROUTE_REACHABLE_NODES).fetchall()
        route_set = {r["id"] for r in route_rows}
        log.info("trace_route: Q6 route 可达集 %d 个", len(route_set))

        for f in findings:
            # 先用 Q6 快速判断是否 route 可达
            if f.node_id not in route_set:
                log.info("trace_route: %s — 不在 route 可达集中，跳过", f.node_id[:30])
                f.confidence = f.confidence * 0.3
                f.evidence += "\n\n[路由可达性分析] 不可达（不在 route 可达集中）"
                continue

            # Q5：反向追溯调用链（限制深度 5，加超时）
            log.info("trace_route: Q5 SQL → WHERE id = '%s' (depth<5)", f.node_id[:40])
            try:
                import sqlite3 as _sqlite3
                # 设置busy timeout + 用短查询
                cg._conn.execute("PRAGMA query_only = ON")
                # 临时替换 Q5 深度为 5（不是 18，避免爆炸）
                from ..codegraph.queries import Q5_REVERSE_CHAIN
                q5_fast = Q5_REVERSE_CHAIN.replace("c.depth < 18", "c.depth < 5")
                chains = cg._conn.execute(q5_fast, {"node_id": f.node_id}).fetchall()
                cg._conn.execute("PRAGMA query_only = OFF")
            except Exception as e:
                log.warning("trace_route: Q5 查询失败 → %s，用 Q6 确认可达即可", str(e)[:100])
                f.evidence += "\n\n[路由可达性分析] 可达（Q5 查询失败，Q6 确认可达）"
                f.confidence = max(f.confidence, 0.7)
                continue

            if not chains:
                # Q5 没找到 route，但 Q6 确认可达 → 标记为可达但链太深
                log.info("trace_route: %s — Q5 未找到 route（链可能超过 5 层），Q6 确认可达", f.node_id[:30])
                f.evidence += "\n\n[路由可达性分析] 可达（调用链超过 5 层，无法提取 route 路径）"
                f.confidence = max(f.confidence, 0.6)
                continue

            # 取最短链
            chain = chains[0]
            chain_path = chain["chain_path"]
            chain_ids = chain["chain_ids"]
            log.info("trace_route: %s — 找到路由链 (depth=%d): %s", f.node_id[:30], chain["depth"], chain_path[:100])

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
                payload = result.updated_payload.strip()
                if payload and not payload.startswith(("POST ", "GET ", "PUT ", "DELETE ", "curl", "http")):
                    import re as _re
                    route_match = _re.search(r"route:(/[^\s]+)", chain_path)
                    route_path = route_match.group(1) if route_match else "/"
                    payload = f"POST {route_path} HTTP/1.1\n\n{payload}"
                    log.info("trace_route: payload 不是 HTTP 格式，已包裹为 POST %s", route_path)
                f.payload = payload
                f.confidence = result.confidence
                f.evidence += f"\n\n[路由可达性分析] 可达。条件: {result.conditions}"
                log.info("trace_route: %s — 可达，payload 已更新", f.node_id[:30])
            else:
                f.confidence = result.confidence * 0.3
                f.evidence += f"\n\n[路由可达性分析] 不可达。原因: {result.conditions}"
                log.info("trace_route: %s — 不可达，置信度降至 %.2f", f.node_id[:30], f.confidence)

    return {"findings": findings}
