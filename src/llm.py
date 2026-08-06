"""LLM 抽象 — LangChain ChatOpenAI + 结构化输出。

通过 DashScope 调 GLM 5.1（OpenAI 兼容）。配置在 .env：
  LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

入口：
  - call_audit_llm(prompt)        -> AuditResult           （审计）
  - call_reachability_llm(prompt) -> ReachabilityResult    （路由可达性分析）
  - call_exploration_llm(prompt)  -> LoginExplorationResult（登录探索）
  - call_verification_llm(prompt) -> PoCVerificationResult （PoC 验证）
  - call_supervisor_llm(prompt)   -> SupervisorDecision    （supervisor 路由）

所有结构化输出都有 fallback：with_structured_output 失败时回退到 raw LLM +
剥 markdown + 手动解析。
"""
from __future__ import annotations

import json
import logging
import os
import re

from langchain_openai import ChatOpenAI

from .state import (
    AuditResult, LoginExplorationResult, PoCVerificationResult,
    ReachabilityResult, SupervisorDecision,
)

# 本地回环地址不走代理（LLM API 走代理，但本地 Chrome CDP / WebGoat 不走）
os.environ.setdefault("NO_PROXY", "127.0.0.1,localhost")

log = logging.getLogger("secgraph.llm")

# 不用 markdown 代码块的强约束（加到每个 prompt 前面）
_NO_MARKDOWN_PREFIX = (
    "重要：你的输出必须是纯 JSON，不要用 ```json 或任何 markdown 代码块包裹，不要有任何多余文本。\n\n"
)

# 角色 → raw LLM 实例（按 role 共享，因为 raw 不绑 model class）
_RAW_CACHE: dict[str, ChatOpenAI] = {}
# (role, model_cls) → 结构化 LLM 实例（按 model class 区分，避免同 role 不同 schema 串号）
_STRUCTURED_CACHE: dict[tuple[str, type], object] = {}


def _create_llm(role: str) -> ChatOpenAI:
    """按 role 创建 ChatOpenAI。优先读 {ROLE}_LLM_* 配置，回退 LLM_*。"""
    key = os.getenv(f"{role.upper()}_LLM_API_KEY") or os.getenv("LLM_API_KEY", "")
    base = os.getenv(f"{role.upper()}_LLM_BASE_URL") or os.getenv("LLM_BASE_URL", "")
    model = os.getenv(f"{role.upper()}_LLM_MODEL") or os.getenv("LLM_MODEL", "glm-5.1")

    llm = ChatOpenAI(
        model=model, api_key=key, base_url=base,
        temperature=0.3, timeout=120, max_retries=1,
    )
    log.info("llm[%s]: model=%s base_url=%s", role, model, base)
    return llm


def _get_raw(role: str) -> ChatOpenAI:
    """取 role 对应的 raw ChatOpenAI（首次创建并缓存）。"""
    raw = _RAW_CACHE.get(role)
    if raw is None:
        raw = _create_llm(role)
        _RAW_CACHE[role] = raw
    return raw


def _get_structured(role: str, model_cls):
    """取 (role, model_cls) 对应的结构化输出 LLM（首次创建并缓存）。

    必须按 (role, model_cls) 二元组 key — 同 role 不同 model class（探索 vs 验证）
    各自独立的 schema，不能共享。
    """
    key = (role, model_cls)
    structured = _STRUCTURED_CACHE.get(key)
    if structured is None:
        raw = _get_raw(role)
        structured = raw.with_structured_output(model_cls, method="json_mode")
        _STRUCTURED_CACHE[key] = structured
    return structured


def _strip_markdown_json(text: str) -> str:
    """剥掉 LLM 返回的 markdown 代码块包裹（```json ... ```）。"""
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        text = match.group(0)
    return text


def _call_structured(prompt: str, model_cls, role: str):
    """结构化输出 + fallback：with_structured_output 失败 → raw + 剥 markdown + 手动解析。

    失败 → 打印 raw 返回内容方便调试 → raise。
    """
    structured_llm = _get_structured(role, model_cls)

    # 尝试 1：with_structured_output (json_mode)
    try:
        result = structured_llm.invoke(_NO_MARKDOWN_PREFIX + prompt)
        log.info("llm: 结构化输出成功 → %s", type(result).__name__)
        return result
    except Exception as e:
        log.warning("llm: 结构化输出失败 → %s，回退到 raw + 手动解析", str(e)[:200])

    # 尝试 2：raw LLM + 剥 markdown + 手动解析
    raw_text = ""
    clean_json = ""
    try:
        raw_llm = _get_raw(role)
        raw_resp = raw_llm.invoke(_NO_MARKDOWN_PREFIX + prompt)
        raw_text = raw_resp.content if hasattr(raw_resp, "content") else str(raw_resp)
        log.info("llm: raw LLM 返回（完整 %d 字）:\n%s", len(raw_text), raw_text)

        clean_json = _strip_markdown_json(raw_text)
        data = json.loads(clean_json)
        result = model_cls.model_validate(data)
        log.info("llm: raw fallback 成功 → %s", type(result).__name__)
        return result
    except json.JSONDecodeError as e2:
        log.error("llm: JSON 解析失败 → %s", str(e2)[:200])
        log.error("llm: raw 返回完整内容:\n%s", raw_text)
        log.error("llm: 剥 markdown 后:\n%s", clean_json)
        raise
    except Exception as e2:
        log.error("llm: raw fallback 也失败 → %s", str(e2)[:200])
        log.error("llm: raw 返回完整内容:\n%s", raw_text)
        raise


# ---------------------------------------------------------------------------
# 各 LLM 入口 — 按 role 使用独立 LLM 实例
# ---------------------------------------------------------------------------

def call_audit_llm(prompt: str) -> AuditResult:
    """漏洞发现 — 用 AUDIT_LLM_* 配置。"""
    return _call_structured(prompt, AuditResult, "audit")


def call_reachability_llm(prompt: str) -> ReachabilityResult:
    """调用链分析 — 用 TRACE_LLM_* 配置。"""
    return _call_structured(prompt, ReachabilityResult, "trace")


def call_exploration_llm(prompt: str) -> LoginExplorationResult:
    """登录探索 — 用 VERIFY_LLM_* 配置。"""
    return _call_structured(prompt, LoginExplorationResult, "verify")


def call_verification_llm(prompt: str) -> PoCVerificationResult:
    """PoC 验证 — 用 VERIFY_LLM_* 配置。"""
    return _call_structured(prompt, PoCVerificationResult, "verify")


def call_supervisor_llm(prompt: str) -> SupervisorDecision:
    """Supervisor 路由 — 用 VERIFY_LLM_* 配置。"""
    return _call_structured(prompt, SupervisorDecision, "supervisor")