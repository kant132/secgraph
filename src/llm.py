"""LLM 抽象 — LangChain ChatOpenAI + 结构化输出。

通过 DashScope 调 GLM 5.1（OpenAI 兼容）。配置在 .env：
  LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

四个入口：
  - call_audit_llm(prompt) -> AuditResult         （审计，结构化输出）
  - call_reachability_llm(prompt) -> ReachabilityResult  （路由可达性分析）
  - call_verification_llm(prompt) -> PoCVerificationResult  （PoC验证）
  - call_supervisor_llm(prompt) -> SupervisorDecision     （supervisor路由）

所有结构化输出调用都有 fallback：如果 with_structured_output 失败
（如 GLM 返回 markdown 包裹的 JSON），回退到 raw LLM + 剥 markdown + 手动解析。
"""
from __future__ import annotations

import os
# 本地回环地址不走代理（LLM API 走代理，但本地 Chrome CDP / WebGoat 不走）
os.environ['NO_PROXY'] = '127.0.0.1,localhost'

import json
import logging
import re

from langchain_openai import ChatOpenAI

from .state import (
    AuditResult, LoginExplorationResult, PoCVerificationResult,
    PayloadRetryResult, ReachabilityResult, SupervisorDecision,
)

log = logging.getLogger("secgraph.llm")

# 不用 markdown 代码块的强约束（加到每个 prompt 前面）
_NO_MARKDOWN_PREFIX = (
    "重要：你的输出必须是纯 JSON，不要用 ```json 或任何 markdown 代码块包裹，不要有任何多余文本。\n\n"
)


def _add_no_markdown_prefix(prompt: str) -> str:
    """在 prompt 前面加强约束：不要用 markdown 代码块。"""
    return _NO_MARKDOWN_PREFIX + prompt


# 三个独立 LLM 实例 — 可配不同模型/密钥
_audit_llm_instance = None    # 漏洞发现
_trace_llm_instance = None   # 调用链分析
_verify_llm_instance = None  # 漏洞验证

# 结构化输出缓存（每个角色独立）
_audit_llm = None
_reach_llm = None
_explore_llm = None
_verify_llm = None
_retry_llm = None
_supervisor_llm = None


def _create_llm(role: str) -> ChatOpenAI:
    """按角色创建独立 LLM 实例。
    role: 'audit' | 'trace' | 'verify'
    优先读角色专用配置（AUDIT_LLM_*），没有则回退到通用配置（LLM_*）。
    """
    key = os.getenv(f"{role.upper()}_LLM_API_KEY") or os.getenv("LLM_API_KEY", "")
    base = os.getenv(f"{role.upper()}_LLM_BASE_URL") or os.getenv("LLM_BASE_URL", "")
    model = os.getenv(f"{role.upper()}_LLM_MODEL") or os.getenv("LLM_MODEL", "glm-5.1")

    llm = ChatOpenAI(
        model=model,
        api_key=key,
        base_url=base,
        temperature=0.3,
    )
    log.info("llm[%s]: model=%s base_url=%s", role, model, base)
    return llm


def _get_audit_llm_raw() -> ChatOpenAI:
    """漏洞发现用 LLM"""
    global _audit_llm_instance
    if _audit_llm_instance is None:
        _audit_llm_instance = _create_llm("audit")
    return _audit_llm_instance


def _get_trace_llm_raw() -> ChatOpenAI:
    """调用链分析用 LLM"""
    global _trace_llm_instance
    if _trace_llm_instance is None:
        _trace_llm_instance = _create_llm("trace")
    return _trace_llm_instance


def _get_verify_llm_raw() -> ChatOpenAI:
    """漏洞验证用 LLM"""
    global _verify_llm_instance
    if _verify_llm_instance is None:
        _verify_llm_instance = _create_llm("verify")
    return _verify_llm_instance


# 旧接口兼容（supervisor 用 verify LLM）
def _get_raw_llm() -> ChatOpenAI:
    """默认用 verify LLM（supervisor 路由决策用）"""
    return _get_verify_llm_raw()


def _strip_markdown_json(text: str) -> str:
    """剥掉 LLM 返回的 markdown 代码块包裹（```json ... ```）"""
    text = text.strip()
    # 去掉开头的 ```json 或 ```
    if text.startswith("```"):
        lines = text.split("\n")
        # 去掉第一行（```json 或 ```）
        lines = lines[1:]
        # 去掉最后的 ```
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    # 也处理前后多余文本
    match = re.search(r'\{[\s\S]*\}', text)
    if match:
        text = match.group(0)
    return text


def _call_structured(prompt: str, model_cls, cached_llm_attr: str,
                     raw_llm_getter=None):
    """通用结构化输出调用 — 带 fallback + 调试输出。

    1. 先试 with_structured_output(method="json_mode")（比默认 function_calling 更兼容）
    2. 失败 → 回退到 raw LLM + 剥 markdown + 手动 json 解析
    3. 都失败 → 打印 raw 返回内容方便调试 → raise

    raw_llm_getter: 指定用哪个 LLM 实例（_get_audit_llm_raw / _get_trace_llm_raw / _get_verify_llm_raw）
    """
    global _audit_llm, _reach_llm, _explore_llm, _verify_llm, _retry_llm, _supervisor_llm
    cached = {"_audit_llm": _audit_llm, "_reach_llm": _reach_llm,
              "_explore_llm": _explore_llm, "_verify_llm": _verify_llm,
              "_retry_llm": _retry_llm, "_supervisor_llm": _supervisor_llm}

    structured_llm = cached.get(cached_llm_attr)
    if structured_llm is None:
        llm = raw_llm_getter() if raw_llm_getter else _get_raw_llm()
        structured_llm = llm.with_structured_output(model_cls, method="json_mode")
        globals()[cached_llm_attr] = structured_llm

    # 尝试 1: with_structured_output (json_mode)
    try:
        result = structured_llm.invoke(_add_no_markdown_prefix(prompt))
        log.info("llm: 结构化输出成功 → %s", type(result).__name__)
        return result
    except Exception as e:
        log.warning("llm: 结构化输出失败 → %s，回退到 raw + 手动解析", str(e)[:200])

    # 尝试 2: raw LLM + 剥 markdown + 手动解析
    raw_text = ""
    clean_json = ""
    try:
        llm = raw_llm_getter() if raw_llm_getter else _get_raw_llm()
        raw_resp = llm.invoke(_add_no_markdown_prefix(prompt))
        raw_text = raw_resp.content if hasattr(raw_resp, "content") else str(raw_resp)

        # 完整打印 raw LLM 返回（log，不截断）
        log.info("llm: raw LLM 返回（完整 %d 字）:\n%s", len(raw_text), raw_text)

        clean_json = _strip_markdown_json(raw_text)
        log.info("llm: 剥 markdown 后 JSON（完整 %d 字）:\n%s", len(clean_json), clean_json)

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
# 各 LLM 入口 — 按角色使用不同 LLM 实例
# ---------------------------------------------------------------------------

def call_audit_llm(prompt: str) -> AuditResult:
    """漏洞发现 — 用 AUDIT_LLM_* 配置"""
    return _call_structured(prompt, AuditResult, "_audit_llm", _get_audit_llm_raw)


def call_reachability_llm(prompt: str) -> ReachabilityResult:
    """调用链分析 — 用 TRACE_LLM_* 配置"""
    return _call_structured(prompt, ReachabilityResult, "_reach_llm", _get_trace_llm_raw)


def call_exploration_llm(prompt: str) -> LoginExplorationResult:
    """登录探索 — 用 VERIFY_LLM_* 配置"""
    return _call_structured(prompt, LoginExplorationResult, "_explore_llm", _get_verify_llm_raw)


def call_verification_llm(prompt: str) -> PoCVerificationResult:
    """PoC 验证 — 用 VERIFY_LLM_* 配置"""
    return _call_structured(prompt, PoCVerificationResult, "_verify_llm", _get_verify_llm_raw)


def call_retry_llm(prompt: str) -> PayloadRetryResult:
    """payload 重构 — 用 TRACE_LLM_* 配置"""
    return _call_structured(prompt, PayloadRetryResult, "_retry_llm", _get_trace_llm_raw)


def call_supervisor_llm(prompt: str) -> SupervisorDecision:
    """Supervisor 路由 — 用 VERIFY_LLM_* 配置"""
    return _call_structured(prompt, SupervisorDecision, "_supervisor_llm", _get_verify_llm_raw)


def call_llm(prompt: str) -> str:
    """原始文本调用（备用）— 用 verify LLM"""
    return _get_verify_llm_raw().invoke(prompt).content
