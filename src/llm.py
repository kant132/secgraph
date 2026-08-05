"""LLM 抽象 — LangChain ChatOpenAI + 结构化输出。

通过 DashScope 调 GLM 5.1（OpenAI 兼容）。配置在 .env：
  LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

三个入口：
  - call_audit_llm(prompt) -> AuditResult         （审计，结构化输出）
  - call_reachability_llm(prompt) -> ReachabilityResult  （路由可达性分析）
  - call_llm(prompt) -> str                       （原始文本）
"""
from __future__ import annotations

import logging
import os

from langchain_openai import ChatOpenAI

from .state import AuditResult, LoginExplorationResult, PoCVerificationResult, PayloadRetryResult, ReachabilityResult

log = logging.getLogger("secgraph.llm")

_raw_llm = None       # 缓存：ChatOpenAI（无结构化输出）
_audit_llm = None     # 缓存：with_structured_output(AuditResult)
_reach_llm = None     # 缓存：with_structured_output(ReachabilityResult)
_explore_llm = None   # 缓存：with_structured_output(LoginExplorationResult)
_verify_llm = None    # 缓存：with_structured_output(PoCVerificationResult)
_retry_llm = None     # 缓存：with_structured_output(PayloadRetryResult)


def _get_raw_llm() -> ChatOpenAI:
    global _raw_llm
    if _raw_llm is None:
        _raw_llm = ChatOpenAI(
            model=os.getenv("LLM_MODEL", "glm-5.1"),
            api_key=os.getenv("LLM_API_KEY", ""),
            base_url=os.getenv("LLM_BASE_URL", ""),
            temperature=0.1,
        )
        log.info("llm: model=%s base_url=%s", os.getenv("LLM_MODEL"), os.getenv("LLM_BASE_URL"))
    return _raw_llm


def get_audit_llm():
    """返回缓存的结构化审计 LLM（绑定 AuditResult schema）。"""
    global _audit_llm
    if _audit_llm is None:
        _audit_llm = _get_raw_llm().with_structured_output(AuditResult)
    return _audit_llm


def get_reachability_llm():
    """返回缓存的结构化可达性 LLM（绑定 ReachabilityResult schema）。"""
    global _reach_llm
    if _reach_llm is None:
        _reach_llm = _get_raw_llm().with_structured_output(ReachabilityResult)
    return _reach_llm


def call_audit_llm(prompt: str) -> AuditResult:
    """结构化审计调用 — 返回 AuditResult（{nodeid: VulnDetail}）。"""
    return get_audit_llm().invoke(prompt)


def call_reachability_llm(prompt: str) -> ReachabilityResult:
    """结构化可达性调用 — 返回 ReachabilityResult。"""
    return get_reachability_llm().invoke(prompt)


def get_exploration_llm():
    """返回缓存的结构化登录探索 LLM（绑定 LoginExplorationResult schema）。"""
    global _explore_llm
    if _explore_llm is None:
        _explore_llm = _get_raw_llm().with_structured_output(LoginExplorationResult)
    return _explore_llm


def call_exploration_llm(prompt: str) -> LoginExplorationResult:
    """结构化登录探索调用 — 返回 LoginExplorationResult。"""
    return get_exploration_llm().invoke(prompt)


def get_verification_llm():
    """返回缓存的结构化 PoC 验证 LLM（绑定 PoCVerificationResult schema）。"""
    global _verify_llm
    if _verify_llm is None:
        _verify_llm = _get_raw_llm().with_structured_output(PoCVerificationResult)
    return _verify_llm


def call_verification_llm(prompt: str) -> PoCVerificationResult:
    """结构化 PoC 验证调用 — 返回 PoCVerificationResult。"""
    return get_verification_llm().invoke(prompt)


def get_retry_llm():
    """返回缓存的结构化 payload 重构 LLM（绑定 PayloadRetryResult schema）。"""
    global _retry_llm
    if _retry_llm is None:
        _retry_llm = _get_raw_llm().with_structured_output(PayloadRetryResult)
    return _retry_llm


def call_retry_llm(prompt: str) -> PayloadRetryResult:
    """结构化 payload 重构调用 — 返回 PayloadRetryResult。"""
    return get_retry_llm().invoke(prompt)


def call_llm(prompt: str) -> str:
    """原始文本调用（备用）。"""
    return _get_raw_llm().invoke(prompt).content
