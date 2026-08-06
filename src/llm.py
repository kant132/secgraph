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

import json
import logging
import os
import re

from langchain_openai import ChatOpenAI

from .state import (
    AuditResult, LoginExplorationResult, PoCVerificationResult,
    PayloadRetryResult, ReachabilityResult, SupervisorDecision,
)

log = logging.getLogger("secgraph.llm")

_raw_llm = None
_audit_llm = None
_reach_llm = None
_explore_llm = None
_verify_llm = None
_retry_llm = None
_supervisor_llm = None


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


def _call_structured(prompt: str, model_cls, cached_llm_attr: str):
    """通用结构化输出调用 — 带 fallback。

    1. 先试 with_structured_output（LangChain 标准方式）
    2. 失败 → 回退到 raw LLM + 剥 markdown + 手动 json 解析
    """
    # 获取或创建结构化 LLM
    global _audit_llm, _reach_llm, _explore_llm, _verify_llm, _retry_llm, _supervisor_llm
    cached = {"_audit_llm": _audit_llm, "_reach_llm": _reach_llm,
              "_explore_llm": _explore_llm, "_verify_llm": _verify_llm,
              "_retry_llm": _retry_llm, "_supervisor_llm": _supervisor_llm}

    structured_llm = cached.get(cached_llm_attr)
    if structured_llm is None:
        structured_llm = _get_raw_llm().with_structured_output(model_cls)
        # 缓存
        globals()[cached_llm_attr] = structured_llm

    # 尝试 1: with_structured_output
    try:
        return structured_llm.invoke(prompt)
    except Exception as e:
        log.warning("llm: 结构化输出失败 → %s，回退到 raw + 手动解析", str(e)[:100])

    # 尝试 2: raw LLM + 剥 markdown + 手动解析
    try:
        raw_resp = _get_raw_llm().invoke(prompt)
        raw_text = raw_resp.content if hasattr(raw_resp, "content") else str(raw_resp)
        clean_json = _strip_markdown_json(raw_text)
        data = json.loads(clean_json)
        return model_cls.model_validate(data)
    except Exception as e2:
        log.error("llm: raw fallback 也失败 → %s", str(e2)[:200])
        raise


# ---------------------------------------------------------------------------
# 各 LLM 入口
# ---------------------------------------------------------------------------

def get_audit_llm():
    return _get_raw_llm().with_structured_output(AuditResult)

def call_audit_llm(prompt: str) -> AuditResult:
    """结构化审计调用 — 返回 AuditResult（{nodeid: VulnDetail}）。"""
    return _call_structured(prompt, AuditResult, "_audit_llm")


def get_reachability_llm():
    return _get_raw_llm().with_structured_output(ReachabilityResult)

def call_reachability_llm(prompt: str) -> ReachabilityResult:
    """结构化可达性调用 — 返回 ReachabilityResult。"""
    return _call_structured(prompt, ReachabilityResult, "_reach_llm")


def get_exploration_llm():
    return _get_raw_llm().with_structured_output(LoginExplorationResult)

def call_exploration_llm(prompt: str) -> LoginExplorationResult:
    """结构化登录探索调用 — 返回 LoginExplorationResult。"""
    return _call_structured(prompt, LoginExplorationResult, "_explore_llm")


def get_verification_llm():
    return _get_raw_llm().with_structured_output(PoCVerificationResult)

def call_verification_llm(prompt: str) -> PoCVerificationResult:
    """结构化 PoC 验证调用 — 返回 PoCVerificationResult。"""
    return _call_structured(prompt, PoCVerificationResult, "_verify_llm")


def get_retry_llm():
    return _get_raw_llm().with_structured_output(PayloadRetryResult)

def call_retry_llm(prompt: str) -> PayloadRetryResult:
    """结构化 payload 重构调用 — 返回 PayloadRetryResult。"""
    return _call_structured(prompt, PayloadRetryResult, "_retry_llm")


def get_supervisor_llm():
    return _get_raw_llm().with_structured_output(SupervisorDecision)

def call_supervisor_llm(prompt: str) -> SupervisorDecision:
    """Supervisor 路由调用 — 返回 SupervisorDecision（next_agent + reasoning）。"""
    return _call_structured(prompt, SupervisorDecision, "_supervisor_llm")


def call_llm(prompt: str) -> str:
    """原始文本调用（备用）。"""
    return _get_raw_llm().invoke(prompt).content
