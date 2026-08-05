"""LangGraph state schema + per-node data contracts.

Maps the 4 codegraph SQL queries (Q1-Q4) into typed structures that flow
through the pipeline: discover -> file_loop -> audit -> verify -> record
                                                        -> reflect (loop back)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Literal, Required, TypedDict

from pydantic import BaseModel, Field, RootModel


# ---------------------------------------------------------------------------
# codegraph query result rows  (one row = one record from nodes/edges tables)
# ---------------------------------------------------------------------------

@dataclass
class MethodNode:
    """Q1 row — a public method with non-empty signature (business-code entry point)."""
    id: str
    qualified_name: str
    name: str
    signature: str
    file_path: str
    start_line: int
    end_line: int


@dataclass
class FieldNode:
    """Q3 row — a field in the audited file (data-flow source / state context)."""
    id: str
    qualified_name: str
    name: str
    start_line: int
    end_line: int


@dataclass
class CallEdge:
    """Q2 row — one caller->callee edge. Multi-row per file: aggregate, don't take one."""
    caller_qualified: str
    caller_name: str
    caller_line: int
    callee_qualified: str
    callee_name: str
    callee_file: str
    callee_line: int
    edge_kind: str


# ---------------------------------------------------------------------------
# pipeline work item + finding
# ---------------------------------------------------------------------------

@dataclass
class FileAuditTask:
    """Per-file audit unit. Filled by discover() from Q1-Q4, consumed by audit_file()."""
    file_path: str
    fields: list[FieldNode]                                  # Q3 scoped to this file
    method_bodies: dict[str, str] = field(default_factory=dict)   # {nodeid: "// fqn\nbody"} — Q1
    calls: dict[str, str] = field(default_factory=dict)          # {callee_nodeid: "// fqn\nbody"} — Q4


@dataclass
class Finding:
    """One suspected vulnerability. status: pending -> verified | false_positive."""
    file_path: str
    node_id: str                       # codegraph nodeid of the method/callee (the JSON key)
    vuln_type: str                     # SQLi / SSRF / deser / path-traversal / ... / unknown
    severity: str                      # critical / high / medium / low / unknown
    evidence: str                      # line refs + taint/logic + sanitization + reachability
    payload: str                       # PoC payload from static analysis, "" if none
    confidence: float                  # 0.0-1.0
    status: str = "pending"            # pending / verified / false_positive
    poc: str | None = None             # executed PoC command (verify phase)
    poc_result: str | None = None      # confirmed / denied / inconclusive
    poc_output: str | None = None


# ---------------------------------------------------------------------------
# LLM structured output schema (Pydantic) — used by langchain with_structured_output
# ---------------------------------------------------------------------------

class VulnDetail(BaseModel):
    """每条漏洞的结构化输出（一个 nodeid 对应一个 VulnDetail）。"""
    vuln_type: str = Field(description="漏洞类型: SQLi|SSRF|deser|path-traversal|XXE|expression-injection|RCE|XSS|JNDI|LDAP-injection|XPath-injection|unknown")
    severity: str = Field(description="严重等级: critical|high|medium|low|unknown")
    evidence: str = Field(description="行号 + 漏洞根因（污点或逻辑哪里有问题）+ 有没有消毒 + 构造漏洞参数或逻辑需要满足的可达条件")
    payload: str = Field(default="", description="攻击载荷，没有为空")
    confidence: float = Field(description="置信度 0.1-1")


class AuditResult(RootModel[Dict[str, VulnDetail]]):
    """LLM 结构化输出整体：{nodeid: VulnDetail}。
    用 RootModel 确保序列化成正确的 JSON Schema（Dict[str,X] 直接传会被当成普通 dict）。"""
    pass


class ReachabilityResult(BaseModel):
    """路由可达性分析结果（AI 判断漏洞是否能从 HTTP 路由到达）。"""
    reachable: bool = Field(description="漏洞是否可从 HTTP 路由到达")
    updated_payload: str = Field(default="", description="更新后的 payload（包含完整 HTTP 请求）")
    conditions: str = Field(description="触发条件：需要什么参数/认证/路径才能到达漏洞")
    confidence: float = Field(description="更新后的置信度 0.1-1")


# ---------------------------------------------------------------------------
# LangGraph state  (TypedDict — passed between nodes, merged by the graph)
# ---------------------------------------------------------------------------

class AuditState(TypedDict, total=False):
    # required config slice — set at START before any node runs
    mode: Required[Literal["dev", "runtime"]]
    codegraph_db: Required[str]
    sources_root: Required[str]
    pkg_prefix: Required[str]
    findings_db: Required[str]
    findings_dir: Required[str]
    logs_dir: Required[str]
    file_limit: Required[int | None]   # dev=10, runtime=None
    run_id: Required[str]
    max_iterations: Required[int]       # self-reflection loop cap
    llm_model: Required[str]

    # accumulated (optional — nodes return partial updates; no reducers,
    # each node reads state.get(...) and returns the full merged list)
    work_list: list[FileAuditTask]
    audit_index: int                   # pointer into work_list for the file loop
    findings: list[Finding]             # all suspected findings -> DB
    verified: list[Finding]            # verified vulns -> .md
    reflection_notes: list[str]
    iteration: int
