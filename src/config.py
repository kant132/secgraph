"""Runtime configuration — parameterized by project_path + group_id.

dev mode:  file_limit=10, verbose logging
runtime:   file_limit=None, normal logging, full sweep

Usage:
    cfg = Config.from_args(project_path="D:/jar/webgoat", group_id="org.owasp.webgoat")
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# load .env from secgraph project root (gitignored — contains LLM API key)
load_dotenv(Path(__file__).parent.parent / ".env")


@dataclass
class Config:
    # required — passed via CLI
    project_path: str          # target project to audit, e.g. D:\jar\webgoat
    group_id: str              # business package prefix, e.g. org.owasp.webgoat

    # options
    mode: str = "dev"          # dev | runtime

    # secgraph's own paths (not the target project's)
    findings_db: str = ""
    findings_dir: str = ""
    logs_dir: str = ""

    # LLM config (from .env)
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = "glm-5.1"

    max_iterations: int = 3

    def __post_init__(self) -> None:
        base = Path(__file__).parent.parent  # D:\secgraph
        if not self.findings_db:
            self.findings_db = str(base / "secgraph.db")
        if not self.findings_dir:
            self.findings_dir = str(base / "findings")
        if not self.logs_dir:
            self.logs_dir = str(base / "logs")
        # LLM config from .env (only if not explicitly passed)
        if not self.llm_api_key:
            self.llm_api_key = os.getenv("LLM_API_KEY", "")
        if not self.llm_base_url:
            self.llm_base_url = os.getenv("LLM_BASE_URL", "")
        if not self.llm_model or self.llm_model == "glm-5.1":
            self.llm_model = os.getenv("LLM_MODEL", "glm-5.1")
        self.ensure_dirs()

    @property
    def codegraph_db(self) -> str:
        return str(Path(self.project_path) / ".codegraph" / "codegraph.db")

    @property
    def sources_root(self) -> str:
        """codegraph index root — file_path in nodes starts with 'sources/'"""
        return self.project_path

    @property
    def pkg_prefix(self) -> str:
        """org.owasp.webgoat → org/owasp/webgoat"""
        return self.group_id.replace(".", "/")

    @property
    def file_limit(self) -> int | None:
        return 10 if self.mode == "dev" else None

    @classmethod
    def from_args(cls, project_path: str, group_id: str, mode: str = "dev") -> "Config":
        return cls(
            project_path=project_path,
            group_id=group_id,
            mode=os.getenv("SECGRAPH_MODE", mode),
            max_iterations=int(os.getenv("SECGRAPH_MAX_ITER", "3")),
        )

    def to_state(self) -> dict:
        return {
            "mode": self.mode,
            "codegraph_db": self.codegraph_db,
            "sources_root": self.sources_root,
            "pkg_prefix": self.pkg_prefix,
            "findings_db": self.findings_db,
            "findings_dir": self.findings_dir,
            "logs_dir": self.logs_dir,
            "file_limit": self.file_limit,
            "llm_model": self.llm_model,
            "max_iterations": self.max_iterations,
        }

    def ensure_dirs(self) -> None:
        for d in (self.findings_dir, self.logs_dir):
            Path(d).mkdir(parents=True, exist_ok=True)
