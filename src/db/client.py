"""SQLAlchemy ORM client for secgraph's findings DB.

Tables are auto-created from the ORM models (no raw SQL needed).
The codegraph.db is read via raw sqlite3 in codegraph/client.py — that's an
external read-only index, not our own DB.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from sqlalchemy import Column, Integer, REAL, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from ..state import Finding

Base = declarative_base()


class RunORM(Base):
    __tablename__ = "runs"
    id = Column(String, primary_key=True)
    mode = Column(String, nullable=False)
    pkg_prefix = Column(String, nullable=False)
    file_limit = Column(Integer)
    files_audited = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    total_verified = Column(Integer, default=0)
    iteration = Column(Integer, default=0)
    started_at = Column(Text, default=lambda: datetime.now().isoformat())
    finished_at = Column(Text)


class FindingORM(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String, nullable=False)
    file_path = Column(Text, nullable=False)
    node_id = Column(Text, nullable=False)
    vuln_type = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    payload = Column(Text, default="")
    confidence = Column(REAL, nullable=False)
    status = Column(Text, default="pending")
    created_at = Column(Text, default=lambda: datetime.now().isoformat())


class VerifiedVulnORM(Base):
    __tablename__ = "verified_vulns"
    finding_id = Column(Integer, primary_key=True)
    run_id = Column(String, nullable=False)
    file_path = Column(Text, nullable=False)
    node_id = Column(Text, nullable=False)
    vuln_type = Column(Text, nullable=False)
    severity = Column(Text, nullable=False)
    evidence = Column(Text, nullable=False)
    payload = Column(Text, default="")
    poc = Column(Text, nullable=False)
    poc_result = Column(Text, nullable=False)
    poc_output = Column(Text)
    md_path = Column(Text)
    verified_at = Column(Text, default=lambda: datetime.now().isoformat())


class FindingsDB:
    """Open (or create) the findings DB via SQLAlchemy ORM. Same interface
    as the old sqlite3 version — record.py needs no changes."""

    def __init__(self, db_path: str) -> None:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(self._engine)
        self._Session = sessionmaker(self._engine, expire_on_commit=False)

    # ---- run lifecycle ----------------------------------------------------

    def start_run(self, run_id: str, mode: str, pkg_prefix: str,
                  file_limit: int | None, iteration: int) -> None:
        with self._Session() as session:
            session.add(RunORM(id=run_id, mode=mode, pkg_prefix=pkg_prefix,
                               file_limit=file_limit, iteration=iteration))
            session.commit()

    def finish_run(self, run_id: str, files_audited: int,
                   total_findings: int, total_verified: int) -> None:
        with self._Session() as session:
            run = session.get(RunORM, run_id)
            if run:
                run.finished_at = datetime.now().isoformat()
                run.files_audited = files_audited
                run.total_findings = total_findings
                run.total_verified = total_verified
                session.commit()

    # ---- findings --------------------------------------------------------

    def insert_finding(self, run_id: str, f: Finding) -> int:
        with self._Session() as session:
            orm = FindingORM(
                run_id=run_id, file_path=f.file_path, node_id=f.node_id,
                vuln_type=f.vuln_type, severity=f.severity,
                evidence=f.evidence, payload=f.payload,
                confidence=f.confidence, status=f.status,
            )
            session.add(orm)
            session.commit()
            return orm.id

    def mark_verified(self, finding_id: int, run_id: str, f: Finding,
                      md_path: str) -> None:
        with self._Session() as session:
            session.add(VerifiedVulnORM(
                finding_id=finding_id, run_id=run_id, file_path=f.file_path,
                node_id=f.node_id, vuln_type=f.vuln_type, severity=f.severity,
                evidence=f.evidence, payload=f.payload,
                poc=f.poc or "", poc_result=f.poc_result or "inconclusive",
                poc_output=f.poc_output or "", md_path=md_path,
            ))
            finding = session.get(FindingORM, finding_id)
            if finding:
                finding.status = "verified"
            session.commit()

    def mark_false_positive(self, finding_id: int) -> None:
        with self._Session() as session:
            finding = session.get(FindingORM, finding_id)
            if finding:
                finding.status = "false_positive"
                session.commit()

    def pending_findings(self, run_id: str) -> list:
        with self._Session() as session:
            return session.query(FindingORM).filter(
                FindingORM.run_id == run_id,
                FindingORM.status == "pending",
            ).all()

    # ---- lifecycle -------------------------------------------------------

    def close(self) -> None:
        self._engine.dispose()

    def __enter__(self) -> "FindingsDB":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
