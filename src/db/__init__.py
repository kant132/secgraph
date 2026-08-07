"""DB 层入口 — ORM 模型导出 + session 工厂。

用法
----
    from src.db import get_session, Run, FindingORM, VerifiedVuln, AuditMemory

    with get_session(codegraph_db) as session:
        session.add(Run(id=run_id, mode="dev", ...))
        session.commit()

session 生命周期
----------------
`get_session(db_path)` 返回的 Session 用 `with` 上下文管理：
- 进入时创建 engine（首次调用时建，按 db_path 缓存）
- 退出时 close（不销毁 engine，下次同 db_path 复用）
- 异常时自动 rollback

engine 缓存
-----------
同 db_path 的 engine 进程级缓存（`_ENGINES: dict[str, Engine]`）。
SQLite engine 默认连接池大小 5，足够单进程用。多线程并发写需要 `check_same_thread=False`
（已在 connect_args 设置）。
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .models import AuditMemory, Base, ChainResultORM, FindingORM, Run, VerifiedVuln

log = logging.getLogger("secgraph.db")

# 进程级 engine 缓存：{db_path: Engine}。SQLite 文件锁是库级的，同 db_path 复用一个 engine。
_ENGINES: dict[str, sessionmaker] = {}


def _get_sessionmaker(db_path: str) -> sessionmaker:
    """取（或创建）db_path 对应的 sessionmaker。按 db_path 进程级缓存。"""
    if db_path not in _ENGINES:
        # SQLite engine 配置：
        # - check_same_thread=False：允许跨线程用（CodegraphClient 裸连接是同进程不同上下文）
        # - future=True：SQLAlchemy 2.0 风格
        engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            future=True,
        )
        _ENGINES[db_path] = sessionmaker(bind=engine, expire_on_commit=False, future=True)
        log.info("db: engine 已建 → %s", db_path)
    return _ENGINES[db_path]


@contextmanager
def get_session(db_path: str) -> Iterator[Session]:
    """取一个 ORM session（with 上下文）。

    用法：
        with get_session(codegraph_db) as session:
            session.add(Run(...))
            session.commit()

    异常自动 rollback，退出自动 close。engine 不销毁（下次同 db_path 复用）。
    """
    session = _get_sessionmaker(db_path)()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_business_tables(db_path: str) -> None:
    """建全部业务表（runs/findings/verified_vulns/audit_memory）。

    等价于原 `executescript(_SCHEMA_DDL)` + `init_memory_table()`。
    用 ORM 的 `Base.metadata.create_all(engine)` 一次性建全部 4 张表 + 索引。
    IF NOT EXISTS 语义（表已存在不报错）。
    """
    from sqlalchemy import create_engine
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False}, future=True)
    Base.metadata.create_all(engine)
    engine.dispose()
    log.info("db: 业务表已建（runs/findings/verified_vulns/audit_memory）→ %s", db_path)


__all__ = [
    "Base", "Run", "FindingORM", "VerifiedVuln", "AuditMemory", "ChainResultORM",
    "get_session", "init_business_tables",
]