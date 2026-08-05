"""verify 子模块 — 拆分为 _login / _payload / _agent + node.py 编排。
"""
from .node import verify_finding

__all__ = ["verify_finding"]
