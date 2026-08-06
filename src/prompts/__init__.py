"""Prompt 模板加载与渲染 — 缓存 + 统一接口。

用法：
    from src.prompts import render
    prompt = render("audit", fields=..., methods=..., calls=...)
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

_TEMPLATE_DIR = Path(__file__).resolve().parent


@lru_cache(maxsize=None)
def load(name: str) -> str:
    """读 {name}_template.md 的全文（进程级缓存）。"""
    path = _TEMPLATE_DIR / f"{name}_template.md"
    return path.read_text(encoding="utf-8")


def render(name: str, /, **vars: str) -> str:
    """读模板并用 str.replace 填充 {key} 占位符。

    不用 str.format：模板里常有 JSON 示例含字面 {}，format 会爆炸。
    """
    tmpl = load(name)
    for key, value in vars.items():
        tmpl = tmpl.replace("{" + key + "}", str(value))
    return tmpl