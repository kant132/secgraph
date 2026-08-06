"""工具注册器 — 运行时动态注册工具给 AI agent。

用法：
    registry = ToolRegistry()
    registry.add("explore_code", "探索代码库...", explore_code_func)
    registry.add("send_http", "发送HTTP请求...", send_http_func)
    # 运行时可以继续加
    registry.add("custom_tool", "自定义工具...", custom_func)
    tools = registry.build()
"""
from __future__ import annotations

import logging
from typing import Callable

log = logging.getLogger("secgraph.tool_registry")


class ToolRegistry:
    """运行时工具注册器 — 动态添加/移除工具。"""

    def __init__(self) -> None:
        self._tools: list = []
        self._names: set[str] = set()

    def add(self, name: str, description: str, func: Callable, **arg_descriptions) -> None:
        """注册一个工具。
        name: 工具名（AI 看到的函数名）
        description: 工具说明（AI 看到的描述）
        func: 实际执行的函数
        arg_descriptions: 参数说明（如 query="符号名或类名", timeout="超时秒数"）
        """
        from langchain_core.tools import tool as tool_decorator
        from functools import wraps

        # 构建 docstring（AI 看到的说明）
        params = "\n".join(f"  {k}: {v}" for k, v in arg_descriptions.items())
        docstring = f"{description}\n\n参数:\n{params}" if params else description

        # 用 @tool 装饰器包装
        @tool_decorator(name, description=docstring)
        @wraps(func)
        def wrapper(**kwargs):
            return func(**kwargs)

        if name in self._names:
            log.warning("tool_registry: 工具 %s 已存在，替换", name)
            self._tools = [t for t in self._tools if t.name != name]
        else:
            self._names.add(name)

        self._tools.append(wrapper)
        log.info("tool_registry: 注册工具 %s（共 %d 个）", name, len(self._tools))

    def remove(self, name: str) -> bool:
        """移除一个工具。"""
        before = len(self._tools)
        self._tools = [t for t in self._tools if t.name != name]
        self._names.discard(name)
        removed = len(self._tools) < before
        if removed:
            log.info("tool_registry: 移除工具 %s", name)
        return removed

    def build(self) -> list:
        """返回当前所有工具列表（传给 create_react_agent）。"""
        return list(self._tools)

    def names(self) -> list[str]:
        """返回所有工具名。"""
        return sorted(self._names)

    def count(self) -> int:
        """工具数量。"""
        return len(self._tools)
