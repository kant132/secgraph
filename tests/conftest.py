"""pytest conftest — 自动标记测试用例 tier。

规则：
- 文件名 test_e2e.py → @pytest.mark.e2e（真实 LLM，大改动才跑）
- 其他 test_*.py → @pytest.mark.unit（默认）或 @pytest.mark.integration（带 DB）
- 类/函数已有显式 mark 的不覆盖

手动标记优先级高于自动推断。
"""
import pytest


def pytest_collection_modifyitems(items):
    """根据文件名自动打 marker，避免每个文件都写 @pytest.mark.unit。"""
    for item in items:
        # 已有显式 mark 的跳过自动推断
        if any(m.name in ("unit", "integration", "e2e") for m in item.iter_markers()):
            continue

        # 文件名包含 e2e → e2e
        if "e2e" in item.nodeid.lower():
            item.add_marker(pytest.mark.e2e)
        # test_refactor_regressions 需要 DB → integration
        elif "refactor_regressions" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        # test_codegraph_tools 检查 SQL 语法 → unit（不连真实 DB）
        elif "codegraph_tools" in item.nodeid:
            item.add_marker(pytest.mark.unit)
        else:
            # 默认 unit
            item.add_marker(pytest.mark.unit)