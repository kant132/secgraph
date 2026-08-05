"""测试入口 — 运行所有测试。

用法：
    py -3 -m pytest tests/ -v
    或
    py -3 tests/run.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
