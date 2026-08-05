"""codegraph explore 工具 — 调用 codegraph CLI 进行语义探索。

返回完整的调用链 + 源码 + 关系图 + blast radius，
比 CodegraphClient 的 SQL 查询丰富得多。
"""
from __future__ import annotations

import logging
import shutil
import subprocess

log = logging.getLogger("secgraph.explore")


def codegraph_explore(query: str, project_path: str, timeout: int = 60) -> str:
    """调用 codegraph explore CLI，返回探索结果。

    返回内容：
    - 调用链（call path among symbols）
    - 源码（verbatim, line-numbered）
    - blast radius（谁依赖这些符号）
    - 关系图（calls/references/decorates/implements/imports）
    """
    # 找 codegraph CLI
    cmd = shutil.which("codegraph") or "codegraph"
    print(f"\n[工具调用] codegraph_explore()")
    print(f"  query: {query}")
    print(f"  project: {project_path}")

    try:
        result = subprocess.run(
            [cmd, "explore", query, "--path", project_path],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        output = result.stdout
        if not output:
            output = result.stderr or "[empty output]"
        print(f"  → 返回 {len(output)} 字符")
        # 打印前 800 字预览（Windows GBK 兼容）
        preview = output[:800]
        try:
            print(f"  预览:\n{preview}")
        except UnicodeEncodeError:
            print(f"  预览:\n{preview.encode('ascii', errors='replace').decode('ascii')}")
        log.info("explore: %s → %d chars", query[:50], len(output))
        return output
    except subprocess.TimeoutExpired:
        msg = f"[timeout] codegraph explore 超时 ({timeout}s)"
        print(f"  → {msg}")
        log.warning("explore: 超时")
        return msg
    except Exception as e:
        # GBK 兼容：异常消息也可能含 Unicode
        safe_e = str(e).encode('ascii', errors='replace').decode('ascii')
        msg = f"[error] codegraph explore 失败: {safe_e}"
        print(f"  → {msg}")
        log.warning("explore: %s", safe_e)
        return msg
