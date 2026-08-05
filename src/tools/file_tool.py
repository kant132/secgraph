"""文件读写工具 — 封装文件读写操作，打印每次调用。

用法：
    tool = FileTool()
    content = tool.read("D:/path/file.txt")
    tool.write("D:/path/out.txt", "content")
    tool.append("D:/path/log.txt", "new line")
    tool.read_json("D:/path/data.json")
    tool.write_json("D:/path/out.json", {"key": "value"})
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger("secgraph.file")


class FileTool:
    """文件读写工具，每次调用都打印操作详情。"""

    @staticmethod
    def read(file_path: str, encoding: str = "utf-8") -> str | None:
        """读文件，返回内容。文件不存在返回 None。"""
        p = Path(file_path)
        print(f"\n[工具调用] read()")
        print(f"  path: {file_path}")
        if not p.exists():
            print(f"  → 文件不存在")
            log.warning("file: read → %s 不存在", file_path)
            return None
        text = p.read_text(encoding=encoding)
        print(f"  → 读取 {len(text)} 字符")
        log.info("file: read → %s (%d chars)", file_path, len(text))
        return text

    @staticmethod
    def read_bytes(file_path: str) -> bytes | None:
        """读二进制文件。"""
        p = Path(file_path)
        print(f"\n[工具调用] read_bytes()")
        print(f"  path: {file_path}")
        if not p.exists():
            print(f"  → 文件不存在")
            return None
        data = p.read_bytes()
        print(f"  → 读取 {len(data)} bytes")
        log.info("file: read_bytes → %s (%d bytes)", file_path, len(data))
        return data

    @staticmethod
    def write(file_path: str, content: str, encoding: str = "utf-8") -> bool:
        """写文件（覆盖），自动创建父目录。"""
        p = Path(file_path)
        print(f"\n[工具调用] write()")
        print(f"  path: {file_path}")
        print(f"  size: {len(content)} 字符")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding=encoding)
        print(f"  → 写入成功")
        log.info("file: write → %s (%d chars)", file_path, len(content))
        return True

    @staticmethod
    def append(file_path: str, content: str, encoding: str = "utf-8") -> bool:
        """追加写文件，自动创建父目录。"""
        p = Path(file_path)
        print(f"\n[工具调用] append()")
        print(f"  path: {file_path}")
        print(f"  size: +{len(content)} 字符")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding=encoding) as f:
            f.write(content)
        print(f"  → 追加成功")
        log.info("file: append → %s (+%d chars)", file_path, len(content))
        return True

    @staticmethod
    def read_json(file_path: str) -> dict | list | None:
        """读 JSON 文件，返回 dict/list。"""
        text = FileTool.read(file_path)
        if text is None:
            return None
        try:
            data = json.loads(text)
            print(f"  → JSON 解析成功 ({len(data) if hasattr(data, '__len__') else '?'} 项)")
            return data
        except json.JSONDecodeError as e:
            print(f"  → JSON 解析失败: {e}")
            log.warning("file: read_json → %s 解析失败: %s", file_path, e)
            return None

    @staticmethod
    def write_json(file_path: str, data: dict | list, indent: int = 2) -> bool:
        """写 JSON 文件，自动创建父目录。"""
        content = json.dumps(data, indent=indent, ensure_ascii=False)
        return FileTool.write(file_path, content)

    @staticmethod
    def exists(file_path: str) -> bool:
        """检查文件是否存在。"""
        p = Path(file_path)
        exists = p.exists()
        print(f"\n[工具调用] exists()")
        print(f"  path: {file_path}")
        print(f"  → {exists}")
        return exists

    @staticmethod
    def list_dir(dir_path: str, pattern: str = "*") -> list[str]:
        """列目录，返回文件名列表。"""
        p = Path(dir_path)
        print(f"\n[工具调用] list_dir()")
        print(f"  dir: {dir_path}")
        print(f"  pattern: {pattern}")
        if not p.exists():
            print(f"  → 目录不存在")
            return []
        items = sorted(f.name for f in p.glob(pattern) if f.is_file())
        print(f"  → {len(items)} 个文件")
        for name in items[:10]:
            print(f"    {name}")
        if len(items) > 10:
            print(f"    ... 共 {len(items)} 个")
        log.info("file: list_dir → %s (%d files)", dir_path, len(items))
        return items
