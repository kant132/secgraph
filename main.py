"""secgraph entry point — build the LangGraph, load config, invoke one run。

用法:
    py -3 main.py --project D:/jar/webgoat --group-id org.owasp.webgoat
    py -3 main.py --project D:/jar/webgoat --group-id org.owasp.webgoat --mode runtime

LLM 配置（GLM 5.1 via DashScope）在 .env（gitignored）:
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL
"""
from __future__ import annotations

import os
# 强制 UTF-8 I/O — 修复 Windows GBK 编码崩溃（通用修复，不针对特定字符）
os.environ["PYTHONUTF8"] = "1"
os.environ["PYTHONIOENCODING"] = "utf-8"

import argparse
import logging
import sys
import uuid
from pathlib import Path

# make `src` importable when run as `py -3 main.py` from the project root
sys.path.insert(0, str(Path(__file__).parent))

from src.config import Config  # noqa: E402
from src.graph import build_graph  # noqa: E402

log = logging.getLogger("secgraph.main")


def main() -> None:
    parser = argparse.ArgumentParser(description="secgraph — langraph Java security audit")
    parser.add_argument("--project", required=True,
                        help="target project path (e.g. D:/jar/webgoat)")
    parser.add_argument("--group-id", required=True,
                        help="business package prefix (e.g. org.owasp.webgoat)")
    parser.add_argument("--mode", default="dev", choices=["dev", "runtime"],
                        help="dev=10 files+debug logs, runtime=full sweep")
    args = parser.parse_args()

    cfg = Config.from_args(project_path=args.project, group_id=args.group_id, mode=args.mode)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)-18s %(levelname)s %(message)s",
    )
    # 压掉第三方库的 DEBUG 噪声
    for name in ("openai", "httpx", "httpcore", "langchain_openai", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)

    run_id = uuid.uuid4().hex[:8]
    log.info("START  run_id=%s  mode=%s  project=%s  group_id=%s  pkg_prefix=%s  file_limit=%s",
             run_id, cfg.mode, cfg.project_path, cfg.group_id, cfg.pkg_prefix, cfg.file_limit)
    log.info("       codegraph_db=%s  llm_model=%s", cfg.codegraph_db, cfg.llm_model)

    # seed the FindingsDB run row
    from src.db import FindingsDB
    with FindingsDB(cfg.findings_db) as db:
        db.start_run(run_id, cfg.mode, cfg.pkg_prefix, cfg.file_limit, iteration=0)

    initial_state = {
        **cfg.to_state(),
        "run_id": run_id,
        "audit_index": 0,
        "iteration": 0,
        "findings": [],
        "verified": [],
        "reflection_notes": [],
    }

    app = build_graph()
    final = app.invoke(initial_state)

    log.info("END    run_id=%s  files_audited=%d  findings=%d  verified=%d  iterations=%d",
             run_id,
             final.get("audit_index", 0),
             len(final.get("findings", [])),
             len(final.get("verified", [])),
             final.get("iteration", 0))


if __name__ == "__main__":
    main()
