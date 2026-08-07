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
from datetime import datetime
from pathlib import Path

# make `src` importable when run as `py -3 main.py` from the project root
sys.path.insert(0, str(Path(__file__).parent))

from src.config import Config  # noqa: E402
from src.graph import build_graph  # noqa: E402

log = logging.getLogger("secgraph.main")


def main() -> None:
    parser = argparse.ArgumentParser(description="secgraph — langgraph Java security audit")
    parser.add_argument("--project", required=True,
                        help="target project path (e.g. D:/jar/webgoat)")
    parser.add_argument("--group-id", required=True,
                        help="business package prefix (e.g. org.owasp.webgoat)")
    parser.add_argument("--mode", default="dev", choices=["dev", "runtime"],
                        help="dev=20 files+debug logs, runtime=full sweep")
    args = parser.parse_args()

    cfg = Config.from_args(project_path=args.project, group_id=args.group_id, mode=args.mode)
    run_id = uuid.uuid4().hex[:8]

    # 日志：控制台只打 INFO 级别关键流程（简洁），文件打 DEBUG 级别全量（LLM prompt/response + SQL 等）
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = Path(cfg.logs_dir) / f"run_{timestamp}.log"

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter("%(asctime)s %(name)-18s %(levelname)s %(message)s"))

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter("%(asctime)s %(name)-18s %(levelname)s %(message)s"))

    logging.basicConfig(level=logging.DEBUG, handlers=[console_handler, file_handler])
    # 压掉第三方库的 DEBUG 噪声
    for name in ("openai", "httpx", "httpcore", "langchain_openai", "urllib3", "sqlalchemy"):
        logging.getLogger(name).setLevel(logging.WARNING)

    log.info("START  run_id=%s  mode=%s  project=%s  group_id=%s  pkg_prefix=%s  file_limit=%s",
             run_id, cfg.mode, cfg.project_path, cfg.group_id, cfg.pkg_prefix, cfg.file_limit)
    log.info("       codegraph_db=%s  llm_model=%s  log_file=%s", cfg.codegraph_db, cfg.llm_model, log_file)

    # 项目初始化：建 route_reachable 表（只执行一次，后续 CodegraphClient 复用）
    from src.codegraph import CodegraphClient
    with CodegraphClient(cfg.codegraph_db) as cg:
        # init_business_tables 建 runs/findings/verified_vulns/audit_memory 表
        from src.db import init_business_tables
        init_business_tables(cfg.codegraph_db)
    log.info("INIT   codegraph + 业务表初始化完成")

    initial_state = {
        **cfg.to_state(),
        "run_id": run_id,
        "audit_index": 0,
        "iteration": 0,
        "findings": [],
        "verified": [],
        "reflection_notes": [],
        "agent_history": [],
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