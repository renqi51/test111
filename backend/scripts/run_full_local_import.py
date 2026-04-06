"""
全量 KG 入库：data/input 下所有支持的文件 → Neo4j（与 POST /api/builder/run-local-import 等价逻辑）。

在终端前台输出带时间戳的 INFO 日志（含 [KG] 进度）。建议在 backend 目录执行：

  set PYTHONUNBUFFERED=1
  python scripts/run_full_local_import.py

可选：--dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not root.handlers:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )
    for h in root.handlers:
        h.setLevel(logging.INFO)
    logging.getLogger("app").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true", help="只抽取，不写 Neo4j")
    return p.parse_args()


async def _run(*, dry_run: bool) -> int:
    _setup_logging()
    log = logging.getLogger("scripts.run_full_local_import")

    from app.core.config import settings
    from app.services.kg_builder_service import get_kg_builder_service
    from app.utils.file_parser import supported_input_suffixes

    log.info(
        "=== FULL LOCAL IMPORT START dry_run=%s input_dir=%s suffixes=%s llm_enabled=%s ===",
        dry_run,
        settings.kg_input_dir,
        sorted(supported_input_suffixes()),
        settings.llm_enabled,
    )
    if not settings.llm_enabled:
        log.error("LLM 未配置（llm_enabled=false），无法入库。请检查 .env 中 EXPOSURE_LLM_*")
        return 2

    result = await get_kg_builder_service().build_graph_from_input(dry_run=dry_run)
    log.info("=== FULL LOCAL IMPORT END ===")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def main() -> None:
    args = _parse_args()
    raise SystemExit(asyncio.run(_run(dry_run=args.dry_run)))


if __name__ == "__main__":
    main()
