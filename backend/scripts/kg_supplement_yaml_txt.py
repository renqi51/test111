"""After a full PDF/MD Neo4j import, ingest only .yaml / .yml / .txt from data/input (no PDF re-parse)."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.kg_builder_service import get_kg_builder_service  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Run LLM extraction but do not write to Neo4j.",
    )
    return p.parse_args()


async def _run(*, dry_run: bool) -> None:
    svc = get_kg_builder_service()
    result = await svc.build_graph_from_input(
        dry_run=dry_run,
        only_extensions=[".yaml", ".yml", ".txt"],
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main() -> None:
    args = _parse_args()
    asyncio.run(_run(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
