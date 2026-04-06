"""
将 kg_builder 落盘的 JSON 写入 Neo4j（仅 merge，不调用 LLM）。

默认读取：data/runtime/kg_last_merge_payload.json（与 settings.kg_merge_payload_path 一致）

用法（在 backend 目录）:
  python scripts/merge_kg_payload_to_neo4j.py
  python scripts/merge_kg_payload_to_neo4j.py --path path/to/payload.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import settings  # noqa: E402
from app.repositories.graph_repository import get_graph_repository  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--path",
        type=str,
        default=None,
        help="payload JSON（含 nodes, edges 列表）；默认用 kg_merge_payload_path",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    path = Path(args.path or settings.kg_merge_payload_path)
    if not path.is_file():
        print(f"Missing payload file: {path}")
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    nodes = data.get("nodes") or []
    edges = data.get("edges") or []
    if not isinstance(nodes, list) or not isinstance(edges, list):
        print("Invalid JSON: expected top-level nodes/edges arrays")
        return 1
    repo = get_graph_repository()
    repo.merge_nodes_edges(nodes, edges)
    g = repo.get_graph()
    print(f"Merged from {path}: wrote nodes={len(nodes)} edges={len(edges)}; graph now nodes={len(g['nodes'])} edges={len(g['edges'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
