"""
从 CSV 种子数据导入图谱到 Neo4j。
假设已通过 Docker 或本地方式启动 Neo4j，并在环境中设置：

  EXPOSURE_GRAPH_BACKEND=neo4j
  EXPOSURE_NEO4J_URI=bolt://localhost:7687
  EXPOSURE_NEO4J_USER=neo4j
  EXPOSURE_NEO4J_PASSWORD=password
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.repositories.graph_repository import get_graph_repository  # noqa: E402
from app.utils.storage import graph_from_csv_seed  # noqa: E402


def main() -> int:
    repo = get_graph_repository()
    seed = graph_from_csv_seed()
    repo.save_graph({"nodes": seed["nodes"], "edges": seed["edges"]})
    print(f"Imported {len(seed['nodes'])} nodes, {len(seed['edges'])} edges into graph backend.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

