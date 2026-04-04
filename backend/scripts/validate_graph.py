"""CLI: validate seed/runtime graph and print report (mirrors POST /api/graph/validate)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.services.graph_engine import validate_graph, compute_stats  # noqa: E402
from app.utils.storage import load_runtime_graph, init_runtime_from_seed_if_missing  # noqa: E402


def main() -> int:
    init_runtime_from_seed_if_missing()
    g = load_runtime_graph()
    vr = validate_graph(g["nodes"], g["edges"])
    st = compute_stats(g["nodes"], g["edges"])
    print("=== Graph validation ===")
    print(f"Nodes: {st['node_count']}  Edges: {st['edge_count']}")
    print(f"OK: {vr.ok}")
    print(f"Orphans ({len(vr.orphan_nodes)}):", ", ".join(vr.orphan_nodes) or "(none)")
    print(f"Dangling edges: {len(vr.dangling_edges)}")
    print(f"Unreferenced docs: {vr.unreferenced_standard_docs}")
    print(f"Risks w/o mitigation: {vr.risks_without_mitigation}")
    return 0 if vr.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
