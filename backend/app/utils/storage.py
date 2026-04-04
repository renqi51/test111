"""File-backed graph persistence — swap for SQLite/Neo4j via repository interface."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from app.core.config import RUNTIME_DIR, SEED_DIR


RUNTIME_GRAPH = RUNTIME_DIR / "graph_state.json"
SEED_NODES = SEED_DIR / "nodes.csv"
SEED_EDGES = SEED_DIR / "edges.csv"


def ensure_runtime_dir() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def graph_from_csv_seed() -> dict[str, Any]:
    import pandas as pd

    nodes_df = pd.read_csv(SEED_NODES)
    edges_df = pd.read_csv(SEED_EDGES)
    nodes = nodes_df.fillna("").to_dict(orient="records")
    edges = edges_df.fillna("").to_dict(orient="records")
    # normalize column names for en_identifier if stored as en_identifier
    for n in nodes:
        if "en_identifier" not in n and "en_label" in n:
            n["en_identifier"] = n.pop("en_label", "")
    return {"nodes": nodes, "edges": edges, "source": "seed_csv"}


def init_runtime_from_seed_if_missing() -> None:
    """Copy seed CSV → runtime JSON when no runtime state exists."""
    ensure_runtime_dir()
    if RUNTIME_GRAPH.exists():
        return
    payload = graph_from_csv_seed()
    save_json(RUNTIME_GRAPH, payload)


def reset_runtime_from_seed() -> None:
    ensure_runtime_dir()
    payload = graph_from_csv_seed()
    save_json(RUNTIME_GRAPH, payload)


def load_runtime_graph() -> dict[str, Any]:
    init_runtime_from_seed_if_missing()
    return load_json(RUNTIME_GRAPH)


def save_runtime_graph(payload: dict[str, Any]) -> None:
    ensure_runtime_dir()
    save_json(RUNTIME_GRAPH, payload)


def backup_runtime(suffix: str = "bak") -> Path:
    ensure_runtime_dir()
    if not RUNTIME_GRAPH.exists():
        return RUNTIME_GRAPH
    bak = RUNTIME_GRAPH.with_suffix(f".{suffix}.json")
    shutil.copy2(RUNTIME_GRAPH, bak)
    return bak
