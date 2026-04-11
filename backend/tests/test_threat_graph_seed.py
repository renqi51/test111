from __future__ import annotations

import json
from pathlib import Path


def test_seed_graph_contains_threat_chain() -> None:
    root = Path(__file__).resolve().parents[1]
    p = root / "data" / "runtime" / "graph_state.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    nodes = {n["id"]: n for n in data["nodes"]}
    edges = data["edges"]
    assert "proto_gtpc" in nodes
    assert nodes["proto_gtpc"]["type"] == "Protocol"
    assert nodes["vuln_gtpc_plane_weakness"]["type"] == "Vulnerability"
    assert nodes["tv_gtpc_session_hijacking"]["type"] == "ThreatVector"
    assert {"source": "proto_gtpc", "target": "vuln_gtpc_plane_weakness", "interaction": "vulnerable_to"} in edges
    assert {"source": "vuln_gtpc_plane_weakness", "target": "tv_gtpc_session_hijacking", "interaction": "enables_vector"} in edges
    assert nodes["vuln_nb_oauth_misbind"]["type"] == "Vulnerability"
    assert any(e["interaction"] == "vulnerable_to" and e["target"] == "vuln_nb_oauth_misbind" for e in edges)
