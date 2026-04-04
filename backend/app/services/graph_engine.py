"""Graph analytics: NetworkX for validation metrics (Neo4j adapter can mirror this API)."""
from __future__ import annotations

from typing import Any

import networkx as nx
import pandas as pd

from app.schemas.graph import ValidateIssue, ValidateResult

RISK_TYPE = "RiskHypothesis"
DOC_TYPE = "StandardDoc"


def payload_to_graph(nodes: list[dict], edges: list[dict]) -> nx.DiGraph:
    g = nx.DiGraph()
    for n in nodes:
        g.add_node(n["id"], **{k: v for k, v in n.items() if k != "id"})
    for e in edges:
        g.add_edge(e["source"], e["target"], interaction=e.get("interaction", ""))
    return g


def compute_stats(nodes: list[dict], edges: list[dict]) -> dict[str, Any]:
    g = payload_to_graph(nodes, edges)
    node_ids = {n["id"] for n in nodes}
    ndf = pd.DataFrame(nodes) if nodes else pd.DataFrame(columns=["id", "type"])
    by_type = ndf.groupby("type").size().to_dict() if len(ndf) else {}
    edf = pd.DataFrame(edges) if edges else pd.DataFrame(columns=["interaction"])
    by_edge = edf.groupby("interaction").size().to_dict() if len(edf) else {}
    deg = dict(g.degree())
    top = sorted(deg.items(), key=lambda x: x[1], reverse=True)[:10]
    top_degree = [{"id": nid, "degree": d} for nid, d in top]
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "by_node_type": {str(k): int(v) for k, v in by_type.items()},
        "by_edge_type": {str(k): int(v) for k, v in by_edge.items()},
        "top_degree_nodes": top_degree,
        "_node_ids": node_ids,
        "_graph": g,
    }


def validate_graph(nodes: list[dict], edges: list[dict]) -> ValidateResult:
    node_ids = {n["id"] for n in nodes}
    node_by_id = {n["id"]: n for n in nodes}
    issues: list[ValidateIssue] = []
    dangling: list[dict[str, str]] = []

    for e in edges:
        if e["source"] not in node_ids:
            dangling.append({"source": e["source"], "target": e["target"], "reason": "missing_source"})
            issues.append(ValidateIssue(code="DANGLING_EDGE", detail=f"source {e['source']} missing"))
        if e["target"] not in node_ids:
            dangling.append({"source": e["source"], "target": e["target"], "reason": "missing_target"})
            issues.append(ValidateIssue(code="DANGLING_EDGE", detail=f"target {e['target']} missing"))

    g = payload_to_graph(nodes, edges)
    orphans = [n for n in node_ids if g.degree(n) == 0]
    if orphans:
        issues.append(ValidateIssue(code="ORPHAN", detail=f"{len(orphans)} isolated nodes"))

    # Standard docs not referenced by documented_in (edge pointing TO doc from entity)
    doc_ids = {nid for nid, n in node_by_id.items() if n.get("type") == DOC_TYPE}
    referenced_docs: set[str] = set()
    for e in edges:
        if e.get("interaction") == "documented_in" and e["target"] in doc_ids:
            referenced_docs.add(e["target"])
    unref_docs = sorted(doc_ids - referenced_docs)

    # Risks without mitigation path: no incoming mitigated_by from WorkProduct, no targets edge with mitigated_by
    risk_ids = {nid for nid, n in node_by_id.items() if n.get("type") == RISK_TYPE}
    mitigated_risks: set[str] = set()
    for e in edges:
        if e.get("interaction") == "mitigated_by" and e["source"] in risk_ids:
            mitigated_risks.add(e["source"])
        # also: WorkProduct -> mitigated_by -> Risk (reverse) — seed uses risk targets X; mitigation edges from work to risk
        if e.get("interaction") == "mitigated_by" and e["target"] in risk_ids:
            mitigated_risks.add(e["target"])
    risks_no_mit = sorted(risk_ids - mitigated_risks)

    stats = compute_stats(nodes, edges)
    ok = not dangling and len(orphans) == 0  # allow unref docs as warnings only
    # Treat unreferenced docs as soft validation: still ok for demo if graph is connected otherwise
    ok = ok and len(orphans) == 0

    return ValidateResult(
        ok=ok and len([i for i in issues if i.code == "DANGLING_EDGE"]) == 0,
        orphan_nodes=orphans,
        dangling_edges=dangling,
        unreferenced_standard_docs=unref_docs,
        risks_without_mitigation=risks_no_mit,
        node_type_counts=stats["by_node_type"],
        edge_type_counts=stats["by_edge_type"],
        top_degree_nodes=stats["top_degree_nodes"],
        issues=issues,
    )


def merge_candidates(
    nodes: list[dict],
    edges: list[dict],
    new_nodes: list[dict],
    new_edges: list[dict],
) -> tuple[int, int, int, int, list[dict], list[dict]]:
    """Merge new nodes/edges; skip duplicate ids / duplicate edges."""
    by_id = {n["id"]: dict(n) for n in nodes}
    added_n = skipped_n = 0
    for n in new_nodes:
        nid = n["id"]
        if nid in by_id:
            skipped_n += 1
            continue
        by_id[nid] = {
            "id": nid,
            "label": n.get("label", nid),
            "type": n.get("type", "Service"),
            "description": n.get("description", ""),
            "evidence_source": n.get("evidence_source", ""),
            "en_identifier": n.get("en_identifier", ""),
        }
        added_n += 1
    merged_nodes = list(by_id.values())

    edge_set = {(e["source"], e["target"], e["interaction"]) for e in edges}
    merged_edges = [dict(e) for e in edges]
    added_e = skipped_e = 0
    node_ids = {n["id"] for n in merged_nodes}
    for e in new_edges:
        key = (e["source"], e["target"], e["interaction"])
        if key in edge_set:
            skipped_e += 1
            continue
        if e["source"] not in node_ids or e["target"] not in node_ids:
            skipped_e += 1
            continue
        merged_edges.append(
            {"source": e["source"], "target": e["target"], "interaction": e["interaction"]}
        )
        edge_set.add(key)
        added_e += 1

    return added_n, added_e, skipped_n, skipped_e, merged_nodes, merged_edges
