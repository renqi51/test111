from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable

from neo4j import GraphDatabase, Driver

from app.core.config import settings
from app.utils import storage
from app.services.trace_service import trace_service


GraphDict = dict[str, list[dict[str, Any]]]


@dataclass
class GraphRepositoryBase(ABC):
    """Abstract graph repository API, backed by file or Neo4j."""

    @abstractmethod
    def get_graph(self) -> GraphDict: ...

    @abstractmethod
    def save_graph(self, payload: GraphDict) -> None: ...

    @abstractmethod
    def merge_nodes_edges(self, nodes: list[dict], edges: list[dict]) -> GraphDict: ...

    @abstractmethod
    def merge_nodes(self, nodes: list[dict]) -> int: ...

    @abstractmethod
    def merge_edges(self, edges: list[dict]) -> int: ...

    # Query helpers
    @abstractmethod
    def get_node(self, node_id: str) -> dict | None: ...

    @abstractmethod
    def neighbors(self, node_id: str, depth: int = 1) -> GraphDict: ...

    def save_staging_graph(self, run_id: str, payload: dict[str, Any]) -> None:
        trace_service.save_staging_graph(run_id, payload)

    def get_staging_graph(self, run_id: str) -> dict[str, Any]:
        return trace_service.load_staging_graph(run_id)


class FileGraphRepository(GraphRepositoryBase):
    """Existing JSON/CSV-based graph store."""

    def get_graph(self) -> GraphDict:
        g = storage.load_runtime_graph()
        return {"nodes": list(g["nodes"]), "edges": list(g["edges"])}

    def save_graph(self, payload: GraphDict) -> None:
        storage.save_runtime_graph(payload)

    def merge_nodes_edges(self, nodes: list[dict], edges: list[dict]) -> GraphDict:
        self.merge_nodes(nodes)
        self.merge_edges(edges)
        return self.get_graph()

    def merge_nodes(self, nodes: list[dict]) -> int:
        current = self.get_graph()
        node_map = {str(n.get("id")): dict(n) for n in current["nodes"] if n.get("id")}
        merged_count = 0
        for node in nodes:
            node_id = str(node.get("id", "")).strip()
            if not node_id:
                continue
            base = node_map.get(node_id, {"id": node_id})
            base["label"] = str(node.get("label", base.get("label", node_id))).strip() or node_id
            base["type"] = str(node.get("type", base.get("type", "Unknown"))).strip() or "Unknown"
            base["description"] = str(node.get("description", base.get("description", ""))).strip()
            base["evidence_source"] = str(
                node.get("evidence_source", base.get("evidence_source", ""))
            ).strip()
            base["en_identifier"] = str(node.get("en_identifier", base.get("en_identifier", node_id))).strip()
            base["properties"] = _merge_dict(base.get("properties"), node.get("properties"))
            base["evidence"] = _merge_evidence(base.get("evidence"), node.get("evidence"))
            node_map[node_id] = base
            merged_count += 1
        current["nodes"] = list(node_map.values())
        self.save_graph(current)
        return merged_count

    def merge_edges(self, edges: list[dict]) -> int:
        current = self.get_graph()
        node_ids = {str(n.get("id")) for n in current["nodes"] if n.get("id")}
        edge_map: dict[tuple[str, str, str], dict[str, Any]] = {}
        for edge in current["edges"]:
            key = (
                str(edge.get("source", "")).strip(),
                str(edge.get("target", "")).strip(),
                str(edge.get("interaction", "")).strip(),
            )
            if not key[0] or not key[1] or not key[2]:
                continue
            edge_map[key] = dict(edge)
        merged_count = 0
        for edge in edges:
            source = str(edge.get("source", "")).strip()
            target = str(edge.get("target", "")).strip()
            interaction = str(edge.get("interaction", "")).strip()
            if not source or not target or not interaction:
                continue
            if source not in node_ids or target not in node_ids:
                continue
            key = (source, target, interaction)
            base = edge_map.get(key, {"source": source, "target": target, "interaction": interaction})
            base["properties"] = _merge_dict(base.get("properties"), edge.get("properties"))
            base["evidence"] = _merge_evidence(base.get("evidence"), edge.get("evidence"))
            edge_map[key] = base
            merged_count += 1
        current["edges"] = list(edge_map.values())
        self.save_graph(current)
        return merged_count

    def get_node(self, node_id: str) -> dict | None:
        g = self.get_graph()
        for n in g["nodes"]:
            if n["id"] == node_id:
                return n
        return None

    def neighbors(self, node_id: str, depth: int = 1) -> GraphDict:
        g = self.get_graph()
        nodes = {n["id"]: dict(n) for n in g["nodes"]}
        edges = g["edges"]
        selected_nodes: dict[str, dict] = {}
        selected_edges: list[dict] = []

        frontier = {node_id}
        for _ in range(depth):
            next_frontier: set[str] = set()
            for e in edges:
                if e["source"] in frontier or e["target"] in frontier:
                    selected_edges.append(dict(e))
                    for nid in (e["source"], e["target"]):
                        if nid in nodes:
                            selected_nodes[nid] = nodes[nid]
                            next_frontier.add(nid)
            frontier = next_frontier
        if node_id in nodes:
            selected_nodes[node_id] = nodes[node_id]
        return {"nodes": list(selected_nodes.values()), "edges": selected_edges}


class Neo4jGraphRepository(GraphRepositoryBase):
    """Neo4j-backed graph store using a generic entity model."""

    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    @classmethod
    def from_settings(cls) -> "Neo4jGraphRepository":
        drv = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )
        return cls(drv)

    # ---- internal helpers -------------------------------------------------

    def _run(self, cypher: str, **params: Any) -> Iterable[dict[str, Any]]:
        with self._driver.session() as sess:
            result = sess.run(cypher, **params)
            for r in result:
                yield r.data()

    # ---- GraphRepositoryBase API -----------------------------------------

    def get_graph(self) -> GraphDict:
        nodes = [
            rec["n"]
            for rec in self._run(
                "MATCH (n:Entity) RETURN {id:n.id,label:n.label,type:n.type,description:n.description,"
                "evidence_source:n.evidence_source,en_identifier:n.en_identifier,properties_json:n.properties_json,"
                "evidence_json:n.evidence_json} AS n"
            )
        ]
        for node in nodes:
            node["properties"] = _json_loads_dict(node.pop("properties_json", ""))
            node["evidence"] = _json_loads_list(node.pop("evidence_json", ""))
        edges = [
            {
                "source": rec["source"],
                "target": rec["target"],
                "interaction": rec["interaction"],
                "properties": _json_loads_dict(rec.get("properties_json", "")),
                "evidence": _json_loads_list(rec.get("evidence_json", "")),
            }
            for rec in self._run(
                "MATCH (a:Entity)-[r]->(b:Entity) "
                "RETURN a.id AS source, b.id AS target, type(r) AS interaction, "
                "r.properties_json AS properties_json, r.evidence_json AS evidence_json"
            )
        ]
        return {"nodes": nodes, "edges": edges}

    def save_graph(self, payload: GraphDict) -> None:
        # For demo: clear and re-import (idempotent import helper).
        with self._driver.session() as sess:
            sess.run("MATCH (n:Entity) DETACH DELETE n")
        self.merge_nodes_edges(payload["nodes"], payload["edges"])

    def merge_nodes_edges(self, nodes: list[dict], edges: list[dict]) -> GraphDict:
        self.merge_nodes(nodes)
        self.merge_edges(edges)
        return self.get_graph()

    def merge_nodes(self, nodes: list[dict]) -> int:
        with self._driver.session() as sess:
            sess.run("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE")
            merged_count = 0
            for node in nodes:
                node_id = str(node.get("id", "")).strip()
                if not node_id:
                    continue
                existing = list(
                    sess.run(
                        "MATCH (e:Entity {id:$id}) "
                        "RETURN e.properties_json AS properties_json, e.evidence_json AS evidence_json",
                        id=node_id,
                    )
                )
                existing_props = _json_loads_dict(existing[0]["properties_json"]) if existing else {}
                existing_evidence = _json_loads_list(existing[0]["evidence_json"]) if existing else []
                merged_props = _merge_dict(existing_props, node.get("properties"))
                merged_evidence = _merge_evidence(existing_evidence, node.get("evidence"))
                labels = "Entity"
                extra_label = _sanitize_neo4j_label(str(node.get("type", "Unknown")).strip() or "Unknown")
                if extra_label:
                    labels = f"{labels}:{extra_label}"
                sess.run(
                    f"MERGE (e:{labels} {{id:$id}}) "
                    "SET e.label=$label, e.type=$type, e.description=$description, "
                    "e.evidence_source=$evidence_source, e.en_identifier=$en_identifier, "
                    "e.properties_json=$properties_json, e.evidence_json=$evidence_json",
                    id=node_id,
                    label=str(node.get("label", node_id)).strip() or node_id,
                    type=str(node.get("type", "Unknown")).strip() or "Unknown",
                    description=str(node.get("description", "")).strip(),
                    evidence_source=str(node.get("evidence_source", "")).strip(),
                    en_identifier=str(node.get("en_identifier", node_id)).strip(),
                    properties_json=json.dumps(merged_props, ensure_ascii=False),
                    evidence_json=json.dumps(merged_evidence, ensure_ascii=False),
                )
                merged_count += 1
        return merged_count

    def merge_edges(self, edges: list[dict]) -> int:
        with self._driver.session() as sess:
            merged_count = 0
            for edge in edges:
                source = str(edge.get("source", "")).strip()
                target = str(edge.get("target", "")).strip()
                interaction = str(edge.get("interaction", "")).strip()
                if not source or not target or not interaction:
                    continue
                relation = interaction.replace("`", "_")
                existing = list(
                    sess.run(
                        "MATCH (a:Entity {id:$source})-[r]->(b:Entity {id:$target}) "
                        "WHERE type(r) = $rel_type "
                        "RETURN r.properties_json AS properties_json, r.evidence_json AS evidence_json",
                        source=source,
                        target=target,
                        rel_type=relation,
                    )
                )
                existing_props = _json_loads_dict(existing[0]["properties_json"]) if existing else {}
                existing_evidence = _json_loads_list(existing[0]["evidence_json"]) if existing else []
                merged_props = _merge_dict(existing_props, edge.get("properties"))
                merged_evidence = _merge_evidence(existing_evidence, edge.get("evidence"))
                sess.run(
                    "MATCH (a:Entity {id:$source}), (b:Entity {id:$target}) "
                    f"MERGE (a)-[r:`{relation}`]->(b) "
                    "SET r.properties_json=$properties_json, r.evidence_json=$evidence_json",
                    source=source,
                    target=target,
                    properties_json=json.dumps(merged_props, ensure_ascii=False),
                    evidence_json=json.dumps(merged_evidence, ensure_ascii=False),
                )
                merged_count += 1
        return merged_count

    def get_node(self, node_id: str) -> dict | None:
        recs = list(
            self._run(
                "MATCH (n:Entity {id:$id}) "
                "RETURN {id:n.id,label:n.label,type:n.type,description:n.description,"
                "evidence_source:n.evidence_source,en_identifier:n.en_identifier,properties_json:n.properties_json,"
                "evidence_json:n.evidence_json} AS n",
                id=node_id,
            )
        )
        if not recs:
            return None
        node = recs[0]["n"]
        node["properties"] = _json_loads_dict(node.pop("properties_json", ""))
        node["evidence"] = _json_loads_list(node.pop("evidence_json", ""))
        return node

    def neighbors(self, node_id: str, depth: int = 1) -> GraphDict:
        depth = max(1, min(depth, 3))
        nodes = [
            rec["n"]
            for rec in self._run(
                "MATCH (c:Entity {id:$id})-[*1..$depth]-(n:Entity) "
                "RETURN DISTINCT {id:n.id,label:n.label,type:n.type,description:n.description,"
                "evidence_source:n.evidence_source,en_identifier:n.en_identifier,properties_json:n.properties_json,"
                "evidence_json:n.evidence_json} AS n",
                id=node_id,
                depth=depth,
            )
        ]
        for node in nodes:
            node["properties"] = _json_loads_dict(node.pop("properties_json", ""))
            node["evidence"] = _json_loads_list(node.pop("evidence_json", ""))
        edges = [
            {
                "source": rec["source"],
                "target": rec["target"],
                "interaction": rec["interaction"],
                "properties": _json_loads_dict(rec.get("properties_json", "")),
                "evidence": _json_loads_list(rec.get("evidence_json", "")),
            }
            for rec in self._run(
                "MATCH (c:Entity {id:$id})-[*1..$depth]-(n:Entity) "
                "WITH collect(DISTINCT n) + c AS ns "
                "UNWIND ns AS a UNWIND ns AS b "
                "MATCH (a)-[r]->(b) "
                "RETURN DISTINCT a.id AS source, b.id AS target, type(r) AS interaction, "
                "r.properties_json AS properties_json, r.evidence_json AS evidence_json",
                id=node_id,
                depth=depth,
            )
        ]
        return {"nodes": nodes, "edges": edges}

    def save_staging_graph(self, run_id: str, payload: dict[str, Any]) -> None:
        # Keep file copy for export/debug compatibility.
        trace_service.save_staging_graph(run_id, payload)
        try:
            with self._driver.session() as sess:
                sess.run(
                    "CREATE CONSTRAINT IF NOT EXISTS FOR (s:StagingNode) "
                    "REQUIRE (s.run_id, s.id) IS UNIQUE"
                )
                sess.run(
                    "MATCH (n:StagingNode {run_id:$run_id}) DETACH DELETE n",
                    run_id=run_id,
                )
                nodes = payload.get("nodes", [])
                edges = payload.get("edges", [])
                for n in nodes:
                    sess.run(
                        "MERGE (s:StagingNode {run_id:$run_id, id:$id}) "
                        "SET s.label=$label, s.type=$type, s.properties=$properties, "
                        "s.source_doc_id=$source_doc_id, s.source_chunk_ids=$source_chunk_ids, "
                        "s.source_worker=$source_worker, s.judge_score=$judge_score, "
                        "s.merge_status=$merge_status, s.created_at=$created_at",
                        run_id=run_id,
                        id=n.get("id"),
                        label=n.get("label", ""),
                        type=n.get("type", "State"),
                        properties=n.get("properties", {}),
                        source_doc_id=n.get("source_doc_id", ""),
                        source_chunk_ids=n.get("source_chunk_ids", []),
                        source_worker=n.get("source_worker", ""),
                        judge_score=float(n.get("judge_score", 0.0)),
                        merge_status=n.get("merge_status", "pending"),
                        created_at=n.get("created_at", ""),
                    )
                for e in edges:
                    sess.run(
                        "MATCH (a:StagingNode {run_id:$run_id, id:$source}), "
                        "(b:StagingNode {run_id:$run_id, id:$target}) "
                        "MERGE (a)-[r:STAGING_EDGE {run_id:$run_id, interaction:$interaction}]->(b) "
                        "SET r.properties=$properties, r.source_doc_id=$source_doc_id, "
                        "r.source_chunk_ids=$source_chunk_ids, r.source_worker=$source_worker, "
                        "r.judge_score=$judge_score, r.merge_status=$merge_status, r.created_at=$created_at",
                        run_id=run_id,
                        source=e.get("source"),
                        target=e.get("target"),
                        interaction=e.get("interaction", "state_transition"),
                        properties=e.get("properties", {}),
                        source_doc_id=e.get("source_doc_id", ""),
                        source_chunk_ids=e.get("source_chunk_ids", []),
                        source_worker=e.get("source_worker", ""),
                        judge_score=float(e.get("judge_score", 0.0)),
                        merge_status=e.get("merge_status", "pending"),
                        created_at=e.get("created_at", ""),
                    )
        except Exception:
            # Neo4j staging persistence is best-effort; file copy remains source of truth fallback.
            return

    def get_staging_graph(self, run_id: str) -> dict[str, Any]:
        try:
            nodes: list[dict[str, Any]] = []
            edges: list[dict[str, Any]] = []
            with self._driver.session() as sess:
                nres = sess.run(
                    "MATCH (s:StagingNode {run_id:$run_id}) RETURN s",
                    run_id=run_id,
                )
                for rec in nres:
                    n = rec["s"]
                    props = dict(n)
                    nodes.append(
                        {
                            "id": props.get("id"),
                            "label": props.get("label", ""),
                            "type": props.get("type", "State"),
                            "properties": props.get("properties", {}),
                            "source_doc_id": props.get("source_doc_id", ""),
                            "source_chunk_ids": props.get("source_chunk_ids", []),
                            "source_worker": props.get("source_worker", ""),
                            "judge_score": props.get("judge_score", 0.0),
                            "merge_status": props.get("merge_status", "pending"),
                            "created_at": props.get("created_at", ""),
                        }
                    )

                eres = sess.run(
                    "MATCH (a:StagingNode {run_id:$run_id})-[r:STAGING_EDGE {run_id:$run_id}]->"
                    "(b:StagingNode {run_id:$run_id}) RETURN a.id AS source, b.id AS target, r",
                    run_id=run_id,
                )
                for rec in eres:
                    r = rec["r"]
                    props = dict(r)
                    edges.append(
                        {
                            "source": rec["source"],
                            "target": rec["target"],
                            "interaction": props.get("interaction", "state_transition"),
                            "properties": props.get("properties", {}),
                            "source_doc_id": props.get("source_doc_id", ""),
                            "source_chunk_ids": props.get("source_chunk_ids", []),
                            "source_worker": props.get("source_worker", ""),
                            "judge_score": props.get("judge_score", 0.0),
                            "merge_status": props.get("merge_status", "pending"),
                            "created_at": props.get("created_at", ""),
                        }
                    )
            if nodes or edges:
                return {"run_id": run_id, "nodes": nodes, "edges": edges}
        except Exception:
            pass
        return trace_service.load_staging_graph(run_id)


_repo: GraphRepositoryBase | None = None


def get_graph_repository() -> GraphRepositoryBase:
    global _repo
    if _repo is not None:
        return _repo
    if settings.graph_backend == "neo4j":
        try:
            _repo = Neo4jGraphRepository.from_settings()
        except Exception:
            # fallback to file-backed graph if Neo4j unavailable
            _repo = FileGraphRepository()
    else:
        _repo = FileGraphRepository()
    return _repo


def _json_loads_dict(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {}
    return obj if isinstance(obj, dict) else {}


def _json_loads_list(raw: str | None) -> list[dict[str, Any]]:
    if not raw:
        return []
    try:
        obj = json.loads(raw)
    except Exception:  # noqa: BLE001
        return []
    return [x for x in obj if isinstance(x, dict)] if isinstance(obj, list) else []


def _merge_dict(base: dict[str, Any] | None, patch: dict[str, Any] | None) -> dict[str, Any]:
    out = dict(base or {})
    for key, value in (patch or {}).items():
        if isinstance(out.get(key), dict) and isinstance(value, dict):
            out[key] = _merge_dict(out.get(key), value)
            continue
        out[key] = value
    return out


def _merge_evidence(
    left: list[dict[str, Any]] | None,
    right: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str]] = set()
    for item in (left or []) + (right or []):
        if not isinstance(item, dict):
            continue
        sf = str(item.get("source_file", "")).strip()
        ci = item.get("chunk_index", -1)
        try:
            chunk_idx = int(ci)
        except Exception:  # noqa: BLE001
            chunk_idx = -1
        quote = str(item.get("quote", "")).strip()
        key = (sf, chunk_idx, quote)
        if key in seen:
            continue
        seen.add(key)
        merged.append({"source_file": sf, "chunk_index": chunk_idx, "quote": quote})
    return merged


def _sanitize_neo4j_label(value: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", value or "")
    clean = re.sub(r"_+", "_", clean).strip("_")
    return clean or "Unknown"

