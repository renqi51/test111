from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterable

from neo4j import GraphDatabase, Driver

from app.core.config import settings
from app.utils import storage
from app.services.trace_service import trace_service
from app.services import graph_engine


GraphDict = dict[str, list[dict[str, Any]]]


def tokenize_question_for_graph_search(question: str, *, max_tokens: int = 24) -> list[str]:
    """
    从用户问题中提取用于子图匹配的候选串（小写、去重、限长）。
    含简单 3GPP TS 号提取，便于匹配标准文档类节点。
    """
    q = (question or "").strip().lower()
    if not q:
        return []
    tokens: set[str] = set()
    # 先抓英文/数字术语，避免 "sip是什么" 这类中英粘连导致术语丢失。
    for m in re.finditer(r"[a-zA-Z][a-zA-Z0-9._\-]{1,}", q):
        t = m.group(0).strip().lower()
        if len(t) >= 2:
            tokens.add(t)
            # 常见术语有复合形态时，再补一层基础词干（例如 oauth2.0 -> oauth2）。
            base = re.split(r"[._\-]", t)[0].strip()
            if len(base) >= 2:
                tokens.add(base)
    for m in re.finditer(r"(?:ts|3gpp)[\s_\-]*(\d+(?:\.\d+)+)", q, flags=re.IGNORECASE):
        num = m.group(1).lower()
        tokens.add(num)
        tokens.add(f"ts_{num.replace('.', '_')}")
        tokens.add(f"ts{num}")
    for raw in re.split(r"[^\w\u4e00-\u9fff]+", q):
        t = raw.strip().lower()
        if len(t) < 2:
            continue
        # 避免 "is"/"ts" 等两字母英文造成海量 CONTAINS 命中
        if len(t) == 2 and t.isalpha():
            continue
        tokens.add(t)
    out = list(tokens)
    out.sort(key=len, reverse=True)
    return out[:max_tokens]


@dataclass
class GraphRepositoryBase(ABC):
    """Abstract graph repository API, backed by file or Neo4j."""

    @abstractmethod
    def get_graph(self) -> GraphDict: ...

    @abstractmethod
    def save_graph(self, payload: GraphDict) -> None: ...

    @abstractmethod
    def merge_nodes_edges(self, nodes: list[dict], edges: list[dict]) -> GraphDict: ...

    # Query helpers
    @abstractmethod
    def get_node(self, node_id: str) -> dict | None: ...

    @abstractmethod
    def neighbors(self, node_id: str, depth: int = 1) -> GraphDict: ...

    def subgraph_for_graph_rag_question(
        self,
        question: str,
        *,
        seed_limit: int = 20,
        max_edges: int = 100,
    ) -> GraphDict:
        """GraphRAG 问答用：默认无子图（Neo4j / File 子类覆盖）。"""
        return {"nodes": [], "edges": []}

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
        current = self.get_graph()
        added_n, added_e, skip_n, skip_e, merged_n, merged_e = graph_engine.merge_candidates(
            current["nodes"],
            current["edges"],
            nodes,
            edges,
        )
        _ = (added_n, added_e, skip_n, skip_e)  # stats currently unused at this level
        out = {"nodes": merged_n, "edges": merged_e}
        self.save_graph(out)
        return out

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

    def subgraph_for_graph_rag_question(
        self,
        question: str,
        *,
        seed_limit: int = 20,
        max_edges: int = 100,
    ) -> GraphDict:
        tokens = tokenize_question_for_graph_search(question)
        if not tokens:
            return {"nodes": [], "edges": []}
        g = self.get_graph()
        hits: list[dict[str, Any]] = []
        for n in g.get("nodes", []):
            nid = str(n.get("id", "")).lower()
            lab = str(n.get("label", "")).lower()
            desc = str(n.get("description", "")).lower()
            if any(t in nid or t in lab or t in desc for t in tokens):
                hits.append(
                    {
                        "id": n.get("id"),
                        "label": n.get("label", n.get("id")),
                        "type": n.get("type", "Unknown"),
                        "description": n.get("description", ""),
                        "evidence_source": n.get("evidence_source", ""),
                        "en_identifier": n.get("en_identifier", ""),
                    }
                )
        hits = hits[: max(1, seed_limit)]
        seed_ids = {str(n["id"]) for n in hits if n.get("id")}
        if not seed_ids:
            return {"nodes": [], "edges": []}
        edges_out: list[dict[str, Any]] = []
        for e in g.get("edges", []):
            s, t = str(e.get("source", "")), str(e.get("target", ""))
            if s in seed_ids or t in seed_ids:
                edges_out.append(
                    {
                        "source": s,
                        "target": t,
                        "interaction": e.get("interaction", ""),
                    }
                )
            if len(edges_out) >= max_edges:
                break
        need_ids = set(seed_ids)
        for e in edges_out:
            need_ids.add(str(e["source"]))
            need_ids.add(str(e["target"]))
        by_id: dict[str, dict[str, Any]] = {str(n["id"]): n for n in hits if n.get("id")}
        for n in g.get("nodes", []):
            nid = str(n.get("id", ""))
            if nid in need_ids and nid not in by_id:
                by_id[nid] = {
                    "id": n.get("id"),
                    "label": n.get("label", nid),
                    "type": n.get("type", "Unknown"),
                    "description": n.get("description", ""),
                    "evidence_source": n.get("evidence_source", ""),
                    "en_identifier": n.get("en_identifier", ""),
                }
        return {"nodes": list(by_id.values()), "edges": edges_out}


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
                "evidence_source:n.evidence_source,en_identifier:n.en_identifier} AS n"
            )
        ]
        edges = [
            {
                "source": rec["source"],
                "target": rec["target"],
                "interaction": rec["interaction"],
            }
            for rec in self._run(
                "MATCH (a:Entity)-[r]->(b:Entity) "
                "RETURN a.id AS source, b.id AS target, type(r) AS interaction"
            )
        ]
        return {"nodes": nodes, "edges": edges}

    def save_graph(self, payload: GraphDict) -> None:
        # For demo: clear and re-import (idempotent import helper).
        with self._driver.session() as sess:
            sess.run("MATCH (n:Entity) DETACH DELETE n")
        self.merge_nodes_edges(payload["nodes"], payload["edges"])

    def merge_nodes_edges(self, nodes: list[dict], edges: list[dict]) -> GraphDict:
        with self._driver.session() as sess:
            # basic uniqueness on :Entity(id)
            sess.run("CREATE CONSTRAINT IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE")

            for n in nodes:
                props = {
                    "id": n["id"],
                    "label": n.get("label", n["id"]),
                    "type": n.get("type", "Unknown"),
                    "description": n.get("description", ""),
                    "evidence_source": n.get("evidence_source", ""),
                    "en_identifier": n.get("en_identifier", ""),
                }
                # 只 MERGE :Entity {id}。不要把 type 加成第二图谱标签：
                # 否则同一 id 先写成 Entity:TypeA 再 MERGE Entity:TypeB 会违反 id 唯一约束（你遇到的 'ue'）。
                sess.run(
                    "MERGE (e:Entity {id:$id}) "
                    "SET e.label=$label, e.type=$type, e.description=$description, "
                    "e.evidence_source=$evidence_source, e.en_identifier=$en_identifier",
                    **props,
                )

            for e in edges:
                itype = e.get("interaction", "")
                if not itype:
                    continue
                # Dedup via MERGE
                sess.run(
                    "MATCH (a:Entity {id:$source}), (b:Entity {id:$target}) "
                    f"MERGE (a)-[r:`{itype}`]->(b)",
                    source=e["source"],
                    target=e["target"],
                )

        return self.get_graph()

    def get_node(self, node_id: str) -> dict | None:
        recs = list(
            self._run(
                "MATCH (n:Entity {id:$id}) "
                "RETURN {id:n.id,label:n.label,type:n.type,description:n.description,"
                "evidence_source:n.evidence_source,en_identifier:n.en_identifier} AS n",
                id=node_id,
            )
        )
        if not recs:
            return None
        return recs[0]["n"]

    def neighbors(self, node_id: str, depth: int = 1) -> GraphDict:
        depth = max(1, min(depth, 3))
        # Neo4j 不支持在可变长度关系中使用参数化 range（[*1..$depth]）。
        # 这里先做范围钳制，再将整数深度内联到 Cypher 字符串中。
        depth_range = f"*1..{depth}"
        nodes = [
            rec["n"]
            for rec in self._run(
                f"MATCH (c:Entity {{id:$id}})-[{depth_range}]-(n:Entity) "
                "RETURN DISTINCT {id:n.id,label:n.label,type:n.type,description:n.description,"
                "evidence_source:n.evidence_source,en_identifier:n.en_identifier} AS n",
                id=node_id,
            )
        ]
        edges = [
            {
                "source": rec["source"],
                "target": rec["target"],
                "interaction": rec["interaction"],
            }
            for rec in self._run(
                f"MATCH (c:Entity {{id:$id}})-[{depth_range}]-(n:Entity) "
                "WITH collect(DISTINCT n.id) + $id AS ids "
                "UNWIND ids AS aid UNWIND ids AS bid "
                "MATCH (a:Entity {id:aid})-[r]->(b:Entity {id:bid}) "
                "RETURN DISTINCT a.id AS source, b.id AS target, type(r) AS interaction",
                id=node_id,
            )
        ]
        return {"nodes": nodes, "edges": edges}

    def subgraph_for_graph_rag_question(
        self,
        question: str,
        *,
        seed_limit: int = 20,
        max_edges: int = 100,
    ) -> GraphDict:
        tokens = tokenize_question_for_graph_search(question)
        if not tokens:
            return {"nodes": [], "edges": []}
        seed_limit = max(1, min(seed_limit, 80))
        max_edges = max(1, min(max_edges, 500))

        seed_rows = list(
            self._run(
                "MATCH (n:Entity) "
                "WHERE any(t IN $tokens WHERE "
                "toLower(coalesce(n.label, '')) CONTAINS t OR "
                "toLower(coalesce(n.description, '')) CONTAINS t OR "
                "toLower(coalesce(n.id, '')) CONTAINS t) "
                "RETURN DISTINCT n.id AS id, n.label AS label, n.type AS type, n.description AS description, "
                "n.evidence_source AS evidence_source, n.en_identifier AS en_identifier "
                "LIMIT $seed_limit",
                tokens=tokens,
                seed_limit=seed_limit,
            )
        )
        nodes: list[dict[str, Any]] = [
            {
                "id": row["id"],
                "label": row.get("label") or row["id"],
                "type": row.get("type") or "Unknown",
                "description": row.get("description") or "",
                "evidence_source": row.get("evidence_source") or "",
                "en_identifier": row.get("en_identifier") or "",
            }
            for row in seed_rows
            if row.get("id")
        ]
        seed_ids = [n["id"] for n in nodes]
        if not seed_ids:
            return {"nodes": [], "edges": []}

        edge_rows = list(
            self._run(
                "MATCH (a:Entity)-[r]->(b:Entity) "
                "WHERE a.id IN $ids OR b.id IN $ids "
                "RETURN DISTINCT a.id AS source, b.id AS target, type(r) AS interaction "
                "LIMIT $max_edges",
                ids=seed_ids,
                max_edges=max_edges,
            )
        )
        edges: list[dict[str, Any]] = [
            {
                "source": row["source"],
                "target": row["target"],
                "interaction": row.get("interaction") or "",
            }
            for row in edge_rows
            if row.get("source") and row.get("target")
        ]

        need_ids: set[str] = set(seed_ids)
        for e in edges:
            need_ids.add(str(e["source"]))
            need_ids.add(str(e["target"]))
        missing = [i for i in need_ids if i not in {n["id"] for n in nodes}]
        if missing:
            extra = list(
                self._run(
                    "MATCH (n:Entity) WHERE n.id IN $ids "
                    "RETURN n.id AS id, n.label AS label, n.type AS type, n.description AS description, "
                    "n.evidence_source AS evidence_source, n.en_identifier AS en_identifier",
                    ids=missing[:200],
                )
            )
            seen = {n["id"] for n in nodes}
            for row in extra:
                rid = row.get("id")
                if not rid or rid in seen:
                    continue
                seen.add(rid)
                nodes.append(
                    {
                        "id": rid,
                        "label": row.get("label") or rid,
                        "type": row.get("type") or "Unknown",
                        "description": row.get("description") or "",
                        "evidence_source": row.get("evidence_source") or "",
                        "en_identifier": row.get("en_identifier") or "",
                    }
                )

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

