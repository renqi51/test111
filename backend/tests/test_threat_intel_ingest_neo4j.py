"""Neo4j ThreatVector 挂载逻辑（Mock driver，不连真实库）。"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.repositories.graph_repository import Neo4jGraphRepository


class _FakeNeo4jSession:
    def run(self, *args: object, **kwargs: object) -> list[object]:
        return []

    def __enter__(self) -> _FakeNeo4jSession:
        return self

    def __exit__(self, *args: object) -> None:
        return None


@pytest.fixture
def neo4j_repo(monkeypatch: pytest.MonkeyPatch) -> Neo4jGraphRepository:
    drv = MagicMock()
    drv.session = MagicMock(return_value=_FakeNeo4jSession())
    repo = Neo4jGraphRepository.__new__(Neo4jGraphRepository)  # noqa: PLC2801
    repo._driver = drv  # type: ignore[attr-defined]

    def fake_run(cypher: str, **params: object) -> list[dict]:
        if "CREATE CONSTRAINT" in cypher:
            return []
        if "MATCH (n:Entity)" in cypher and "RETURN DISTINCT n.id" in cypher:
            if params.get("needle") == "nf-not-found":
                return []
            return [{"id": "nf_nef"}]
        if "UNWIND $entity_ids" in cypher:
            return []
        return []

    repo._run = fake_run  # type: ignore[method-assign]
    return repo


def test_ingest_static_threat_playbooks_dry_run_counts_edges(neo4j_repo: Neo4jGraphRepository) -> None:
    rows = [
        {
            "target_node_type": "NetworkFunction",
            "target_node_name": "NEF",
            "threat_name": "T1",
            "vulnerability_type": "v",
            "description": "d",
            "payload_template": "curl",
        }
    ]
    stats = neo4j_repo.ingest_static_threat_playbooks(rows, dry_run=True)
    assert stats["dry_run"] is True
    assert stats["linked_edges"] == 1
    assert stats["skipped_no_entity"] == 0


def test_ingest_skips_when_no_entity_match(neo4j_repo: Neo4jGraphRepository) -> None:
    rows = [
        {
            "target_node_type": "NetworkFunction",
            "target_node_name": "nf-not-found",
            "threat_name": "T2",
            "vulnerability_type": "v",
            "description": "d",
            "payload_template": "curl",
        }
    ]
    stats = neo4j_repo.ingest_static_threat_playbooks(rows, dry_run=True)
    assert stats["linked_edges"] == 0
    assert stats["skipped_no_entity"] == 1


def test_graph_rag_verbatim_block_helper() -> None:
    from app.services.graph_rag_query_service import _threat_vector_verbatim_block

    s = _threat_vector_verbatim_block(
        [{"threat_id": "x", "payload_template": "a'b"}],
    )
    assert "THREAT_VECTOR_VERBATIM_JSON" in s
    assert "payload_template" in s
