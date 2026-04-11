from __future__ import annotations

from unittest.mock import patch

import pytest

from app.schemas.exposure import ExposureAssessment, ExposureCandidate, CandidateEvidenceBundle
from app.services import exposure_service


@pytest.mark.asyncio
async def test_build_attack_paths_invokes_graph_rag_synthesis() -> None:
    cand = ExposureCandidate(
        candidate_id="cand_000",
        candidate_fqdn="api.example.com",
        service="Open Gateway",
        protocols=["HTTPS"],
        network_functions=["NEF"],
        confidence=0.7,
        evidence=CandidateEvidenceBundle(evidence_docs=["TS 33.501"], graph_paths=[], related_risks=[], source_kind=["graph_inference"]),
        probe_status={"https_ok": True, "service_hints": ["h2"]},
    )
    assess = ExposureAssessment(candidate_id="cand_000", risk_level="medium", score=0.55, summary="x")

    class _FakeGR:
        async def synthesize_exposure_attack_path(self, **kwargs):  # noqa: ANN003
            from app.schemas.graph_rag_synthesis import AttackPathSynthesisBatch, AttackPathSynthesisRow

            return AttackPathSynthesisBatch(
                paths=[
                    AttackPathSynthesisRow(
                        confidence=0.66,
                        pivots=["probe_hint:h2"],
                        target_asset="NEF",
                        likelihood=0.55,
                        impact="medium",
                        prerequisites=["authorized lab"],
                        validation_status="partially_validated",
                        techniques=["对北向 HTTPS 实施 OAuth2 redirect_uri 绑定矩阵测试"],
                        threat_vectors=["北向 API 滥用"],
                        vulnerabilities=["OAuth 配置缺陷"],
                        evidence_refs=["neo4j:entity:proto_https"],
                    )
                ],
                analyst_notes=["unit"],
            )

    with patch("app.services.exposure_service.get_graph_rag_query_service", return_value=_FakeGR()):
        paths = await exposure_service._build_attack_paths_via_graph_rag(  # noqa: SLF001
            service="Open Gateway",
            candidates=[cand],
            assessments=[assess],
        )
    assert len(paths) == 1
    assert paths[0].techniques[0].startswith("对北向")
    assert paths[0].graph_rag_confidence == 0.66
    assert "北向 API" in paths[0].threat_vectors[0]
