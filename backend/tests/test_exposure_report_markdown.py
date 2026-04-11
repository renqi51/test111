from __future__ import annotations

from app.schemas.exposure import (
    AttackPath,
    ExposureAnalysisResponse,
    ExposureAssessment,
    ExposureCandidate,
    CandidateEvidenceBundle,
    ExposurePattern,
)
from app.services.exposure_service import _report_markdown  # noqa: SLF001


def test_report_markdown_lists_concrete_steps() -> None:
    cand = ExposureCandidate(
        candidate_id="cand_000",
        candidate_fqdn="x.example.com",
        service="IMS",
        protocols=["SIP"],
        network_functions=["P-CSCF"],
        confidence=0.5,
        evidence=CandidateEvidenceBundle(),
        probe_status={},
    )
    assess = ExposureAssessment(
        candidate_id="cand_000",
        risk_level="high",
        score=0.8,
        attack_points=["SIP 边界鉴权"],
        validation_tasks=["抓包比对 REGISTER 与 401 挑战流程"],
    )
    ap = AttackPath(
        path_id="p1",
        candidate_id="cand_000",
        entrypoint="x.example.com",
        techniques=["尝试伪造特定 Header 绕过鉴权"],
        threat_vectors=["SIP 滥用"],
        vulnerabilities=["弱鉴权"],
        graph_rag_confidence=0.7,
    )
    data = ExposureAnalysisResponse(
        run_id="exp_test",
        service="IMS",
        mcc="460",
        mnc="01",
        patterns=[ExposurePattern(pattern_id="pat", service="IMS", category="fqdn", expression="x", rationale="")],
        candidates=[cand],
        assessments=[assess],
        attack_paths=[ap],
        probe_run=None,
    )
    md = _report_markdown(data)
    assert "针对该资产的建议测试操作" in md
    assert "抓包比对 REGISTER" in md
    assert "尝试伪造特定 Header" in md
