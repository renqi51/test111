from __future__ import annotations

from app.schemas.graph_rag_synthesis import AttackPathSynthesisBatch, AttackPathSynthesisRow, ExposureAssessmentSynthesis


def test_attack_path_synthesis_batch_roundtrip() -> None:
    raw = {
        "paths": [
            {
                "confidence": 0.82,
                "pivots": ["p1"],
                "target_asset": "NEF",
                "likelihood": 0.61,
                "impact": "high",
                "prerequisites": ["lab"],
                "validation_status": "partially_validated",
                "techniques": ["抓包分析 SIP REGISTER", "尝试伪造特定 Header 绕过鉴权"],
                "threat_vectors": ["令牌滥用"],
                "vulnerabilities": ["OAuth 绑定错误"],
                "evidence_refs": ["doc#1"],
            }
        ],
        "analyst_notes": ["ok"],
    }
    b = AttackPathSynthesisBatch.model_validate(raw)
    assert b.paths[0].techniques[0].startswith("抓包")
    assert b.paths[0].confidence == 0.82


def test_exposure_assessment_synthesis_defaults() -> None:
    s = ExposureAssessmentSynthesis(risk_level="high", score=0.71, attack_points=["x"], validation_tasks=["y"])
    assert s.risk_level == "high"
