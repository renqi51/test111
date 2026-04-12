"""Phase 1: outside-in assets → probe-backed rows (no graph FQDN guessing)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.exposure import ExposureAssessment
from app.schemas.probe import ProbeRunResponse, ProbeTargetResult
from app.services import exposure_service


def test_expand_real_asset_targets_dedupes_and_caps_cidr() -> None:
    out = exposure_service.expand_real_asset_targets(
        domains=["HTTPS://Example.COM/path", "example.com"],
        ips=["10.0.0.1"],
        cidrs=["10.0.0.0/30"],
        extra_hosts=["  example.com "],
        max_cidr_hosts=10,
    )
    assert "example.com" in out
    assert "10.0.0.1" in out
    # /30 has .1 and .2 as usable hosts in hosts()
    assert any(x.startswith("10.0.0.") for x in out)


def test_expand_single_host_cidr() -> None:
    out = exposure_service.expand_real_asset_targets(
        domains=[],
        ips=[],
        cidrs=["192.0.2.5/32"],
        extra_hosts=None,
        max_cidr_hosts=10,
    )
    assert out == ["192.0.2.5"]


def test_rows_from_probe_merges_ports_and_hints() -> None:
    run = {
        "results": [
            {
                "host": "gw.lab.local",
                "target": "gw.lab.local",
                "permitted": True,
                "policy_reason": "open_mode",
                "dns_ok": True,
                "open_ports": [443, 5060],
                "open_udp_ports": [500],
                "service_hints": ["https", "sip"],
                "https_ok": True,
                "https_status": 404,
            }
        ]
    }
    rows = exposure_service.rows_from_probe_run(run, service="IMS")
    assert len(rows) == 1
    r = rows[0]
    assert r["candidate_fqdn"] == "gw.lab.local"
    labels = r["protocol_stack"]
    assert "tcp/443" in labels
    assert "udp/500" in labels
    assert "https" in labels
    assert r["risk_hypotheses"]
    assert r["confidence"] > 0.4


@pytest.mark.asyncio
async def test_generate_probe_backed_rows_uses_probe_service() -> None:
    fake = ProbeRunResponse(
        run_id="t1",
        started_at="",
        finished_at="",
        probe_mode="open",
        results=[
            ProbeTargetResult(
                target="1.2.3.4",
                host="1.2.3.4",
                permitted=True,
                policy_reason="open_mode",
                dns_ok=True,
                open_ports=[443],
                service_hints=["https"],
            )
        ],
        summary={},
    )
    with patch("app.services.exposure_service.probe_service.run_probe", new=AsyncMock(return_value=fake)):
        rows, dumped = await exposure_service.generate_probe_backed_rows(
            service="Open Gateway",
            domains=[],
            ips=["1.2.3.4"],
            cidrs=[],
            extra_hosts=None,
            include_probe=True,
        )
    assert dumped["run_id"] == "t1"
    assert rows[0]["candidate_fqdn"] == "1.2.3.4"
    assert "tcp/443" in rows[0]["protocol_stack"]


@pytest.mark.asyncio
async def test_analyze_exposure_maps_probe_status(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = ProbeRunResponse(
        run_id="t2",
        started_at="",
        finished_at="",
        probe_mode="open",
        results=[
            ProbeTargetResult(
                target="api.op.example",
                host="api.op.example",
                permitted=True,
                policy_reason="open_mode",
                dns_ok=True,
                https_ok=True,
                https_status=401,
                open_ports=[443],
                service_hints=["https"],
            )
        ],
        summary={},
    )
    monkeypatch.setattr("app.services.exposure_service.probe_service.run_probe", AsyncMock(return_value=fake))

    async def _assess(c: object) -> ExposureAssessment:
        from app.schemas.exposure import ExposureCandidate

        assert isinstance(c, ExposureCandidate)
        return ExposureAssessment(candidate_id=c.candidate_id, risk_level="low", score=0.1, summary="unit")

    monkeypatch.setattr(exposure_service, "_graph_rag_assessment_for_candidate", _assess)

    async def _no_paths(*args: object, **kwargs: object) -> list:
        return []

    monkeypatch.setattr(exposure_service, "_build_attack_paths_via_graph_rag", _no_paths)

    resp = await exposure_service.analyze_exposure(
        "Open Gateway",
        "460",
        "01",
        domains=["api.op.example"],
        ips=[],
        cidrs=[],
        include_probe=True,
        extra_hosts=None,
        use_llm=False,
    )
    assert len(resp.candidates) == 1
    assert resp.candidates[0].probe_status.get("https_status") == 401
    assert resp.probe_run is not None
    assert resp.patterns[0].rationale.startswith("Observed")


def test_exposure_generate_request_requires_assets() -> None:
    from pydantic import ValidationError

    from app.schemas.exposure import ExposureGenerateRequest

    with pytest.raises(ValidationError):
        ExposureGenerateRequest(service="IMS", domains=[], ips=[], cidrs=[])
