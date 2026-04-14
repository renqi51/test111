from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.services import p0_ops_service


def test_delta_detects_tcp_udp_and_https_changes() -> None:
    prev = {
        "results": [
            {"host": "a.lab", "open_ports": [443], "open_udp_ports": [500], "https_status": 401},
        ]
    }
    curr = {
        "results": [
            {"host": "a.lab", "open_ports": [443, 8443], "open_udp_ports": [], "https_status": 200},
            {"host": "b.lab", "open_ports": [80], "open_udp_ports": [], "https_status": None},
        ]
    }
    out = p0_ops_service._delta(prev, curr)  # noqa: SLF001
    assert out["kind"] == "delta"
    assert out["new_hosts"] == ["b.lab"]
    assert out["changed_hosts"]["a.lab"]["tcp_added"] == [8443]
    assert out["changed_hosts"]["a.lab"]["udp_removed"] == [500]
    assert out["changed_hosts"]["a.lab"]["https_status_old"] == 401
    assert out["changed_hosts"]["a.lab"]["https_status_new"] == 200


def test_p0_assets_upsert_requires_api_key(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(settings, "api_tokens", "admin:adminkey,viewer:viewkey")
    # isolate runtime files
    tmp = tmp_path / "p0"
    monkeypatch.setattr(p0_ops_service, "P0_DIR", tmp)
    monkeypatch.setattr(p0_ops_service, "ASSETS_PATH", tmp / "assets.json")
    monkeypatch.setattr(p0_ops_service, "JOBS_PATH", tmp / "jobs.json")
    monkeypatch.setattr(p0_ops_service, "RUNS_PATH", tmp / "runs.json")
    monkeypatch.setattr(p0_ops_service, "AUDIT_PATH", tmp / "audit.jsonl")

    client = TestClient(app)
    r1 = client.post("/api/p0/assets/upsert", json={"assets": ["a.example.com"], "source": "test"})
    assert r1.status_code == 401

    r2 = client.post(
        "/api/p0/assets/upsert",
        headers={"X-API-Key": "adminkey"},
        json={"assets": ["a.example.com"], "source": "test"},
    )
    assert r2.status_code == 200
    body = r2.json()
    assert body["assets"][0]["asset"] == "a.example.com"
