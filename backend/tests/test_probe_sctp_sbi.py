"""SCTP (Scapy) 与 HTTP/2 SBI 未授权探测的单元测试（网络调用均 mock）。"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services import probe_service


def test_sctp_init_returns_no_scapy_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """当 _SCAPY_AVAILABLE 为 False 时，应返回可观测的 pip 安装提示，而非空列表。"""
    monkeypatch.setattr(probe_service, "_SCAPY_AVAILABLE", False)
    lines = probe_service._sctp_init_probe_sync("example.com", 38412, 0.1)
    assert lines and "SCAPY_NOT_INSTALLED" in lines[0]


def test_sctp_init_reply_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """打桩 sr1 返回伪造应答，验证 INIT_reply 分支与 summary 拼接。"""

    class _Ans:
        def summary(self) -> str:
            return "IP / SCTP / SCTPChunkInitAck"

    monkeypatch.setattr(probe_service, "_SCAPY_AVAILABLE", True)
    monkeypatch.setattr(probe_service, "_sr1_dispatch", lambda *a, **k: _Ans())
    monkeypatch.setattr(probe_service, "_resolve_target_ip_for_l3", lambda h: ("192.0.2.1", "ipv4"))
    lines = probe_service._sctp_init_probe_sync("amf.lab", 38412, 0.2)
    assert any("INIT_reply" in x for x in lines)
    assert "SCTPChunkInitAck" in lines[0]


@pytest.mark.asyncio
async def test_sbi_unauth_probe_records_http2_status(monkeypatch: pytest.MonkeyPatch) -> None:
    """打桩 httpx.AsyncClient：验证每个 SBI 路径记录 status 与 http_version。"""

    class FakeResp:
        def __init__(self, code: int) -> None:
            self.status_code = code
            self.http_version = "HTTP/2"
            self.headers = {"www-authenticate": 'Bearer realm="oauth2"'}

    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            self._n = 0

        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, headers: object | None = None) -> FakeResp:
            self._n += 1
            return FakeResp(401 if "nnrf" in url else 403)

    monkeypatch.setattr(probe_service.httpx, "AsyncClient", lambda **kw: FakeClient())
    out = await probe_service._probe_sbi_http2_unauth("api.example")
    assert "paths" in out
    assert out["paths"]["/nnrf-nfm/v1/nf-instances"]["status"] == 401
    assert out["paths"]["/nnrf-nfm/v1/nf-instances"]["http_version"] == "HTTP/2"
    assert out["paths"]["/nudm-ueau/v1/imsi-460001234567890/security-information"]["status"] == 403


def test_resolve_target_ip_prefers_ipv4(monkeypatch: pytest.MonkeyPatch) -> None:
    """getaddrinfo 打桩：优先返回 IPv4 元组，供 SCTP IP() 层封装。"""
    monkeypatch.setattr(
        probe_service.socket,
        "getaddrinfo",
        lambda *a, **k: [
            (2, 1, 6, "", ("192.0.2.2", 0)),
            (10, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
        ],
    )
    ip, fam = probe_service._resolve_target_ip_for_l3("x.test")
    assert ip == "192.0.2.2"
    assert fam == "ipv4"
