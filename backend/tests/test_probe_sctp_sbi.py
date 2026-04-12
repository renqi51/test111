"""SCTP (Scapy) 与 HTTP/2 SBI 未授权探测的单元测试（网络调用均 mock）。"""

from __future__ import annotations

import ssl
from unittest.mock import AsyncMock, MagicMock

import httpx
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
    """打桩 httpx.AsyncClient：验证 NRF 发现路径记录 status 与 http_version。"""

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
            assert "/nnrf-disc/v1/nf-instances" in url
            return FakeResp(401)

    monkeypatch.setattr(probe_service.httpx, "AsyncClient", lambda **kw: FakeClient())
    out = await probe_service._probe_sbi_http2_unauth("api.example")
    assert "paths" in out
    p = out["paths"]["/nnrf-disc/v1/nf-instances"]
    assert p["status"] == 401
    assert p["http_version"] == "HTTP/2"


@pytest.mark.asyncio
async def test_sbi_probe_does_not_mark_mtls_for_generic_handshake_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """泛化 handshake failure（无证书语义）不应标 mTLS，避免噪声污染暴露面分级。"""

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, headers: object | None = None) -> None:
            inner = ssl.SSLError("TLSV1_ALERT_HANDSHAKE_FAILURE")
            req = httpx.Request("GET", url)
            raise httpx.ConnectError("handshake failed", request=req) from inner

    monkeypatch.setattr(probe_service.httpx, "AsyncClient", lambda **kw: FakeClient())
    out = await probe_service._probe_sbi_http2_unauth("plain.example")
    row = out["paths"]["/nnrf-disc/v1/nf-instances"]
    assert row.get("mTLS_Enforced") is not True


@pytest.mark.asyncio
async def test_sbi_probe_marks_mtls_enforced_on_tls_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    """TLS 握手链上若出现证书类 SSLError，应标记 mTLS_Enforced 而非泛化 timeout。"""

    class FakeClient:
        async def __aenter__(self) -> FakeClient:
            return self

        async def __aexit__(self, *args: object) -> None:
            return None

        async def get(self, url: str, headers: object | None = None) -> None:
            inner = ssl.SSLError("TLSV1_ALERT_CERTIFICATE_REQUIRED")
            req = httpx.Request("GET", url)
            raise httpx.ConnectError("handshake failed", request=req) from inner

    monkeypatch.setattr(probe_service.httpx, "AsyncClient", lambda **kw: FakeClient())
    out = await probe_service._probe_sbi_http2_unauth("mtls.example")
    row = out["paths"]["/nnrf-disc/v1/nf-instances"]
    assert row.get("mTLS_Enforced") is True
    assert row.get("status") is None


@pytest.mark.asyncio
async def test_resolve_target_ip_async_uses_event_loop_getaddrinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    """SCTP 异步解析应走 loop.getaddrinfo，避免在主协程阻塞 socket.getaddrinfo。"""

    async def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[int, ...]]:
        return [
            (2, 1, 6, "", ("192.0.2.2", 0)),
            (10, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]

    mock_loop = MagicMock()
    mock_loop.getaddrinfo = fake_getaddrinfo
    monkeypatch.setattr(probe_service.asyncio, "get_running_loop", lambda: mock_loop)
    ip, fam = await probe_service._resolve_target_ip_async("x.test")
    assert ip == "192.0.2.2"
    assert fam == "ipv4"


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
