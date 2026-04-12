"""Unit tests for UDP spike matrix and IKE packet helpers (no live network)."""

from __future__ import annotations

import socket
from unittest.mock import MagicMock

import pytest

from app.services import probe_service


def test_ike_sa_init_packet_v2_length() -> None:
    pkt = probe_service._ike_sa_init_packet(2, 0)
    assert len(pkt) == 28
    assert pkt[17] == 0x20
    assert pkt[18] == 34  # IKE_SA_INIT


def test_ike_malformed_version_byte() -> None:
    pkt = probe_service._ike_sa_init_packet(3, 1)
    assert pkt[17] == 0x31


def test_gtpu_spikes_non_empty() -> None:
    assert len(probe_service._gtpu_echo_spike()) >= 8
    assert len(probe_service._gtpu_truncated_spike()) >= 8


def test_udp_spikes_all_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe_service, "_udp_send_recv_once", lambda *a, **k: None)
    ok, lines = probe_service._udp_spikes_for_port("192.0.2.1", 500, 0.05)
    assert ok is False
    assert len(lines) == 3
    assert all("SILENT_DROP_OR_TIMEOUT" in x for x in lines)


def test_udp_spikes_first_probe_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def _fake_send(_host: str, _port: int, payload: bytes, _timeout: float) -> bytes | None:
        calls.append(payload.hex()[:16])
        if len(payload) == 28 and payload[17] == 0x20:
            return b"\x00" * 64
        return None

    monkeypatch.setattr(probe_service, "_udp_send_recv_once", _fake_send)
    ok, lines = probe_service._udp_spikes_for_port("192.0.2.2", 500, 0.05)
    assert ok is True
    assert any("REPLY" in x for x in lines)
    assert any("SILENT" in x for x in lines)


def test_parse_ike_response_hint_reads_exchange() -> None:
    # minimal 28-byte IKE-shaped reply
    data = b"\x00" * 16 + bytes([0, 0x20, 34, 0]) + b"\x00" * 8
    hint = probe_service._parse_ike_response_hint(data)
    assert "exchange_type=34" in hint


@pytest.mark.asyncio
async def test_resolve_udp_sockaddrs_async_uses_loop_getaddrinfo(monkeypatch: pytest.MonkeyPatch) -> None:
    """UDP 解析应走 loop.getaddrinfo，与主探测异步 DNS 策略一致。"""

    async def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[int, ...]]:
        return [(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("192.0.2.9", 500))]

    mock_loop = MagicMock()
    mock_loop.getaddrinfo = fake_getaddrinfo
    monkeypatch.setattr(probe_service.asyncio, "get_running_loop", lambda: mock_loop)
    rows = await probe_service._resolve_udp_sockaddrs_async("svc.lab", 500)
    assert rows and rows[0][1][0] == "192.0.2.9"


@pytest.mark.asyncio
async def test_udp_spikes_async_all_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    """无解析结果时应全部为 SILENT，与同步矩阵语义一致。"""

    async def _no_addrs(*a: object, **k: object) -> list[tuple[int, tuple]]:
        return []

    monkeypatch.setattr(probe_service, "_resolve_udp_sockaddrs_async", _no_addrs)
    ok, lines = await probe_service._udp_spikes_for_port_async("192.0.2.1", 500, 0.05)
    assert ok is False
    assert len(lines) == 3
    assert all("SILENT_DROP_OR_TIMEOUT" in x for x in lines)
