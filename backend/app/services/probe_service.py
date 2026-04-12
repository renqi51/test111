"""Authorized-lab reachability checks: DNS resolution + HTTPS HEAD.

Policy is enforced via settings (allowlist suffixes or open mode for partner lab).
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from app.core.config import settings
from app.schemas.probe import ProbeRunRequest, ProbeRunResponse, ProbeTargetResult, ProbeStatusPayload

_LAST_RUN: dict[str, Any] | None = None

# 3GPP / 核心网常见 UDP 服务（授权实验室内连通性探测）
UDP_PROBE_PORTS: tuple[int, ...] = (500, 4500, 2152)


def get_last_run() -> dict[str, Any] | None:
    return _LAST_RUN


def probe_status() -> ProbeStatusPayload:
    suf = (settings.probe_allowlist_suffixes or "").strip()
    return ProbeStatusPayload(
        enabled=settings.probe_enabled,
        probe_mode=settings.probe_mode,
        allowlist_configured=bool(suf),
        verify_tls=settings.probe_verify_tls,
        timeout_sec=settings.probe_timeout_sec,
        max_concurrent=settings.probe_max_concurrent,
    )


def _normalize_host(raw: str) -> str:
    s = raw.strip()
    if not s:
        return ""
    if "://" in s:
        parsed = urlparse(s)
        h = parsed.hostname
        return (h or "").lower()
    # host:port
    return s.split("/")[0].split(":")[0].lower().strip(".")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_allowlist_cidrs() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = (settings.probe_allowlist_cidrs or "").strip()
    if not raw:
        return []
    out: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in raw.split(","):
        p = part.strip()
        if not p:
            continue
        try:
            out.append(ipaddress.ip_network(p, strict=False))
        except ValueError:
            continue
    return out


def _ip_allowed_by_cidr_allowlist(host: str) -> tuple[bool, str]:
    if not _is_ip_literal(host):
        return False, "not_ip_literal"
    nets = _parse_allowlist_cidrs()
    if not nets:
        return False, "cidr_allowlist_empty"
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False, "invalid_ip"
    for net in nets:
        if addr in net:
            return True, f"cidr_match:{net}"
    return False, "ip_not_in_cidr_allowlist"


def _host_permitted(host: str) -> tuple[bool, str]:
    if not settings.probe_enabled:
        return False, "probe_disabled"
    mode = (settings.probe_mode or "allowlist").lower()
    if mode == "open":
        return True, "open_mode"
    if _is_ip_literal(host):
        ok, why = _ip_allowed_by_cidr_allowlist(host)
        if ok:
            return True, why
        return False, why if why != "cidr_allowlist_empty" else "ip_not_allowed_in_allowlist_mode"

    suf_raw = (settings.probe_allowlist_suffixes or "").strip()
    if not suf_raw:
        return False, "allowlist_empty_configure_EXPOSURE_PROBE_ALLOWLIST_SUFFIXES"

    host_l = host.lower()
    for part in suf_raw.split(","):
        p = part.strip().lower().strip(".")
        if not p:
            continue
        if host_l == p or host_l.endswith("." + p):
            return True, f"suffix_match:{p}"
    return False, "host_not_in_allowlist"


def _resolve_dns(host: str) -> tuple[bool, list[str], str | None]:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addrs: list[str] = []
        for item in infos:
            sockaddr = item[4]
            if sockaddr:
                addrs.append(sockaddr[0])
        uniq = list(dict.fromkeys(addrs))
        return bool(uniq), uniq, None
    except OSError as exc:
        return False, [], str(exc)


async def _https_head(host: str) -> tuple[bool | None, int | None, float | None, str | None]:
    url = f"https://{host}/"
    verify = settings.probe_verify_tls
    timeout = httpx.Timeout(settings.probe_timeout_sec, connect=min(3.0, settings.probe_timeout_sec))
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=timeout, verify=verify, follow_redirects=False) as client:
            resp = await client.head(url)
            elapsed = (time.perf_counter() - started) * 1000.0
            # Any HTTP status means TLS + server spoke HTTP (405/404/401 still "reachable").
            return True, resp.status_code, elapsed, None
    except httpx.HTTPError as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return False, None, elapsed, str(exc)
    except Exception as exc:  # noqa: BLE001
        elapsed = (time.perf_counter() - started) * 1000.0
        return False, None, elapsed, str(exc)


def _parse_ports() -> list[int]:
    values: list[int] = []
    for x in (settings.probe_tcp_ports or "").split(","):
        s = x.strip()
        if not s:
            continue
        try:
            p = int(s)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            values.append(p)
    return list(dict.fromkeys(values))


def _ike_sa_init_packet(major: int, minor: int) -> bytes:
    """IKE header (SPIi/SPIr + 12B header); exchange=IKE_SA_INIT(34). major/minor nibble-encoded."""
    spi_i = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    spi_r = b"\x00" * 8
    ver = ((major & 0x0F) << 4) | (minor & 0x0F)
    length = 28
    hdr = struct.pack("!BBBBII", 0, ver, 34, 0, 0, length)
    return spi_i + spi_r + hdr


def _gtpu_echo_spike() -> bytes:
    """Minimal GTP-U v1 echo request–like payload for UDP 2152."""
    return struct.pack("!BBHI", 0x20, 1, 4, 0) + b"\x00\x00\x00\x00"


def _gtpu_truncated_spike() -> bytes:
    """Declared length shorter than payload — some stacks answer with error, others hard-drop."""
    return struct.pack("!BBHI", 0x20, 1, 8, 0) + b"\x00\x00\x00\x00\x00\x00"


def _udp_send_recv_once(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
    except OSError:
        return None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(_fam, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(payload, sockaddr[:2])
            data, _ = sock.recvfrom(4096)
            return data if data else None
        except socket.timeout:
            pass
        except OSError:
            pass
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    return None


def _parse_ike_response_hint(data: bytes) -> str:
    if len(data) < 28:
        return f"short_packet_len={len(data)}"
    next_p = data[16]
    ver_b = data[17]
    exch = data[18]
    maj, mn = (ver_b >> 4) & 0x0F, ver_b & 0x0F
    notes = [f"next_payload={next_p}", f"peer_hdr_version={maj}.{mn}", f"exchange_type={exch}"]
    # NOTIFY often present on INVALID_SYNTAX / INVALID_MAJOR_VERSION style replies
    if b"INVALID" in data.upper() or next_p == 41:
        notes.append("likely_NOTIFY")
    return ";".join(notes)


def _udp_spikes_for_port(host: str, port: int, timeout: float) -> tuple[bool, list[str]]:
    """Run multiple lightweight spikes per UDP port; record reply vs silent drop."""
    findings: list[str] = []
    any_reply = False
    if port in (500, 4500):
        probes: list[tuple[str, bytes]] = [
            ("ikev2_sa_init_v2_0", _ike_sa_init_packet(2, 0)),
            ("ike_invalid_major_3_1", _ike_sa_init_packet(3, 1)),
            ("ike_invalid_major_15_15", _ike_sa_init_packet(15, 15)),
        ]
    elif port == 2152:
        probes = [
            ("gtpv1_echo_std", _gtpu_echo_spike()),
            ("gtpv1_bad_msgtype_ff", struct.pack("!BBHI", 0x20, 0xFF, 8, 0) + b"\x00\x00\x00\x00"),
            ("gtp_trunc_length", _gtpu_truncated_spike()),
        ]
    else:
        probes = [("raw_zero2", b"\x00\x00")]
    for name, pkt in probes:
        data = _udp_send_recv_once(host, port, pkt, timeout)
        if data:
            any_reply = True
            hx = data[:48].hex()
            hint = _parse_ike_response_hint(data) if port in (500, 4500) else f"len={len(data)}"
            findings.append(f"udp:{port}:{name}:REPLY bytes={len(data)} hex48={hx} {hint}")
        else:
            findings.append(f"udp:{port}:{name}:SILENT_DROP_OR_TIMEOUT")
    return any_reply, findings


def _sip_options_probe(host: str, timeout: float) -> str | None:
    req = (
        f"OPTIONS sip:{host} SIP/2.0\r\n"
        "Via: SIP/2.0/TCP probe;branch=z9hG4bK-redteam\r\n"
        f"To: <sip:{host}>\r\n"
        f"From: <sip:probe@{host}>;tag=p1\r\n"
        "Call-ID: redteam-probe@local\r\n"
        "CSeq: 1 OPTIONS\r\n"
        "Max-Forwards: 70\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode()
    try:
        with socket.create_connection((host, 5060), timeout=min(3.0, timeout)) as s:
            s.settimeout(timeout)
            s.sendall(req)
            buf = s.recv(8192)
            if not buf:
                return None
            first = buf.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            return first[:500]
    except OSError:
        return None


def _http_head_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=min(3.0, timeout)) as s:
            s.settimeout(timeout)
            s.sendall(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
            buf = s.recv(2048)
            if not buf:
                return None
            return buf.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")[:500]
    except OSError:
        return None


def _tcp_peek_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=min(3.0, timeout)) as s:
            s.settimeout(timeout)
            buf = s.recv(512)
            if not buf:
                return None
            return buf.decode("utf-8", errors="replace")[:500]
    except OSError:
        return None


async def _tcp_banner_grab(host: str, open_tcp: list[int]) -> dict[str, str]:
    to = min(2.5, settings.probe_timeout_sec)
    out: dict[str, str] = {}

    async def _one(port: int) -> None:
        key = str(port)
        if port == 5060:
            line = await asyncio.to_thread(_sip_options_probe, host, to)
            if line:
                out[key] = line
            return
        if port == 80:
            line = await asyncio.to_thread(_http_head_banner, host, 80, to)
            if line:
                out[key] = line
            return
        if port == 443:
            return
        line = await asyncio.to_thread(_tcp_peek_banner, host, port, to)
        if line:
            out[key] = line

    await asyncio.gather(*[_one(p) for p in open_tcp])
    return out


async def _scan_tcp_ports(host: str) -> list[int]:
    ports = _parse_ports()
    if not ports:
        return []

    async def _check(port: int) -> int | None:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=min(2.5, settings.probe_timeout_sec))
            writer.close()
            await writer.wait_closed()
            return port
        except Exception:  # noqa: BLE001
            return None

    checked = await asyncio.gather(*[_check(p) for p in ports])
    return [p for p in checked if p is not None]


async def _scan_udp_ports(host: str) -> tuple[list[int], list[str]]:
    timeout = min(2.5, settings.probe_timeout_sec)
    findings_acc: list[str] = []

    async def _check(port: int) -> tuple[int | None, list[str]]:
        ok, lines = await asyncio.to_thread(_udp_spikes_for_port, host, port, timeout)
        return (port if ok else None), lines

    checked = await asyncio.gather(*[_check(p) for p in UDP_PROBE_PORTS])
    open_list: list[int] = []
    for port_maybe, lines in checked:
        findings_acc.extend(lines)
        if port_maybe is not None:
            open_list.append(port_maybe)
    return sorted({*open_list}), findings_acc


def _infer_services(tcp_ports: list[int], udp_ports: list[int]) -> list[str]:
    hints: list[str] = []
    tcp_map = {
        443: "https",
        80: "http",
        5060: "sip",
        2152: "gtp-u",
        38412: "ngap",
    }
    udp_map = {
        500: "ipsec/epdg",
        4500: "ipsec/epdg",
        2152: "gtp-u",
    }
    for p in tcp_ports:
        hints.append(tcp_map.get(p, f"tcp-{p}"))
    for p in udp_ports:
        hints.append(udp_map.get(p, f"udp-{p}"))
    seen: set[str] = set()
    out: list[str] = []
    for h in hints:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _fetch_tls_subject(host: str) -> str | None:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=min(3.0, settings.probe_timeout_sec)) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert() or {}
                subject = cert.get("subject")
                if not subject:
                    return None
                parts: list[str] = []
                for group in subject:
                    for k, v in group:
                        parts.append(f"{k}={v}")
                return ", ".join(parts) if parts else None
    except Exception:  # noqa: BLE001
        return None


async def _probe_one(host: str, original: str, sem: asyncio.Semaphore) -> ProbeTargetResult:
    permitted, reason = _host_permitted(host)
    if not permitted:
        return ProbeTargetResult(
            target=original,
            host=host,
            permitted=False,
            policy_reason=reason,
        )

    async with sem:
        dns_ok, addrs, dns_err = await asyncio.to_thread(_resolve_dns, host)
        res = ProbeTargetResult(
            target=original,
            host=host,
            permitted=True,
            policy_reason=reason,
            dns_ok=dns_ok,
            dns_addresses=addrs[:8],
            error=dns_err,
        )
        if not dns_ok:
            return res

        open_tcp, udp_pair = await asyncio.gather(_scan_tcp_ports(host), _scan_udp_ports(host))
        open_udp, udp_findings = udp_pair
        res.open_ports = open_tcp
        res.open_udp_ports = open_udp
        res.udp_spike_findings = udp_findings
        res.service_hints = _infer_services(open_tcp, open_udp)

        res.tcp_banners = await _tcp_banner_grab(host, open_tcp)

        https_ok, status, lat, tls_err = await _https_head(host)
        res.https_ok = https_ok
        res.https_status = status
        res.https_latency_ms = round(lat, 2) if lat is not None else None
        res.tls_error = tls_err
        if 443 in open_tcp:
            res.tls_subject = await asyncio.to_thread(_fetch_tls_subject, host)
        return res


async def run_probe(req: ProbeRunRequest) -> ProbeRunResponse:
    if not settings.probe_enabled:
        raise RuntimeError("Probing is disabled (EXPOSURE_PROBE_ENABLED=false).")

    run_id = str(uuid4())
    started = datetime.now(timezone.utc).isoformat()

    seen: set[str] = set()
    normalized: list[tuple[str, str]] = []
    for t in req.targets:
        h = _normalize_host(t)
        if not h or h in seen:
            continue
        seen.add(h)
        normalized.append((h, t.strip()))

    sem = asyncio.Semaphore(max(1, settings.probe_max_concurrent))
    results = await asyncio.gather(*[_probe_one(h, orig, sem) for h, orig in normalized])

    finished = datetime.now(timezone.utc).isoformat()
    summary = {
        "total": len(results),
        "permitted": sum(1 for r in results if r.permitted),
        "dns_ok": sum(1 for r in results if r.dns_ok),
        "https_ok": sum(1 for r in results if r.https_ok is True),
        "tcp_open": sum(1 for r in results if bool(r.open_ports)),
        "udp_open": sum(1 for r in results if bool(r.open_udp_ports)),
        "sip_hint": sum(1 for r in results if "sip" in r.service_hints),
        "gtp_hint": sum(1 for r in results if "gtp-u" in r.service_hints),
        "ipsec_hint": sum(1 for r in results if "ipsec/epdg" in r.service_hints),
        "tcp_banner_ports": sum(len(r.tcp_banners or {}) for r in results),
        "udp_spike_reply_lines": sum(
            sum(1 for line in (r.udp_spike_findings or []) if ":REPLY " in line) for r in results
        ),
    }

    payload = ProbeRunResponse(
        run_id=run_id,
        started_at=started,
        finished_at=finished,
        probe_mode=(settings.probe_mode or "allowlist").lower(),
        results=list(results),
        summary=summary,
    )
    global _LAST_RUN
    _LAST_RUN = payload.model_dump()
    return payload
