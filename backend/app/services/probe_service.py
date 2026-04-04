"""Authorized-lab reachability checks: DNS resolution + HTTPS HEAD.

Policy is enforced via settings (allowlist suffixes or open mode for partner lab).
"""
from __future__ import annotations

import asyncio
import ipaddress
import ssl
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from app.core.config import settings
from app.schemas.probe import ProbeRunRequest, ProbeRunResponse, ProbeTargetResult, ProbeStatusPayload

_LAST_RUN: dict[str, Any] | None = None


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


def _host_permitted(host: str) -> tuple[bool, str]:
    if not settings.probe_enabled:
        return False, "probe_disabled"
    mode = (settings.probe_mode or "allowlist").lower()
    if mode == "open":
        return True, "open_mode"
    if _is_ip_literal(host):
        return False, "ip_not_allowed_in_allowlist_mode"

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


def _infer_services(open_ports: list[int]) -> list[str]:
    hints: list[str] = []
    mapping = {
        443: "https",
        80: "http",
        5060: "sip",
        2152: "gtp-u",
        38412: "ngap",
    }
    for p in open_ports:
        name = mapping.get(p, f"tcp-{p}")
        hints.append(name)
    return hints


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

        open_ports = await _scan_tcp_ports(host)
        res.open_ports = open_ports
        res.service_hints = _infer_services(open_ports)

        https_ok, status, lat, tls_err = await _https_head(host)
        res.https_ok = https_ok
        res.https_status = status
        res.https_latency_ms = round(lat, 2) if lat is not None else None
        res.tls_error = tls_err
        if 443 in open_ports:
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
        "sip_hint": sum(1 for r in results if "sip" in r.service_hints),
        "gtp_hint": sum(1 for r in results if "gtp-u" in r.service_hints),
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
