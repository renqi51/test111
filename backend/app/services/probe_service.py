"""Authorized-lab reachability checks: DNS resolution + HTTPS HEAD.

Policy is enforced via settings (allowlist suffixes or open mode for partner lab).
"""
from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import ssl
import struct
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from app.core.config import settings
from app.schemas.probe import ProbeRunRequest, ProbeRunResponse, ProbeTargetResult, ProbeStatusPayload

_LAST_RUN: dict[str, Any] | None = None

# 3GPP / 核心网常见 UDP 服务（授权实验室内连通性探测）
UDP_PROBE_PORTS: tuple[int, ...] = (500, 4500, 2152)

# SCTP 探测端口：38412 为 3GPP NG-RAN 与 AMF 间 N2 口 NGAP 在现网中最常见的 SCTP 偶联目的端口（TS 38.412）。
# 注意：与 TCP 38412 无必然等价关系；此处仅针对 SCTP 四元组发送 INIT，不依赖 TCP connect 成功。
SCTP_PROBE_PORTS: tuple[int, ...] = (38412,)

# ---------------------------------------------------------------------------
# Scapy 可选加载：未安装时 SCTP 探测返回明确原因字符串，避免“假装已扫 SCTP”。
# sr1 的类型在运行时由 Scapy 提供；此处用 Callable 描述“发送 1 包并收 1 应”的抽象接口便于单测打桩。
# ---------------------------------------------------------------------------
_scapy_sr1: Callable[..., Any] | None
try:
    from scapy.all import sr1 as _scapy_sr1_import  # type: ignore[import-untyped, import-not-found]

    _scapy_sr1 = _scapy_sr1_import
    _SCAPY_AVAILABLE = True
except ImportError:
    _scapy_sr1 = None
    _SCAPY_AVAILABLE = False


def _sr1_dispatch(pkt: Any, timeout: float, *, verbose: int = 0) -> Any:
    """
    对 Scapy sr1 的薄封装，便于单元测试 patch 本函数而无需 import 重型 scapy 依赖。

    参数:
    - pkt: Scapy 已构造好的分层报文（如 IP/SCTP/SCTPChunkInit），由上层保证 dst 合法且在授权范围内。
    - timeout: 秒；传给 sr1 作为“等待一个应答”的最大阻塞时间，防止探针无限挂起。
    - verbose: 传入 sr1 的 verbose；0 表示关闭交互式刷屏日志。
    """
    if _scapy_sr1 is None:
        raise RuntimeError("scapy_sr1_unavailable")
    return _scapy_sr1(pkt, timeout=timeout, verbose=verbose)


def _resolve_target_ip_for_l3(host: str) -> tuple[str | None, str]:
    """
    将 FQDN 解析为用于 L3（IP/IPv6）封装的第一个可用地址（同步版，仅保留给单元测试打桩或遗留同步调用）。

    生产路径请使用 ``_resolve_target_ip_async``：在协程里直接 ``socket.getaddrinfo`` 会阻塞事件循环，
    SCTP 探测若未来误在主协程调用同步解析将导致整服务卡死。
    """
    # 使用默认 getaddrinfo（不传 type），避免 SOCK_RAW 在 Windows 等平台对解析路径不兼容。
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return None, "ipv4"
    for fam, _, _, _, sockaddr in infos:
        if fam == socket.AF_INET and sockaddr:
            return str(sockaddr[0]), "ipv4"
    for fam, _, _, _, sockaddr in infos:
        if fam == socket.AF_INET6 and sockaddr:
            return str(sockaddr[0]), "ipv6"
    return None, "ipv4"


async def _resolve_target_ip_async(host: str) -> tuple[str | None, str]:
    """
    异步 DNS：通过 ``asyncio`` 事件循环的 ``getaddrinfo`` 完成解析，避免阻塞主 loop。

    为什么 SCTP 场景必须走此路径：
    - 旧实现把 ``socket.getaddrinfo`` 放在 ``to_thread`` 里虽能缓解，但仍占用线程池且在高并发探测下
      会与大量 ``to_thread`` 任务争抢 worker；更关键的是一旦代码路径回归主协程调用同步解析，
      将直接卡死事件循环。统一 ``await loop.getaddrinfo`` 与 HTTPS/SBI 等异步 I/O 模型一致。
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=0, proto=0, flags=0)
    except OSError:
        return None, "ipv4"
    for fam, _, _, _, sockaddr in infos:
        if fam == socket.AF_INET and sockaddr:
            return str(sockaddr[0]), "ipv4"
    for fam, _, _, _, sockaddr in infos:
        if fam == socket.AF_INET6 and sockaddr:
            return str(sockaddr[0]), "ipv6"
    return None, "ipv4"


def _sctp_scapy_init_on_resolved_ip(dst_ip: str, fam: str, dport: int, timeout: float) -> list[str]:
    """
    在已解析的 IP 上发送 SCTP INIT（Scapy），并记录 INIT-ACK/静默丢弃/异常。

    与 ``_sctp_init_probe_sync`` 的区别：本函数**不做 DNS**，仅执行 Scapy 阻塞 I/O；
    调用方应先在协程里 ``await _resolve_target_ip_async``，再 ``asyncio.to_thread`` 进入此函数，
    从而把「可异步的解析」与「必须同步的 raw 发包」清晰分层。
    """
    if not _SCAPY_AVAILABLE:
        return [f"sctp:{dport}:SCAPY_NOT_INSTALLED pip_install_scapy"]

    sport = random.randint(30000, 60000)
    try:
        if fam == "ipv4":
            # IP(dst=...): IPv4 目的地址字段；ttl 使用 Scapy 默认，由内核路由表决定转发路径。
            from scapy.layers.inet import IP  # noqa: PLC0415
            from scapy.layers.sctp import SCTP, SCTPChunkInit  # noqa: PLC0415

            # SCTP(sport,dport): SCTP 公共头源/目的端口；dport 与 3GPP 侧监听进程绑定。
            # SCTPChunkInit(): 构造 INIT 分片；内部字段（initiate_tag、a_rwnd、outbound_streams 等）
            #                  由 Scapy 填默认值，足以触发多数实现返回 INIT-ACK 或 ABORT。
            pkt = IP(dst=dst_ip) / SCTP(sport=sport, dport=dport) / SCTPChunkInit()
        else:
            # IPv6(dst=...): 双栈目标走 SCTP over IPv6；其余与 IPv4 分支语义一致。
            from scapy.layers.inet6 import IPv6  # noqa: PLC0415
            from scapy.layers.sctp import SCTP, SCTPChunkInit  # noqa: PLC0415

            pkt = IPv6(dst=dst_ip) / SCTP(sport=sport, dport=dport) / SCTPChunkInit()

        # sr1: 发 1 包收 1 答；若超时无答返回 None —— 常见于防火墙静默丢或端口未监听 SCTP。
        ans = _sr1_dispatch(pkt, timeout=timeout, verbose=0)
        if ans is None:
            return [f"sctp:{dport}:INIT_timeout_or_silent_drop sport={sport} dst_ip={dst_ip}"]
        return [f"sctp:{dport}:INIT_reply sport={sport} dst_ip={dst_ip} summary={ans.summary()}"]
    except Exception as exc:  # noqa: BLE001 — 捕获 WinPcap/Npcap 未装、权限不足等环境错误并回传截断信息
        return [f"sctp:{dport}:INIT_send_failed sport={sport} err={str(exc)[:220]}"]


def _sctp_init_probe_sync(host: str, dport: int, timeout: float) -> list[str]:
    """
    同步 SCTP 单端口探测（含同步 DNS）：仅用于单测打桩或工具式调用；生产路径请用 ``_sctp_probe_all_ports_async``。
    """
    if not _SCAPY_AVAILABLE:
        return [f"sctp:{dport}:SCAPY_NOT_INSTALLED pip_install_scapy"]
    dst_ip, fam = _resolve_target_ip_for_l3(host)
    if not dst_ip:
        return [f"sctp:{dport}:NO_IP_FOR_L3 host_resolve_failed"]
    return _sctp_scapy_init_on_resolved_ip(dst_ip, fam, dport, timeout)


async def _sctp_probe_all_ports_async(host: str, ports: tuple[int, ...], timeout: float) -> list[str]:
    """
    对多个 SCTP 端口顺序执行 INIT：先 ``await`` 异步 DNS，再逐端口 ``to_thread`` 跑 Scapy。

    为什么必须先异步解析再 to_thread：
    - DNS 解析属于网络就绪等待，应交给事件循环调度；若整段包进单个线程函数，线程池易被
      慢解析占满，且违背「解析异步化、仅 raw 发包进线程」的分层原则。
    """
    if not _SCAPY_AVAILABLE:
        return [f"sctp:{p}:SCAPY_NOT_INSTALLED pip_install_scapy" for p in ports]
    dst_ip, fam = await _resolve_target_ip_async(host)
    if not dst_ip:
        return [f"sctp:{p}:NO_IP_FOR_L3 host_resolve_failed" for p in ports]
    out: list[str] = []
    for p in ports:
        lines = await asyncio.to_thread(_sctp_scapy_init_on_resolved_ip, dst_ip, fam, p, timeout)
        out.extend(lines)
    return out


def _iter_exception_chain(root: BaseException) -> list[BaseException]:
    """遍历 __cause__ / __context__ 链，供 TLS/mTLS 语义判断。"""
    chain: list[BaseException] = []
    seen: set[int] = set()
    stack: list[BaseException] = [root]
    while stack:
        e = stack.pop()
        if id(e) in seen:
            continue
        seen.add(id(e))
        chain.append(e)
        if e.__cause__ is not None and id(e.__cause__) not in seen:
            stack.append(e.__cause__)
        if e.__context__ is not None and e.__context__ is not e.__cause__ and id(e.__context__) not in seen:
            stack.append(e.__context__)
    return chain


def _tls_handshake_suggests_mtls_enforced(exc: BaseException) -> bool:
    """
    判断异常是否更像「服务端强制 mTLS（要求客户端证书）」而非普通超时。

    为什么需要单独分支：
    - 现网 5G SBI 大量在 TLS 层要求双向证书；httpx 无客户端证书时往往在握手阶段失败，
      若简单映射为 timeout/ConnectError，红队观测会误判为「网络不可达」而忽略安全控制强度。
    - 启发式刻意**收紧**：不再把泛化的 ``handshake failure`` / ``tlsv1 alert`` 一律标成 mTLS，
      否则无 SNI、协议版本不匹配、中间盒 RST 等噪声会被误标为 ``mTLS_Enforced``，污染暴露面分级。
    - 仅当异常链上出现「证书/CA/对端要求客户端证书」类关键词或等价 SSLError 子类型时才返回 True。
    """
    _mtls_needles = (
        "alert certificate",
        "certificate required",
        "certificate_required",  # OpenSSL：TLSV1_ALERT_CERTIFICATE_REQUIRED
        "alert unknown ca",
        "unknown ca",
        "bad certificate",
        "cert chain",
        "unable to get local issuer certificate",
    )
    for cur in _iter_exception_chain(exc):
        low = str(cur).lower()
        if isinstance(cur, ssl.SSLError) and any(k in low for k in _mtls_needles):
            return True
        if any(k in low for k in _mtls_needles):
            return True
    return False


def _sbi_path_error_payload(exc: BaseException) -> dict[str, Any]:
    """将 httpx/下层 TLS 异常规整为 paths[path] 条目。"""
    row: dict[str, Any] = {"status": None, "http_version": None, "error": str(exc)[:260]}
    if _tls_handshake_suggests_mtls_enforced(exc):
        row["mTLS_Enforced"] = True
    return row


async def _probe_sbi_http2_unauth(host: str) -> dict[str, Any]:
    """
    使用 httpx 强制启用 HTTP/2 客户端栈，对 NRF 发现类无状态接口发起 GET，用于越权/鉴权/mTLS 边界观测。

    设计要点:
    - http2=True: 要求底层尝试 TLS ALPN 协商 h2；若对端仅 http/1.1，httpx 会记录实际协商版本，便于区分“老栈”与“真 SBI”。
    - 路径选用 ``Nnrf_NFDiscovery`` 的 ``GET /nnrf-disc/v1/nf-instances``（TS 29.510）：不依赖 SUPI/IMSI，
      比硬编码 UDM 假 IMSI 更接近真实「服务发现」暴露面；若需 UDM 业务语义应在拿到合法标识后再测。
    - Authorization: 使用结构上像 JWT 但签名无效的 Bearer，逼迫 API 网关走完整 token 校验分支，
      从而用 HTTP 状态码区分：401（未认证）、403（已认证无权限）、200（异常放行风险）等。
    - follow_redirects=False: 禁止跟随 302 到门户页，避免把登录页 HTML 误判为 API 成功响应。
    - verify: 与全局 probe 配置一致，防止实验室内错误信任非法 TLS 证书。
    """
    timeout = httpx.Timeout(settings.probe_timeout_sec, connect=min(3.0, settings.probe_timeout_sec))
    paths = ("/nnrf-disc/v1/nf-instances",)
    out: dict[str, Any] = {"paths": {}, "note": "nrf_discovery_nf_instances_http2_probe_no_supi"}
    headers = {
        # Bearer 令牌三段式外观 + 明显无效签名：触发 API 网关解析与验签，而非被当作缺失头直接 401。
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.forced-invalid-sig",
        "Accept": "application/json",
        "User-Agent": "5g-core-sbi-redteam-probe/1.0",
    }
    base = f"https://{host}"
    try:
        # AsyncClient 生命周期内复用连接池；http2=True 打开 HTTP/2 帧编解码与多路复用路径。
        async with httpx.AsyncClient(
            http2=True,
            verify=settings.probe_verify_tls,
            timeout=timeout,
            follow_redirects=False,
        ) as client:
            for path in paths:
                url = f"{base}{path}"
                try:
                    # GET: SBI 为 REST 语义；GET 对只读列表/资源模板仍可能返回 401/403/404，足以做鉴权面分级。
                    resp = await client.get(url, headers=headers)
                    # http_version: httpx 在响应上暴露协商到的应用层版本字符串，如 "HTTP/2" 或 "HTTP/1.1"。
                    hver = getattr(resp, "http_version", None) or "unknown"
                    out["paths"][path] = {
                        "status": resp.status_code,
                        "http_version": hver,
                        "www_authenticate": (resp.headers.get("www-authenticate") or "")[:200],
                    }
                except httpx.HTTPError as exc:
                    out["paths"][path] = _sbi_path_error_payload(exc)
    except Exception as exc:  # noqa: BLE001 — TLS 握手失败、连接重置等写入顶层，避免整段探测无声崩溃
        out["fatal"] = str(exc)[:400]
        if _tls_handshake_suggests_mtls_enforced(exc):
            out["mTLS_Enforced"] = True
    return out


def get_last_run() -> dict[str, Any] | None:
    return _LAST_RUN


def probe_status() -> ProbeStatusPayload:
    suf = (settings.probe_allowlist_suffixes or "").strip()
    cid = (settings.probe_allowlist_cidrs or "").strip()
    suf_ok = bool(suf)
    cid_ok = bool(cid)
    return ProbeStatusPayload(
        enabled=settings.probe_enabled,
        probe_mode=settings.probe_mode,
        allowlist_configured=suf_ok or cid_ok,
        allowlist_suffixes_configured=suf_ok,
        allowlist_cidrs_configured=cid_ok,
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


async def _resolve_dns_async(host: str) -> tuple[bool, list[str], str | None]:
    """
    异步 DNS：与 SCTP 侧一致，使用 ``loop.getaddrinfo`` 替代 ``socket.getaddrinfo``。

    为什么主探测路径不能用同步 getaddrinfo（即便包在 to_thread 里）：
    - 批量主机探测时，每个目标再起线程做解析会放大调度开销；统一异步解析可把 DNS 与 httpx I/O
      纳入同一事件循环，避免线程池在「纯等待 DNS」场景下被无意义占满。
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM, family=socket.AF_UNSPEC)
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
    """
    对根路径执行 HTTPS HEAD；AsyncClient 强制 http2=True 以便与 SBI 侧 ALPN=h2 行为对齐。

    - HEAD: 减少下行 body；若服务端拒绝 HEAD 可能返回 405，仍视为 TLS+HTTP 栈存活。
    - http2=True: 启用 HTTP/2 协商路径；失败时由 httpx 抛错或退回底层实现记录于 tls_error。
    """
    url = f"https://{host}/"
    verify = settings.probe_verify_tls
    timeout = httpx.Timeout(settings.probe_timeout_sec, connect=min(3.0, settings.probe_timeout_sec))
    started = time.perf_counter()
    try:
        # limits: 限制连接池并发，避免在批量探测目标时 httpx 默认池过大占用文件描述符。
        async with httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            follow_redirects=False,
            http2=True,
            limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
        ) as client:
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


def _udp_send_recv_on_sockaddrs(fam_sockaddrs: list[tuple[int, tuple[Any, ...]]], payload: bytes, timeout: float) -> bytes | None:
    """
    在给定已解析的 UDP 套接字地址列表上尝试 send/recv（同步阻塞）。

    为什么从 ``_udp_send_recv_once`` 拆出本函数：
    - DNS 解析已上移到协程 ``await loop.getaddrinfo`` 后，线程内只应做短阻塞的 UDP I/O，
      避免在 ``asyncio.to_thread`` 里再次调用 ``getaddrinfo`` 双重占线程且拉长临界区。
    """
    for fam, sockaddr in fam_sockaddrs:
        sock: socket.socket | None = None
        try:
            sock = socket.socket(fam, socket.SOCK_DGRAM)
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


async def _resolve_udp_sockaddrs_async(host: str, port: int) -> list[tuple[int, tuple[Any, ...]]]:
    """
    异步解析 UDP 目的地址元组列表（与 SCTP/DNS 主路径一致走 ``loop.getaddrinfo``）。

    为什么 UDP spike 也必须异步解析：
    - ``_scan_udp_ports`` 在协程里 ``gather`` 多个端口任务；若每个任务在线程里 ``getaddrinfo``，
      高并发目标扫描时仍会把默认线程池打满；解析提到此处可与 TCP/HTTPS 调度合并。
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except OSError:
        return []
    out: list[tuple[int, tuple[Any, ...]]] = []
    seen: set[tuple[Any, ...]] = set()
    for fam, _typ, _proto, _canon, sockaddr in infos:
        if not sockaddr:
            continue
        if sockaddr in seen:
            continue
        seen.add(sockaddr)
        out.append((fam, sockaddr))
    return out


def _udp_resolve_sync(host: str, port: int) -> list[tuple[int, tuple[Any, ...]]]:
    """同步解析 UDP 地址列表（单测打桩或工具调用）；生产路径请用 ``_resolve_udp_sockaddrs_async``。"""
    try:
        infos = socket.getaddrinfo(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except OSError:
        return []
    out: list[tuple[int, tuple[Any, ...]]] = []
    seen: set[tuple[Any, ...]] = set()
    for fam, _typ, _proto, _canon, sockaddr in infos:
        if not sockaddr:
            continue
        if sockaddr in seen:
            continue
        seen.add(sockaddr)
        out.append((fam, sockaddr))
    return out


def _udp_send_recv_once(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    """同步路径：解析 + 发送（供单测 monkeypatch 或遗留调用）。"""
    addrs = _udp_resolve_sync(host, port)
    if not addrs:
        return None
    return _udp_send_recv_on_sockaddrs(addrs, payload, timeout)


async def _udp_send_recv_once_async(host: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    """生产路径：先 await DNS，再线程内跑 UDP I/O，避免阻塞事件循环。"""
    addrs = await _resolve_udp_sockaddrs_async(host, port)
    if not addrs:
        return None
    return await asyncio.to_thread(_udp_send_recv_on_sockaddrs, addrs, payload, timeout)


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
    """同步 UDP spike 矩阵（单测默认打桩 ``_udp_send_recv_once``）；生产请用 ``_udp_spikes_for_port_async``。"""
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


async def _udp_spikes_for_port_async(host: str, port: int, timeout: float) -> tuple[bool, list[str]]:
    """异步 DNS + 线程 UDP I/O 的 spike 矩阵；与 ``_scan_udp_ports`` 主路径对接。"""
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
        data = await _udp_send_recv_once_async(host, port, pkt, timeout)
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
        ok, lines = await _udp_spikes_for_port_async(host, port, timeout)
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
        dns_ok, addrs, dns_err = await _resolve_dns_async(host)
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

        # SCTP：DNS 在协程内 await；仅 Scapy sr1 进 to_thread，避免把可异步解析与阻塞 raw 发包绑在同一任务里。
        sctp_timeout = min(2.5, settings.probe_timeout_sec)
        res.sctp_probe_findings = await _sctp_probe_all_ports_async(host, SCTP_PROBE_PORTS, sctp_timeout)

        https_ok, status, lat, tls_err = await _https_head(host)
        res.https_ok = https_ok
        res.https_status = status
        res.https_latency_ms = round(lat, 2) if lat is not None else None
        res.tls_error = tls_err
        if 443 in open_tcp:
            res.tls_subject = await asyncio.to_thread(_fetch_tls_subject, host)

        # 仅在 HTTPS 可达或已观测到 443/tcp 开放时触发 SBI 路径探测，减少对纯内网非 TLS 目标的无效 TLS 握手风暴。
        if https_ok is True or (443 in open_tcp):
            res.sbi_unauth_probe = await _probe_sbi_http2_unauth(host)
        else:
            res.sbi_unauth_probe = {"skipped": "no_https_and_no_tcp443", "https_ok": https_ok}

        if any("INIT_reply" in x for x in res.sctp_probe_findings):
            res.service_hints = list(dict.fromkeys([*res.service_hints, "sctp-ngap-init-reply"]))

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
        "sctp_init_replies": sum(1 for r in results if any("INIT_reply" in x for x in (r.sctp_probe_findings or []))),
        "sbi_paths_probed": sum(
            1 for r in results if isinstance(r.sbi_unauth_probe, dict) and r.sbi_unauth_probe.get("paths")
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
