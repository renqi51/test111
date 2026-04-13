from typing import Any

from pydantic import BaseModel, Field


class ProbeRunRequest(BaseModel):
    """对给定主机名或字面 IP 执行 DNS/端口/HTTPS 探测（需在配置的策略内）。"""

    targets: list[str] = Field(
        min_length=1,
        max_length=64,
        description="FQDN、字面 IPv4/IPv6，或 https://host / host:port 形式（CIDR 应在调用方展开）",
    )
    context: str | None = Field(default=None, description="可选：来源说明，如 exposure:VoWiFi")


class ProbeTargetResult(BaseModel):
    target: str
    host: str
    permitted: bool
    policy_reason: str
    dns_ok: bool = False
    dns_addresses: list[str] = Field(default_factory=list)
    https_ok: bool | None = None
    https_status: int | None = None
    https_latency_ms: float | None = None
    open_ports: list[int] = Field(default_factory=list, description="TCP 开放端口")
    open_udp_ports: list[int] = Field(default_factory=list, description="UDP 有响应端口（连通性探测）")
    service_hints: list[str] = Field(default_factory=list)
    tls_subject: str | None = None
    tls_error: str | None = None
    error: str | None = None
    tcp_banners: dict[str, str] = Field(
        default_factory=dict,
        description="端口(字符串键) -> 可打印的 banner/首行响应前缀（含 SIP OPTIONS、HTTP 等）",
    )
    udp_spike_findings: list[str] = Field(
        default_factory=list,
        description="各 UDP spike（含畸形版本 IKE、截断 GTP-U 等）的响应摘要或 silent_drop 标记",
    )
    sctp_probe_findings: list[str] = Field(
        default_factory=list,
        description="SCTP INIT（如 38412 NGAP）探测回显摘要；无 Scapy/权限时记录不可用原因",
    )
    sbi_unauth_probe: dict[str, Any] = Field(
        default_factory=dict,
        description="HTTP/2 优先的 SBI 路径未授权 GET 结果：各路径状态码、协商版本，用于越权面研判",
    )


class ProbeRunResponse(BaseModel):
    run_id: str
    started_at: str
    finished_at: str
    probe_mode: str
    results: list[ProbeTargetResult]
    summary: dict[str, int]


class ProbeStatusPayload(BaseModel):
    enabled: bool
    probe_mode: str
    # 任一为真表示 allowlist 模式下「至少有一种」放行规则已配置（后缀域名 或 字面 IP 的 CIDR）
    allowlist_configured: bool
    allowlist_suffixes_configured: bool
    allowlist_cidrs_configured: bool
    verify_tls: bool
    timeout_sec: float
    max_concurrent: int
