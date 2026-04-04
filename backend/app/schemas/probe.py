from pydantic import BaseModel, Field


class ProbeRunRequest(BaseModel):
    """对给定主机名执行 DNS + HTTPS 可达性检查（需在配置的策略内）。"""

    targets: list[str] = Field(min_length=1, max_length=64, description="主机名或 https://host 形式")
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
    open_ports: list[int] = Field(default_factory=list)
    service_hints: list[str] = Field(default_factory=list)
    tls_subject: str | None = None
    tls_error: str | None = None
    error: str | None = None


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
    allowlist_configured: bool
    verify_tls: bool
    timeout_sec: float
    max_concurrent: int
