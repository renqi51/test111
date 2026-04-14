from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class AssetRecord(BaseModel):
    asset: str
    asset_type: Literal["domain", "ip", "cidr", "host"] = "host"
    status: Literal["active", "inactive"] = "active"
    source: str = "manual"
    first_seen_at: datetime
    last_seen_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class AssetUpsertRequest(BaseModel):
    assets: list[str] = Field(min_length=1, max_length=200)
    source: str = "manual"


class ScanJobCreateRequest(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    targets: list[str] = Field(min_length=1, max_length=200)
    interval_minutes: int = Field(default=60, ge=5, le=1440)
    enabled: bool = True


class ScanJobRecord(BaseModel):
    job_id: str
    name: str
    targets: list[str]
    interval_minutes: int
    enabled: bool
    created_at: datetime
    updated_at: datetime
    next_run_at: datetime
    last_run_at: datetime | None = None
    last_run_id: str | None = None


class ScanRunSummary(BaseModel):
    run_id: str
    job_id: str
    started_at: datetime
    finished_at: datetime
    targets_total: int
    permitted_targets: int
    reachable_https: int
    findings_delta: dict[str, Any] = Field(default_factory=dict)


class AuditRecord(BaseModel):
    ts: datetime
    actor: str
    role: str
    action: str
    resource: str
    detail: dict[str, Any] = Field(default_factory=dict)
