from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.core.config import RUNTIME_DIR
from app.schemas.p0_ops import AssetRecord, AuditRecord, ScanJobRecord, ScanRunSummary
from app.schemas.probe import ProbeRunRequest
from app.services import probe_service

P0_DIR = RUNTIME_DIR / "p0"
ASSETS_PATH = P0_DIR / "assets.json"
JOBS_PATH = P0_DIR / "jobs.json"
RUNS_PATH = P0_DIR / "runs.json"
AUDIT_PATH = P0_DIR / "audit.jsonl"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure() -> None:
    P0_DIR.mkdir(parents=True, exist_ok=True)


def _read_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def append_audit(actor: str, role: str, action: str, resource: str, detail: dict[str, Any] | None = None) -> None:
    _ensure()
    rec = AuditRecord(ts=_now(), actor=actor, role=role, action=action, resource=resource, detail=detail or {})
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(rec.model_dump_json(ensure_ascii=False) + "\n")


def list_assets() -> list[AssetRecord]:
    _ensure()
    data = _read_json(ASSETS_PATH, {"assets": []})
    return [AssetRecord(**x) for x in data.get("assets", [])]


def upsert_assets(raw_assets: list[str], source: str) -> list[AssetRecord]:
    cur = {x.asset: x for x in list_assets()}
    ts = _now()
    for raw in raw_assets:
        item = str(raw).strip()
        if not item:
            continue
        if "/" in item:
            asset_type = "cidr"
        elif item.replace(".", "").isdigit() and item.count(".") == 3:
            asset_type = "ip"
        elif "." in item:
            asset_type = "domain"
        else:
            asset_type = "host"
        prev = cur.get(item)
        if prev is None:
            cur[item] = AssetRecord(
                asset=item,
                asset_type=asset_type,
                status="active",
                source=source,
                first_seen_at=ts,
                last_seen_at=ts,
            )
        else:
            prev.last_seen_at = ts
            prev.status = "active"
            prev.source = source or prev.source
    out = list(cur.values())
    _write_json(ASSETS_PATH, {"assets": [x.model_dump(mode="json") for x in out]})
    return out


def _load_jobs() -> list[ScanJobRecord]:
    _ensure()
    data = _read_json(JOBS_PATH, {"jobs": []})
    return [ScanJobRecord(**x) for x in data.get("jobs", [])]


def _save_jobs(rows: list[ScanJobRecord]) -> None:
    _write_json(JOBS_PATH, {"jobs": [x.model_dump(mode="json") for x in rows]})


def create_job(name: str, targets: list[str], interval_minutes: int, enabled: bool = True) -> ScanJobRecord:
    ts = _now()
    job = ScanJobRecord(
        job_id=f"job_{uuid4().hex[:10]}",
        name=name,
        targets=targets,
        interval_minutes=interval_minutes,
        enabled=enabled,
        created_at=ts,
        updated_at=ts,
        next_run_at=ts,
    )
    jobs = _load_jobs()
    jobs.append(job)
    _save_jobs(jobs)
    return job


def list_jobs() -> list[ScanJobRecord]:
    return _load_jobs()


def _load_runs() -> dict[str, Any]:
    return _read_json(RUNS_PATH, {"runs": []})


def _save_runs(payload: dict[str, Any]) -> None:
    _write_json(RUNS_PATH, payload)


def _extract_surface_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    idx: dict[str, dict[str, Any]] = {}
    for row in run.get("results", []):
        host = str(row.get("host") or row.get("target") or "").strip()
        if not host:
            continue
        idx[host] = {
            "open_ports": sorted(int(p) for p in row.get("open_ports", []) if isinstance(p, int) or str(p).isdigit()),
            "open_udp_ports": sorted(int(p) for p in row.get("open_udp_ports", []) if isinstance(p, int) or str(p).isdigit()),
            "https_status": row.get("https_status"),
        }
    return idx


def _delta(prev_run: dict[str, Any] | None, curr_run: dict[str, Any]) -> dict[str, Any]:
    if prev_run is None:
        return {"kind": "baseline_created", "new_hosts": len(curr_run.get("results", []))}
    prev_idx = _extract_surface_index(prev_run)
    curr_idx = _extract_surface_index(curr_run)
    new_hosts = [h for h in curr_idx if h not in prev_idx]
    removed_hosts = [h for h in prev_idx if h not in curr_idx]
    port_changes: dict[str, Any] = {}
    for h in curr_idx:
        if h not in prev_idx:
            continue
        p_old = set(prev_idx[h]["open_ports"])
        p_new = set(curr_idx[h]["open_ports"])
        u_old = set(prev_idx[h]["open_udp_ports"])
        u_new = set(curr_idx[h]["open_udp_ports"])
        if p_old != p_new or u_old != u_new or prev_idx[h]["https_status"] != curr_idx[h]["https_status"]:
            port_changes[h] = {
                "tcp_added": sorted(p_new - p_old),
                "tcp_removed": sorted(p_old - p_new),
                "udp_added": sorted(u_new - u_old),
                "udp_removed": sorted(u_old - u_new),
                "https_status_old": prev_idx[h]["https_status"],
                "https_status_new": curr_idx[h]["https_status"],
            }
    return {"kind": "delta", "new_hosts": new_hosts, "removed_hosts": removed_hosts, "changed_hosts": port_changes}


async def run_job_once(job_id: str) -> ScanRunSummary:
    jobs = _load_jobs()
    job = next((x for x in jobs if x.job_id == job_id), None)
    if job is None:
        raise ValueError("job_not_found")
    started = _now()
    probe_payload = await probe_service.run_probe(ProbeRunRequest(targets=job.targets, context=f"p0_job:{job.name}"))
    finished = _now()

    runs_db = _load_runs()
    prev_run = None
    for r in reversed(runs_db.get("runs", [])):
        if r.get("job_id") == job_id:
            prev_run = r.get("probe")
            break
    delta = _delta(prev_run, probe_payload.model_dump())

    run_id = f"run_{uuid4().hex[:12]}"
    runs_db.setdefault("runs", []).append(
        {
            "run_id": run_id,
            "job_id": job_id,
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "probe": probe_payload.model_dump(),
            "delta": delta,
        }
    )
    _save_runs(runs_db)

    for idx, row in enumerate(jobs):
        if row.job_id != job_id:
            continue
        row.last_run_at = finished
        row.last_run_id = run_id
        row.next_run_at = finished + timedelta(minutes=row.interval_minutes)
        row.updated_at = finished
        jobs[idx] = row
        break
    _save_jobs(jobs)

    results = probe_payload.results
    return ScanRunSummary(
        run_id=run_id,
        job_id=job_id,
        started_at=started,
        finished_at=finished,
        targets_total=len(results),
        permitted_targets=sum(1 for r in results if r.permitted),
        reachable_https=sum(1 for r in results if r.https_ok is True),
        findings_delta=delta,
    )


async def run_due_jobs() -> list[ScanRunSummary]:
    now = _now()
    out: list[ScanRunSummary] = []
    for job in _load_jobs():
        if not job.enabled:
            continue
        if job.next_run_at <= now:
            out.append(await run_job_once(job.job_id))
    return out


def list_runs(job_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    rows = _load_runs().get("runs", [])
    if job_id:
        rows = [x for x in rows if x.get("job_id") == job_id]
    return list(reversed(rows))[:limit]
