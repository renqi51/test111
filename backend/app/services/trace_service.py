from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import RUNTIME_DIR
from app.utils.storage import load_json, save_json

EXTRACTION_RUNTIME_DIR = RUNTIME_DIR / "extraction_runs"
EVIDENCE_PACK_DIR = RUNTIME_DIR / "evidence_packs"
STAGING_GRAPH_DIR = RUNTIME_DIR / "staging_graphs"
TRACE_DIR = RUNTIME_DIR / "traces"
REPORT_DIR = RUNTIME_DIR / "reports"


def ensure_extraction_runtime_dirs() -> None:
    for p in [EXTRACTION_RUNTIME_DIR, EVIDENCE_PACK_DIR, STAGING_GRAPH_DIR, TRACE_DIR, REPORT_DIR]:
        p.mkdir(parents=True, exist_ok=True)


@dataclass
class StageTrace:
    stage: str
    started_at: str
    finished_at: str
    summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


class TraceService:
    def __init__(self) -> None:
        ensure_extraction_runtime_dirs()

    def begin(self, stage: str) -> StageTrace:
        now = datetime.now(timezone.utc).isoformat()
        return StageTrace(stage=stage, started_at=now, finished_at=now)

    def end(self, trace: StageTrace, summary: dict[str, Any], error: str | None = None) -> StageTrace:
        trace.finished_at = datetime.now(timezone.utc).isoformat()
        trace.summary = summary
        trace.error = error
        return trace

    def save_run(self, run_id: str, payload: dict[str, Any]) -> Path:
        path = EXTRACTION_RUNTIME_DIR / f"{run_id}.json"
        save_json(path, payload)
        return path

    def load_run(self, run_id: str) -> dict[str, Any] | None:
        path = EXTRACTION_RUNTIME_DIR / f"{run_id}.json"
        if not path.exists():
            return None
        return load_json(path)

    def save_trace(self, run_id: str, traces: list[dict[str, Any]]) -> Path:
        path = TRACE_DIR / f"{run_id}.json"
        save_json(path, {"run_id": run_id, "traces": traces})
        return path

    def load_trace(self, run_id: str) -> dict[str, Any]:
        path = TRACE_DIR / f"{run_id}.json"
        if not path.exists():
            return {"run_id": run_id, "traces": []}
        return load_json(path)

    def save_report(self, run_id: str, markdown: str) -> Path:
        path = REPORT_DIR / f"{run_id}.md"
        path.write_text(markdown, encoding="utf-8")
        return path

    def load_report(self, run_id: str) -> str:
        path = REPORT_DIR / f"{run_id}.md"
        if not path.exists():
            return ""
        return path.read_text(encoding="utf-8")

    def save_evidence_pack(self, run_id: str, payload: dict[str, Any]) -> None:
        save_json(EVIDENCE_PACK_DIR / f"{run_id}.json", payload)

    def load_evidence_pack(self, run_id: str) -> dict[str, Any]:
        p = EVIDENCE_PACK_DIR / f"{run_id}.json"
        if not p.exists():
            return {}
        return load_json(p)

    def save_staging_graph(self, run_id: str, payload: dict[str, Any]) -> None:
        save_json(STAGING_GRAPH_DIR / f"{run_id}.json", payload)

    def load_staging_graph(self, run_id: str) -> dict[str, Any]:
        p = STAGING_GRAPH_DIR / f"{run_id}.json"
        if not p.exists():
            return {}
        return load_json(p)

    def latest_run_id(self) -> str | None:
        files = sorted(EXTRACTION_RUNTIME_DIR.glob("run_*.json"), key=lambda x: x.stat().st_mtime, reverse=True)
        if not files:
            return None
        return files[0].stem

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        files = sorted(
            EXTRACTION_RUNTIME_DIR.glob("run_*.json"),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )[: max(1, limit)]
        out: list[dict[str, Any]] = []
        for f in files:
            payload = load_json(f)
            out.append(
                {
                    "run_id": payload.get("run_id", f.stem),
                    "created_at": payload.get("created_at"),
                    "scenario_hint": payload.get("request", {}).get("scenario_hint"),
                    "budget_mode": payload.get("request", {}).get("budget_mode"),
                    "recommended_worker": payload.get("judge", {}).get("recommended_worker"),
                    "needs_repair": payload.get("judge", {}).get("needs_repair"),
                    "staging_nodes": len(payload.get("staging_graph", {}).get("nodes", [])),
                    "staging_edges": len(payload.get("staging_graph", {}).get("edges", [])),
                }
            )
        return out


trace_service = TraceService()

