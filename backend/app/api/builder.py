from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.kg_builder_service import get_kg_builder_service

router = APIRouter(tags=["builder"])


class BuilderRunRequest(BaseModel):
    dry_run: bool = Field(default=False, description="When true, run extraction/merge-preview without writing graph.")
    max_files: int | None = Field(default=None, ge=1, description="Optional limit for debugging local import.")


@router.post("/builder/run-local-import")
async def run_local_import(body: BuilderRunRequest):
    try:
        result = await get_kg_builder_service().build_graph_from_input(
            dry_run=body.dry_run,
            max_files=body.max_files,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"local import failed: {str(exc)[:220]}") from exc
    return result
