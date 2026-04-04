from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas.kg_extraction import LocalImportRequest, LocalImportResponse
from app.services.kg_builder_service import get_kg_builder_service

router = APIRouter(tags=["builder"])


@router.post("/builder/run-local-import", response_model=LocalImportResponse)
async def run_local_import(body: LocalImportRequest):
    try:
        result = await get_kg_builder_service().build_graph_from_input(
            dry_run=body.dry_run,
            max_files=body.max_files,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"local import failed: {str(exc)[:220]}") from exc
    return result
