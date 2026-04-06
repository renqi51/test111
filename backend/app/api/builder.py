from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException

from app.schemas.kg_extraction import LocalImportRequest, LocalImportResponse
from app.services.kg_builder_service import get_kg_builder_service

router = APIRouter(tags=["builder"])
logger = logging.getLogger(__name__)


@router.post("/builder/run-local-import", response_model=LocalImportResponse)
async def run_local_import(body: LocalImportRequest):
    try:
        logger.info(
            "POST /api/builder/run-local-import: Neo4j KG import (LLM per chunk). dry_run=%s max_files=%s only_extensions=%s",
            body.dry_run,
            body.max_files,
            body.only_extensions,
        )
        result = await get_kg_builder_service().build_graph_from_input(
            dry_run=body.dry_run,
            max_files=body.max_files,
            only_extensions=body.only_extensions,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)[:220]) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"local import failed: {str(exc)[:220]}") from exc
    return result
