from __future__ import annotations

import json
import logging
from typing import AsyncIterator
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.core.config import settings
from app.services.graph_rag_ingest_service import get_graph_rag_ingest_service
from app.services.graph_rag_query_service import get_graph_rag_query_service
from app.utils.file_parser import read_rule_context_multi

router = APIRouter(tags=["graph-rag"])
logger = logging.getLogger(__name__)


class GraphRAGIngestRequest(BaseModel):
    text: str = Field(min_length=1, description="待入库的原始文本文档。")
    source_file: str = Field(min_length=1, description="来源文件名（用于追踪）。")
    rule_context: str | None = Field(default=None, description="可选：额外抽取规则文本。")


class GraphRAGQueryRequest(BaseModel):
    question: str = Field(min_length=1, description="用户自然语言问题。")
    top_k: int | None = Field(default=None, ge=1, le=100, description="可选：覆盖默认召回数量。")


@router.post("/graph-rag/ingest-text")
async def graph_rag_ingest_text(body: GraphRAGIngestRequest):
    try:
        logger.warning(
            "POST /api/graph-rag/ingest-text: runs LLM extraction on EVERY chunk (paid chat). "
            "For Neo4j-first then embed-only Milvus load, use: "
            "python scripts/build_graphrag_from_existing_graph.py",
        )
        rule_context = body.rule_context
        if rule_context is None:
            rule_context = read_rule_context_multi(Path(settings.kg_rule_dir))
        result = await get_graph_rag_ingest_service().ingest_text(
            text=body.text,
            source_file=body.source_file,
            rule_context=rule_context or "",
        )
        return result
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"graph-rag ingest failed: {str(exc)[:220]}") from exc


@router.post("/graph-rag/query")
async def graph_rag_query(body: GraphRAGQueryRequest):
    try:
        logger.info("POST /api/graph-rag/query: retrieval + LLM answer (chat completion)")
        result = await get_graph_rag_query_service().ask(
            question=body.question,
            top_k=body.top_k,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"graph-rag query failed: {str(exc)[:220]}") from exc


@router.post("/graph-rag/query-stream")
async def graph_rag_query_stream(body: GraphRAGQueryRequest):
    async def _gen() -> AsyncIterator[bytes]:
        # NDJSON streaming: one JSON object per line.
        yield (json.dumps({"type": "start"}, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            async for evt in get_graph_rag_query_service().ask_stream(
                question=body.question,
                top_k=body.top_k,
            ):
                yield (json.dumps(evt, ensure_ascii=False) + "\n").encode("utf-8")
        except Exception as exc:  # noqa: BLE001
            msg = f"graph-rag query failed: {str(exc)[:220]}"
            yield (json.dumps({"type": "error", "error": msg}, ensure_ascii=False) + "\n").encode("utf-8")

    return StreamingResponse(_gen(), media_type="application/x-ndjson")

