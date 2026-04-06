from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.graph_rag_ingest_service import get_graph_rag_ingest_service
from app.services.graph_rag_query_service import get_graph_rag_query_service
from app.utils.file_parser import read_rule_context
from app.core.config import settings

router = APIRouter(tags=["graph-rag"])


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
        rule_context = body.rule_context
        if rule_context is None:
            rule_context = read_rule_context(Path(settings.kg_rule_dir))
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
        result = await get_graph_rag_query_service().ask(
            question=body.question,
            top_k=body.top_k,
        )
        return result
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"graph-rag query failed: {str(exc)[:220]}") from exc

