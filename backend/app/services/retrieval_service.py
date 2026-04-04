from __future__ import annotations

from uuid import uuid4

from app.schemas.extraction_pipeline import DocumentChunk, EvidenceItem, EvidencePack
from app.services.retrieval_plugins.base import RetrieverBase, RerankerBase
from app.services.retrieval_plugins.bm25 import BM25Retriever
from app.services.retrieval_plugins.keyword_overlap import KeywordOverlapRetriever
from app.services.retrieval_plugins.rerank import NoopReranker
from app.services.retrieval_plugins.vector import VectorRetriever


class RetrievalService:
    """Pluggable retrieval layer: keyword / BM25 / vector-placeholder + rerank hook."""

    def __init__(self) -> None:
        self._retrievers: dict[str, RetrieverBase] = {
            "keyword_overlap": KeywordOverlapRetriever(),
            "bm25": BM25Retriever(),
            "vector": VectorRetriever(),
        }
        self._rerankers: dict[str, RerankerBase] = {"noop": NoopReranker()}

    def build_evidence_pack(
        self,
        chunks: list[DocumentChunk],
        query: str,
        scenario_hint: str,
        top_k: int = 10,
        strategy: str = "keyword_overlap",
        rerank_used: bool = False,
        rerank_strategy: str = "noop",
    ) -> EvidencePack:
        retriever = self._retrievers.get(strategy) or self._retrievers["keyword_overlap"]
        ranked = retriever.retrieve(chunks=chunks, query=query, scenario_hint=scenario_hint, top_k=top_k)
        selected = ranked
        if rerank_used:
            reranker = self._rerankers.get(rerank_strategy) or self._rerankers["noop"]
            selected = reranker.rerank(selected, query=query)

        items: list[EvidenceItem] = []
        for idx, (score, chunk) in enumerate(selected[: max(1, min(top_k, len(selected)))]):
            items.append(
                EvidenceItem(
                    evidence_id=f"ev_{idx:03d}_{chunk.chunk_id}",
                    chunk_id=chunk.chunk_id,
                    document_id=chunk.document_id,
                    heading=chunk.heading,
                    text=chunk.text,
                    relevance_score=round(score, 4),
                    source_locator={
                        "section_id": chunk.section_id,
                        "char_start": chunk.char_start,
                        "char_end": chunk.char_end,
                    },
                    tags=[scenario_hint] if scenario_hint else [],
                )
            )
        return EvidencePack(
            pack_id=f"pack_{uuid4().hex[:10]}",
            query=query,
            document_id=chunks[0].document_id if chunks else "",
            scenario_hint=scenario_hint,
            items=items,
            retrieval_strategy=retriever.name,
            retrieval_version=retriever.version,
            rerank_used=rerank_used,
            rerank_strategy=rerank_strategy if rerank_used else None,
            retriever_config={"top_k": top_k},
            retrieval_trace=[
                {
                    "strategy": retriever.name,
                    "strategy_version": retriever.version,
                    "top_k": top_k,
                    "total_chunks": len(chunks),
                    "rerank_used": rerank_used,
                    "rerank_strategy": rerank_strategy if rerank_used else None,
                }
            ],
        )

    def list_retrievers(self) -> list[dict[str, str]]:
        return [{"name": r.name, "version": r.version} for r in self._retrievers.values()]


retrieval_service = RetrievalService()

