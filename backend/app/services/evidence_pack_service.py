from __future__ import annotations

from app.schemas.extraction_pipeline import DocumentChunk, EvidencePack
from app.services.retrieval_service import retrieval_service


class EvidencePackService:
    def build(
        self,
        chunks: list[DocumentChunk],
        query: str,
        scenario_hint: str,
        top_k: int,
        strategy: str = "keyword_overlap",
        rerank_used: bool = False,
        rerank_strategy: str = "noop",
    ) -> EvidencePack:
        return retrieval_service.build_evidence_pack(
            chunks=chunks,
            query=query,
            scenario_hint=scenario_hint,
            top_k=top_k,
            strategy=strategy,
            rerank_used=rerank_used,
            rerank_strategy=rerank_strategy,
        )


evidence_pack_service = EvidencePackService()

