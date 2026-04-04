from __future__ import annotations

from app.schemas.extraction_pipeline import DocumentChunk
from app.services.retrieval_plugins.base import RerankerBase


class NoopReranker(RerankerBase):
    name = "noop"
    version = "v1"

    def rerank(
        self,
        ranked_items: list[tuple[float, DocumentChunk]],
        query: str,  # noqa: ARG002
    ) -> list[tuple[float, DocumentChunk]]:
        return ranked_items

