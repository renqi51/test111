from __future__ import annotations

from abc import ABC, abstractmethod

from app.schemas.extraction_pipeline import DocumentChunk


class RetrieverBase(ABC):
    name: str = "base"
    version: str = "v0"

    @abstractmethod
    def retrieve(
        self,
        chunks: list[DocumentChunk],
        query: str,
        scenario_hint: str,
        top_k: int,
    ) -> list[tuple[float, DocumentChunk]]: ...


class RerankerBase(ABC):
    name: str = "noop"
    version: str = "v0"

    def rerank(
        self,
        ranked_items: list[tuple[float, DocumentChunk]],
        query: str,
    ) -> list[tuple[float, DocumentChunk]]:
        return ranked_items

