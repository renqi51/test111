from __future__ import annotations

import math
import re
from collections import Counter

from app.schemas.extraction_pipeline import DocumentChunk
from app.services.retrieval_plugins.base import RetrieverBase

TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]+|[\u4e00-\u9fff]{1,4}")


class VectorRetriever(RetrieverBase):
    """
    Placeholder local vector retriever.
    Uses sparse token vectors + cosine to keep infra-free behavior.
    """

    name = "vector_placeholder"
    version = "v0"

    def retrieve(
        self,
        chunks: list[DocumentChunk],
        query: str,
        scenario_hint: str,
        top_k: int,
    ) -> list[tuple[float, DocumentChunk]]:
        q_vec = Counter(self._tokenize(f"{query} {scenario_hint}"))
        scored: list[tuple[float, DocumentChunk]] = []
        for chunk in chunks:
            d_vec = Counter(self._tokenize(f"{chunk.heading} {chunk.text}"))
            score = self._cosine(q_vec, d_vec)
            scored.append((score, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[: max(1, min(top_k, len(scored)))]

    def _tokenize(self, text: str) -> list[str]:
        return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]

    def _cosine(self, a: Counter[str], b: Counter[str]) -> float:
        dot = sum(v * b.get(k, 0) for k, v in a.items())
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        if na == 0 or nb == 0:
            return 0.0
        return min(1.0, dot / (na * nb))

