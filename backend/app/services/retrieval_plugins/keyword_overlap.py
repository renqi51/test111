from __future__ import annotations

import math
import re
from collections import Counter

from app.schemas.extraction_pipeline import DocumentChunk
from app.services.retrieval_plugins.base import RetrieverBase

TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]+|[\u4e00-\u9fff]{1,4}")


class KeywordOverlapRetriever(RetrieverBase):
    name = "keyword_overlap"
    version = "v1"

    def retrieve(
        self,
        chunks: list[DocumentChunk],
        query: str,
        scenario_hint: str,
        top_k: int,
    ) -> list[tuple[float, DocumentChunk]]:
        q_tokens = self._tokenize(f"{query} {scenario_hint}")
        q_count = Counter(q_tokens)
        ranked: list[tuple[float, DocumentChunk]] = []
        for chunk in chunks:
            score = self._score(q_count, chunk.text, chunk.heading)
            ranked.append((score, chunk))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return ranked[: max(1, min(top_k, len(ranked)))]

    def _tokenize(self, text: str) -> list[str]:
        return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]

    def _score(self, query_count: Counter[str], text: str, heading: str) -> float:
        doc_tokens = self._tokenize(f"{heading} {text}")
        if not doc_tokens:
            return 0.0
        d_count = Counter(doc_tokens)
        overlap = sum(min(v, d_count.get(k, 0)) for k, v in query_count.items())
        norm = math.sqrt(sum(v * v for v in query_count.values()) * sum(v * v for v in d_count.values()))
        if norm <= 0:
            return 0.0
        base = overlap / norm
        bonus = 0.08 if heading else 0.0
        return min(1.0, base + bonus)

