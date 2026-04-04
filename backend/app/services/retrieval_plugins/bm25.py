from __future__ import annotations

import math
import re
from collections import Counter

from app.schemas.extraction_pipeline import DocumentChunk
from app.services.retrieval_plugins.base import RetrieverBase

TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]+|[\u4e00-\u9fff]{1,4}")


class BM25Retriever(RetrieverBase):
    name = "bm25"
    version = "v1"

    def retrieve(
        self,
        chunks: list[DocumentChunk],
        query: str,
        scenario_hint: str,
        top_k: int,
    ) -> list[tuple[float, DocumentChunk]]:
        docs = [self._tokenize(f"{c.heading} {c.text}") for c in chunks]
        q_terms = self._tokenize(f"{query} {scenario_hint}")
        n_docs = len(docs)
        if n_docs == 0:
            return []
        avgdl = sum(len(d) for d in docs) / max(1, n_docs)
        df = Counter()
        for d in docs:
            for t in set(d):
                df[t] += 1

        k1 = 1.5
        b = 0.75
        scored: list[tuple[float, DocumentChunk]] = []
        for idx, d in enumerate(docs):
            tf = Counter(d)
            score = 0.0
            for t in q_terms:
                if t not in tf:
                    continue
                idf = math.log(1 + (n_docs - df[t] + 0.5) / (df[t] + 0.5))
                denom = tf[t] + k1 * (1 - b + b * len(d) / max(1.0, avgdl))
                score += idf * (tf[t] * (k1 + 1)) / max(1e-9, denom)
            norm_score = min(1.0, score / max(1.0, score + 2.0))
            scored.append((norm_score, chunks[idx]))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored[: max(1, min(top_k, len(scored)))]

    def _tokenize(self, text: str) -> list[str]:
        return [m.group(0).lower() for m in TOKEN_RE.finditer(text)]

