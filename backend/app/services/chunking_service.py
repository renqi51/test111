from __future__ import annotations

import re

from app.schemas.extraction_pipeline import DocumentChunk, DocumentInput


class ChunkingService:
    """Simple heading/blank-line aware chunking."""

    def chunk_document(self, doc: DocumentInput, max_chars: int = 900) -> list[DocumentChunk]:
        text = re.sub(r"\r\n?", "\n", doc.raw_text).strip()
        blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
        chunks: list[DocumentChunk] = []
        cursor = 0
        order = 0
        for block in blocks:
            heading = self._detect_heading(block)
            for piece in self._split_long(block, max_chars=max_chars):
                chunk_id = f"{doc.document_id}_c{order:03d}"
                char_start = text.find(piece, cursor)
                if char_start < 0:
                    char_start = cursor
                char_end = char_start + len(piece)
                chunks.append(
                    DocumentChunk(
                        chunk_id=chunk_id,
                        document_id=doc.document_id,
                        section_id=f"s{order // 3 + 1}",
                        heading=heading,
                        text=piece,
                        order=order,
                        char_start=char_start,
                        char_end=char_end,
                        metadata={"length": len(piece)},
                    )
                )
                cursor = char_end
                order += 1
        return chunks

    def _detect_heading(self, block: str) -> str:
        first = block.split("\n", maxsplit=1)[0].strip()
        if re.match(r"^(\d+(\.\d+)*|[A-Z][\w\s-]{0,40})$", first):
            return first[:80]
        return ""

    def _split_long(self, block: str, max_chars: int) -> list[str]:
        if len(block) <= max_chars:
            return [block]
        parts: list[str] = []
        sentences = re.split(r"(?<=[。！？.!?])\s+", block)
        buf = ""
        for sent in sentences:
            if len(buf) + len(sent) + 1 <= max_chars:
                buf = f"{buf} {sent}".strip()
            else:
                if buf:
                    parts.append(buf)
                buf = sent
        if buf:
            parts.append(buf)
        return parts or [block[:max_chars]]


chunking_service = ChunkingService()

