from __future__ import annotations

from uuid import uuid4

from app.schemas.extraction_pipeline import DocumentInput


class DocumentIngestService:
    """Normalize incoming extraction input into DocumentInput."""

    def build_input(
        self,
        text: str,
        title: str = "",
        source_type: str = "text",
        metadata: dict | None = None,
    ) -> DocumentInput:
        clean_text = (text or "").strip()
        if not clean_text:
            raise ValueError("document text is empty")
        return DocumentInput(
            document_id=f"doc_{uuid4().hex[:10]}",
            title=title or "Untitled standard fragment",
            source_type=source_type,  # type: ignore[arg-type]
            raw_text=clean_text,
            metadata=metadata or {},
        )


document_ingest_service = DocumentIngestService()

