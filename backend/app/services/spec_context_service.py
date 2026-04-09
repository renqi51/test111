"""Local 3GPP/GSMA-oriented spec corpus loading and retrieval for exposure analysis."""
from __future__ import annotations

import json
import re
from pathlib import Path
from app.core.config import BACKEND_ROOT, DATA_DIR, settings
from app.schemas.extraction_pipeline import DocumentChunk, EvidencePack
from app.services.retrieval_service import retrieval_service

CHUNK_TARGET = 1600
CHUNK_OVERLAP = 200


def _stable_document_id(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(BACKEND_ROOT)).replace("\\", "/")
    except ValueError:
        return path.name


def _chunk_text(*, text: str, document_id: str, base_heading: str = "") -> list[DocumentChunk]:
    if not text.strip():
        return []
    chunks: list[DocumentChunk] = []
    t = text.strip()
    start = 0
    order = 0
    n = len(t)
    while start < n:
        end = min(n, start + CHUNK_TARGET)
        if end < n:
            window = t[start:end]
            br = window.rfind("\n\n")
            if br > CHUNK_TARGET // 2:
                end = start + br
        piece = t[start:end].strip()
        if piece:
            cid = f"{document_id}#t{order}"
            chunks.append(
                DocumentChunk(
                    chunk_id=cid,
                    document_id=document_id,
                    section_id=f"char_{start}_{end}",
                    heading=base_heading,
                    text=piece,
                    order=order,
                    char_start=start,
                    char_end=end,
                    metadata={"kind": "text"},
                )
            )
            order += 1
        if end >= n:
            break
        start = max(start + 1, end - CHUNK_OVERLAP)
    return chunks


def _chunk_markdown(*, text: str, document_id: str) -> list[DocumentChunk]:
    if not text.strip():
        return []
    out: list[DocumentChunk] = []
    order = 0
    lines = text.splitlines()
    current_heading = ""
    buf: list[str] = []

    def flush() -> None:
        nonlocal order, buf
        body = "\n".join(buf).strip()
        buf = []
        if not body:
            return
        for c in _chunk_text(text=body, document_id=document_id, base_heading=current_heading):
            c.order = order
            c.chunk_id = f"{document_id}#md{order}"
            order += 1
            out.append(c)

    for line in lines:
        m = re.match(r"^#{1,6}\s+(.+)$", line)
        if m:
            flush()
            current_heading = m.group(1).strip()
            continue
        buf.append(line)
    flush()
    if not out:
        return _chunk_text(text=text, document_id=document_id, base_heading="")
    return out


def _load_json_as_chunks(path: Path) -> list[DocumentChunk]:
    doc_id = _stable_document_id(path)
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _chunk_text(text=raw, document_id=doc_id, base_heading=path.name)
    if isinstance(data, (dict, list)):
        text = json.dumps(data, ensure_ascii=False, indent=2)
    else:
        text = str(data)
    return _chunk_text(text=text, document_id=doc_id, base_heading=path.name)


def _build_query(
    *,
    service: str,
    network_functions: list[str],
    protocols: list[str],
    related_risks: list[str],
) -> str:
    static = (
        "authorization authentication exposure threat security requirement "
        "resource exhaustion access control input validation JSON parameter "
        "HTTP/2 HTTP northbound API Open Gateway IMS VoWiFi 3GPP GSMA "
        "token scope trust boundary"
    )
    parts = [
        service,
        " ".join(network_functions),
        " ".join(protocols),
        " ".join(related_risks),
        static,
    ]
    return " ".join(p for p in parts if p).strip()


class SpecContextService:
    """Loads local spec-like files into DocumentChunks and retrieves via retrieval_service."""

    def __init__(self) -> None:
        self._chunks: list[DocumentChunk] | None = None

    def _discover_roots(self) -> list[Path]:
        roots: list[Path] = []
        primary = Path(settings.exposure_spec_docs_path)
        if not primary.is_absolute():
            primary = (BACKEND_ROOT / primary).resolve()
        else:
            primary = primary.resolve()
        if primary.is_dir():
            roots.append(primary)
        for extra in (DATA_DIR / "rule", DATA_DIR / "input"):
            er = extra.resolve()
            if er.is_dir() and er not in roots:
                roots.append(er)
        return roots

    def load_chunks(self) -> list[DocumentChunk]:
        if self._chunks is not None:
            return self._chunks
        collected: list[DocumentChunk] = []
        for root in self._discover_roots():
            try:
                for path in sorted(root.rglob("*")):
                    if not path.is_file():
                        continue
                    suf = path.suffix.lower()
                    if suf not in {".md", ".txt", ".json"}:
                        continue
                    doc_id = _stable_document_id(path)
                    try:
                        if suf == ".json":
                            collected.extend(_load_json_as_chunks(path))
                        elif suf == ".md":
                            text = path.read_text(encoding="utf-8", errors="replace")
                            collected.extend(_chunk_markdown(text=text, document_id=doc_id))
                        else:
                            text = path.read_text(encoding="utf-8", errors="replace")
                            collected.extend(_chunk_text(text=text, document_id=doc_id, base_heading=path.name))
                    except OSError:
                        continue
            except OSError:
                continue
        for i, c in enumerate(collected):
            c.order = i
        self._chunks = collected
        return self._chunks

    def retrieve_for_candidate(
        self,
        *,
        service: str,
        network_functions: list[str],
        protocols: list[str],
        related_risks: list[str],
        top_k: int | None = None,
    ) -> EvidencePack:
        chunks = self.load_chunks()
        k = top_k if top_k is not None else settings.exposure_evidence_top_k
        if not chunks:
            return EvidencePack(
                pack_id="pack_empty",
                query="",
                document_id="",
                scenario_hint="exposure_spec",
                items=[],
                retrieval_strategy="none",
                retrieval_version="v0",
            )
        query = _build_query(
            service=service,
            network_functions=network_functions or [],
            protocols=protocols or [],
            related_risks=related_risks or [],
        )
        return retrieval_service.build_evidence_pack(
            chunks=chunks,
            query=query,
            scenario_hint="exposure_spec",
            top_k=max(1, k),
            strategy=settings.extraction_retrieval_strategy,
            rerank_used=settings.extraction_rerank_enabled,
            rerank_strategy=settings.extraction_rerank_strategy,
        )


spec_context_service = SpecContextService()
