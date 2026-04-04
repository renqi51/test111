from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class ParsedInputDocument:
    source_file: str
    text: str


def load_rule_context(rule_dir: Path) -> str:
    supported = {".txt", ".md", ".json", ".yaml", ".yml"}
    if not rule_dir.exists():
        return ""
    parts: list[str] = []
    for path in sorted([p for p in rule_dir.iterdir() if p.is_file() and p.suffix.lower() in supported]):
        try:
            content = path.read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if not content:
            continue
        parts.append(f"# RULE FILE: {path.name}\n{content}")
    return "\n\n".join(parts).strip()


def load_input_documents(input_dir: Path) -> tuple[list[ParsedInputDocument], list[str]]:
    supported_text = {".md", ".txt", ".yaml", ".yml"}
    supported_pdf = {".pdf"}
    docs: list[ParsedInputDocument] = []
    failed: list[str] = []
    if not input_dir.exists():
        return docs, failed
    for path in sorted([p for p in input_dir.iterdir() if p.is_file()]):
        ext = path.suffix.lower()
        if ext in supported_text:
            try:
                text = path.read_text(encoding="utf-8").strip()
            except Exception as exc:
                failed.append(f"{path.name}: {str(exc)[:180]}")
                continue
            if not text:
                continue
            docs.append(ParsedInputDocument(source_file=path.name, text=text))
            continue
        if ext in supported_pdf:
            try:
                text = _extract_pdf_text(path)
            except Exception as exc:
                failed.append(f"{path.name}: {str(exc)[:180]}")
                continue
            if not text.strip():
                failed.append(f"{path.name}: empty_pdf_text")
                continue
            docs.append(ParsedInputDocument(source_file=path.name, text=text.strip()))
    return docs, failed


def chunk_text(
    text: str,
    source_file: str,
    *,
    chunk_size: int = 4000,
    chunk_overlap: int = 400,
) -> list[dict[str, str | int]]:
    clean = text.strip()
    if not clean:
        return []
    size = max(200, int(chunk_size))
    overlap = max(0, min(int(chunk_overlap), size - 1))
    step = max(1, size - overlap)
    chunks: list[dict[str, str | int]] = []
    start = 0
    idx = 0
    total = len(clean)
    while start < total:
        end = min(start + size, total)
        chunk = clean[start:end].strip()
        if chunk:
            chunks.append({"source_file": source_file, "chunk_index": idx, "text": chunk})
            idx += 1
        if end >= total:
            break
        start += step
    return chunks


def _extract_pdf_text(path: Path) -> str:
    import fitz

    pages: list[str] = []
    with fitz.open(path) as doc:
        for page in doc:
            pages.append(page.get_text("text"))
    return "\n".join(pages)
