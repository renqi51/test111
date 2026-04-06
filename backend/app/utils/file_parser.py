from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

logger = logging.getLogger(__name__)


def read_rule_context(rule_dir: Path) -> str:
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


def _rule_directory_candidates(primary: Path) -> list[Path]:
    """Prefer ``data/rule`` (settings default), then sibling ``data/rules`` if present."""
    out: list[Path] = []
    seen: set[str] = set()
    for d in (primary, primary.parent / "rules"):
        try:
            if not d.is_dir():
                continue
            key = str(d.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(d)
        except OSError:
            continue
    return out


def read_rule_context_multi(primary_rule_dir: Path) -> str:
    """
    Load rule files from the configured directory and from ``<data>/rules`` when it exists.
    Supported per file: .txt, .md, .json, .yaml, .yml (same as ``read_rule_context``).
    """
    dirs = _rule_directory_candidates(primary_rule_dir)
    if not dirs:
        logger.warning(
            "Rules: no directories found (checked %s and %s)",
            primary_rule_dir,
            primary_rule_dir.parent / "rules",
        )
        return ""
    blocks: list[str] = []
    for d in dirs:
        block = read_rule_context(d)
        if not block:
            logger.info(
                "Rules: directory %s — no readable rule files (.txt/.md/.json/.yaml/.yml)",
                d,
            )
            continue
        logger.info("Rules: loaded %s — %s characters", d, len(block))
        blocks.append(block)
    merged = "\n\n".join(blocks).strip()
    logger.info(
        "Rules: merged context total %s characters from %s director(y/ies)",
        len(merged),
        len(blocks),
    )
    return merged


def supported_input_suffixes() -> frozenset[str]:
    """Extensions the KG / GraphRAG input pipeline can read from ``data/input``."""
    return frozenset({".md", ".pdf", ".txt", ".yaml", ".yml"})


def iter_input_documents(
    input_dir: Path,
    suffixes: frozenset[str] | set[str] | None = None,
) -> Iterable[tuple[str, str]]:
    """Yield (filename, text) for each readable input file. If ``suffixes`` is set, only those extensions are read."""
    if not input_dir.exists():
        return
    allowed = supported_input_suffixes() if suffixes is None else frozenset(suffixes)
    for path in sorted([p for p in input_dir.iterdir() if p.is_file()]):
        ext = path.suffix.lower()
        if ext not in allowed:
            continue
        if ext in {".md", ".txt", ".yaml", ".yml"}:
            try:
                text = path.read_text(encoding="utf-8").strip()
            except Exception:
                continue
            if not text:
                continue
            yield path.name, text
            continue
        if ext == ".pdf":
            try:
                text = _extract_pdf_text(path)
            except Exception:
                continue
            if not text.strip():
                continue
            yield path.name, text.strip()


def chunk_text(
    text: str, *,
    chunk_size: int = 4000,
    chunk_overlap: int = 400,
) -> list[dict[str, Any]]:
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
            chunks.append({"chunk_index": idx, "text": chunk})
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
