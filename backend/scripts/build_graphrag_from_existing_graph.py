"""
GraphRAG / Milvus：仅向量化入库（embedding），不调用抽取用的大模型 chat。

Neo4j 必须先由 ``POST /api/builder/run-local-import`` 写好；本脚本从 Neo4j 读节点/边，
并把 ``data/input`` 下已支持的文件切块写入向量库。

---------------------------------------------------------------------------
推荐顺序（最稳，避免重复花钱买抽取）
---------------------------------------------------------------------------
1) 启动 Neo4j（及 Milvus，若用 Docker）：``docker compose -f docker-compose.neo4j.yml up -d`` 等。
2) 启动 API 时不要 ``--reload``（长任务不会被文件监视打断）::

     cd backend
     set PYTHONUNBUFFERED=1
     python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level info

3) Neo4j 入库（LLM 抽取，计费）::

     POST http://127.0.0.1:8000/api/builder/run-local-import
     body: {"dry_run": false}

4) 仅 embedding 写入 Milvus（计费为 embedding API，无 chat 抽取）::

     cd backend
     python scripts/build_graphrag_from_existing_graph.py

不要调用 ``POST /api/graph-rag/ingest-text`` 做第 4 步：该接口会对每个 chunk 再跑一遍 LLM 抽取。
---------------------------------------------------------------------------
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path

from langchain_core.documents import Document

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.core.config import settings  # noqa: E402
from app.repositories.graph_repository import get_graph_repository  # noqa: E402
from app.services.graph_rag_ingest_service import get_graph_rag_ingest_service  # noqa: E402
from app.utils.file_parser import chunk_text, iter_input_documents, supported_input_suffixes  # noqa: E402

logger = logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build GraphRAG vectors without calling LLM extraction again.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Optional max number of input files (for incremental runs).",
    )
    parser.add_argument(
        "--source-prefix",
        type=str,
        default="input",
        help="Prefix for source_file metadata when writing chunk docs.",
    )
    return parser.parse_args()


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


async def _run(max_files: int | None, source_prefix: str) -> None:
    _configure_logging()
    logger.info(
        "[GraphRAG-embed-only] start — NO LLM KG extraction; input_suffixes=%s milvus_uri=%s collection=%s embed_model=%s",
        sorted(supported_input_suffixes()),
        settings.graph_rag_milvus_uri,
        settings.graph_rag_collection,
        settings.graph_rag_embedding_model,
    )

    ingest_service = get_graph_rag_ingest_service()
    repo = get_graph_repository()
    graph = repo.get_graph()
    n_nodes = len(graph.get("nodes", []))
    n_edges = len(graph.get("edges", []))
    logger.info(
        "[GraphRAG-embed-only] loaded Neo4j snapshot nodes=%s edges=%s (graph_backend=%s)",
        n_nodes,
        n_edges,
        settings.graph_backend,
    )

    # 1) 复用 input 文档，直接切块后写入 chunk 向量（不做 LLM 抽取）
    docs: list[Document] = []
    files = list(iter_input_documents(Path(settings.kg_input_dir)))
    if max_files is not None and max_files > 0:
        files = files[:max_files]

    chunk_total = 0
    for source_name, full_text in files:
        chunks = chunk_text(
            full_text,
            chunk_size=settings.kg_chunk_size,
            chunk_overlap=settings.kg_chunk_overlap,
        )
        for item in chunks:
            chunk_index = int(item["chunk_index"])
            text = str(item["text"])
            docs.append(
                Document(
                    page_content=text,
                    metadata={
                        "type": "chunk",
                        "source_file": f"{source_prefix}:{source_name}",
                        "chunk_index": chunk_index,
                    },
                )
            )
            chunk_total += 1

    logger.info(
        "[GraphRAG-embed-only] input files=%s chunk_documents=%s",
        len(files),
        chunk_total,
    )

    # 2) 复用 Neo4j 里已构建好的节点/边，写入 node/edge 向量
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    for node in nodes:
        docs.append(
            Document(
                page_content=ingest_service._node_to_text(node),  # noqa: SLF001
                metadata={
                    "type": "node",
                    "source_file": "neo4j-graph",
                    "chunk_index": -1,
                    "node_id": node.get("id", ""),
                    "node_type": node.get("type", ""),
                },
            )
        )

    for edge in edges:
        docs.append(
            Document(
                page_content=ingest_service._edge_to_text(edge),  # noqa: SLF001
                metadata={
                    "type": "edge",
                    "source_file": "neo4j-graph",
                    "chunk_index": -1,
                    "source": edge.get("source", ""),
                    "target": edge.get("target", ""),
                    "interaction": edge.get("interaction", ""),
                },
            )
        )

    if not docs:
        logger.warning("[GraphRAG-embed-only] no documents generated; exit")
        return

    # 3) 按批次写 Milvus，避免单次大 payload 压垮 embedding 接口
    store = ingest_service._build_vector_store()  # noqa: SLF001
    batch_size = max(1, int(settings.graph_rag_ingest_batch_size))
    sleep_sec = max(0.0, float(settings.graph_rag_ingest_batch_sleep_sec))
    inserted = 0
    n_batches = (len(docs) + batch_size - 1) // batch_size
    for batch_idx, start in enumerate(range(0, len(docs), batch_size), start=1):
        batch = docs[start : start + batch_size]
        logger.info(
            "[GraphRAG-embed-only] embedding batch %s/%s size=%s (calls embedding API only)",
            batch_idx,
            n_batches,
            len(batch),
        )
        store.add_documents(batch)
        inserted += len(batch)
        if start + batch_size < len(docs) and sleep_sec > 0:
            await asyncio.sleep(sleep_sec)

    logger.info(
        "[GraphRAG-embed-only] done files=%s chunks=%s nodes=%s edges=%s inserted_docs=%s",
        len(files),
        chunk_total,
        len(nodes),
        len(edges),
        inserted,
    )


def main() -> int:
    args = _parse_args()
    asyncio.run(_run(args.max_files, args.source_prefix))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
