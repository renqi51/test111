from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_milvus import Milvus
from langchain_openai import OpenAIEmbeddings
from pymilvus import MilvusClient
from pymilvus.orm.connections import connections

from app.core.config import settings
from app.services.kg_builder_service import get_kg_builder_service
from app.utils.file_parser import chunk_text

logger = logging.getLogger(__name__)
_MILVUS_CLIENT_PATCHED = False


def _enable_milvus_orm_alias_compat() -> None:
    """
    兼容补丁：
    - langchain_milvus 内部会用 MilvusClient._using 去构造 ORM Collection；
    - 在 pymilvus 2.6.x 中，该 alias 默认不是 ORM 已注册连接，可能触发
      `ConnectionNotExistException: should create connection first.`。
    - 这里将 alias 固定到可控值并显式注册 ORM 连接，保证远程/Docker Milvus 可用。
    """
    global _MILVUS_CLIENT_PATCHED
    if _MILVUS_CLIENT_PATCHED:
        return

    original_init = MilvusClient.__init__

    def patched_init(  # type: ignore[no-untyped-def]
        self,
        uri: str = "http://localhost:19530",
        user: str = "",
        password: str = "",
        db_name: str = "",
        token: str = "",
        timeout: float | None = None,
        **kwargs,
    ) -> None:
        alias = str(kwargs.pop("alias", "graph-rag"))
        original_init(
            self,
            uri=uri,
            user=user,
            password=password,
            db_name=db_name,
            token=token,
            timeout=timeout,
            **kwargs,
        )
        try:
            connections.connect(
                alias=alias,
                uri=uri,
                user=user,
                password=password,
                db_name=db_name,
                token=token,
            )
            self._using = alias
        except Exception:  # noqa: BLE001
            # 若 ORM alias 注册失败，回退到原行为，避免影响其他调用场景。
            pass

    MilvusClient.__init__ = patched_init  # type: ignore[method-assign]
    _MILVUS_CLIENT_PATCHED = True


class GraphRAGIngestService:
    """
    GraphRAG 入库服务：
    1) 文本切块；
    2) 调用 KG 抽取得到节点/边；
    3) 将 chunk/node/edge 三类文本统一向量化并写入 Milvus。
    """

    def _resolve_milvus_uri(self) -> str:
        """
        将 Milvus Lite 的本地路径规范化，并确保父目录存在。
        说明：
        - Milvus Lite 使用 sqlite-like 的本地文件持久化；
        - 这里统一写到 settings.graph_rag_milvus_uri 指定位置。
        """
        raw = settings.graph_rag_milvus_uri.strip()
        # Docker/远程 Milvus 场景：如果是 URI（如 http://127.0.0.1:19530），直接返回。
        if "://" in raw:
            return raw
        path = Path(raw)
        if not path.is_absolute():
            # 以 backend 工作目录为基准，避免不同 cwd 下路径漂移。
            path = (Path.cwd() / path).resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)

    def _build_embeddings(self) -> OpenAIEmbeddings:
        """
        构建 Embedding 客户端：
        - 不硬编码 key/base_url；
        - 优先读取 graph_rag_embedding_*；
        - 未配置时复用 llm_* 配置。
        """
        api_key = settings.graph_rag_embedding_api_key_value or settings.llm_api_key_value
        base_url = settings.graph_rag_embedding_base_url or settings.llm_base_url
        if not api_key:
            raise RuntimeError("Embedding API key is not configured")
        # base_url 允许为空（官方默认域名），兼容 OpenAI 与兼容网关。
        kwargs: dict[str, Any] = {
            "model": settings.graph_rag_embedding_model,
            "api_key": api_key,
            # 显式声明超时与重试，降低网络抖动造成的单批失败概率。
            "request_timeout": settings.graph_rag_embedding_request_timeout,
            "max_retries": settings.graph_rag_embedding_max_retries,
        }
        if base_url:
            kwargs["base_url"] = base_url
        return OpenAIEmbeddings(**kwargs)

    @staticmethod
    def _iter_doc_batches(docs: list[Document], batch_size: int) -> list[list[Document]]:
        size = max(1, int(batch_size))
        return [docs[i : i + size] for i in range(0, len(docs), size)]

    def _build_vector_store(self) -> Milvus:
        """
        构建（或连接）Milvus 向量库。
        说明：
        - 使用 langchain_milvus 简化 schema 与 collection 初始化；
        - auto_id=True 表示主键自动生成，便于持续 append 数据。
        """
        embeddings = self._build_embeddings()
        uri = self._resolve_milvus_uri()
        _enable_milvus_orm_alias_compat()
        return Milvus(
            embedding_function=embeddings,
            collection_name=settings.graph_rag_collection,
            connection_args={"uri": uri, "alias": "graph-rag"},
            auto_id=True,
            drop_old=False,
        )

    @staticmethod
    def _node_to_text(node: dict[str, Any]) -> str:
        """
        将节点序列化为可检索的自然语言描述文本。
        这样向量库可直接召回“图谱结构语义”，而不是只召回原文片段。
        """
        node_id = node.get("id", "")
        label = node.get("label", "")
        node_type = node.get("type", "")
        props = node.get("properties", {}) or {}
        desc = props.get("description", "")
        return f"实体名称: {label}; 实体ID: {node_id}; 类型: {node_type}; 描述: {desc}"

    @staticmethod
    def _edge_to_text(edge: dict[str, Any]) -> str:
        """
        将边序列化为自然语言描述，便于关系型问答检索。
        """
        source = edge.get("source", "")
        target = edge.get("target", "")
        interaction = edge.get("interaction", "")
        props = edge.get("properties", {}) or {}
        return f"关系: {source} --[{interaction}]--> {target}; 属性: {props}"

    async def ingest_text(
        self,
        *,
        text: str,
        source_file: str,
        rule_context: str,
    ) -> dict[str, Any]:
        """
        单文档入库主流程（核心）：
        1) 切块；
        2) 每块调用 KG 抽取；
        3) 组装三类文档（chunk/node/edge）；
        4) 向量化并写入 Milvus。
        """
        if not text.strip():
            return {
                "source_file": source_file,
                "chunks_total": 0,
                "nodes_total": 0,
                "edges_total": 0,
                "inserted_docs": 0,
                "notes": ["empty text, skipped"],
            }

        logger.info(
            "[GraphRAG] ingest_text begin source_file=%s text_len=%s rule_context_len=%s — "
            "will call LLM chat per chunk (NOT embed-only)",
            source_file,
            len(text),
            len(rule_context or ""),
        )

        chunks = chunk_text(
            text,
            chunk_size=settings.kg_chunk_size,
            chunk_overlap=settings.kg_chunk_overlap,
        )
        kg_service = get_kg_builder_service()

        all_nodes: list[dict[str, Any]] = []
        all_edges: list[dict[str, Any]] = []
        docs: list[Document] = []

        for chunk in chunks:
            chunk_index = int(chunk["chunk_index"])
            chunk_text_value = str(chunk["text"])

            # 1) 原始 chunk 文档（用于“原文证据”召回）
            docs.append(
                Document(
                    page_content=chunk_text_value,
                    metadata={
                        "type": "chunk",
                        "source_file": source_file,
                        "chunk_index": chunk_index,
                    },
                )
            )

            # 2) 逐块做知识图谱抽取
            extraction = await kg_service.process_document_chunk(
                chunk_text_value=chunk_text_value,
                source_file=source_file,
                chunk_index=chunk_index,
                rule_context=rule_context,
            )
            nodes = [n.model_dump() for n in extraction.nodes]
            edges = [e.model_dump() for e in extraction.edges]
            all_nodes.extend(nodes)
            all_edges.extend(edges)

            # 3) 节点文本化文档
            for node in nodes:
                docs.append(
                    Document(
                        page_content=self._node_to_text(node),
                        metadata={
                            "type": "node",
                            "source_file": source_file,
                            "chunk_index": chunk_index,
                            "node_id": node.get("id", ""),
                            "node_type": node.get("type", ""),
                        },
                    )
                )

            # 4) 边文本化文档
            for edge in edges:
                docs.append(
                    Document(
                        page_content=self._edge_to_text(edge),
                        metadata={
                            "type": "edge",
                            "source_file": source_file,
                            "chunk_index": chunk_index,
                            "source": edge.get("source", ""),
                            "target": edge.get("target", ""),
                            "interaction": edge.get("interaction", ""),
                        },
                    )
                )

        if not docs:
            return {
                "source_file": source_file,
                "chunks_total": len(chunks),
                "nodes_total": 0,
                "edges_total": 0,
                "inserted_docs": 0,
                "notes": ["no documents generated for vector store"],
            }

        try:
            store = self._build_vector_store()
            # 避免一次性大 payload 导致超时或上游限流：
            # 将文档按批次写入，每批之间短暂 sleep 平滑流量。
            batches = self._iter_doc_batches(docs, settings.graph_rag_ingest_batch_size)
            sleep_sec = max(0.0, float(settings.graph_rag_ingest_batch_sleep_sec))
            for idx, batch in enumerate(batches, start=1):
                store.add_documents(batch)
                logger.info(
                    "[GraphRAG] ingest_text embedding batch %s/%s size=%s source_file=%s",
                    idx,
                    len(batches),
                    len(batch),
                    source_file,
                )
                # 最后一批无需等待；其余批次适度让出时间片，降低突发压测效应。
                if idx < len(batches) and sleep_sec > 0:
                    await asyncio.sleep(sleep_sec)
        except Exception as exc:  # noqa: BLE001
            logger.exception("GraphRAG ingest failed: source_file=%s err=%s", source_file, str(exc)[:220])
            raise

        logger.info(
            "[GraphRAG] ingest_text done source_file=%s chunks=%s inserted_docs=%s (included LLM extraction)",
            source_file,
            len(chunks),
            len(docs),
        )
        return {
            "source_file": source_file,
            "chunks_total": len(chunks),
            "nodes_total": len(all_nodes),
            "edges_total": len(all_edges),
            "inserted_docs": len(docs),
            "notes": [],
        }


_graph_rag_ingest_service: GraphRAGIngestService | None = None


def get_graph_rag_ingest_service() -> GraphRAGIngestService:
    global _graph_rag_ingest_service
    if _graph_rag_ingest_service is None:
        _graph_rag_ingest_service = GraphRAGIngestService()
    return _graph_rag_ingest_service

