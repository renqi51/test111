from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from langchain_core.documents import Document
from langchain_milvus import Milvus
from langchain_openai import OpenAIEmbeddings

from app.core.config import settings
from app.services.kg_builder_service import get_kg_builder_service
from app.utils.file_parser import chunk_text

logger = logging.getLogger(__name__)


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
        raw = settings.graph_rag_milvus_uri
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
        }
        if base_url:
            kwargs["base_url"] = base_url
        return OpenAIEmbeddings(**kwargs)

    def _build_vector_store(self) -> Milvus:
        """
        构建（或连接）Milvus 向量库。
        说明：
        - 使用 langchain_milvus 简化 schema 与 collection 初始化；
        - auto_id=True 表示主键自动生成，便于持续 append 数据。
        """
        embeddings = self._build_embeddings()
        uri = self._resolve_milvus_uri()
        return Milvus(
            embedding_function=embeddings,
            collection_name=settings.graph_rag_collection,
            connection_args={"uri": uri},
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
            # LangChain Milvus 内部会完成 embedding + insert。
            store.add_documents(docs)
        except Exception as exc:  # noqa: BLE001
            logger.exception("GraphRAG ingest failed: source_file=%s err=%s", source_file, str(exc)[:220])
            raise

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

