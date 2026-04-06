import { defineStore } from "pinia";
import { ref } from "vue";
import { ingestGraphRagText, queryGraphRag, queryGraphRagStream } from "@/api/graphRag";
import type {
  GraphRAGIngestRequest,
  GraphRAGIngestResponse,
  GraphRAGQueryRequest,
  GraphRAGQueryResponse,
} from "@/types/graphRag";

export const useGraphRagStore = defineStore("graph-rag", () => {
  const loading = ref(false);
  const error = ref<string | null>(null);
  const lastIngest = ref<GraphRAGIngestResponse | null>(null);
  const lastAnswer = ref<GraphRAGQueryResponse | null>(null);

  async function ingest(payload: GraphRAGIngestRequest) {
    loading.value = true;
    error.value = null;
    try {
      const data = await ingestGraphRagText(payload);
      lastIngest.value = data;
      return data;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "graph-rag ingest failed";
      throw e;
    } finally {
      loading.value = false;
    }
  }

  async function ask(payload: GraphRAGQueryRequest) {
    loading.value = true;
    error.value = null;
    try {
      const data = await queryGraphRag(payload);
      lastAnswer.value = data;
      return data;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "graph-rag query failed";
      throw e;
    } finally {
      loading.value = false;
    }
  }

  async function askStream(payload: GraphRAGQueryRequest) {
    loading.value = true;
    error.value = null;
    lastAnswer.value = { answer: "", confidence: 0, citations: [], notes: [] };
    try {
      await queryGraphRagStream(payload, {
        onDelta: (delta) => {
          if (!lastAnswer.value) return;
          lastAnswer.value.answer += delta;
        },
        onFinal: (data) => {
          lastAnswer.value = data;
        },
        onError: (msg) => {
          error.value = msg;
        },
      });
      return lastAnswer.value;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "graph-rag stream query failed";
      throw e;
    } finally {
      loading.value = false;
    }
  }

  return {
    loading,
    error,
    lastIngest,
    lastAnswer,
    ingest,
    ask,
    askStream,
  };
});

