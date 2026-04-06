import client from "@/api/client";
import type {
  GraphRAGIngestRequest,
  GraphRAGIngestResponse,
  GraphRAGQueryRequest,
  GraphRAGQueryResponse,
} from "@/types/graphRag";

export async function ingestGraphRagText(payload: GraphRAGIngestRequest) {
  const { data } = await client.post<GraphRAGIngestResponse>("/api/graph-rag/ingest-text", payload);
  return data;
}

export async function queryGraphRag(payload: GraphRAGQueryRequest) {
  const { data } = await client.post<GraphRAGQueryResponse>("/api/graph-rag/query", payload);
  return data;
}

function resolveApiBase() {
  const base = (import.meta.env.VITE_API_BASE ?? "").trim();
  if (!base) return "";
  return base.endsWith("/") ? base.slice(0, -1) : base;
}

export async function queryGraphRagStream(
  payload: GraphRAGQueryRequest,
  handlers: {
    onStart?: () => void;
    onDelta?: (textDelta: string) => void;
    onFinal?: (data: GraphRAGQueryResponse) => void;
    onError?: (message: string) => void;
  },
) {
  const url = `${resolveApiBase()}/api/graph-rag/query-stream`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok || !res.body) {
    throw new Error(`stream request failed: ${res.status}`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx = buffer.indexOf("\n");
    while (idx >= 0) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) {
        const evt = JSON.parse(line) as any;
        if (evt.type === "start") handlers.onStart?.();
        else if (evt.type === "delta") handlers.onDelta?.(String(evt.delta ?? ""));
        else if (evt.type === "final") handlers.onFinal?.(evt.payload as GraphRAGQueryResponse);
        else if (evt.type === "error") handlers.onError?.(String(evt.error ?? "stream error"));
      }
      idx = buffer.indexOf("\n");
    }
  }
}

