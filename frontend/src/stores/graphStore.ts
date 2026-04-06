import { defineStore } from "pinia";
import { ref } from "vue";
import client from "@/api/client";
import type { GraphEdge, GraphNode, GraphPayload } from "@/types/graph";

export const useGraphStore = defineStore("graph", () => {
  const nodes = ref<GraphNode[]>([]);
  const edges = ref<GraphEdge[]>([]);
  const loading = ref(false);
  const error = ref<string | null>(null);

  async function load() {
    loading.value = true;
    error.value = null;
    try {
      const { data } = await client.get<GraphPayload>("/api/graph");
      nodes.value = data.nodes;
      edges.value = data.edges;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "加载图谱失败";
    } finally {
      loading.value = false;
    }
  }

  async function loadSubgraphByQuery(q: string, opts?: { seedLimit?: number; maxEdges?: number }) {
    loading.value = true;
    error.value = null;
    try {
      const params = {
        q,
        seed_limit: opts?.seedLimit ?? 20,
        max_edges: opts?.maxEdges ?? 120,
      };
      const { data } = await client.get<GraphPayload>("/api/graph/subgraph/search", { params });
      nodes.value = data.nodes;
      edges.value = data.edges;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "加载子图失败";
    } finally {
      loading.value = false;
    }
  }

  function mergePayload(p: GraphPayload) {
    const nodeMap = new Map<string, GraphNode>();
    for (const n of nodes.value) nodeMap.set(n.id, n);
    for (const n of p.nodes) nodeMap.set(n.id, n);

    const edgeMap = new Map<string, GraphEdge>();
    const keyOf = (e: GraphEdge) => `${e.source}__${e.interaction}__${e.target}`;
    for (const e of edges.value) edgeMap.set(keyOf(e), e);
    for (const e of p.edges) edgeMap.set(keyOf(e), e);

    nodes.value = Array.from(nodeMap.values());
    edges.value = Array.from(edgeMap.values());
  }

  async function loadNeighbors(nodeId: string, depth = 1) {
    loading.value = true;
    error.value = null;
    try {
      const { data } = await client.get<GraphPayload>(`/api/graph/neighbors/${encodeURIComponent(nodeId)}`, {
        params: { depth },
      });
      mergePayload(data);
      return data;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "加载邻居子图失败";
      throw e;
    } finally {
      loading.value = false;
    }
  }

  function setFromPayload(p: GraphPayload) {
    nodes.value = p.nodes;
    edges.value = p.edges;
  }

  return { nodes, edges, loading, error, load, loadSubgraphByQuery, loadNeighbors, mergePayload, setFromPayload };
});
