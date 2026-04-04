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

  function setFromPayload(p: GraphPayload) {
    nodes.value = p.nodes;
    edges.value = p.edges;
  }

  return { nodes, edges, loading, error, load, setFromPayload };
});
