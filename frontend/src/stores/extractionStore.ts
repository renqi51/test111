import { defineStore } from "pinia";
import { ref } from "vue";
import client from "@/api/client";
import type { ExtractionRunResponse } from "@/types/extraction";

export const useExtractionStore = defineStore("extraction", () => {
  const loading = ref(false);
  const error = ref<string | null>(null);
  const currentRun = ref<ExtractionRunResponse | null>(null);
  const runDetail = ref<any | null>(null);
  const trace = ref<any[]>([]);
  const reportMarkdown = ref("");
  const mergeResult = ref<any | null>(null);
  const runHistory = ref<any[]>([]);
  const stagingDiff = ref<any | null>(null);

  async function runExtraction(payload: {
    text: string;
    title?: string;
    source_type?: string;
    scenario_hint: string;
    budget_mode: "default" | "high_precision";
    high_precision: boolean;
  }) {
    loading.value = true;
    error.value = null;
    try {
      const { data } = await client.post<ExtractionRunResponse>("/api/extraction/run", payload);
      currentRun.value = data;
      await loadDetail(data.run_id);
      return data;
    } catch (e: unknown) {
      error.value = e instanceof Error ? e.message : "extraction failed";
      throw e;
    } finally {
      loading.value = false;
    }
  }

  async function loadDetail(runId: string) {
    const [detail, tr, report, diff] = await Promise.all([
      client.get(`/api/extraction/${runId}`),
      client.get(`/api/extraction/${runId}/trace`),
      client.get(`/api/extraction/${runId}/report`),
      client.get(`/api/extraction/${runId}/staging-diff`),
    ]);
    runDetail.value = detail.data;
    trace.value = tr.data?.traces ?? [];
    reportMarkdown.value = report.data?.markdown ?? "";
    stagingDiff.value = diff.data ?? null;
  }

  async function loadRunHistory(limit = 20) {
    const { data } = await client.get(`/api/extraction/runs?limit=${limit}`);
    runHistory.value = data?.runs ?? [];
  }

  function setCurrentRunFromDetail(detail: any) {
    currentRun.value = {
      run_id: detail.run_id,
      stage: "loaded_from_history",
      evidence_pack: detail.evidence_pack,
      worker_results: detail.worker_results,
      judge: detail.judge,
      repair: detail.repair,
      staging_graph_summary: {
        node_count: detail.staging_graph?.nodes?.length ?? 0,
        edge_count: detail.staging_graph?.edges?.length ?? 0,
      },
      trace_summary: detail.trace_summary ?? {},
    } as ExtractionRunResponse;
  }

  async function merge(runId: string, payload: any = { selected_nodes: [], selected_edges: [] }) {
    const { data } = await client.post(`/api/extraction/${runId}/merge`, payload);
    mergeResult.value = data;
    return data;
  }

  async function repair(runId: string) {
    const { data } = await client.post(`/api/extraction/${runId}/repair`);
    if (runDetail.value) runDetail.value.repair = data;
    return data;
  }

  return {
    loading,
    error,
    currentRun,
    runDetail,
    trace,
    reportMarkdown,
    mergeResult,
    runHistory,
    stagingDiff,
    runExtraction,
    loadDetail,
    loadRunHistory,
    setCurrentRunFromDetail,
    merge,
    repair,
  };
});

