<template>
  <div class="wrap">
    <h1 class="page-title">Extraction Workspace</h1>
    <p class="page-sub">
      以大模型抽取为主，采用共享 evidence pack、双 worker + 单 judge + 可选 repair，并先写入 staging graph
      由人工确认后再合并入主图。
    </p>

    <el-row :gutter="12">
      <el-col :xs="24" :lg="8">
        <div class="panel glass-card">
          <div class="panel-title">输入与预算</div>
          <el-input v-model="title" placeholder="文档标题（可选）" class="mb" />
          <el-select v-model="scenarioHint" class="mb" style="width: 100%">
            <el-option label="IMS" value="IMS" />
            <el-option label="VoWiFi" value="VoWiFi" />
            <el-option label="Open Gateway" value="Open Gateway" />
          </el-select>
          <el-radio-group v-model="budgetMode" class="mb">
            <el-radio-button label="default">默认预算</el-radio-button>
            <el-radio-button label="high_precision">高精度</el-radio-button>
          </el-radio-group>
          <el-input
            v-model="text"
            type="textarea"
            :rows="16"
            placeholder="粘贴 3GPP / GSMA / IMS / VoWiFi / Open Gateway 标准片段..."
          />
          <div class="row mt">
            <el-button type="primary" :loading="store.loading" @click="run">启动抽取</el-button>
            <el-button :disabled="!runId" @click="refresh">刷新 run</el-button>
            <el-button :disabled="!runId" @click="runRepair">执行 repair</el-button>
          </div>
          <el-alert v-if="store.error" type="error" :title="store.error" show-icon class="mt" />
        </div>
        <div class="panel glass-card">
          <div class="panel-title">Run 历史</div>
          <el-table :data="store.runHistory" size="small" stripe max-height="260">
            <el-table-column prop="run_id" label="run_id" min-width="180" show-overflow-tooltip />
            <el-table-column prop="scenario_hint" label="scenario" width="100" />
            <el-table-column prop="needs_repair" label="repair" width="70">
              <template #default="{ row }">
                <el-tag :type="row.needs_repair ? 'warning' : 'success'" size="small">
                  {{ row.needs_repair ? "yes" : "no" }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="action" width="90">
              <template #default="{ row }">
                <el-button link type="primary" @click="loadRun(row.run_id)">打开</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-col>

      <el-col :xs="24" :lg="16">
        <div class="panel glass-card">
          <div class="panel-title">Run 状态</div>
          <el-descriptions :column="2" border size="small">
            <el-descriptions-item label="run_id">{{ runId || "—" }}</el-descriptions-item>
            <el-descriptions-item label="stage">{{ store.currentRun?.stage || "—" }}</el-descriptions-item>
            <el-descriptions-item label="recommended_worker">{{
              store.currentRun?.judge?.recommended_worker || "—"
            }}</el-descriptions-item>
            <el-descriptions-item label="needs_repair">{{
              store.currentRun?.judge?.needs_repair ? "yes" : "no"
            }}</el-descriptions-item>
          </el-descriptions>
        </div>

        <div class="panel glass-card">
          <el-tabs v-model="tab">
            <el-tab-pane label="Evidence Pack" name="evidence">
              <el-table :data="evidenceItems" size="small" stripe max-height="260">
                <el-table-column prop="heading" label="heading" width="180" />
                <el-table-column prop="relevance_score" label="score" width="90" />
                <el-table-column prop="text" label="chunk text" min-width="320" show-overflow-tooltip />
              </el-table>
            </el-tab-pane>

            <el-tab-pane label="Workers / Judge" name="judge">
              <el-row :gutter="8" class="mb">
                <el-col :span="12">
                  <div class="subhead">Worker A/B</div>
                  <el-table :data="workerRows" size="small" stripe max-height="180">
                    <el-table-column prop="worker_name" label="worker" width="120" />
                    <el-table-column prop="state_count" label="states" width="80" />
                    <el-table-column prop="transition_count" label="transitions" width="100" />
                    <el-table-column prop="mode" label="mode" />
                  </el-table>
                </el-col>
                <el-col :span="12">
                  <div class="subhead">Judge 评分</div>
                  <el-table :data="judgeRows" size="small" stripe max-height="180">
                    <el-table-column prop="worker_name" label="worker" width="120" />
                    <el-table-column prop="schema_validity_score" label="schema" width="80" />
                    <el-table-column prop="evidence_alignment_score" label="evidence" width="90" />
                    <el-table-column prop="total_score" label="total" width="80" />
                  </el-table>
                </el-col>
              </el-row>
              <div class="subhead">Conflict Set</div>
              <el-table :data="conflictRows" size="small" stripe max-height="180">
                <el-table-column prop="field_path" label="field" width="180" />
                <el-table-column prop="conflict_type" label="type" width="140" />
                <el-table-column prop="severity" label="severity" width="90" />
                <el-table-column prop="description" label="description" />
              </el-table>
            </el-tab-pane>

            <el-tab-pane label="Staging Graph" name="staging">
              <div class="subhead">待审核子图（人工确认后可合并）</div>
              <el-table :data="stagingNodes" size="small" stripe max-height="180">
                <el-table-column prop="id" label="id" width="120" />
                <el-table-column prop="label" label="label" width="140" />
                <el-table-column prop="type" label="type" width="120" />
                <el-table-column prop="source_worker" label="worker" width="100" />
                <el-table-column prop="judge_score" label="judge" width="90" />
              </el-table>
              <div class="subhead mt">staging edges</div>
              <el-table :data="stagingEdges" size="small" stripe max-height="180">
                <el-table-column prop="source" label="source" width="100" />
                <el-table-column prop="interaction" label="interaction" width="150" />
                <el-table-column prop="target" label="target" width="100" />
                <el-table-column prop="source_worker" label="worker" width="100" />
              </el-table>
              <div class="subhead mt">staging vs main diff</div>
              <el-table :data="nodeDiffRows" size="small" stripe max-height="140">
                <el-table-column prop="id" label="node" min-width="180" show-overflow-tooltip />
                <el-table-column prop="status" label="status" width="90">
                  <template #default="{ row }">
                    <el-tag :type="row.status === 'new' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
                  </template>
                </el-table-column>
              </el-table>
              <el-table :data="edgeDiffRows" size="small" stripe max-height="140" class="mt">
                <el-table-column prop="id" label="edge" min-width="260" show-overflow-tooltip />
                <el-table-column prop="status" label="status" width="90">
                  <template #default="{ row }">
                    <el-tag :type="row.status === 'new' ? 'success' : 'info'" size="small">{{ row.status }}</el-tag>
                  </template>
                </el-table-column>
              </el-table>
              <div class="row mt">
                <el-button type="success" :disabled="!runId" @click="mergeToMain">确认并合并到主图</el-button>
              </div>
              <p class="hint" v-if="store.mergeResult">
                {{ store.mergeResult.message }}（nodes: {{ store.mergeResult.merged_nodes }} / edges:
                {{ store.mergeResult.merged_edges }}）
              </p>
            </el-tab-pane>

            <el-tab-pane label="Trace / Report" name="trace">
              <el-timeline>
                <el-timeline-item
                  v-for="(t, idx) in store.trace"
                  :key="idx"
                  :timestamp="t.stage"
                  :type="t.error ? 'danger' : 'primary'"
                >
                  <pre class="trace">{{ JSON.stringify(t.summary, null, 2) }}</pre>
                </el-timeline-item>
              </el-timeline>
              <div class="subhead">Markdown Report</div>
              <pre class="report">{{ store.reportMarkdown || "暂无报告" }}</pre>
            </el-tab-pane>
          </el-tabs>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useExtractionStore } from "@/stores/extractionStore";

const store = useExtractionStore();

const text = ref("");
const title = ref("");
const scenarioHint = ref("IMS");
const budgetMode = ref<"default" | "high_precision">("default");
const tab = ref("evidence");

const runId = computed(() => store.currentRun?.run_id || "");
const evidenceItems = computed(() => store.currentRun?.evidence_pack?.items ?? []);
const workerRows = computed(() =>
  (store.currentRun?.worker_results ?? []).map((w) => ({
    worker_name: w.worker_name,
    state_count: w.states.length,
    transition_count: w.transitions.length,
    mode: w.extraction_mode,
  }))
);
const judgeRows = computed(() => store.currentRun?.judge?.score_details ?? []);
const conflictRows = computed(() => store.currentRun?.judge?.conflict_set ?? []);
const stagingNodes = computed(() => store.runDetail?.staging_graph?.nodes ?? []);
const stagingEdges = computed(() => store.runDetail?.staging_graph?.edges ?? []);
const nodeDiffRows = computed(() => store.stagingDiff?.node_diff ?? []);
const edgeDiffRows = computed(() => store.stagingDiff?.edge_diff ?? []);

async function run() {
  if (!text.value.trim()) return;
  await store.runExtraction({
    text: text.value,
    title: title.value,
    source_type: "text",
    scenario_hint: scenarioHint.value,
    budget_mode: budgetMode.value,
    high_precision: budgetMode.value === "high_precision",
  });
  tab.value = "evidence";
}

async function refresh() {
  if (!runId.value) return;
  await store.loadDetail(runId.value);
}

async function runRepair() {
  if (!runId.value) return;
  await store.repair(runId.value);
  await refresh();
}

async function mergeToMain() {
  if (!runId.value) return;
  await store.merge(runId.value, { selected_nodes: [], selected_edges: [], notes: "approved in UI" });
}

async function loadRun(id: string) {
  await store.loadDetail(id);
  const detail = store.runDetail;
  if (detail) {
    store.setCurrentRunFromDetail(detail);
  }
}

onMounted(async () => {
  await store.loadRunHistory(20);
});
</script>

<style scoped>
.wrap {
  max-width: 1200px;
}
.panel {
  padding: 12px 14px;
  margin-bottom: 12px;
}
.panel-title {
  font-weight: 650;
  margin-bottom: 8px;
}
.row {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.subhead {
  font-weight: 600;
  color: var(--muted);
  margin-bottom: 8px;
}
.mb {
  margin-bottom: 8px;
}
.mt {
  margin-top: 8px;
}
.trace,
.report {
  background: rgba(10, 16, 28, 0.75);
  border: 1px solid rgba(160, 190, 255, 0.16);
  border-radius: 8px;
  padding: 8px;
  overflow: auto;
  max-height: 220px;
  white-space: pre-wrap;
  color: #cbd8f5;
  font-size: 12px;
}
.hint {
  font-size: 12px;
  color: var(--muted);
}
</style>
