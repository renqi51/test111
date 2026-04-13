<template>
  <div class="wrap">
    <h1 class="page-title">总览</h1>
    <p class="page-sub">图谱规模、校验摘要、探测与 Agent 最近运行一览。</p>

    <el-skeleton v-if="loading && !stats" :rows="6" animated />
    <el-alert v-else-if="err" type="error" :title="err" show-icon class="mb" />
    <template v-else>
      <el-row :gutter="12" class="mb">
        <el-col v-for="c in cards" :key="c.k" :xs="24" :sm="12" :lg="6">
          <div class="stat glass-card">
            <div class="stat-label">{{ c.label }}</div>
            <div class="stat-value">{{ c.value }}</div>
            <div class="stat-hint">{{ c.hint }}</div>
          </div>
        </el-col>
      </el-row>

      <el-row :gutter="12" class="mb">
        <el-col :xs="24" :lg="12">
          <div class="panel glass-card">
            <div class="panel-head">节点类型分布</div>
            <div ref="chartTypes" class="chart"></div>
          </div>
        </el-col>
        <el-col :xs="24" :lg="12">
          <div class="panel glass-card">
            <div class="panel-head">关系类型分布</div>
            <div ref="chartEdges" class="chart"></div>
          </div>
        </el-col>
      </el-row>

      <el-row :gutter="12">
        <el-col :xs="24" :lg="12">
          <div class="panel glass-card">
            <div class="panel-head">服务类节点（示例）</div>
            <el-table :data="serviceRows" size="small" stripe empty-text="暂无数据">
              <el-table-column prop="label" label="名称" />
              <el-table-column prop="type" label="类型" width="120" />
              <el-table-column prop="id" label="ID" width="160" />
            </el-table>
          </div>
        </el-col>
        <el-col :xs="24" :lg="12">
          <div class="panel glass-card">
            <div class="panel-head">实验验证状态概览</div>
            <el-table :data="expSummary" size="small" stripe>
              <el-table-column prop="status" label="状态" width="130">
                <template #default="{ row }">
                  <el-tag :type="tagType(row.status)" size="small">{{ row.status }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="count" label="任务数" width="90" />
            </el-table>
            <p class="hint">以上为 mock 任务统计汇总。</p>
          </div>
        </el-col>
      </el-row>

      <el-row :gutter="12" class="mb">
        <el-col :xs="24" :lg="12">
          <div class="panel glass-card">
            <div class="panel-head">最近 Agent 运行</div>
            <el-table :data="agentRuns" size="small" stripe empty-text="暂无 Agent 运行记录">
              <el-table-column prop="id" label="run_id" width="220" />
              <el-table-column prop="goal" label="goal" />
            </el-table>
          </div>
        </el-col>
        <el-col :xs="24" :lg="12">
          <div class="panel glass-card">
            <div class="panel-head">系统连接状态</div>
            <el-descriptions :column="1" border size="small">
              <el-descriptions-item label="Graph">
                <b>{{ systemStatus.graph_backend }}</b>
                <span v-if="systemStatus.neo4j.enabled">（Neo4j: {{ systemStatus.neo4j.ok ? 'OK' : '未就绪' }}）</span>
              </el-descriptions-item>
              <el-descriptions-item label="LLM">
                <b>{{ systemStatus.llm.enabled ? 'Enabled' : 'Disabled' }}</b>
              </el-descriptions-item>
              <el-descriptions-item label="Agent">
                <b>{{ systemStatus.agent.enabled ? 'Enabled' : 'Disabled' }}</b>
              </el-descriptions-item>
              <el-descriptions-item label="探测策略">
                <b>{{ systemStatus.probe?.enabled ? systemStatus.probe.mode : 'Off' }}</b>
                <span v-if="systemStatus.probe?.mode === 'open'" class="muted-inline">（open：全量放行，仅建议本机靶场）</span>
                <span
                  v-else-if="
                    systemStatus.probe?.allowlist_suffixes_configured || systemStatus.probe?.allowlist_cidrs_configured
                  "
                  class="muted-inline"
                >
                  （已配：
                  <template v-if="systemStatus.probe?.allowlist_suffixes_configured">域名后缀</template>
                  <template v-if="systemStatus.probe?.allowlist_suffixes_configured && systemStatus.probe?.allowlist_cidrs_configured"> · </template>
                  <template v-if="systemStatus.probe?.allowlist_cidrs_configured">CIDR（字面 IP）</template>
                  ）
                </span>
                <span v-else class="muted-inline">（allowlist 下需在 .env 配置 EXPOSURE_PROBE_ALLOWLIST_SUFFIXES 或 EXPOSURE_PROBE_ALLOWLIST_CIDRS）</span>
              </el-descriptions-item>
            </el-descriptions>
          </div>
        </el-col>
      </el-row>

      <el-row v-if="probeLast" :gutter="12" class="mb">
        <el-col :span="24">
          <div class="panel glass-card">
            <div class="panel-head">最近一次授权探测</div>
            <p class="probe-meta">
              run_id <code>{{ probeLast.run_id }}</code> · 模式 {{ probeLast.probe_mode }} · DNS 成功
              {{ probeLast.summary?.dns_ok ?? 0 }}/{{ probeLast.summary?.total ?? 0 }} · HTTPS 响应
              {{ probeLast.summary?.https_ok ?? 0 }}/{{ probeLast.summary?.total ?? 0 }}
            </p>
            <el-table :data="probeLast.results" size="small" stripe max-height="240">
              <el-table-column prop="host" label="主机" min-width="160" />
              <el-table-column label="策略" width="100">
                <template #default="{ row }">
                  <el-tag v-if="row.permitted" type="success" size="small">允许</el-tag>
                  <el-tag v-else type="info" size="small">跳过</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="DNS" width="80">
                <template #default="{ row }">
                  <el-tag v-if="!row.permitted" type="info" size="small">—</el-tag>
                  <el-tag v-else-if="row.dns_ok" type="success" size="small">OK</el-tag>
                  <el-tag v-else type="danger" size="small">Fail</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="HTTPS" width="100">
                <template #default="{ row }">
                  <span v-if="!row.permitted">—</span>
                  <span v-else-if="row.https_ok">{{ row.https_status ?? "—" }}</span>
                  <span v-else class="err">{{ row.tls_error || row.error || "—" }}</span>
                </template>
              </el-table-column>
              <el-table-column prop="https_latency_ms" label="延迟 ms" width="100" />
            </el-table>
          </div>
        </el-col>
      </el-row>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import * as echarts from "echarts";
import client from "@/api/client";
import type { ExperimentTask, GraphPayload, GraphStats, ProbeRun, ValidateResult } from "@/types/graph";

type AgentRunBrief = { id: string; goal: string };

const loading = ref(true);
const err = ref<string | null>(null);
const stats = ref<GraphStats | null>(null);
const validation = ref<ValidateResult | null>(null);
const graph = ref<GraphPayload | null>(null);
const experiments = ref<ExperimentTask[]>([]);
const systemStatus = ref<any>({
  graph_backend: "—",
  neo4j: { enabled: false, ok: false, uri: null },
  llm: { enabled: false, provider: null, model: null },
  agent: { enabled: false },
  probe: {
    enabled: false,
    mode: "allowlist",
    allowlist_configured: false,
    allowlist_suffixes_configured: false,
    allowlist_cidrs_configured: false,
  },
});
const agentRuns = ref<AgentRunBrief[]>([]);
const probeLast = ref<ProbeRun | null>(null);
const extractionStatus = ref<any>(null);
const extractionLatest = ref<any>(null);

const chartTypes = ref<HTMLDivElement | null>(null);
const chartEdges = ref<HTMLDivElement | null>(null);
let instTypes: echarts.ECharts | null = null;
let instEdges: echarts.ECharts | null = null;

const cards = computed(() => {
  const s = stats.value;
  const v = validation.value;
  const ex = experiments.value;
  const validated = ex.filter((t) => t.status === "validated").length;
  const hi = v?.risks_without_mitigation?.length ?? 0;
  return [
    { k: "n", label: "节点总数", value: s ? String(s.node_count) : "—", hint: "含服务 / 网元 / 文档 / 风险等" },
    { k: "e", label: "关系总数", value: s ? String(s.edge_count) : "—", hint: "uses / depends / documented_in …" },
    {
      k: "v",
      label: "引用完整性",
      value: v ? (v.ok ? "PASS" : "FAIL") : "—",
      hint: "悬空边 / 孤立节点检查",
    },
    { k: "x", label: "高风险候选数", value: v ? String(hi) : "—", hint: "尚未被工具/产物缓解的风险" },
    { k: "y", label: "Neo4j 状态", value: systemStatus.value.neo4j.enabled ? (systemStatus.value.neo4j.ok ? "OK" : "未就绪") : "File", hint: "连接与读取状态" },
    { k: "z", label: "LLM / Agent", value: systemStatus.value.llm.enabled ? "LLM On" : "LLM Off", hint: "Agent 已注册可执行" },
    {
      k: "ex",
      label: "Extraction Pipeline",
      value: extractionStatus.value?.llm?.enabled ? "Ready" : "Degraded",
      hint: extractionStatus.value?.budget?.default_workers ? `W${extractionStatus.value.budget.default_workers}+J1` : "2W+1J",
    },
  ];
});

const serviceRows = computed(() => {
  const g = graph.value;
  if (!g) return [];
  return g.nodes.filter((n) => n.type === "Service").slice(0, 8);
});

const expSummary = computed(() => {
  const m = { planned: 0, "in-progress": 0, validated: 0 } as Record<string, number>;
  for (const t of experiments.value) m[t.status] = (m[t.status] ?? 0) + 1;
  return Object.entries(m).map(([status, count]) => ({ status, count }));
});

function tagType(s: string) {
  if (s === "validated") return "success";
  if (s === "in-progress") return "warning";
  return "info";
}

function renderCharts() {
  const s = stats.value;
  if (!s || !chartTypes.value || !chartEdges.value) return;
  if (!instTypes) instTypes = echarts.init(chartTypes.value, "dark");
  if (!instEdges) instEdges = echarts.init(chartEdges.value, "dark");
  const nt = Object.entries(s.by_node_type);
  const et = Object.entries(s.by_edge_type);
  instTypes.setOption({
    backgroundColor: "transparent",
    grid: { left: 48, right: 16, top: 16, bottom: 48 },
    xAxis: { type: "category", data: nt.map((x) => x[0]), axisLabel: { rotate: 28 } },
    yAxis: { type: "value" },
    series: [{ type: "bar", data: nt.map((x) => x[1]), itemStyle: { color: "#5b8cff" } }],
  });
  instEdges.setOption({
    backgroundColor: "transparent",
    grid: { left: 48, right: 16, top: 16, bottom: 64 },
    xAxis: { type: "category", data: et.map((x) => x[0]), axisLabel: { rotate: 35 } },
    yAxis: { type: "value" },
    series: [{ type: "bar", data: et.map((x) => x[1]), itemStyle: { color: "#3dd6c6" } }],
  });
}

async function loadAll() {
  loading.value = true;
  err.value = null;
  try {
    const [st, val, gp, ex, sys, runs, pl, ext] = await Promise.all([
      client.get<GraphStats>("/api/graph/stats"),
      client.post<ValidateResult>("/api/graph/validate"),
      client.get<GraphPayload>("/api/graph"),
      client.get<{ tasks: ExperimentTask[] }>("/api/experiments"),
      client.get<any>("/api/system/status"),
      client.get<{ runs: any[] }>("/api/agent/runs"),
      client.get<{ run: ProbeRun | null }>("/api/probe/last"),
      client.get<any>("/api/extraction/status"),
    ]);
    stats.value = st.data;
    validation.value = val.data;
    graph.value = gp.data;
    experiments.value = ex.data.tasks ?? [];
    systemStatus.value = sys.data ?? sys;
    agentRuns.value = (runs.data?.runs ?? []).slice(0, 5).map((r) => ({ id: r.id, goal: r.goal }));
    probeLast.value = pl.data?.run ?? null;
    extractionStatus.value = ext.data ?? null;
    extractionLatest.value = ext.data?.latest ?? null;
    renderCharts();
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : "加载失败（请确认后端已启动）";
  } finally {
    loading.value = false;
  }
}

onMounted(() => {
  loadAll();
  window.addEventListener("resize", () => {
    instTypes?.resize();
    instEdges?.resize();
  });
});

watch(stats, () => renderCharts());

onUnmounted(() => {
  instTypes?.dispose();
  instEdges?.dispose();
});
</script>

<style scoped>
.wrap {
  max-width: 1200px;
}
.mb {
  margin-bottom: 12px;
}
.stat {
  padding: 14px 16px;
  margin-bottom: 12px;
}
.stat-label {
  color: var(--muted);
  font-size: 13px;
}
.stat-value {
  font-size: 1.6rem;
  font-weight: 700;
  margin: 6px 0;
}
.stat-hint {
  font-size: 12px;
  color: var(--muted);
}
.panel {
  padding: 14px 16px 8px;
  margin-bottom: 12px;
}
.panel-head {
  font-weight: 600;
  margin-bottom: 8px;
}
.chart {
  height: 280px;
  width: 100%;
}
.hint {
  font-size: 12px;
  color: var(--muted);
  margin: 8px 4px 0;
}
.probe-meta {
  font-size: 13px;
  color: var(--muted);
  margin: 0 0 10px;
}
.probe-meta code {
  font-size: 12px;
}
.muted-inline {
  font-weight: normal;
  color: var(--muted);
  margin-left: 6px;
}
.err {
  color: #f56c6c;
  font-size: 12px;
}
</style>
