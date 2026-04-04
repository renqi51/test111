<template>
  <div class="wrap">
    <h1 class="page-title">候选暴露面生成</h1>
    <p class="page-sub">
      基于图谱上下文与 MCC/MNC 动态拼接候选 FQDN，并关联协议栈、网元、证据与风险假设。可在下方对<strong>授权实验网</strong>主机执行 DNS + HTTPS 探测（由后端白名单或 open 模式约束）。
    </p>

    <div class="panel glass-card form-panel">
      <el-form :inline="true" @submit.prevent="generate">
        <el-form-item label="服务">
          <el-select v-model="service" style="width: 200px">
            <el-option label="VoWiFi" value="VoWiFi" />
            <el-option label="IMS" value="IMS" />
            <el-option label="Open Gateway" value="Open Gateway" />
          </el-select>
        </el-form-item>
        <el-form-item label="MCC">
          <el-input v-model="mcc" maxlength="3" style="width: 100px" placeholder="460" />
        </el-form-item>
        <el-form-item label="MNC">
          <el-input v-model="mnc" maxlength="3" style="width: 100px" placeholder="001" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" @click="generate">生成</el-button>
          <el-button type="warning" :loading="analysisLoading" @click="analyzeExposure">分析暴露面</el-button>
          <el-button :loading="loading" @click="exportCsv">导出 CSV</el-button>
          <el-button text type="primary" @click="presetOperator">运营商预设 MCC/MNC</el-button>
        </el-form-item>
      </el-form>
      <el-checkbox v-model="useLlmInAnalysis">分析时启用 LLM 保守解释</el-checkbox>
      <el-alert v-if="err" type="error" :title="err" show-icon />
    </div>

    <div class="panel glass-card">
      <el-skeleton v-if="loading" :rows="5" animated />
      <el-empty v-else-if="!rows.length" description="点击生成查看结果" />
      <el-table v-else :data="rows" size="small" stripe @row-click="onRowClick">
        <el-table-column prop="candidate_fqdn" label="候选 FQDN" min-width="220" />
        <el-table-column label="协议栈" min-width="160">
          <template #default="{ row }">{{ row.protocol_stack.join(", ") }}</template>
        </el-table-column>
        <el-table-column label="网元" min-width="160">
          <template #default="{ row }">{{ row.network_functions.join(", ") }}</template>
        </el-table-column>
        <el-table-column prop="confidence" label="置信度" width="90" />
      </el-table>
      <p class="hint">点击行：尝试跳转到图谱中的相关服务节点（新窗口路由）。</p>
    </div>

    <div class="panel glass-card probe-panel">
      <div class="probe-head">
        <span class="probe-title">授权环境探测</span>
        <el-tag v-if="probeStatus?.probe_mode === 'open'" type="warning" size="small">open 模式</el-tag>
        <el-tag v-else-if="probeStatus?.allowlist_configured" type="success" size="small">后缀白名单已配置</el-tag>
        <el-tag v-else type="info" size="small">请配置 EXPOSURE_PROBE_ALLOWLIST_SUFFIXES</el-tag>
      </div>
      <p class="probe-hint">
        对下方主机列表执行并发探测（最多 {{ probeStatus?.max_concurrent ?? "—" }} 路）。未命中策略的主机会被跳过并标注原因。
      </p>
      <el-input
        v-model="extraHosts"
        type="textarea"
        :rows="2"
        placeholder="额外主机（每行一个，可选），例如实验网 API 网关"
        class="mb-sm"
      />
      <div class="probe-actions">
        <el-button type="success" :loading="probeLoading" :disabled="!rows.length && !extraHosts.trim()" @click="runProbe">
          探测：表格 FQDN + 额外主机
        </el-button>
        <el-button :loading="probeLoading" @click="fetchProbeStatus">刷新策略</el-button>
      </div>
      <el-alert v-if="probeErr" type="error" :title="probeErr" show-icon class="mb-sm" />
      <el-table v-if="probeRun" :data="probeRun.results" size="small" stripe max-height="320">
        <el-table-column prop="host" label="主机" min-width="200" />
        <el-table-column label="策略" width="88">
          <template #default="{ row }">
            <el-tag v-if="row.permitted" size="small" type="success">允许</el-tag>
            <el-tag v-else size="small" type="info">跳过</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="DNS" width="72">
          <template #default="{ row }">
            <el-tag v-if="!row.permitted" size="small" type="info">—</el-tag>
            <el-tag v-else-if="row.dns_ok" size="small" type="success">OK</el-tag>
            <el-tag v-else size="small" type="danger">×</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="HTTPS" min-width="120">
          <template #default="{ row }">
            <span v-if="!row.permitted">{{ row.policy_reason }}</span>
            <span v-else-if="row.https_ok">状态 {{ row.https_status }}</span>
            <span v-else class="err-txt">{{ row.tls_error || row.error }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="https_latency_ms" label="ms" width="72" />
        <el-table-column label="开放端口" min-width="120">
          <template #default="{ row }">
            <span class="ip-cell">{{ (row.open_ports || []).join(", ") || "—" }}</span>
          </template>
        </el-table-column>
        <el-table-column label="服务指纹" min-width="140">
          <template #default="{ row }">
            <span class="ip-cell">{{ (row.service_hints || []).join(", ") || "—" }}</span>
          </template>
        </el-table-column>
        <el-table-column label="解析 IP" min-width="160">
          <template #default="{ row }">
            <span class="ip-cell">{{ row.dns_addresses?.join(", ") }}</span>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <div class="panel glass-card" v-if="analysis">
      <div class="probe-head">
        <span class="probe-title">暴露面分析结果</span>
        <el-tag size="small" type="success">run_id: {{ analysis.run_id }}</el-tag>
      </div>
      <p class="probe-hint">
        候选 {{ analysis.summary?.total_candidates ?? 0 }}，高风险 {{ analysis.summary?.high_or_critical ?? 0 }}，
        授权可达 {{ analysis.summary?.probe_reachable ?? 0 }}，路径 {{ analysis.summary?.attack_paths ?? 0 }}，
        已验证路径 {{ analysis.summary?.validated_paths ?? 0 }}，LLM {{ analysis.summary?.llm_used ? "已使用" : "未使用" }}
      </p>
      <el-table :data="analysisRows" size="small" stripe>
        <el-table-column prop="candidate_fqdn" label="候选 FQDN" min-width="220" />
        <el-table-column prop="risk_level" label="风险级别" width="100">
          <template #default="{ row }">
            <el-tag :type="riskTagType(row.risk_level)" size="small">{{ row.risk_level }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="score" label="分数" width="90" />
        <el-table-column label="探测" min-width="140">
          <template #default="{ row }">
            DNS {{ row.dns_ok ? "OK" : "×" }} / HTTPS {{ row.https_ok === true ? row.https_status : "×" }}
          </template>
        </el-table-column>
        <el-table-column label="指纹" min-width="160">
          <template #default="{ row }">
            Ports {{ row.open_ports.length ? row.open_ports.join(",") : "—" }} /
            {{ row.service_hints.length ? row.service_hints.join(",") : "unknown" }}
          </template>
        </el-table-column>
        <el-table-column label="来源" min-width="180">
          <template #default="{ row }">
            {{ row.source_kind.join(", ") }}
          </template>
        </el-table-column>
        <el-table-column prop="summary" label="保守结论" min-width="260" />
      </el-table>

      <el-collapse class="mt-sm">
        <el-collapse-item title="模式与证据" name="patterns">
          <el-table :data="analysis.patterns" size="small" stripe>
            <el-table-column prop="pattern_id" label="pattern_id" width="180" />
            <el-table-column prop="expression" label="表达式/候选模式" min-width="220" />
            <el-table-column label="证据文档" min-width="220">
              <template #default="{ row }">{{ row.evidence_docs?.join(", ") || "n/a" }}</template>
            </el-table-column>
            <el-table-column prop="rationale" label="依据" min-width="240" />
          </el-table>
        </el-collapse-item>
        <el-collapse-item title="攻击路径（推演）" name="paths">
          <el-table :data="analysis.attack_paths" size="small" stripe>
            <el-table-column prop="path_id" label="path_id" width="180" />
            <el-table-column prop="entrypoint" label="入口" min-width="220" />
            <el-table-column label="跳板/路径" min-width="220">
              <template #default="{ row }">{{ row.pivots?.join(" -> ") || "n/a" }}</template>
            </el-table-column>
            <el-table-column prop="target_asset" label="目标资产" min-width="140" />
            <el-table-column prop="likelihood" label="可能性" width="90" />
            <el-table-column prop="impact" label="影响" width="90" />
            <el-table-column prop="validation_status" label="验证状态" width="130" />
          </el-table>
        </el-collapse-item>
      </el-collapse>

      <div class="probe-actions mt-sm">
        <el-button :loading="reportLoading" @click="loadReport">查看报告</el-button>
      </div>
      <el-input
        v-if="reportMarkdown"
        v-model="reportMarkdown"
        type="textarea"
        :rows="14"
        readonly
        class="mt-sm"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import client from "@/api/client";
import type { ExposureAnalysisResponse, ExposureAssessment, ExposureCandidate, ExposureRow, ProbeRun, ProbeStatusPayload } from "@/types/graph";

const router = useRouter();
const service = ref("IMS");
const mcc = ref("460");
const mnc = ref("001");
const loading = ref(false);
const err = ref<string | null>(null);
const rows = ref<ExposureRow[]>([]);

const extraHosts = ref("");
const probeStatus = ref<ProbeStatusPayload | null>(null);
const probeRun = ref<ProbeRun | null>(null);
const probeLoading = ref(false);
const probeErr = ref<string | null>(null);
const analysis = ref<ExposureAnalysisResponse | null>(null);
const analysisLoading = ref(false);
const reportLoading = ref(false);
const reportMarkdown = ref("");
const useLlmInAnalysis = ref(true);

const analysisRows = computed(() => {
  if (!analysis.value) return [];
  const byId = new Map<string, ExposureAssessment>();
  analysis.value.assessments.forEach((x) => byId.set(x.candidate_id, x));
  return analysis.value.candidates.map((c: ExposureCandidate) => {
    const a = byId.get(c.candidate_id);
    return {
      candidate_fqdn: c.candidate_fqdn,
      risk_level: a?.risk_level ?? "low",
      score: a?.score ?? 0,
      summary: a?.summary ?? "",
      dns_ok: !!c.probe_status?.dns_ok,
      https_ok: c.probe_status?.https_ok,
      https_status: c.probe_status?.https_status,
      open_ports: c.probe_status?.open_ports ?? [],
      service_hints: c.probe_status?.service_hints ?? [],
      source_kind: c.evidence?.source_kind ?? [],
    };
  });
});

onMounted(() => {
  void fetchProbeStatus();
});

function presetOperator() {
  mcc.value = "460";
  mnc.value = "01";
}

async function fetchProbeStatus() {
  try {
    const { data } = await client.get<ProbeStatusPayload>("/api/probe/status");
    probeStatus.value = data;
  } catch {
    probeStatus.value = null;
  }
}

async function runProbe() {
  probeLoading.value = true;
  probeErr.value = null;
  const fromTable = rows.value.map((r) => r.candidate_fqdn);
  const extras = extraHosts.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  const targets = [...fromTable, ...extras];
  if (!targets.length) {
    probeLoading.value = false;
    probeErr.value = "没有可探测的主机";
    return;
  }
  try {
    const { data } = await client.post<ProbeRun>("/api/probe/run", {
      targets,
      context: `exposure:${service.value}`,
    });
    probeRun.value = data;
  } catch (e: unknown) {
    probeErr.value = e instanceof Error ? e.message : "探测失败（检查后端策略与网络）";
    probeRun.value = null;
  } finally {
    probeLoading.value = false;
  }
}

function riskTagType(level: string) {
  if (level === "critical") return "danger";
  if (level === "high") return "warning";
  if (level === "medium") return "info";
  return "success";
}

function svcNodeId(s: string) {
  const k = s.toLowerCase().replace(/\s+/g, "");
  if (k.includes("ims")) return "svc_ims";
  if (k.includes("vowifi") || k === "vowifi") return "svc_vowifi";
  if (k.includes("gateway")) return "svc_open_gateway";
  return "svc_ims";
}

async function generate() {
  loading.value = true;
  err.value = null;
  try {
    const { data } = await client.post<ExposureRow[]>("/api/exposure/generate", {
      service: service.value,
      mcc: mcc.value,
      mnc: mnc.value,
    });
    rows.value = data;
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : "生成失败（检查 MCC/MNC 为数字）";
    rows.value = [];
  } finally {
    loading.value = false;
  }
}

async function analyzeExposure() {
  analysisLoading.value = true;
  err.value = null;
  reportMarkdown.value = "";
  try {
    const extras = extraHosts.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const { data } = await client.post<ExposureAnalysisResponse>("/api/exposure/analyze", {
      service: service.value,
      mcc: mcc.value,
      mnc: mnc.value,
      include_probe: true,
      extra_hosts: extras,
      use_llm: useLlmInAnalysis.value,
    });
    analysis.value = data;
    if (data.probe_run && (data.probe_run as ProbeRun).results) {
      probeRun.value = data.probe_run as ProbeRun;
    }
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : "分析失败";
    analysis.value = null;
  } finally {
    analysisLoading.value = false;
  }
}

async function loadReport() {
  if (!analysis.value?.run_id) return;
  reportLoading.value = true;
  try {
    const { data } = await client.get<string>(`/api/exposure/${analysis.value.run_id}/report`, {
      responseType: "text",
    });
    reportMarkdown.value = data;
  } catch {
    reportMarkdown.value = "报告加载失败";
  } finally {
    reportLoading.value = false;
  }
}

async function exportCsv() {
  try {
    const { data } = await client.post<string>(
      "/api/exposure/export_csv",
      { service: service.value, mcc: mcc.value, mnc: mnc.value },
      { responseType: "text" },
    );
    const blob = new Blob([data], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "exposure_candidates.csv";
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    err.value = "CSV 导出失败";
  }
}

function onRowClick(row: ExposureRow) {
  void row;
  router.push({ path: "/graph", query: { select: svcNodeId(service.value) } });
}
</script>

<style scoped>
.wrap {
  max-width: 1100px;
}
.panel {
  padding: 14px 16px;
  margin-bottom: 12px;
}
.form-panel {
  margin-bottom: 12px;
}
.hint {
  font-size: 12px;
  color: var(--muted);
  margin-top: 8px;
}
.probe-panel {
  margin-top: 16px;
}
.probe-head {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 8px;
}
.probe-title {
  font-weight: 600;
  font-size: 15px;
}
.probe-hint {
  font-size: 12px;
  color: var(--muted);
  margin: 0 0 10px;
}
.probe-actions {
  display: flex;
  gap: 10px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.mb-sm {
  margin-bottom: 10px;
}
.err-txt {
  color: #f56c6c;
  font-size: 12px;
}
.ip-cell {
  font-size: 12px;
  word-break: break-all;
}
.mt-sm {
  margin-top: 10px;
}
</style>
