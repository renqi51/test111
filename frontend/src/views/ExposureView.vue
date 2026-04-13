<template>
  <div class="wrap">
    <h1 class="page-title">候选暴露面生成</h1>
    <p class="page-sub">
      提交域名 / IP / CIDR，在策略内探测后生成候选；分析页可看端口事实与 LLM 摘要。MCC/MNC 为报表标签。
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
      <el-input
        v-model="domainsInput"
        type="textarea"
        :rows="2"
        placeholder="主域名 / 主机（每行一个），可含 https://host 形式"
        class="mb-sm"
      />
      <div class="asset-inline">
        <el-input v-model="ipsInput" type="textarea" :rows="2" placeholder="字面 IP（每行一个），需命中 open 或 CIDR 白名单" />
        <el-input v-model="cidrsInput" type="textarea" :rows="2" placeholder="CIDR（每行一个），在配置上限内展开后探测" />
      </div>
      <el-checkbox v-model="useLlmInAnalysis">分析时启用 LLM</el-checkbox>
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
      </el-table>
      <p class="hint">点击行可跳转图谱相关节点。</p>
    </div>

    <div class="panel glass-card probe-panel">
      <div class="probe-head">
        <span class="probe-title">授权环境探测</span>
        <el-tag v-if="probeStatus?.probe_mode === 'open'" type="warning" size="small">open 模式</el-tag>
        <template v-else>
          <el-tag v-if="probeStatus?.allowlist_suffixes_configured" type="success" size="small">域名后缀白名单</el-tag>
          <el-tag v-if="probeStatus?.allowlist_cidrs_configured" type="success" size="small">CIDR 白名单（字面 IP）</el-tag>
          <el-tag v-if="!probeStatus?.allowlist_configured" type="info" size="small">未配置放行规则</el-tag>
        </template>
      </div>
      <el-alert
        v-if="probeStatus && probeStatus.probe_mode === 'allowlist' && !probeStatus.allowlist_cidrs_configured"
        type="warning"
        show-icon
        :closable="false"
        class="mb-sm"
        title="字面 IP 需配置 EXPOSURE_PROBE_ALLOWLIST_CIDRS（后缀白名单不生效）"
        description="例：127.0.0.0/8,::1/128 或实验网 CIDR；本机可设 EXPOSURE_PROBE_MODE=open。改 .env 后重启 API。"
      />
      <p class="probe-hint">
        最多 {{ probeStatus?.max_concurrent ?? "—" }} 路并发；未放行主机会跳过。展开行可看 SCTP / UDP / SBI / TCP 细节。
      </p>
      <p v-if="probeRun?.summary" class="probe-hint muted-sum">
        本轮汇总：SCTP INIT 有应答 {{ probeRun.summary.sctp_init_replies ?? "—" }} · SBI 路径已请求
        {{ probeRun.summary.sbi_paths_probed ?? "—" }} · UDP spike 回包行 {{ probeRun.summary.udp_spike_reply_lines ?? "—" }}
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
      <el-table v-if="probeRun" :data="probeRun.results" size="small" stripe max-height="420">
        <el-table-column type="expand" width="48">
          <template #default="{ row }">
            <div class="probe-expand">
              <template v-if="(row.sctp_probe_findings || []).length">
                <div class="expand-title">SCTP（INIT 探针）</div>
                <pre class="expand-pre">{{ (row.sctp_probe_findings || []).join("\n") }}</pre>
              </template>
              <template v-if="(row.udp_spike_findings || []).length">
                <div class="expand-title">UDP spike 矩阵</div>
                <pre class="expand-pre">{{ (row.udp_spike_findings || []).join("\n") }}</pre>
              </template>
              <template v-if="row.sbi_unauth_probe?.paths && Object.keys(row.sbi_unauth_probe.paths).length">
                <div class="expand-title">SBI HTTP/2 未授权 GET（鉴权面）</div>
                <pre class="expand-pre">{{ formatSbiProbe(row.sbi_unauth_probe) }}</pre>
              </template>
              <template v-else-if="row.sbi_unauth_probe?.skipped || row.sbi_unauth_probe?.fatal">
                <div class="expand-title">SBI 探测</div>
                <pre class="expand-pre">{{ JSON.stringify(row.sbi_unauth_probe, null, 2) }}</pre>
              </template>
              <template v-if="row.tcp_banners && Object.keys(row.tcp_banners).length">
                <div class="expand-title">TCP banner / SIP OPTIONS</div>
                <pre class="expand-pre">{{ JSON.stringify(row.tcp_banners, null, 2) }}</pre>
              </template>
              <div v-if="!expandHasExtra(row)" class="muted-dash">无 SCTP/SBI/UDP 扩展字段（旧缓存或探测被跳过）</div>
            </div>
          </template>
        </el-table-column>
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
        <el-table-column label="开放端口" min-width="160">
          <template #default="{ row }">
            <span class="ip-cell">
              <template v-if="(row.open_ports || []).length || (row.open_udp_ports || []).length">
                <span v-if="(row.open_ports || []).length">TCP {{ row.open_ports.join(", ") }}</span>
                <span v-if="(row.open_udp_ports || []).length">
                  {{ (row.open_ports || []).length ? " · " : "" }}UDP {{ row.open_udp_ports.join(", ") }}
                </span>
              </template>
              <template v-else>—</template>
            </span>
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
        候选 {{ analysis.summary?.total_candidates ?? 0 }} · 高危 {{ analysis.summary?.high_or_critical ?? 0 }} ·
        可达 {{ analysis.summary?.probe_reachable ?? 0 }} · 路径 {{ analysis.summary?.attack_paths ?? 0 }} · LLM
        {{ analysis.summary?.llm_used ? "开" : "关" }}
      </p>
      <el-table :data="analysisRows" size="small" stripe>
        <el-table-column type="expand" width="48">
          <template #default="{ row }">
            <div class="probe-expand">
              <div class="expand-title">候选 {{ row.candidate_fqdn }} — 探测原始字段</div>
              <pre class="expand-pre">{{ JSON.stringify(row.probe_status || {}, null, 2) }}</pre>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="candidate_fqdn" label="候选 FQDN" min-width="220" />
        <el-table-column prop="risk_level" label="风险" width="88">
          <template #default="{ row }">
            <el-tag :type="riskTagType(row.risk_level)" size="small">{{ row.risk_level }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="探测" min-width="140">
          <template #default="{ row }">
            DNS {{ row.dns_ok ? "OK" : "×" }} / HTTPS {{ row.https_ok === true ? row.https_status : "×" }}
          </template>
        </el-table-column>
        <el-table-column label="指纹" min-width="200">
          <template #default="{ row }">
            TCP {{ row.open_ports.length ? row.open_ports.join(",") : "—" }} · UDP
            {{ row.open_udp_ports?.length ? row.open_udp_ports.join(",") : "—" }} /
            {{ row.service_hints.length ? row.service_hints.join(",") : "unknown" }}
            <div v-if="row.sbi_hint" class="sbi-hint">{{ row.sbi_hint }}</div>
          </template>
        </el-table-column>
        <el-table-column label="潜在攻击点" min-width="220">
          <template #default="{ row }">
            <template v-if="row.attack_points?.length">
              <el-tag
                v-for="(t, i) in row.attack_points"
                :key="i"
                type="danger"
                effect="plain"
                size="small"
                class="tag-gap"
              >
                {{ t }}
              </el-tag>
            </template>
            <span v-else class="muted-dash">—</span>
          </template>
        </el-table-column>
        <el-table-column label="验证任务" min-width="220">
          <template #default="{ row }">
            <template v-if="row.validation_tasks?.length">
              <el-tag
                v-for="(t, i) in row.validation_tasks"
                :key="i"
                type="warning"
                effect="plain"
                size="small"
                class="tag-gap"
              >
                {{ t }}
              </el-tag>
            </template>
            <span v-else class="muted-dash">—</span>
          </template>
        </el-table-column>
        <el-table-column prop="summary" label="摘要" min-width="200" show-overflow-tooltip />
      </el-table>

      <el-collapse class="mt-sm">
        <el-collapse-item title="模式与证据" name="patterns">
          <el-table :data="analysis.patterns" size="small" stripe>
            <el-table-column prop="expression" label="模式" min-width="200" />
            <el-table-column prop="rationale" label="依据" min-width="260" show-overflow-tooltip />
          </el-table>
        </el-collapse-item>
        <el-collapse-item title="攻击路径（推演）" name="paths">
          <el-table :data="analysis.attack_paths" size="small" stripe>
            <el-table-column prop="path_id" label="路径" width="140" show-overflow-tooltip />
            <el-table-column prop="entrypoint" label="入口" min-width="200" />
            <el-table-column label="跳板" min-width="200">
              <template #default="{ row }">{{ row.pivots?.join(" -> ") || "—" }}</template>
            </el-table-column>
            <el-table-column prop="target_asset" label="目标" min-width="120" />
            <el-table-column prop="validation_status" label="验证" width="110" />
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
import client, { TIMEOUT_EXPOSURE_ANALYZE_MS } from "@/api/client";
import type {
  ExposureAnalysisResponse,
  ExposureAssessment,
  ExposureCandidate,
  ExposureRow,
  ProbeRun,
  ProbeStatusPayload,
  ProbeTargetResult,
} from "@/types/graph";

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
const domainsInput = ref("");
const ipsInput = ref("");
const cidrsInput = ref("");

function parseLines(s: string): string[] {
  return s
    .split(/\r?\n/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function assetPayload() {
  return {
    domains: parseLines(domainsInput.value),
    ips: parseLines(ipsInput.value),
    cidrs: parseLines(cidrsInput.value),
  };
}

function requireAssets(): boolean {
  const a = assetPayload();
  if (!a.domains.length && !a.ips.length && !a.cidrs.length) {
    err.value = "请至少填写主域名、IP 或 CIDR 中的一项";
    return false;
  }
  return true;
}

/** 展开行是否有 SCTP/SBI/UDP/banner 任一内容，用于占位提示 */
function expandHasExtra(row: ProbeTargetResult) {
  const sbi = row.sbi_unauth_probe;
  const sbiPaths = sbi?.paths && Object.keys(sbi.paths).length;
  return !!(
    (row.sctp_probe_findings || []).length ||
    (row.udp_spike_findings || []).length ||
    (row.tcp_banners && Object.keys(row.tcp_banners).length) ||
    sbiPaths ||
    sbi?.skipped ||
    sbi?.fatal
  );
}

/** 将 SBI 探测结果格式化为可读文本（路径 -> status / http_version） */
function formatSbiProbe(raw: NonNullable<ProbeTargetResult["sbi_unauth_probe"]>) {
  const paths = raw.paths || {};
  const lines: string[] = [];
  for (const [p, v] of Object.entries(paths)) {
    const st = v.status != null ? String(v.status) : v.error ? `err:${String(v.error).slice(0, 80)}` : "?";
    const ver = v.http_version != null ? String(v.http_version) : "";
    lines.push(`${p}  →  HTTP ${st}  (${ver})`);
  }
  return lines.join("\n") || JSON.stringify(raw, null, 2);
}

/** 从 probe_status.sbi_unauth_probe 提取一行摘要，便于表格列展示 */
function sbiSummaryFromProbe(ps: Record<string, unknown>): string {
  const sbi = ps.sbi_unauth_probe as ProbeTargetResult["sbi_unauth_probe"];
  if (!sbi || sbi.skipped) return "";
  const paths = sbi.paths || {};
  const parts = Object.entries(paths)
    .map(([k, v]) => `${k.split("/").filter(Boolean).slice(-2).join("/")}:${v.status ?? "?"}`)
    .slice(0, 2);
  return parts.length ? `SBI: ${parts.join(" · ")}` : "";
}

const analysisRows = computed(() => {
  if (!analysis.value) return [];
  const byId = new Map<string, ExposureAssessment>();
  analysis.value.assessments.forEach((x) => byId.set(x.candidate_id, x));
  return analysis.value.candidates.map((c: ExposureCandidate) => {
    const a = byId.get(c.candidate_id);
    const ps = (c.probe_status || {}) as Record<string, unknown>;
    return {
      candidate_id: c.candidate_id,
      candidate_fqdn: c.candidate_fqdn,
      risk_level: a?.risk_level ?? "low",
      summary: a?.summary ?? "",
      attack_points: a?.attack_points ?? [],
      validation_tasks: a?.validation_tasks ?? [],
      dns_ok: !!c.probe_status?.dns_ok,
      https_ok: c.probe_status?.https_ok,
      https_status: c.probe_status?.https_status,
      open_ports: c.probe_status?.open_ports ?? [],
      open_udp_ports: c.probe_status?.open_udp_ports ?? [],
      service_hints: c.probe_status?.service_hints ?? [],
      probe_status: ps,
      sbi_hint: sbiSummaryFromProbe(ps),
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
  if (!requireAssets()) return;
  loading.value = true;
  err.value = null;
  try {
    const { data } = await client.post<ExposureRow[]>("/api/exposure/generate", {
      service: service.value,
      mcc: mcc.value,
      mnc: mnc.value,
      include_probe: true,
      ...assetPayload(),
    });
    rows.value = data;
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : "生成失败（检查资产格式与探测策略）";
    rows.value = [];
  } finally {
    loading.value = false;
  }
}

async function analyzeExposure() {
  if (!requireAssets()) return;
  analysisLoading.value = true;
  err.value = null;
  reportMarkdown.value = "";
  try {
    const extras = extraHosts.value
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const { data } = await client.post<ExposureAnalysisResponse>(
      "/api/exposure/analyze",
      {
        service: service.value,
        mcc: mcc.value,
        mnc: mnc.value,
        include_probe: true,
        extra_hosts: extras,
        use_llm: useLlmInAnalysis.value,
        ...assetPayload(),
      },
      { timeout: TIMEOUT_EXPOSURE_ANALYZE_MS },
    );
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
  if (!requireAssets()) return;
  try {
    const { data } = await client.post<string>(
      "/api/exposure/export_csv",
      { service: service.value, mcc: mcc.value, mnc: mnc.value, include_probe: true, ...assetPayload() },
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
.asset-inline {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-bottom: 10px;
}
@media (max-width: 720px) {
  .asset-inline {
    grid-template-columns: 1fr;
  }
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
.tag-gap {
  margin-right: 6px;
  margin-bottom: 4px;
  white-space: normal;
  height: auto;
  line-height: 1.35;
}
.muted-dash {
  color: var(--muted);
}
.muted-sum {
  opacity: 0.9;
}
.probe-expand {
  padding: 8px 12px 12px;
  max-width: 900px;
}
.expand-title {
  font-weight: 600;
  font-size: 12px;
  margin: 10px 0 4px;
  color: #a8c4ff;
}
.expand-pre {
  margin: 0;
  padding: 8px 10px;
  background: rgba(0, 0, 0, 0.25);
  border-radius: 8px;
  font-size: 11px;
  line-height: 1.45;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 280px;
  overflow: auto;
}
.sbi-hint {
  font-size: 11px;
  color: #c9e78a;
  margin-top: 4px;
}
</style>
