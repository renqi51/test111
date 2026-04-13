<template>
  <div class="wrap">
    <h1 class="page-title">Agent / Skill / ReAct</h1>
    <p class="page-sub">
      发现并手动运行 Skill；下方 Agent 一般<strong>只填资产</strong>即可，后端会生成任务说明并驱动 ReAct（probe → GraphRAG → 综合 → 沙箱）。
    </p>

    <el-alert v-if="err" type="error" :title="err" show-icon class="mb" />
    <el-skeleton v-if="loading && !skills.length" :rows="10" animated />

    <div v-else class="grid">
      <div class="panel glass-card">
        <div class="panel-title">Skill 列表（可发现工具）</div>
        <el-table :data="skills" size="small" stripe height="280" empty-text="暂无技能注册结果">
          <el-table-column prop="name" label="name" width="200" />
          <el-table-column prop="display_name" label="显示名" min-width="200" />
        </el-table>
        <div class="hint">发现接口：<code>GET /api/skills</code></div>
      </div>

      <div class="panel glass-card">
        <div class="panel-title">手动运行 Skill</div>
        <el-form label-position="top" @submit.prevent class="form">
          <el-form-item label="选择 Skill">
            <el-select v-model="selectedSkill" placeholder="请选择技能" style="width: 100%">
              <el-option v-for="s in skills" :key="s.name" :label="s.display_name" :value="s.name" />
            </el-select>
          </el-form-item>
          <el-form-item label="input JSON（会被后端校验并运行）">
            <el-input
              v-model="skillInput"
              type="textarea"
              :rows="6"
              placeholder='例如：{"text":"..."} 或 {"node_id":"svc_ims","depth":1}'
            />
          </el-form-item>
          <div class="row">
            <el-button type="primary" :loading="runningSkill" @click="runSkill">运行</el-button>
            <el-button :disabled="!skillTrace" @click="skillTrace = null">清空输出</el-button>
          </div>
          <el-alert v-if="skillErr" type="error" :title="skillErr" show-icon class="mb" />
          <el-card v-if="skillTrace" class="out">
            <template #header>输出（JSON）</template>
            <pre class="pre">{{ pretty(skillTrace) }}</pre>
          </el-card>
        </el-form>
      </div>
    </div>

    <div class="panel glass-card mt">
      <div class="panel-title">ReAct Agent（LLM + 探测 / GraphRAG / 沙箱）</div>
      <el-row :gutter="12" class="agent-row">
        <el-col :xs="24" :lg="10">
          <el-alert
            type="info"
            :closable="false"
            show-icon
            class="mb"
            title="字段怎么进大模型？"
            description="每轮 ReAct 会把 goal、资产、场景、补充说明与当前观测打成 JSON，作为 LLM 用户侧上下文；模型只返回下一步动作（如 probe）的 JSON。只填资产时，后端会自动补全 goal。"
          />
          <el-form label-position="top">
            <el-form-item label="资产（主机名或 IP，必填其一）">
              <el-input v-model="agentTargetAsset" placeholder="例：amf.lab.example 或 127.0.0.1（IP 须命中 CIDR 白名单）" />
            </el-form-item>
            <el-collapse v-model="agentCollapse" class="agent-collapse">
              <el-collapse-item title="可选：自定义任务说明、补充背景、场景标签" name="opt">
                <el-form-item label="任务说明（goal，不填则由后端根据资产自动生成）">
                  <el-input v-model="agentGoal" type="textarea" :rows="2" placeholder="留空即可；有明确意图时再写" />
                </el-form-item>
                <el-form-item label="补充背景（text）">
                  <el-input v-model="agentText" type="textarea" :rows="3" placeholder="日志、网元角色等，帮助模型缩小检索范围" />
                </el-form-item>
                <el-form-item label="场景 service / MCC / MNC">
                  <div class="row-tight">
                    <el-select v-model="agentService" style="width: 160px" clearable placeholder="可选">
                      <el-option label="IMS" value="IMS" />
                      <el-option label="Open Gateway" value="Open Gateway" />
                      <el-option label="VoWiFi" value="VoWiFi" />
                    </el-select>
                    <el-input v-model="agentMcc" maxlength="3" style="width: 90px" placeholder="MCC" />
                    <el-input v-model="agentMnc" maxlength="3" style="width: 90px" placeholder="MNC" />
                  </div>
                </el-form-item>
              </el-collapse-item>
            </el-collapse>
            <el-button type="primary" :loading="runningAgent" @click="runAgent" class="mt-sm">运行 Agent</el-button>
            <div class="hint">
              需 LLM；一轮可能数分钟。首步报错看步骤 <code>output.error</code>；探测跳过查 CIDR 与沙箱策略。
            </div>
          </el-form>
        </el-col>
        <el-col :xs="24" :lg="14">
          <el-alert
            v-if="agentErr"
            type="error"
            title="运行失败"
            :description="agentErr"
            show-icon
            class="mb"
          />
          <el-skeleton v-if="agentLoading" :rows="8" animated />
          <div v-else>
            <el-card v-if="agentRun" class="out">
              <template #header>运行记录</template>
              <div class="run-meta">
                <div><span class="k">run</span><b>{{ agentRun.id }}</b></div>
                <div><span class="k">goal</span><span class="v">{{ agentRun.goal }}</span></div>
              </div>
              <el-divider />
              <el-steps :active="0" direction="vertical" finish-status="success">
                <el-step v-for="s in agentRun.steps" :key="s.index" :title="`#${s.index} ${s.skill_name}`">
                  <template #description>
                    <div class="step-desc">
                      {{ s.status }} · {{ prettyTime(s.started_at) }} → {{ prettyTime(s.finished_at) }}
                    </div>
                    <el-alert
                      v-if="s.status === 'error' && stepErrorText(s.output)"
                      type="error"
                      :closable="false"
                      class="step-err"
                      :title="stepErrorText(s.output)"
                    />
                  </template>
                  <div class="step-box">
                    <div v-if="s.thought" class="thought-line"><span class="k">thought</span> {{ s.thought }}</div>
                    <div class="step-label">input</div>
                    <pre class="pre small">{{ pretty(s.input) }}</pre>
                    <div class="step-label">output</div>
                    <pre class="pre small">{{ pretty(s.output) }}</pre>
                  </div>
                </el-step>
              </el-steps>
              <el-divider />
              <div class="sub-head">综合建议</div>
              <ul v-if="(agentRun.final_recommendations || []).length" class="rec-list">
                <li v-for="(r, i) in agentRun.final_recommendations" :key="i">{{ r }}</li>
              </ul>
              <el-empty v-else description="无建议（未完成或 LLM 未返回）" />
              <template v-if="agentRun.final_playbook?.evidence?.length">
                <div class="sub-head mt8">沙箱验证</div>
                <el-table :data="agentRun.final_playbook.evidence" size="small" stripe>
                  <el-table-column prop="title" label="标题" width="120" />
                  <el-table-column prop="validation_status" label="验证状态" width="150" />
                  <el-table-column prop="command_executed" label="已执行命令" min-width="200" show-overflow-tooltip />
                  <el-table-column prop="exit_code" label="exit" width="60" />
                  <el-table-column label="stdout 摘录" min-width="160" show-overflow-tooltip>
                    <template #default="{ row }">{{ row.stdout_excerpt }}</template>
                  </el-table-column>
                  <el-table-column label="stderr / 策略" min-width="140" show-overflow-tooltip>
                    <template #default="{ row }">{{ row.stderr_excerpt || row.sandbox_decision_reason }}</template>
                  </el-table-column>
                </el-table>
              </template>
            </el-card>
            <el-empty v-else description="点击「运行 Agent」查看步骤与建议"></el-empty>
          </div>
        </el-col>
      </el-row>
    </div>

    <div class="panel glass-card mt">
      <div class="panel-title">最近 Agent 运行</div>
      <el-skeleton v-if="runsLoading" :rows="5" animated />
      <el-empty v-else-if="!agentRuns.length" description="暂无运行记录" />
      <el-table v-else :data="agentRuns" size="small" stripe height="260" @row-click="viewRun">
        <el-table-column prop="id" label="run_id" width="210" />
        <el-table-column prop="goal" label="goal" />
        <el-table-column prop="steps" label="steps" width="90">
          <template #default="{ row }">{{ row.steps?.length || 0 }}</template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import client, { TIMEOUT_AGENT_RUN_MS } from "@/api/client";
import type { ReactAgentRun } from "@/types/graph";

interface SkillTool {
  name: string;
  display_name: string;
  description: string;
  input_schema: any;
  output_schema: any;
  tags: string[];
}

const loading = ref(false);
const err = ref<string | null>(null);
const skills = ref<SkillTool[]>([]);
const selectedSkill = ref<string>("");
const skillInput = ref<string>('{"text":"IMS 与 SIP 共现，示例说明：IMS 体系与 SIP 会话控制。"}');
const runningSkill = ref(false);
const skillErr = ref<string | null>(null);
const skillTrace = ref<any | null>(null);

const agentGoal = ref("");
const agentTargetAsset = ref("");
const agentService = ref("");
const agentMcc = ref("");
const agentMnc = ref("");
const agentText = ref("");
const agentCollapse = ref<string[]>([]);
const runningAgent = ref(false);
const agentErr = ref<string | null>(null);
const agentLoading = ref(false);
const agentRun = ref<ReactAgentRun | null>(null);

const runsLoading = ref(false);
const agentRuns = ref<ReactAgentRun[]>([]);

function stepErrorText(output: unknown): string {
  if (!output || typeof output !== "object") return "";
  const err = (output as Record<string, unknown>).error;
  return typeof err === "string" && err.trim() ? err.trim() : "";
}

function pretty(obj: any) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch {
    return String(obj);
  }
}

function prettyTime(ts: string) {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString();
}

async function loadSkills() {
  loading.value = true;
  err.value = null;
  try {
    const { data } = await client.get<{ skills: SkillTool[] }>("/api/skills");
    skills.value = data.skills || [];
    if (skills.value.length && !selectedSkill.value) selectedSkill.value = skills.value[0].name;
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : "加载 skills 失败";
  } finally {
    loading.value = false;
  }
}

async function runSkill() {
  if (!selectedSkill.value) return;
  skillErr.value = null;
  skillTrace.value = null;
  runningSkill.value = true;
  try {
    let parsed: any = {};
    try {
      parsed = skillInput.value ? JSON.parse(skillInput.value) : {};
    } catch (e: unknown) {
      throw new Error("input JSON 解析失败：" + (e instanceof Error ? e.message : String(e)));
    }
    const { data } = await client.post("/api/skills/run", { name: selectedSkill.value, input: parsed });
    skillTrace.value = data.output ?? data;
  } catch (e: unknown) {
    skillErr.value = e instanceof Error ? e.message : "Skill 运行失败";
  } finally {
    runningSkill.value = false;
  }
}

async function loadRuns() {
  runsLoading.value = true;
  try {
    const { data } = await client.get<{ runs: ReactAgentRun[] }>("/api/agent/runs");
    agentRuns.value = (data.runs || []).slice(0, 10);
  } finally {
    runsLoading.value = false;
  }
}

function agentRunPayload(): Record<string, string> {
  const o: Record<string, string> = {};
  const g = agentGoal.value.trim();
  const ta = agentTargetAsset.value.trim();
  const tx = agentText.value.trim();
  const svc = agentService.value.trim();
  const mcc = agentMcc.value.trim();
  const mnc = agentMnc.value.trim();
  if (g) o.goal = g;
  if (ta) o.target_asset = ta;
  if (tx) o.text = tx;
  if (svc) o.service = svc;
  if (mcc) o.mcc = mcc;
  if (mnc) o.mnc = mnc;
  return o;
}

async function runAgent() {
  agentErr.value = null;
  if (!agentGoal.value.trim() && !agentTargetAsset.value.trim()) {
    agentErr.value = "请填写「资产」，或展开可选区域填写「任务说明」。";
    return;
  }
  agentLoading.value = true;
  runningAgent.value = true;
  agentRun.value = null;
  try {
    const payload = agentRunPayload();
    const { data } = await client.post<{ run: ReactAgentRun }>("/api/agent/run", payload, {
      timeout: TIMEOUT_AGENT_RUN_MS,
    });
    agentRun.value = data.run;
    await loadRuns();
  } catch (e: unknown) {
    if (typeof e === "object" && e !== null && "response" in e) {
      const ax = e as { response?: { data?: { detail?: string | { msg: string }[] } } };
      const d = ax.response?.data?.detail;
      if (typeof d === "string") {
        agentErr.value = d;
      } else if (Array.isArray(d)) {
        agentErr.value = d.map((x) => (typeof x === "object" && x && "msg" in x ? String((x as { msg: string }).msg) : String(x))).join("; ");
      } else {
        agentErr.value = e instanceof Error ? e.message : "Agent 运行失败";
      }
    } else {
      agentErr.value = e instanceof Error ? e.message : "Agent 运行失败";
    }
  } finally {
    agentLoading.value = false;
    runningAgent.value = false;
  }
}

async function viewRun(row: ReactAgentRun) {
  agentRun.value = row;
}

onMounted(async () => {
  await loadSkills();
  await loadRuns();
});
</script>

<style scoped>
.wrap {
  max-width: 1200px;
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1.4fr;
  gap: 12px;
}
.panel {
  padding: 14px 16px;
  margin-bottom: 12px;
}
.panel-title {
  font-weight: 650;
  margin-bottom: 10px;
}
.mb {
  margin-bottom: 12px;
}
.mt-sm {
  margin-top: 10px;
}
.mt {
  margin-top: 12px;
}
.agent-collapse {
  margin-bottom: 4px;
}
.form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.row {
  display: flex;
  gap: 10px;
  align-items: center;
}
.out {
  margin-top: 12px;
}
.pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-size: 12px;
  color: #dbe5ff;
}
.pre.small {
  font-size: 11px;
}
.step-box {
  background: rgba(0, 0, 0, 0.15);
  border: 1px solid rgba(255, 255, 255, 0.08);
  border-radius: 12px;
  padding: 10px 12px;
  margin-top: 8px;
}
.step-label {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
}
.run-meta {
  display: grid;
  gap: 8px;
}
.run-meta .k {
  color: var(--muted);
  margin-right: 10px;
  font-size: 12px;
}
.tags {
  color: var(--muted);
  font-size: 12px;
}
.agent-row {
  align-items: flex-start;
}
.hint {
  font-size: 12px;
  color: var(--muted);
  margin-top: 8px;
}
.row-tight {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.sub-head {
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 6px;
}
.mt8 {
  margin-top: 12px;
}
.rec-list {
  margin: 0 0 12px 18px;
  padding: 0;
  font-size: 12px;
  line-height: 1.5;
  color: #e8eeff;
}
.thought-line {
  font-size: 11px;
  color: #b8c8ff;
  margin-bottom: 8px;
  line-height: 1.4;
}
.thought-line .k {
  color: #7a8ab0;
  margin-right: 6px;
}
.step-desc {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 6px;
}
.step-err {
  margin-bottom: 8px;
}
</style>

