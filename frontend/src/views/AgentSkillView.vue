<template>
  <div class="wrap">
    <h1 class="page-title">Agent / Skill 平台</h1>
    <p class="page-sub">
      可发现 Skill（MCP-like tool schema），支持手动运行 Skill；也支持输入高层 goal 让 Agent 自动调度多步流程，并展示 trace。
    </p>

    <el-alert v-if="err" type="error" :title="err" show-icon class="mb" />
    <el-skeleton v-if="loading && !skills.length" :rows="10" animated />

    <div v-else class="grid">
      <div class="panel glass-card">
        <div class="panel-title">Skill 列表（可发现工具）</div>
        <el-table :data="skills" size="small" stripe height="280" empty-text="暂无技能注册结果">
          <el-table-column prop="name" label="name" width="200" />
          <el-table-column prop="display_name" label="显示名" />
          <el-table-column prop="tags" label="tags" width="240">
            <template #default="{ row }">
              <span class="tags">{{ (row.tags || []).join(", ") }}</span>
            </template>
          </el-table-column>
        </el-table>
        <div class="hint">工具发现接口：`GET /api/mcp/tools` 或 `GET /api/skills`。</div>
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
      <div class="panel-title">Agent 一键调度（自动规划 + trace 展示）</div>
      <el-row :gutter="12" class="agent-row">
        <el-col :xs="24" :lg="10">
          <el-form label-position="top">
            <el-form-item label="高层研究意图（goal）">
              <el-input v-model="agentGoal" placeholder="例如：从这段文本抽取知识并更新图谱，然后做完整性检查" />
            </el-form-item>
            <el-form-item label="可选标准文本（text）">
              <el-input v-model="agentText" type="textarea" :rows="6" placeholder="粘贴标准说明片段..." />
            </el-form-item>
            <el-button type="primary" :loading="runningAgent" @click="runAgent">运行 Agent</el-button>
            <div class="hint">当前 Agent 内置流程：抽取 -> merge -> validate -> build_demo_report（可在后续扩展为更复杂 planner）。</div>
          </el-form>
        </el-col>
        <el-col :xs="24" :lg="14">
          <el-alert v-if="agentErr" type="error" :title="agentErr" show-icon class="mb" />
          <el-skeleton v-if="agentLoading" :rows="8" animated />
          <div v-else>
            <el-card v-if="agentRun" class="out">
              <template #header>Agent Run Trace</template>
              <div class="run-meta">
                <div><span class="k">run_id</span><b>{{ agentRun.id }}</b></div>
                <div><span class="k">goal</span><span class="v">{{ agentRun.goal }}</span></div>
              </div>
              <el-divider />
              <el-steps :active="0" direction="vertical" finish-status="success">
                <el-step
                  v-for="s in agentRun.steps"
                  :key="s.index"
                  :title="`#${s.index} ${s.skill_name}`"
                  :description="`${s.status} · ${prettyTime(s.started_at)} → ${prettyTime(s.finished_at)}`"
                >
                  <div class="step-box">
                    <div class="step-label">input</div>
                    <pre class="pre small">{{ pretty(s.input) }}</pre>
                    <div class="step-label">output</div>
                    <pre class="pre small">{{ pretty(s.output) }}</pre>
                  </div>
                </el-step>
              </el-steps>
            </el-card>
            <el-empty v-else description="点击运行 Agent 生成 trace"></el-empty>
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
import { computed, onMounted, ref } from "vue";
import client from "@/api/client";

interface SkillTool {
  name: string;
  display_name: string;
  description: string;
  input_schema: any;
  output_schema: any;
  tags: string[];
}

interface AgentStep {
  index: number;
  skill_name: string;
  input: any;
  output: any;
  started_at: string;
  finished_at: string;
  status: string;
}

interface AgentRun {
  id: string;
  goal: string;
  created_at: string;
  steps: AgentStep[];
}

const loading = ref(false);
const err = ref<string | null>(null);
const skills = ref<SkillTool[]>([]);
const selectedSkill = ref<string>("");
const skillInput = ref<string>('{"text":"IMS 与 SIP 共现，示例说明：IMS 体系与 SIP 会话控制。"}');
const runningSkill = ref(false);
const skillErr = ref<string | null>(null);
const skillTrace = ref<any | null>(null);

const agentGoal = ref("从这段文本抽取知识并更新图谱，然后生成候选暴露面与完整性检查");
const agentText = ref("在运营商 IMS 部署中，P-CSCF/I-CSCF/S-CSCF 协作并通过 SIP 建立会话；非 3GPP 接入可涉及 ePDG、DNS 解析与 IKEv2/IPsec；北向开放能力在 Open Gateway / CAMARA 相关材料中可被对照。");
const runningAgent = ref(false);
const agentErr = ref<string | null>(null);
const agentLoading = ref(false);
const agentRun = ref<AgentRun | null>(null);

const runsLoading = ref(false);
const agentRuns = ref<AgentRun[]>([]);

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
    const { data } = await client.get<{ runs: AgentRun[] }>("/api/agent/runs");
    agentRuns.value = (data.runs || []).slice(0, 10);
  } finally {
    runsLoading.value = false;
  }
}

async function runAgent() {
  agentErr.value = null;
  agentLoading.value = true;
  runningAgent.value = true;
  agentRun.value = null;
  try {
    const payload = { goal: agentGoal.value, text: agentText.value };
    const { data } = await client.post<{ run: AgentRun }>("/api/agent/run", payload);
    agentRun.value = data.run;
    await loadRuns();
  } catch (e: unknown) {
    agentErr.value = e instanceof Error ? e.message : "Agent 运行失败";
  } finally {
    agentLoading.value = false;
    runningAgent.value = false;
  }
}

async function viewRun(row: AgentRun) {
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
.mt {
  margin-top: 12px;
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
</style>

