<template>
  <div class="wrap">
    <h1 class="page-title">P0 运维中心</h1>
    <p class="page-sub">资产库存、周期任务、运行差异、审计日志（需 X-API-Key）。</p>

    <el-alert v-if="err" type="error" :title="err" show-icon class="mb" />

    <div class="panel glass-card mb">
      <div class="panel-head">访问凭证</div>
      <el-form inline>
        <el-form-item label="X-API-Key">
          <el-input v-model="apiKey" show-password placeholder="输入后保存在当前浏览器" style="width: 360px" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" @click="refreshAll">刷新全部</el-button>
        </el-form-item>
      </el-form>
      <p class="hint">后端需设置 `EXPOSURE_API_TOKENS`，例如 admin/operator/viewer 三类 token。</p>
    </div>

    <el-row :gutter="12" class="mb">
      <el-col :xs="24" :lg="12">
        <div class="panel glass-card">
          <div class="panel-head">资产管理</div>
          <el-form @submit.prevent>
            <el-form-item label="批量资产（每行一个）">
              <el-input v-model="assetText" type="textarea" :rows="5" placeholder="example.com&#10;192.0.2.1&#10;198.51.100.0/30" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="upsertAssets">写入/激活资产</el-button>
            </el-form-item>
          </el-form>
          <el-table :data="assets" size="small" stripe max-height="260">
            <el-table-column prop="asset" label="资产" min-width="200" />
            <el-table-column prop="asset_type" label="类型" width="90" />
            <el-table-column prop="status" label="状态" width="90" />
            <el-table-column prop="last_seen_at" label="最近出现" min-width="170" />
          </el-table>
        </div>
      </el-col>

      <el-col :xs="24" :lg="12">
        <div class="panel glass-card">
          <div class="panel-head">任务创建</div>
          <el-form label-width="120px" @submit.prevent>
            <el-form-item label="任务名"><el-input v-model="jobForm.name" /></el-form-item>
            <el-form-item label="targets(逗号)"><el-input v-model="jobForm.targets" /></el-form-item>
            <el-form-item label="周期(分钟)"><el-input-number v-model="jobForm.interval_minutes" :min="5" :max="1440" /></el-form-item>
            <el-form-item label="启用资产库存"><el-switch v-model="jobForm.use_asset_inventory" /></el-form-item>
            <el-form-item>
              <el-button type="primary" @click="createJob">创建任务</el-button>
            </el-form-item>
          </el-form>
        </div>
      </el-col>
    </el-row>

    <div class="panel glass-card mb">
      <div class="panel-head">任务列表</div>
      <el-table :data="jobs" size="small" stripe>
        <el-table-column prop="job_id" label="job_id" min-width="180" />
        <el-table-column prop="name" label="名称" min-width="120" />
        <el-table-column prop="interval_minutes" label="周期" width="80" />
        <el-table-column prop="use_asset_inventory" label="库存" width="70">
          <template #default="{ row }">{{ row.use_asset_inventory ? 'on' : 'off' }}</template>
        </el-table-column>
        <el-table-column prop="last_error" label="最近错误" min-width="160" />
        <el-table-column label="操作" width="300" fixed="right">
          <template #default="{ row }">
            <el-space>
              <el-button size="small" type="primary" @click="runJob(row.job_id)">执行</el-button>
              <el-button size="small" @click="toggleJob(row)">{{ row.enabled ? '停用' : '启用' }}</el-button>
              <el-button size="small" type="danger" @click="deleteJob(row.job_id)">删除</el-button>
            </el-space>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-row :gutter="12">
      <el-col :xs="24" :lg="12">
        <div class="panel glass-card">
          <div class="panel-head">最近运行</div>
          <el-table :data="runs" size="small" stripe max-height="280">
            <el-table-column prop="run_id" label="run_id" min-width="180" />
            <el-table-column prop="job_id" label="job_id" min-width="150" />
            <el-table-column prop="attempts" label="重试" width="60" />
            <el-table-column prop="finished_at" label="结束时间" min-width="170" />
          </el-table>
        </div>
      </el-col>
      <el-col :xs="24" :lg="12">
        <div class="panel glass-card">
          <div class="panel-head">审计日志</div>
          <el-table :data="auditRows" size="small" stripe max-height="280">
            <el-table-column prop="ts" label="时间" min-width="170" />
            <el-table-column prop="role" label="角色" width="80" />
            <el-table-column prop="action" label="动作" min-width="120" />
            <el-table-column prop="resource" label="资源" min-width="150" />
          </el-table>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from "vue";
import { ElMessage, ElMessageBox } from "element-plus";
import client from "@/api/client";

const apiKey = ref(localStorage.getItem("p0_api_key") ?? "");
const loading = ref(false);
const err = ref<string | null>(null);

const assets = ref<any[]>([]);
const jobs = ref<any[]>([]);
const runs = ref<any[]>([]);
const auditRows = ref<any[]>([]);

const assetText = ref("");
const jobForm = reactive({
  name: "daily-scan",
  targets: "example.com",
  interval_minutes: 60,
  use_asset_inventory: true,
});

const headers = () => ({ "X-API-Key": apiKey.value.trim() });

watch(apiKey, (v) => localStorage.setItem("p0_api_key", v));

async function refreshAll() {
  loading.value = true;
  err.value = null;
  try {
    const [a, j, r, au] = await Promise.all([
      client.get("/api/p0/assets", { headers: headers() }),
      client.get("/api/p0/jobs", { headers: headers() }),
      client.get("/api/p0/runs?limit=20", { headers: headers() }),
      client.get("/api/p0/audit?limit=20", { headers: headers() }),
    ]);
    assets.value = a.data.assets ?? [];
    jobs.value = j.data.jobs ?? [];
    runs.value = r.data.runs ?? [];
    auditRows.value = au.data.rows ?? [];
  } catch (e: any) {
    err.value = e?.response?.data?.detail || e?.message || "加载失败";
  } finally {
    loading.value = false;
  }
}

async function upsertAssets() {
  const rows = assetText.value
    .split(/\r?\n/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (!rows.length) return;
  await client.post(
    "/api/p0/assets/upsert",
    { assets: rows, source: "frontend" },
    { headers: headers() },
  );
  ElMessage.success("资产已更新");
  await refreshAll();
}

async function createJob() {
  const targets = jobForm.targets
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  await client.post(
    "/api/p0/jobs",
    {
      name: jobForm.name,
      targets,
      interval_minutes: jobForm.interval_minutes,
      use_asset_inventory: jobForm.use_asset_inventory,
      enabled: true,
    },
    { headers: headers() },
  );
  ElMessage.success("任务已创建");
  await refreshAll();
}

async function runJob(jobId: string) {
  await client.post(`/api/p0/jobs/${jobId}/run`, {}, { headers: headers() });
  ElMessage.success("任务已执行");
  await refreshAll();
}

async function toggleJob(row: any) {
  await client.patch(`/api/p0/jobs/${row.job_id}`, { enabled: !row.enabled }, { headers: headers() });
  ElMessage.success("任务状态已更新");
  await refreshAll();
}

async function deleteJob(jobId: string) {
  await ElMessageBox.confirm("确认删除该任务？", "提示", { type: "warning" });
  await client.delete(`/api/p0/jobs/${jobId}`, { headers: headers() });
  ElMessage.success("任务已删除");
  await refreshAll();
}

onMounted(refreshAll);
</script>

<style scoped>
.hint {
  color: var(--muted);
  margin: 0;
}
</style>
