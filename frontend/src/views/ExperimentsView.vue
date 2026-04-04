<template>
  <div class="wrap">
    <h1 class="page-title">实验验证展示</h1>
    <p class="page-sub">
      Mock 任务面板：描述后续可在<strong>合法开源实验环境</strong>中验证的对象与方式；<strong>不包含</strong>对公网或未授权目标的探测能力。
    </p>

    <el-skeleton v-if="loading" :rows="6" animated />
    <el-alert v-else-if="err" type="error" :title="err" show-icon />
    <el-row v-else :gutter="12">
      <el-col v-for="t in tasks" :key="t.id" :xs="24" :md="12">
        <div class="card glass-card">
          <div class="head">
            <h3>{{ t.title }}</h3>
            <el-tag :type="tagType(t.status)" effect="dark">{{ t.status }}</el-tag>
          </div>
          <div class="field"><span>对象</span>{{ t.object }}</div>
          <div class="field"><span>方式</span>{{ t.method }}</div>
          <div class="field"><span>环境</span>{{ t.environment }}</div>
          <p class="notes">{{ t.notes }}</p>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import client from "@/api/client";
import type { ExperimentTask } from "@/types/graph";

const loading = ref(true);
const err = ref<string | null>(null);
const tasks = ref<ExperimentTask[]>([]);

function tagType(s: string) {
  if (s === "validated") return "success";
  if (s === "in-progress") return "warning";
  return "info";
}

onMounted(async () => {
  try {
    const { data } = await client.get<{ tasks: ExperimentTask[] }>("/api/experiments");
    tasks.value = data.tasks;
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : "加载失败";
  } finally {
    loading.value = false;
  }
});
</script>

<style scoped>
.wrap {
  max-width: 1100px;
}
.card {
  padding: 16px 18px;
  margin-bottom: 12px;
  min-height: 200px;
}
.head {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 10px;
  margin-bottom: 10px;
}
.head h3 {
  margin: 0;
  font-size: 1.05rem;
}
.field {
  display: grid;
  grid-template-columns: 44px 1fr;
  gap: 8px;
  font-size: 13px;
  margin-bottom: 6px;
}
.field span {
  color: var(--muted);
}
.notes {
  margin: 10px 0 0;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.5;
}
</style>
