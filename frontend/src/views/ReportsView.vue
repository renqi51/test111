<template>
  <div class="wrap">
    <h1 class="page-title">报告与导出</h1>
    <p class="page-sub">查看图谱校验 Markdown、下载 Mermaid、导出候选暴露面 CSV 与 Demo 摘要。</p>

    <el-row :gutter="12" class="mb">
      <el-col :xs="24" :md="14">
        <div class="panel glass-card">
          <div class="toolbar">
            <span class="panel-title">图谱校验报告（Markdown）</span>
            <el-button size="small" @click="fetchValidation" :loading="vLoading">刷新</el-button>
            <el-button size="small" type="primary" @click="downloadBlob('/api/reports/validation', 'validation.md', 'text/markdown')">
              下载
            </el-button>
          </div>
          <el-skeleton v-if="vLoading" :rows="8" animated />
          <div v-else class="md" v-html="renderedValidation"></div>
        </div>
      </el-col>
      <el-col :xs="24" :md="10">
        <div class="panel glass-card">
          <div class="panel-title">快捷下载</div>
          <el-space direction="vertical" style="width: 100%" fill>
            <el-button @click="downloadBlob('/api/reports/mermaid', 'graph.mmd', 'text/plain')">Mermaid 图谱 (.mmd)</el-button>
            <el-button @click="downloadBlob('/api/reports/demo_summary_md', 'demo_summary.md', 'text/markdown')">
              Demo 摘要 (.md)
            </el-button>
            <el-button
              @click="
                downloadBlobPost('/api/exposure/export_csv', { service: 'IMS', mcc: '460', mnc: '001' }, 'exposure_ims.csv')
              "
            >
              候选暴露面 CSV（示例 IMS / 460 / 001）
            </el-button>
          </el-space>

          <el-divider />
          <div class="panel-title">Demo 摘要预览</div>
          <el-skeleton v-if="sLoading" :rows="5" animated />
          <div v-else class="md small" v-html="renderedSummary"></div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import MarkdownIt from "markdown-it";
import { onMounted, ref } from "vue";
import client from "@/api/client";

const md = new MarkdownIt({ html: false, linkify: true, breaks: true });

const vLoading = ref(false);
const sLoading = ref(false);
const validationMd = ref("");
const summaryMd = ref("");

const renderedValidation = ref("");
const renderedSummary = ref("");

async function fetchValidation() {
  vLoading.value = true;
  try {
    const { data } = await client.get<string>("/api/reports/validation", { responseType: "text" });
    validationMd.value = data;
    renderedValidation.value = md.render(data);
  } finally {
    vLoading.value = false;
  }
}

async function fetchSummary() {
  sLoading.value = true;
  try {
    const { data } = await client.get<{ markdown: string }>("/api/demo/summary");
    summaryMd.value = data.markdown;
    renderedSummary.value = md.render(data.markdown);
  } finally {
    sLoading.value = false;
  }
}

async function downloadBlob(path: string, filename: string, mime: string) {
  const { data } = await client.get<string>(path, { responseType: "text" });
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function downloadBlobPost(path: string, body: object, filename: string) {
  const { data } = await client.post<string>(path, body, { responseType: "text" });
  const blob = new Blob([data], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

onMounted(() => {
  fetchValidation();
  fetchSummary();
});
</script>

<style scoped>
.wrap {
  max-width: 1200px;
}
.mb {
  margin-bottom: 12px;
}
.panel {
  padding: 14px 16px;
  margin-bottom: 12px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.panel-title {
  font-weight: 600;
  margin-bottom: 8px;
}
.md {
  font-size: 14px;
  line-height: 1.6;
  color: #dbe5ff;
}
.md.small {
  font-size: 13px;
  max-height: 320px;
  overflow: auto;
}
.md :deep(h1),
.md :deep(h2),
.md :deep(h3) {
  color: #fff;
}
.md :deep(code) {
  background: rgba(255, 255, 255, 0.06);
  padding: 1px 6px;
  border-radius: 4px;
}
.md :deep(ul) {
  padding-left: 1.2rem;
}
</style>
