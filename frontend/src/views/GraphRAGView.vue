<template>
  <div class="wrap">
    <h1 class="page-title">GraphRAG</h1>
    <p class="page-sub">图谱 + 原文混合检索问答。</p>

    <el-row :gutter="12">
      <el-col :xs="24" :lg="24">
        <div class="panel glass-card">
          <div class="panel-title">混合检索问答</div>
          <el-input
            v-model="question"
            type="textarea"
            :rows="6"
            placeholder="输入问题，例如：IMS 为什么依赖 SIP？请同时给出协议关系和标准文档引用。"
          />
          <div class="row mt">
            <el-button type="success" :loading="store.loading" @click="runAsk">开始问答</el-button>
          </div>

          <div v-if="store.lastAnswer" class="answer mt">
            <div class="subhead">回答</div>
            <div class="text">{{ store.lastAnswer.answer || "(empty)" }}</div>
            <div class="subhead mt">引用</div>
            <el-tag
              v-for="c in store.lastAnswer.citations"
              :key="c"
              size="small"
              class="mr mb8"
            >
              {{ c }}
            </el-tag>
            <div class="subhead mt">备注</div>
            <div class="text">{{ store.lastAnswer.notes?.join(" | ") || "-" }}</div>
          </div>
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { useGraphRagStore } from "@/stores/graphRagStore";

const store = useGraphRagStore();

const question = ref("IMS 为什么依赖 SIP？请同时给出协议关系和标准文档引用。");

async function runAsk() {
  if (!question.value.trim()) return;
  await store.askStream({
    question: question.value,
    top_k: 15,
  });
}
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
  align-items: center;
  flex-wrap: wrap;
}
.subhead {
  font-weight: 600;
  color: var(--muted);
}
.text {
  line-height: 1.7;
  white-space: pre-wrap;
}
.answer {
  background: rgba(10, 16, 28, 0.45);
  border: 1px solid rgba(160, 190, 255, 0.16);
  border-radius: 8px;
  padding: 10px;
}
.mb {
  margin-bottom: 8px;
}
.mb8 {
  margin-bottom: 8px;
}
.mr {
  margin-right: 8px;
}
.mt {
  margin-top: 8px;
}
</style>

