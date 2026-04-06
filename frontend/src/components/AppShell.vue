<template>
  <el-container class="shell">
    <el-aside width="220px" class="aside glass-card">
      <div class="brand">
        <div class="brand-title">开放暴露面工作台</div>
        <div class="brand-sub">3GPP / GSMA · 图谱 · 抽取 · 授权环境探测</div>
      </div>
      <el-menu
        :default-active="active"
        class="menu"
        background-color="transparent"
        text-color="#c8d6f5"
        active-text-color="#ffffff"
        router
      >
        <el-menu-item index="/">
          <el-icon><Odometer /></el-icon>
          <span>总览</span>
        </el-menu-item>
        <el-menu-item index="/graph">
          <el-icon><Share /></el-icon>
          <span>知识图谱</span>
        </el-menu-item>
        <el-menu-item index="/extract">
          <el-icon><Document /></el-icon>
          <span>标准抽取</span>
        </el-menu-item>
        <el-menu-item index="/agent">
          <el-icon><Document /></el-icon>
          <span>Agent / Skill</span>
        </el-menu-item>
        <el-menu-item index="/graph-rag">
          <el-icon><ChatLineSquare /></el-icon>
          <span>GraphRAG</span>
        </el-menu-item>
        <el-menu-item index="/exposure">
          <el-icon><Aim /></el-icon>
          <span>候选暴露面</span>
        </el-menu-item>
        <el-menu-item index="/experiments">
          <el-icon><Cpu /></el-icon>
          <span>实验验证</span>
        </el-menu-item>
        <el-menu-item index="/reports">
          <el-icon><Tickets /></el-icon>
          <span>报告导出</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header glass-card">
        <div class="header-inner">
          <span class="pill">合作方授权测试环境 · 策略内探测</span>
          <span class="muted">FastAPI + Vue3 · Neo4j / 文件</span>
        </div>
      </el-header>
      <el-main class="main">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from "vue";
import { useRoute } from "vue-router";
import { Odometer, Share, Document, Aim, Cpu, Tickets, ChatLineSquare } from "@element-plus/icons-vue";

const route = useRoute();
const active = computed(() => (route.path === "/" ? "/" : route.path));
</script>

<style scoped>
.shell {
  height: 100%;
  background: radial-gradient(1200px 600px at 20% -10%, #1c2b52 0%, transparent 55%),
    radial-gradient(900px 500px at 100% 0%, #153243 0%, transparent 50%), var(--bg-deep);
}
.aside {
  margin: 12px 0 12px 12px;
  padding: 16px 8px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.brand-title {
  font-weight: 700;
  font-size: 1rem;
  padding: 0 12px;
}
.brand-sub {
  font-size: 12px;
  color: var(--muted);
  padding: 0 12px;
  line-height: 1.4;
}
.menu {
  border-right: none;
  flex: 1;
}
.header {
  margin: 12px 12px 0 12px;
  height: 52px !important;
  display: flex;
  align-items: center;
  border-radius: 14px;
}
.header-inner {
  display: flex;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  padding: 0 16px;
}
.pill {
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--border);
  color: var(--accent-2);
}
.muted {
  color: var(--muted);
  font-size: 13px;
}
.main {
  padding: 12px 12px 16px 12px;
}
.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.15s ease;
}
.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}
</style>
