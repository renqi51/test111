import { createRouter, createWebHistory } from "vue-router";
import AppShell from "@/components/AppShell.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      component: AppShell,
      children: [
        { path: "", name: "dashboard", component: () => import("@/views/DashboardView.vue") },
        { path: "graph", name: "graph", component: () => import("@/views/GraphView.vue") },
        { path: "extract", name: "extract", component: () => import("@/views/ExtractView.vue") },
        { path: "agent", name: "agent", component: () => import("@/views/AgentSkillView.vue") },
        { path: "graph-rag", name: "graph-rag", component: () => import("@/views/GraphRAGView.vue") },
        { path: "exposure", name: "exposure", component: () => import("@/views/ExposureView.vue") },
        { path: "experiments", name: "experiments", component: () => import("@/views/ExperimentsView.vue") },
        { path: "reports", name: "reports", component: () => import("@/views/ReportsView.vue") },
        { path: "p0", name: "p0", component: () => import("@/views/P0OpsView.vue") },
      ],
    },
  ],
});

export default router;
