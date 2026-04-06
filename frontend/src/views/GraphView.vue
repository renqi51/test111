<template>
  <div class="graph-page">
    <div class="top">
      <div>
        <h1 class="page-title">知识图谱</h1>
        <p class="page-sub">Cytoscape.js · 类型着色 / 形状 · 过滤 · 导出（PNG / JSON）</p>
      </div>
      <div class="cy-toolbar">
        <el-input v-model="subgraphQuery" placeholder="子图关键词（如 ims / oauth / ts 23.402）" clearable style="width: 280px" />
        <el-popover trigger="click" placement="bottom" :width="320">
          <template #reference>
            <el-button>高级设置</el-button>
          </template>
          <div class="adv-grid">
            <div class="adv-row">
              <span class="adv-label">seed_limit</span>
              <el-input-number v-model="seedLimit" :min="5" :max="200" :step="5" controls-position="right" />
            </div>
            <div class="adv-row">
              <span class="adv-label">max_edges</span>
              <el-input-number v-model="maxEdges" :min="20" :max="3000" :step="20" controls-position="right" />
            </div>
            <p class="adv-tip">默认值：seed_limit=20，max_edges=120。值越大越全，但也越容易卡。</p>
          </div>
        </el-popover>
        <el-button type="success" @click="loadSubgraph">加载子图</el-button>
        <el-button @click="reloadFullGraph">全量图（可能很卡）</el-button>
        <el-switch v-model="autoExpandOnTap" inline-prompt active-text="点选扩展" inactive-text="不扩展" />
        <el-input-number v-model="neighborDepth" :min="1" :max="2" :step="1" size="default" controls-position="right" />
        <el-input v-model="search" placeholder="搜索节点 label / id" clearable style="width: 220px" />
        <el-select v-model="layoutName" placeholder="布局" style="width: 140px">
          <el-option label="Grid" value="grid" />
          <el-option label="Breadthfirst" value="breadthfirst" />
          <el-option label="CoSE" value="cose" />
        </el-select>
        <el-button type="primary" @click="applyLayout">应用布局</el-button>
        <el-button @click="exportPng">导出 PNG</el-button>
        <el-button @click="exportJson">导出 JSON</el-button>
        <el-button @click="reloadCurrent">刷新当前数据</el-button>
      </div>
    </div>

    <el-row :gutter="12" class="row">
      <el-col :xs="24" :md="5">
        <div class="side glass-card">
          <div class="side-title">节点类型</div>
          <el-checkbox-group v-model="typeFilter">
            <el-checkbox v-for="t in allTypes" :key="t" :label="t">{{ t }}</el-checkbox>
          </el-checkbox-group>
          <el-divider />
          <div class="side-title">关系类型</div>
          <el-select v-model="edgeFilter" multiple collapse-tags placeholder="全部" style="width: 100%">
            <el-option v-for="e in allInteractions" :key="e" :label="e" :value="e" />
          </el-select>
          <p class="tiny">未勾选关系时显示全部边；勾选后仅显示所选类型。</p>
        </div>
      </el-col>
      <el-col :xs="24" :md="14">
        <div v-loading="store.loading" class="cy-wrap glass-card">
          <div v-if="store.error" class="err">{{ store.error }}</div>
          <div ref="cyHost" class="cy-host"></div>
        </div>
      </el-col>
      <el-col :xs="24" :md="5">
        <div class="side glass-card detail">
          <template v-if="selected">
            <div class="side-title">节点详情</div>
            <div class="kv"><span>中文名</span><b>{{ selected.label }}</b></div>
            <div class="kv"><span>标识</span><code>{{ selected.id }}</code></div>
            <div class="kv"><span>英文/原始</span><span>{{ selected.en_identifier || "—" }}</span></div>
            <div class="kv"><span>类型</span><el-tag size="small">{{ selected.type }}</el-tag></div>
            <div class="block">
              <div class="lbl">描述</div>
              <p>{{ selected.description || "—" }}</p>
            </div>
            <div class="block">
              <div class="lbl">证据来源</div>
              <p>{{ selected.evidence_source || "—" }}</p>
            </div>
            <div class="block">
              <div class="lbl">相关关系</div>
              <ul>
                <li v-for="(r, i) in relatedEdges" :key="i">
                  <code>{{ r.other }}</code>
                  <span class="dim">{{ r.dir }}</span>
                  <el-tag size="small" type="info">{{ r.interaction }}</el-tag>
                </li>
              </ul>
            </div>
          </template>
          <el-empty v-else description="点击节点查看详情" />
        </div>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import cytoscape from "cytoscape";
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { useGraphStore } from "@/stores/graphStore";
import type { GraphEdge, GraphNode } from "@/types/graph";

const store = useGraphStore();
const route = useRoute();
const cyHost = ref<HTMLDivElement | null>(null);
let cy: cytoscape.Core | null = null;

const search = ref("");
const layoutName = ref<"grid" | "breadthfirst" | "cose">("cose");
const typeFilter = ref<string[]>([]);
const edgeFilter = ref<string[]>([]);
const selected = ref<GraphNode | null>(null);
let searchTimer: number | null = null;
const subgraphQuery = ref("ims");
const seedLimit = ref(20);
const maxEdges = ref(120);
const autoExpandOnTap = ref(true);
const neighborDepth = ref(1);
const expandedNodeIds = ref<Set<string>>(new Set());
let expanding = false;

const allTypes = computed(() => {
  const s = new Set(store.nodes.map((n) => n.type));
  return Array.from(s).sort();
});

const allInteractions = computed(() => {
  const s = new Set(store.edges.map((e) => e.interaction));
  return Array.from(s).sort();
});

const relatedEdges = computed(() => {
  const id = selected.value?.id;
  if (!id) return [];
  const out: { other: string; interaction: string; dir: string }[] = [];
  for (const e of store.edges) {
    if (e.source === id) out.push({ other: e.target, interaction: e.interaction, dir: "→" });
    else if (e.target === id) out.push({ other: e.source, interaction: e.interaction, dir: "←" });
  }
  return out.slice(0, 40);
});

const TYPE_COLOR: Record<string, string> = {
  Service: "#5b8cff",
  NetworkFunction: "#3dd6c6",
  Protocol: "#e6a23c",
  Interface: "#b37feb",
  Platform: "#67c23a",
  Capability: "#f56c6c",
  FQDNPattern: "#909399",
  StandardDoc: "#79bbff",
  RiskHypothesis: "#ff6b6b",
  WorkProduct: "#95d475",
  Metric: "#d3adf7",
};

const TYPE_SHAPE: Record<string, string> = {
  Service: "round-rectangle",
  NetworkFunction: "rectangle",
  Protocol: "ellipse",
  Interface: "tag",
  Platform: "round-rectangle",
  Capability: "hexagon",
  FQDNPattern: "diamond",
  StandardDoc: "round-tag",
  RiskHypothesis: "octagon",
  WorkProduct: "round-rectangle",
  Metric: "barrel",
};

function buildElements(nodes: GraphNode[], edges: GraphEdge[]) {
  const nf = typeFilter.value;
  const useType = nf.length === 0 || nf.length === allTypes.value.length ? null : new Set(nf);
  const ef = edgeFilter.value;
  const useEdge = ef.length === 0 ? null : new Set(ef);

  const nodeIds = new Set<string>();
  const ns = nodes.filter((n) => !useType || useType.has(n.type));
  ns.forEach((n) => nodeIds.add(n.id));

  const es = edges.filter((e) => {
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) return false;
    if (useEdge && !useEdge.has(e.interaction)) return false;
    return true;
  });

  const els: cytoscape.ElementDefinition[] = ns.map((n) => ({
    data: { id: n.id, label: n.label, raw: n, type: n.type },
  }));
  es.forEach((e, i) => {
    els.push({
      data: {
        id: `e${i}-${e.source}-${e.target}-${e.interaction}`,
        source: e.source,
        target: e.target,
        interaction: e.interaction,
      },
    });
  });
  return els;
}

function applyLayout() {
  if (!cy) return;
  const name = layoutName.value;
  // 兼顾观感与性能：中小图保留动画，大图自动关闭动画防止卡顿。
  const nodeCount = cy.nodes().length;
  const edgeCount = cy.edges().length;
  const shouldAnimate = nodeCount <= 600 && edgeCount <= 1200;
  const layout = cy.layout({
    name,
    animate: shouldAnimate,
    animationDuration: shouldAnimate ? 420 : 0,
    fit: true,
    padding: 24,
    randomize: name === "cose",
  } as cytoscape.LayoutOptions);
  layout.run();
}

function typeStylesheet(): cytoscape.Stylesheet[] {
  return Object.keys(TYPE_COLOR).map((t) => ({
    selector: `node[type="${t}"]`,
    style: {
      "background-color": TYPE_COLOR[t],
      shape: (TYPE_SHAPE[t] ?? "ellipse") as string,
    },
  }));
}

function bindCy() {
  if (!cyHost.value) return;
  cy?.destroy();
  cy = cytoscape({
    container: cyHost.value,
    elements: buildElements(store.nodes, store.edges),
    style: [
      {
        selector: "node",
        style: {
          "background-color": "#5b8cff",
          shape: "ellipse",
          label: "data(label)",
          color: "#e8eefc",
          "font-size": 10,
          "text-wrap": "wrap",
          "text-max-width": 90,
          width: 26,
          height: 26,
          "border-width": 1,
          "border-color": "rgba(255,255,255,0.25)",
        },
      },
      ...typeStylesheet(),
      {
        selector: "edge",
        style: {
          width: 2,
          "line-color": "rgba(140,170,230,0.45)",
          "target-arrow-color": "rgba(140,170,230,0.45)",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 0.9,
          label: "",
          "font-size": 8,
          color: "#9db0d0",
        },
      },
      { selector: "edge.show-label", style: { label: "data(interaction)" } },
      { selector: ".hidden", style: { display: "none" } },
      { selector: "node:selected", style: { "border-width": 3, "border-color": "#ffffff" } },
      { selector: "node.hl", style: { "border-width": 3, "border-color": "#ffd04b" } },
    ],
    wheelSensitivity: 0.25,
  });
  cy.on("tap", "node", (evt) => {
    const raw = evt.target.data("raw") as GraphNode;
    selected.value = raw;
    void expandNeighborsFromTap(raw.id);
  });
  cy.on("tap", (evt) => {
    if (evt.target === cy) selected.value = null;
  });
  cy.on("zoom", () => {
    updateEdgeLabelVisibility();
  });
  applyFilters();
  updateEdgeLabelVisibility();
  applyLayout();
}

async function expandNeighborsFromTap(nodeId: string) {
  if (!autoExpandOnTap.value || expanding) return;
  const id = (nodeId || "").trim();
  if (!id || expandedNodeIds.value.has(id)) return;
  try {
    expanding = true;
    await store.loadNeighbors(id, neighborDepth.value);
    expandedNodeIds.value.add(id);
    await nextTick();
    bindCy();
  } catch {
    // 错误已由 store 记录到 error，这里不重复提示
  } finally {
    expanding = false;
  }
}

function updateEdgeLabelVisibility() {
  if (!cy) return;
  const shouldShow = cy.zoom() >= 1.3 && cy.edges().length <= 1500;
  if (shouldShow) cy.edges().addClass("show-label");
  else cy.edges().removeClass("show-label");
}

function applyFilters() {
  if (!cy) return;
  const nf = typeFilter.value;
  const useType = nf.length === 0 || nf.length === allTypes.value.length ? null : new Set(nf);
  const ef = edgeFilter.value;
  const useEdge = ef.length === 0 ? null : new Set(ef);

  cy.batch(() => {
    cy.nodes().forEach((n) => {
      const raw = n.data("raw") as GraphNode;
      const hidden = !!useType && !useType.has(raw.type);
      n.toggleClass("hidden", hidden);
    });

    cy.edges().forEach((e) => {
      const source = e.source();
      const target = e.target();
      const interaction = String(e.data("interaction") || "");
      const hiddenByNode = source.hasClass("hidden") || target.hasClass("hidden");
      const hiddenByEdgeType = !!useEdge && !useEdge.has(interaction);
      e.toggleClass("hidden", hiddenByNode || hiddenByEdgeType);
    });
  });
}

function exportPng() {
  if (!cy) return;
  const png = cy.png({ full: true, scale: 2, bg: "#0b1220" });
  const a = document.createElement("a");
  a.href = png;
  a.download = "graph.png";
  a.click();
}

function exportJson() {
  const payload = { nodes: store.nodes, edges: store.edges };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "graph.json";
  a.click();
  URL.revokeObjectURL(url);
}

async function reloadCurrent() {
  if (subgraphQuery.value.trim()) await loadSubgraph();
  else await reloadFullGraph();
}

async function reloadFullGraph() {
  await store.load();
  expandedNodeIds.value.clear();
  selected.value = null;
  await nextTick();
  bindCy();
}

async function loadSubgraph() {
  const q = subgraphQuery.value.trim();
  if (!q) return;
  await store.loadSubgraphByQuery(q, {
    seedLimit: seedLimit.value,
    maxEdges: maxEdges.value,
  });
  expandedNodeIds.value.clear();
  selected.value = null;
  await nextTick();
  bindCy();
}

watch([typeFilter, edgeFilter], async () => {
  await nextTick();
  applyFilters();
  updateEdgeLabelVisibility();
});

watch(search, (q) => {
  if (!cy) return;
  if (searchTimer !== null) window.clearTimeout(searchTimer);
  searchTimer = window.setTimeout(() => {
    if (!cy) return;
    cy.nodes().removeClass("hl");
    if (!q.trim()) return;
    const qq = q.trim().toLowerCase();
    cy.nodes().forEach((n) => {
      const raw = n.data("raw") as GraphNode;
      if (raw.id.toLowerCase().includes(qq) || raw.label.toLowerCase().includes(qq)) n.addClass("hl");
    });
  }, 220);
});

onMounted(async () => {
  const q = (route.query.q as string | undefined)?.trim();
  if (q) subgraphQuery.value = q;
  if (subgraphQuery.value.trim()) {
    await loadSubgraph();
  } else {
    await reloadFullGraph();
  }
  if (store.nodes.length > 1000) layoutName.value = "grid";
  if (typeFilter.value.length === 0) typeFilter.value = [...allTypes.value];
  const sel = route.query.select as string | undefined;
  if (sel) {
    const n = store.nodes.find((x) => x.id === sel);
    if (n) selected.value = n;
  }
});

onUnmounted(() => {
  if (searchTimer !== null) window.clearTimeout(searchTimer);
  cy?.destroy();
  cy = null;
});
</script>

<style scoped>
.graph-page {
  height: calc(100vh - 96px);
  display: flex;
  flex-direction: column;
}
.top {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.cy-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.adv-grid {
  display: grid;
  gap: 10px;
}
.adv-row {
  display: grid;
  grid-template-columns: 90px 1fr;
  align-items: center;
  gap: 8px;
}
.adv-label {
  font-size: 12px;
  color: var(--muted);
}
.adv-tip {
  margin: 0;
  font-size: 12px;
  color: var(--muted);
  line-height: 1.35;
}
.row {
  flex: 1;
  min-height: 0;
}
.side {
  padding: 12px;
  height: 100%;
  min-height: 420px;
  overflow: auto;
}
.side-title {
  font-weight: 600;
  margin-bottom: 8px;
}
.tiny {
  font-size: 11px;
  color: var(--muted);
  line-height: 1.4;
}
.cy-wrap {
  position: relative;
  height: 100%;
  min-height: 420px;
  padding: 0;
  overflow: hidden;
}
.cy-host {
  width: 100%;
  height: 100%;
  min-height: 420px;
}
.err {
  padding: 12px;
  color: var(--danger);
}
.detail .kv {
  display: grid;
  grid-template-columns: 72px 1fr;
  gap: 6px;
  font-size: 13px;
  margin-bottom: 6px;
}
.detail .kv span:first-child {
  color: var(--muted);
}
.block {
  margin-top: 10px;
}
.lbl {
  font-size: 12px;
  color: var(--muted);
  margin-bottom: 4px;
}
.dim {
  color: var(--muted);
  margin: 0 4px;
  font-size: 12px;
}
</style>
