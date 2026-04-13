import axios from "axios";

const client = axios.create({
  baseURL: import.meta.env.VITE_API_BASE ?? "",
  timeout: 60_000,
});

/** ReAct Agent：多轮 LLM + 探测 + 沙箱，默认 60s 不够，对单次 POST 传入此值 */
export const TIMEOUT_AGENT_RUN_MS = 900_000;

/** 暴露面分析（含 LLM）可能较慢 */
export const TIMEOUT_EXPOSURE_ANALYZE_MS = 360_000;

export default client;
