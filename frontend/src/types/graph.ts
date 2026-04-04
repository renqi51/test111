export interface GraphNode {
  id: string;
  label: string;
  type: string;
  description: string;
  evidence_source: string;
  en_identifier: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  interaction: string;
}

export interface GraphPayload {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphStats {
  node_count: number;
  edge_count: number;
  by_node_type: Record<string, number>;
  by_edge_type: Record<string, number>;
  top_degree_nodes: { id: string; degree: number }[];
}

export interface ValidateResult {
  ok: boolean;
  orphan_nodes: string[];
  dangling_edges: { source: string; target: string; reason?: string }[];
  unreferenced_standard_docs: string[];
  risks_without_mitigation: string[];
  node_type_counts: Record<string, number>;
  edge_type_counts: Record<string, number>;
  top_degree_nodes: { id: string; degree: number }[];
  issues: { code: string; detail: string }[];
}

export interface CandidateNode {
  id: string;
  label: string;
  type: string;
  description: string;
  evidence_source: string;
  en_identifier: string;
  confidence: number;
}

export interface CandidateEdge {
  source: string;
  target: string;
  interaction: string;
  confidence: number;
}

export interface ExposureRow {
  candidate_fqdn: string;
  protocol_stack: string[];
  network_functions: string[];
  evidence_docs: string[];
  risk_hypotheses: string[];
  confidence: number;
}

export interface ExposurePattern {
  pattern_id: string;
  service: string;
  category: "fqdn" | "interface" | "platform" | "route";
  expression: string;
  rationale: string;
  evidence_docs: string[];
}

export interface CandidateEvidenceBundle {
  evidence_docs: string[];
  graph_paths: string[];
  related_risks: string[];
  source_kind: ("standard_pattern" | "graph_inference" | "probe_observation" | "manual")[];
}

export interface ExposureCandidate {
  candidate_id: string;
  candidate_fqdn: string;
  service: string;
  protocols: string[];
  network_functions: string[];
  confidence: number;
  evidence: CandidateEvidenceBundle;
  probe_status: Record<string, any>;
}

export interface ExposureAssessment {
  candidate_id: string;
  risk_level: "low" | "medium" | "high" | "critical";
  score: number;
  summary: string;
  conservative_explanation: string;
  attack_surface_notes: string[];
  missing_evidence: string[];
  evidence_refs: string[];
  model_name: string;
  fallback_used: boolean;
}

export interface AttackPath {
  path_id: string;
  candidate_id: string;
  entrypoint: string;
  pivots: string[];
  target_asset: string;
  likelihood: number;
  impact: "low" | "medium" | "high";
  prerequisites: string[];
  evidence_refs: string[];
  validation_status: "hypothesis" | "partially_validated" | "validated";
}

export interface ExposureAnalysisResponse {
  run_id: string;
  created_at: string;
  service: string;
  mcc: string;
  mnc: string;
  patterns: ExposurePattern[];
  candidates: ExposureCandidate[];
  assessments: ExposureAssessment[];
  attack_paths: AttackPath[];
  probe_run: ProbeRun | Record<string, any> | null;
  report_path: string;
  summary: Record<string, any>;
}

export interface ExperimentTask {
  id: string;
  title: string;
  object: string;
  method: string;
  environment: string;
  status: "planned" | "in-progress" | "validated";
  notes: string;
}

export interface ProbeTargetResult {
  target: string;
  host: string;
  permitted: boolean;
  policy_reason: string;
  dns_ok: boolean;
  dns_addresses: string[];
  https_ok: boolean | null;
  https_status: number | null;
  https_latency_ms: number | null;
  open_ports: number[];
  service_hints: string[];
  tls_subject: string | null;
  tls_error: string | null;
  error: string | null;
}

export interface ProbeRun {
  run_id: string;
  started_at: string;
  finished_at: string;
  probe_mode: string;
  results: ProbeTargetResult[];
  summary: Record<string, number>;
}

export interface ProbeStatusPayload {
  enabled: boolean;
  probe_mode: string;
  allowlist_configured: boolean;
  verify_tls: boolean;
  timeout_sec: number;
  max_concurrent: number;
}
