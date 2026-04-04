export interface EvidenceItem {
  evidence_id: string;
  chunk_id: string;
  document_id: string;
  heading: string;
  text: string;
  relevance_score: number;
  source_locator: Record<string, any>;
  tags: string[];
}

export interface EvidencePack {
  pack_id: string;
  query: string;
  document_id: string;
  scenario_hint: string;
  items: EvidenceItem[];
  retrieval_trace: Record<string, any>[];
  created_at: string;
}

export interface StateNodeCandidate {
  temp_id: string;
  name: string;
  normalized_name: string;
  description: string;
  state_type: string;
  confidence: number;
  evidence_ids: string[];
  attributes: Record<string, any>;
}

export interface TransitionCandidate {
  temp_id: string;
  from_state: string;
  to_state: string;
  trigger: string;
  guard: string;
  action: string;
  confidence: number;
  evidence_ids: string[];
  attributes: Record<string, any>;
}

export interface ExtractionResult {
  run_id: string;
  worker_name: string;
  extraction_mode: "conservative" | "structural" | "repair";
  states: StateNodeCandidate[];
  transitions: TransitionCandidate[];
  assumptions: string[];
  open_questions: string[];
  confidence_summary: Record<string, number>;
}

export interface JudgeScoreDetail {
  worker_name: string;
  schema_validity_score: number;
  evidence_alignment_score: number;
  graph_consistency_score: number;
  completeness_score: number;
  conservativeness_score: number;
  total_score: number;
  comments: string[];
}

export interface ConflictItem {
  field_path: string;
  conflict_type: string;
  description: string;
  candidate_values: Record<string, any>;
  related_evidence_ids: string[];
  severity: "low" | "medium" | "high";
}

export interface JudgeDecision {
  judge_run_id: string;
  score_details: JudgeScoreDetail[];
  recommended_worker: string;
  conflict_set: ConflictItem[];
  needs_repair: boolean;
  repair_instruction: string;
}

export interface ExtractionRunResponse {
  run_id: string;
  stage: string;
  evidence_pack: EvidencePack;
  worker_results: ExtractionResult[];
  judge: JudgeDecision;
  repair: any | null;
  staging_graph_summary: Record<string, any>;
  trace_summary: Record<string, any>;
}

