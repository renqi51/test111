export interface GraphRAGIngestRequest {
  text: string;
  source_file: string;
  rule_context?: string;
}

export interface GraphRAGIngestResponse {
  source_file: string;
  chunks_total: number;
  nodes_total: number;
  edges_total: number;
  inserted_docs: number;
  notes: string[];
}

export interface GraphRAGQueryRequest {
  question: string;
  top_k?: number;
}

export interface GraphRAGQueryResponse {
  answer: string;
  confidence: number;
  citations: string[];
  notes: string[];
}

