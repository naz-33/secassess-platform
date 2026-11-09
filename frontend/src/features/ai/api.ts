import { apiClient } from "../../api/client";
import type {
  AIStatusRead,
  AIAnalysisRead,
  AIFunction,
  AIAnalysisStatus,
  AIReviewStatus,
  PromoteSuggestionRequest,
  ReviewAnalysisRequest,
  FindingRead,
} from "../../api/types";

export interface AIAnalysesListParams {
  function?: AIFunction;
  status?: AIAnalysisStatus;
  review_status?: AIReviewStatus;
  limit?: number;
  offset?: number;
}

export const aiApi = {
  getStatus: async (): Promise<AIStatusRead> => {
    return apiClient<AIStatusRead>("/api/v1/ai/status");
  },

  interpretScan: async (assessmentId: string, scanId: string, force = false): Promise<AIAnalysisRead> => {
    return apiClient<AIAnalysisRead>(
      `/api/v1/assessments/${assessmentId}/scans/${scanId}/ai/interpret${force ? "?force=true" : ""}`,
      { method: "POST" }
    );
  },

  prioritize: async (assessmentId: string, force = false): Promise<AIAnalysisRead> => {
    return apiClient<AIAnalysisRead>(
      `/api/v1/assessments/${assessmentId}/ai/prioritize${force ? "?force=true" : ""}`,
      { method: "POST" }
    );
  },

  explainFinding: async (findingId: string, force = false): Promise<AIAnalysisRead> => {
    return apiClient<AIAnalysisRead>(
      `/api/v1/findings/${findingId}/ai/explain${force ? "?force=true" : ""}`,
      { method: "POST" }
    );
  },

  summarizeAssessment: async (assessmentId: string, force = false): Promise<AIAnalysisRead> => {
    return apiClient<AIAnalysisRead>(
      `/api/v1/assessments/${assessmentId}/ai/summary${force ? "?force=true" : ""}`,
      { method: "POST" }
    );
  },

  getAnalysis: async (analysisId: string): Promise<AIAnalysisRead> => {
    return apiClient<AIAnalysisRead>(`/api/v1/ai-analyses/${analysisId}`);
  },

  listAnalyses: async (assessmentId: string, params: AIAnalysesListParams = {}): Promise<AIAnalysisRead[]> => {
    const query = new URLSearchParams();
    if (params.function) query.set("function", params.function);
    if (params.status) query.set("status", params.status);
    if (params.review_status) query.set("review_status", params.review_status);
    if (params.limit !== undefined) query.set("limit", params.limit.toString());
    if (params.offset !== undefined) query.set("offset", params.offset.toString());

    const qs = query.toString();
    const endpoint = `/api/v1/assessments/${assessmentId}/ai-analyses${qs ? `?${qs}` : ""}`;
    return apiClient<AIAnalysisRead[]>(endpoint);
  },

  promoteSuggestion: async (analysisId: string, data: PromoteSuggestionRequest): Promise<FindingRead> => {
    return apiClient<FindingRead>(`/api/v1/ai-analyses/${analysisId}/promote`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  reviewAnalysis: async (analysisId: string, data: ReviewAnalysisRequest): Promise<AIAnalysisRead> => {
    return apiClient<AIAnalysisRead>(`/api/v1/ai-analyses/${analysisId}/review`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },
};

