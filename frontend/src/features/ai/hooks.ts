import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { aiApi, AIAnalysesListParams } from "./api";
import type {
  AIStatusRead,
  AIAnalysisRead,
  PromoteSuggestionRequest,
  ReviewAnalysisRequest,
  FindingRead,
} from "../../api/types";
import { ApiError } from "../../api/client";
import { findingKeys } from "../findings/hooks";

export const aiKeys = {
  all: ["ai"] as const,
  status: () => [...aiKeys.all, "status"] as const,
  analyses: () => [...aiKeys.all, "analyses"] as const,
  analysis: (id: string) => [...aiKeys.all, "analysis", id] as const,
  list: (assessmentId: string, params: AIAnalysesListParams) =>
    [...aiKeys.analyses(), assessmentId, params] as const,
};

export function useAIStatus() {
  return useQuery<AIStatusRead, ApiError>({
    queryKey: aiKeys.status(),
    queryFn: () => aiApi.getStatus(),
    staleTime: 60000,
  });
}

export function useAIAnalysis(analysisId?: string, enabled = true) {
  return useQuery<AIAnalysisRead, ApiError>({
    queryKey: aiKeys.analysis(analysisId || ""),
    queryFn: () => {
      if (!analysisId) throw new Error("Analysis ID is required");
      return aiApi.getAnalysis(analysisId);
    },
    enabled: !!analysisId && enabled,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return 2000;
      if (data.status === "completed" || data.status === "failed") {
        return false;
      }
      return 2500;
    },
  });
}

export function useAIAnalyses(assessmentId?: string, params: AIAnalysesListParams = {}) {
  return useQuery<AIAnalysisRead[], ApiError>({
    queryKey: aiKeys.list(assessmentId || "", params),
    queryFn: () => {
      if (!assessmentId) throw new Error("Assessment ID is required");
      return aiApi.listAnalyses(assessmentId, params);
    },
    enabled: !!assessmentId,
  });
}

export function useInterpretScan(assessmentId: string, scanId: string) {
  const queryClient = useQueryClient();
  return useMutation<AIAnalysisRead, ApiError, { force?: boolean }>({
    mutationFn: ({ force }) => aiApi.interpretScan(assessmentId, scanId, force),
    onSuccess: (data) => {
      queryClient.setQueryData(aiKeys.analysis(data.id), data);
      queryClient.invalidateQueries({ queryKey: aiKeys.analyses() });
    },
  });
}

export function usePrioritizeFindings(assessmentId: string) {
  const queryClient = useQueryClient();
  return useMutation<AIAnalysisRead, ApiError, { force?: boolean }>({
    mutationFn: ({ force }) => aiApi.prioritize(assessmentId, force),
    onSuccess: (data) => {
      queryClient.setQueryData(aiKeys.analysis(data.id), data);
      queryClient.invalidateQueries({ queryKey: aiKeys.analyses() });
    },
  });
}

export function useExplainFinding(findingId: string) {
  const queryClient = useQueryClient();
  return useMutation<AIAnalysisRead, ApiError, { force?: boolean }>({
    mutationFn: ({ force }) => aiApi.explainFinding(findingId, force),
    onSuccess: (data) => {
      queryClient.setQueryData(aiKeys.analysis(data.id), data);
      queryClient.invalidateQueries({ queryKey: aiKeys.analyses() });
    },
  });
}

export function useSummarizeAssessment(assessmentId: string) {
  const queryClient = useQueryClient();
  return useMutation<AIAnalysisRead, ApiError, { force?: boolean }>({
    mutationFn: ({ force }) => aiApi.summarizeAssessment(assessmentId, force),
    onSuccess: (data) => {
      queryClient.setQueryData(aiKeys.analysis(data.id), data);
      queryClient.invalidateQueries({ queryKey: aiKeys.analyses() });
    },
  });
}

export function usePromoteSuggestion(analysisId: string) {
  const queryClient = useQueryClient();
  return useMutation<FindingRead, ApiError, PromoteSuggestionRequest>({
    mutationFn: (data) => aiApi.promoteSuggestion(analysisId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      queryClient.invalidateQueries({ queryKey: findingKeys.summaries() });
      queryClient.invalidateQueries({ queryKey: aiKeys.analysis(analysisId) });
    },
  });
}

export function useReviewAnalysis(analysisId: string) {
  const queryClient = useQueryClient();
  return useMutation<AIAnalysisRead, ApiError, ReviewAnalysisRequest>({
    mutationFn: (data) => aiApi.reviewAnalysis(analysisId, data),
    onSuccess: (data) => {
      queryClient.setQueryData(aiKeys.analysis(analysisId), data);
      queryClient.invalidateQueries({ queryKey: aiKeys.analyses() });
    },
  });
}

