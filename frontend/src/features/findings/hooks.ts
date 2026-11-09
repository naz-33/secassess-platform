import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { findingsApi, FindingsListParams } from "./api";
import type {
  FindingRead,
  FindingsSummary,
  VerificationRead,
  VerificationCreate,
  SeverityUpdateRequest,
  SeverityChangeRead,
  EvidenceRead,
  NoteEvidenceCreate,
} from "../../api/types";
import { ApiError } from "../../api/client";

export const findingKeys = {
  all: ["findings"] as const,
  lists: () => [...findingKeys.all, "list"] as const,
  list: (assessmentId: string | undefined, params: FindingsListParams) =>
    [...findingKeys.lists(), assessmentId || "all", params] as const,
  summaries: () => [...findingKeys.all, "summary"] as const,
  summary: (assessmentId: string) => [...findingKeys.summaries(), assessmentId] as const,
  details: () => [...findingKeys.all, "detail"] as const,
  detail: (findingId: string) => [...findingKeys.details(), findingId] as const,
  verifications: (findingId: string) => [...findingKeys.detail(findingId), "verifications"] as const,
  severityHistory: (findingId: string) => [...findingKeys.detail(findingId), "severityHistory"] as const,
};

export function useFindings(assessmentId?: string, params: FindingsListParams = {}) {
  return useQuery<FindingRead[], ApiError>({
    queryKey: findingKeys.list(assessmentId, params),
    queryFn: () => {
      return findingsApi.list(assessmentId, params);
    },
  });
}

export function useFindingsSummary(assessmentId?: string) {
  return useQuery<FindingsSummary, ApiError>({
    queryKey: findingKeys.summary(assessmentId || ""),
    queryFn: () => {
      if (!assessmentId) throw new Error("Assessment ID is required");
      return findingsApi.summary(assessmentId);
    },
    enabled: !!assessmentId,
  });
}

export function useFinding(findingId?: string) {
  return useQuery<FindingRead, ApiError>({
    queryKey: findingKeys.detail(findingId || ""),
    queryFn: () => {
      if (!findingId) throw new Error("Finding ID is required");
      return findingsApi.get(findingId);
    },
    enabled: !!findingId,
  });
}

export function useFindingVerifications(findingId?: string) {
  return useQuery<VerificationRead[], ApiError>({
    queryKey: findingKeys.verifications(findingId || ""),
    queryFn: () => {
      if (!findingId) throw new Error("Finding ID is required");
      return findingsApi.verifications(findingId);
    },
    enabled: !!findingId,
  });
}

export function useFindingSeverityHistory(findingId?: string) {
  return useQuery<SeverityChangeRead[], ApiError>({
    queryKey: findingKeys.severityHistory(findingId || ""),
    queryFn: () => {
      if (!findingId) throw new Error("Finding ID is required");
      return findingsApi.severityHistory(findingId);
    },
    enabled: !!findingId,
  });
}

export function useVerifyFinding(findingId: string) {
  const queryClient = useQueryClient();

  return useMutation<VerificationRead, ApiError, VerificationCreate>({
    mutationFn: (data) => findingsApi.verify(findingId, data),
    onSuccess: () => {
      // Refresh finding detail, verifications, list, and summary
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(findingId) });
      queryClient.invalidateQueries({ queryKey: findingKeys.verifications(findingId) });
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      queryClient.invalidateQueries({ queryKey: findingKeys.summaries() });
    },
  });
}

export function useUpdateFindingSeverity(findingId: string) {
  const queryClient = useQueryClient();

  return useMutation<FindingRead, ApiError, SeverityUpdateRequest>({
    mutationFn: (data) => findingsApi.updateSeverity(findingId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(findingId) });
      queryClient.invalidateQueries({ queryKey: findingKeys.severityHistory(findingId) });
      queryClient.invalidateQueries({ queryKey: findingKeys.lists() });
      queryClient.invalidateQueries({ queryKey: findingKeys.summaries() });
    },
  });
}

export function useUploadEvidence(findingId: string) {
  const queryClient = useQueryClient();

  return useMutation<EvidenceRead, ApiError, FormData>({
    mutationFn: (formData) => findingsApi.uploadEvidence(findingId, formData),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(findingId) });
    },
  });
}

export function useAddEvidenceNote(findingId: string) {
  const queryClient = useQueryClient();

  return useMutation<EvidenceRead, ApiError, NoteEvidenceCreate>({
    mutationFn: (data) => findingsApi.addEvidenceNote(findingId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: findingKeys.detail(findingId) });
    },
  });
}

