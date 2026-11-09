import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import * as api from "./api";
import type { AssessmentCreate, ScanCreate, WebAssessmentRequest } from "../../api/types";
import { useToast } from "../../components/Toast";

export function useAssessments(limit = 100, offset = 0) {
  return useQuery({
    queryKey: ["assessments", { limit, offset }],
    queryFn: () => api.fetchAssessments(limit, offset),
  });
}

export function useAssessment(id: string | undefined) {
  return useQuery({
    queryKey: ["assessment", id],
    queryFn: () => (id ? api.fetchAssessment(id) : Promise.reject("No assessment ID")),
    enabled: !!id,
  });
}

export function useCreateAssessment() {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (payload: AssessmentCreate) => api.createAssessment(payload),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["assessments"] });
      toast.success("Assessment created", `Assessment "${data.name}" initialized.`);
    },
    onError: (err: any) => {
      toast.error("Failed to create assessment", err?.message || "An error occurred.");
    },
  });
}

export function useAssessmentScans(assessmentId: string | undefined) {
  return useQuery({
    queryKey: ["scans", assessmentId],
    queryFn: () => (assessmentId ? api.fetchAssessmentScans(assessmentId) : Promise.resolve([])),
    enabled: !!assessmentId,
    // Auto-poll every 3 seconds if any scan is pending or running
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      const hasActive = data.some((s) => s.status === "pending" || s.status === "running");
      return hasActive ? 3000 : false;
    },
  });
}

export function useScanDetail(assessmentId: string | undefined, scanId: string | undefined) {
  return useQuery({
    queryKey: ["scan", assessmentId, scanId],
    queryFn: () =>
      assessmentId && scanId ? api.fetchScanDetail(assessmentId, scanId) : Promise.reject("Missing IDs"),
    enabled: !!assessmentId && !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      return data.status === "pending" || data.status === "running" ? 3000 : false;
    },
  });
}

export function useTriggerReconScan(assessmentId: string) {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (payload: ScanCreate) => api.triggerReconScan(assessmentId, payload),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans", assessmentId] });
      toast.success("Scan queued", `${scan.tool.toUpperCase()} scan launched with status "${scan.status}".`);
    },
    onError: (err: any) => {
      if (err.status === 403) {
        toast.error("Scope Rejected (403)", err.message || "Asset is outside authorized boundaries.");
      } else if (err.status === 409) {
        toast.warning("Scan in progress (409)", "Another scan is currently executing for this assessment.");
      } else {
        toast.error("Failed to trigger scan", err.message || "Execution failed.");
      }
    },
  });
}

export function useTriggerWebAssessment(assessmentId: string) {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (payload: WebAssessmentRequest) => api.triggerWebAssessment(assessmentId, payload),
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans", assessmentId] });
      toast.success("Web assessment queued", `Web assessment scan queued with status "${scan.status}".`);
    },
    onError: (err: any) => {
      if (err.status === 403) {
        toast.error("Scope Rejected (403)", err.message || "Target web host is outside authorized boundaries.");
      } else if (err.status === 409) {
        toast.warning("Scan in progress (409)", "Another scan is currently active.");
      } else {
        toast.error("Web assessment trigger failed", err.message || "Execution error.");
      }
    },
  });
}

export function useAssessmentAssets(
  assessmentId: string | undefined,
  filters?: { type?: string; scanId?: string }
) {
  return useQuery({
    queryKey: ["assets", assessmentId, filters],
    queryFn: () => (assessmentId ? api.fetchAssessmentAssets(assessmentId, filters) : Promise.resolve([])),
    enabled: !!assessmentId,
  });
}

