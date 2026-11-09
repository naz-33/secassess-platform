import { apiClient } from "../../api/client";
import type {
  AssessmentRead,
  AssessmentCreate,
  ScanRead,
  ScanCreate,
  WebAssessmentRequest,
  AssetRead,
} from "../../api/types";

export async function fetchAssessments(limit = 100, offset = 0): Promise<AssessmentRead[]> {
  return apiClient<AssessmentRead[]>(`/api/v1/assessments?limit=${limit}&offset=${offset}`);
}

export async function fetchAssessment(id: string): Promise<AssessmentRead> {
  return apiClient<AssessmentRead>(`/api/v1/assessments/${id}`);
}

export async function createAssessment(payload: AssessmentCreate): Promise<AssessmentRead> {
  return apiClient<AssessmentRead>("/api/v1/assessments", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchAssessmentScans(assessmentId: string): Promise<ScanRead[]> {
  return apiClient<ScanRead[]>(`/api/v1/assessments/${assessmentId}/scans`);
}

export async function fetchScanDetail(assessmentId: string, scanId: string): Promise<ScanRead> {
  return apiClient<ScanRead>(`/api/v1/assessments/${assessmentId}/scans/${scanId}`);
}

export async function triggerReconScan(
  assessmentId: string,
  payload: ScanCreate
): Promise<ScanRead> {
  return apiClient<ScanRead>(`/api/v1/assessments/${assessmentId}/scans`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function triggerWebAssessment(
  assessmentId: string,
  payload: WebAssessmentRequest
): Promise<ScanRead> {
  return apiClient<ScanRead>(`/api/v1/assessments/${assessmentId}/web-assessment`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchAssessmentAssets(
  assessmentId: string,
  filters?: { type?: string; scanId?: string }
): Promise<AssetRead[]> {
  const query = new URLSearchParams();
  if (filters?.type) query.set("type", filters.type);
  if (filters?.scanId) query.set("scan_id", filters.scanId);

  const qs = query.toString() ? `?${query.toString()}` : "";
  return apiClient<AssetRead[]>(`/api/v1/assessments/${assessmentId}/assets${qs}`);
}
