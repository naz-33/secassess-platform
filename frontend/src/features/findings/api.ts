import { apiClient, downloadBlob } from "../../api/client";
import type {
  FindingRead,
  FindingsSummary,
  VerificationRead,
  VerificationCreate,
  SeverityUpdateRequest,
  SeverityChangeRead,
  EvidenceRead,
  NoteEvidenceCreate,
  FindingSeverity,
  FindingStatus,
  FindingSource,
} from "../../api/types";

export interface FindingsListParams {
  assessment_id?: string;
  category?: string;
  severity?: FindingSeverity;
  effective_severity?: FindingSeverity;
  status?: FindingStatus;
  source?: FindingSource;
  scan_id?: string;
  verified_by?: string;
  limit?: number;
  offset?: number;
}

export const findingsApi = {
  list: async (assessmentId?: string, params: FindingsListParams = {}): Promise<FindingRead[]> => {
    const query = new URLSearchParams();
    const effectiveAssessmentId = assessmentId || params.assessment_id;
    if (params.category) query.set("category", params.category);
    if (params.severity) query.set("severity", params.severity);
    if (params.effective_severity) query.set("effective_severity", params.effective_severity);
    if (params.status) query.set("status", params.status);
    if (params.source) query.set("source", params.source);
    if (params.scan_id) query.set("scan_id", params.scan_id);
    if (params.verified_by) query.set("verified_by", params.verified_by);
    if (params.limit !== undefined) query.set("limit", params.limit.toString());
    if (params.offset !== undefined) query.set("offset", params.offset.toString());

    if (assessmentId) {
      const qs = query.toString();
      const endpoint = `/api/v1/assessments/${assessmentId}/findings${qs ? `?${qs}` : ""}`;
      return apiClient<FindingRead[]>(endpoint);
    } else {
      if (effectiveAssessmentId) query.set("assessment_id", effectiveAssessmentId);
      const qs = query.toString();
      const endpoint = `/api/v1/findings${qs ? `?${qs}` : ""}`;
      return apiClient<FindingRead[]>(endpoint);
    }
  },

  summary: async (assessmentId: string): Promise<FindingsSummary> => {
    return apiClient<FindingsSummary>(`/api/v1/assessments/${assessmentId}/findings/summary`);
  },

  get: async (findingId: string): Promise<FindingRead> => {
    return apiClient<FindingRead>(`/api/v1/findings/${findingId}`);
  },

  verify: async (findingId: string, data: VerificationCreate): Promise<VerificationRead> => {
    return apiClient<VerificationRead>(`/api/v1/findings/${findingId}/verify`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  verifications: async (findingId: string): Promise<VerificationRead[]> => {
    return apiClient<VerificationRead[]>(`/api/v1/findings/${findingId}/verifications`);
  },

  updateSeverity: async (findingId: string, data: SeverityUpdateRequest): Promise<FindingRead> => {
    return apiClient<FindingRead>(`/api/v1/findings/${findingId}/severity`, {
      method: "PATCH",
      body: JSON.stringify(data),
    });
  },

  severityHistory: async (findingId: string): Promise<SeverityChangeRead[]> => {
    return apiClient<SeverityChangeRead[]>(`/api/v1/findings/${findingId}/severity-history`);
  },

  uploadEvidence: async (findingId: string, formData: FormData): Promise<EvidenceRead> => {
    return apiClient<EvidenceRead>(`/api/v1/findings/${findingId}/evidence/upload`, {
      method: "POST",
      body: formData,
    });
  },

  addEvidenceNote: async (findingId: string, data: NoteEvidenceCreate): Promise<EvidenceRead> => {
    return apiClient<EvidenceRead>(`/api/v1/findings/${findingId}/evidence/note`, {
      method: "POST",
      body: JSON.stringify(data),
    });
  },

  downloadEvidence: async (evidenceId: string): Promise<{ blob: Blob; filename?: string }> => {
    return downloadBlob(`/api/v1/evidence/${evidenceId}/download`);
  },
};

