import { apiClient, downloadBlob } from "../../api/client";
import type {
  AssessmentDashboardResponse,
  GlobalDashboardResponse,
  ReportRead,
  ReportGenerateRequest,
  UserRead,
  UserCreate,
  UserUpdate,
  AuditLogRead,
} from "../../api/types";

export const dashboardApi = {
  getGlobal: async (limit = 50, offset = 0): Promise<GlobalDashboardResponse> => {
    return apiClient<GlobalDashboardResponse>(`/api/v1/dashboard?limit=${limit}&offset=${offset}`);
  },

  getAssessmentDashboard: async (assessmentId: string): Promise<AssessmentDashboardResponse> => {
    return apiClient<AssessmentDashboardResponse>(`/api/v1/assessments/${assessmentId}/dashboard`);
  },
};

export const reportsApi = {
  listByAssessment: async (assessmentId: string): Promise<ReportRead[]> => {
    return apiClient<ReportRead[]>(`/api/v1/assessments/${assessmentId}/reports`);
  },

  generate: async (assessmentId: string, payload: ReportGenerateRequest): Promise<ReportRead> => {
    return apiClient<ReportRead>(`/api/v1/assessments/${assessmentId}/reports`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  getReport: async (reportId: string): Promise<ReportRead> => {
    return apiClient<ReportRead>(`/api/v1/reports/${reportId}`);
  },

  deleteReport: async (reportId: string): Promise<{ success: boolean }> => {
    return apiClient<{ success: boolean }>(`/api/v1/reports/${reportId}`, {
      method: "DELETE",
    });
  },

  downloadReport: async (reportId: string): Promise<{ blob: Blob; filename?: string }> => {
    return downloadBlob(`/api/v1/reports/${reportId}/download`);
  },

  exportFindings: async (
    assessmentId: string,
    format: "csv" | "json" = "csv",
    status: string = "confirmed"
  ): Promise<{ blob: Blob; filename?: string }> => {
    const params = new URLSearchParams({ format, status });
    return downloadBlob(`/api/v1/assessments/${assessmentId}/findings/export?${params.toString()}`);
  },
};

export const adminApi = {
  listUsers: async (limit = 100, offset = 0): Promise<UserRead[]> => {
    return apiClient<UserRead[]>(`/api/v1/users?limit=${limit}&offset=${offset}`);
  },

  createUser: async (payload: UserCreate): Promise<UserRead> => {
    return apiClient<UserRead>("/api/v1/users", {
      method: "POST",
      body: JSON.stringify(payload),
    });
  },

  updateUser: async (userId: string, payload: UserUpdate): Promise<UserRead> => {
    return apiClient<UserRead>(`/api/v1/users/${userId}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    });
  },

  listAuditLogs: async (params: {
    action?: string;
    user_id?: string;
    start_date?: string;
    end_date?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<AuditLogRead[]> => {
    const query = new URLSearchParams();
    if (params.action) query.set("action", params.action);
    if (params.user_id) query.set("user_id", params.user_id);
    if (params.start_date) query.set("start_date", params.start_date);
    if (params.end_date) query.set("end_date", params.end_date);
    if (params.limit !== undefined) query.set("limit", params.limit.toString());
    if (params.offset !== undefined) query.set("offset", params.offset.toString());
    const qs = query.toString();
    return apiClient<AuditLogRead[]>(`/api/v1/audit-log${qs ? `?${qs}` : ""}`);
  },
};

