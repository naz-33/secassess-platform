import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { dashboardApi, reportsApi, adminApi } from "./api";
import type {
  ReportGenerateRequest,
  ReportRead,
  UserRead,
  UserCreate,
  UserUpdate,
} from "../../api/types";

// =================== Dashboard Hooks ===================

export function useGlobalDashboard(limit = 50, offset = 0) {
  return useQuery({
    queryKey: ["dashboard", "global", limit, offset],
    queryFn: () => dashboardApi.getGlobal(limit, offset),
  });
}

export function useAssessmentDashboard(assessmentId: string | undefined) {
  return useQuery({
    queryKey: ["dashboard", "assessment", assessmentId],
    queryFn: () => dashboardApi.getAssessmentDashboard(assessmentId!),
    enabled: Boolean(assessmentId),
  });
}

// =================== Reports Hooks ===================

export function useAssessmentReports(assessmentId: string | undefined) {
  return useQuery({
    queryKey: ["reports", "assessment", assessmentId],
    queryFn: () => reportsApi.listByAssessment(assessmentId!),
    enabled: Boolean(assessmentId),
  });
}

export function useGenerateReport(assessmentId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ReportGenerateRequest) =>
      reportsApi.generate(assessmentId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports", "assessment", assessmentId] });
      queryClient.invalidateQueries({ queryKey: ["dashboard", "assessment", assessmentId] });
    },
  });
}

/**
 * Polls a specific report until completed or failed, respecting unmount / document visibility.
 */
export function useReportPoller(
  reportId: string | null,
  options?: {
    onCompleted?: (report: ReportRead) => void;
    onFailed?: (report: ReportRead) => void;
  }
) {
  const queryClient = useQueryClient();
  const [currentReport, setCurrentReport] = useState<ReportRead | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const [pollError, setPollError] = useState<string | null>(null);
  const [durationExceeded, setDurationExceeded] = useState(false);

  const startTimeRef = useRef<number>(0);
  const consecutiveErrorsRef = useRef<number>(0);

  useEffect(() => {
    if (!reportId) {
      setIsPolling(false);
      setCurrentReport(null);
      setPollError(null);
      setDurationExceeded(false);
      return;
    }

    let isMounted = true;
    let timerId: ReturnType<typeof setTimeout> | null = null;
    startTimeRef.current = Date.now();
    consecutiveErrorsRef.current = 0;
    setIsPolling(true);
    setPollError(null);
    setDurationExceeded(false);

    const MAX_DURATION_MS = 180000; // 3 minutes timeout notice

    const poll = async () => {
      if (!isMounted) return;

      // Skip polling if tab is hidden
      if (document.hidden) {
        timerId = setTimeout(poll, 3000);
        return;
      }

      // Check max duration
      if (Date.now() - startTimeRef.current > MAX_DURATION_MS) {
        if (isMounted) {
          setDurationExceeded(true);
          setIsPolling(false);
        }
        return;
      }

      try {
        const report = await reportsApi.getReport(reportId);
        if (!isMounted) return;

        consecutiveErrorsRef.current = 0;
        setCurrentReport(report);

        if (report.status === "completed") {
          setIsPolling(false);
          queryClient.invalidateQueries({ queryKey: ["reports", "assessment", report.assessment_id] });
          queryClient.invalidateQueries({ queryKey: ["dashboard", "assessment", report.assessment_id] });
          options?.onCompleted?.(report);
          return;
        }

        if (report.status === "failed") {
          setIsPolling(false);
          queryClient.invalidateQueries({ queryKey: ["reports", "assessment", report.assessment_id] });
          options?.onFailed?.(report);
          return;
        }

        // Still running / pending: poll again with 2s interval
        timerId = setTimeout(poll, 2000);
      } catch (err: any) {
        if (!isMounted) return;
        consecutiveErrorsRef.current += 1;
        setPollError(err.message || "Failed to retrieve report status");

        // Exponential backoff up to 10s on error
        const delay = Math.min(2000 * Math.pow(1.5, consecutiveErrorsRef.current), 10000);
        timerId = setTimeout(poll, delay);
      }
    };

    poll();

    return () => {
      isMounted = false;
      if (timerId) clearTimeout(timerId);
    };
  }, [reportId]);

  return {
    report: currentReport,
    isPolling,
    pollError,
    durationExceeded,
  };
}

// =================== Admin Hooks ===================

export function useUsers(limit = 100, offset = 0) {
  return useQuery({
    queryKey: ["admin", "users", limit, offset],
    queryFn: () => adminApi.listUsers(limit, offset),
  });
}

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: UserCreate) => adminApi.createUser(payload),
    onSuccess: (newUser) => {
      queryClient.setQueryData(["admin", "users", 100, 0], (old: UserRead[] | undefined) => {
        return old ? [...old, newUser] : [newUser];
      });
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
      queryClient.invalidateQueries({ queryKey: ["admin", "audit"] });
    },
  });
}

export function useUpdateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, payload }: { userId: string; payload: UserUpdate }) =>
      adminApi.updateUser(userId, payload),
    onSuccess: (updatedUser) => {
      queryClient.setQueryData(["admin", "users", 100, 0], (old: UserRead[] | undefined) => {
        return old ? old.map((u) => (u.id === updatedUser.id ? updatedUser : u)) : [updatedUser];
      });
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
      queryClient.invalidateQueries({ queryKey: ["admin", "audit"] });
    },
  });
}

export function useAuditLogs(params: {
  action?: string;
  user_id?: string;
  start_date?: string;
  end_date?: string;
  limit?: number;
  offset?: number;
} = {}) {
  return useQuery({
    queryKey: ["admin", "audit", params],
    queryFn: () => adminApi.listAuditLogs(params),
  });
}
