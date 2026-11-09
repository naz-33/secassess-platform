import { useState } from "react";
import { Link } from "react-router-dom";
import {
  BarChart3,
  Layers,
  Shield,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
} from "lucide-react";
import { useGlobalDashboard } from "../hooks";
import { LoadingState, ErrorState, EmptyState } from "../../../components/StatusStates";
import { Badge } from "../../../components/Badge";
import { Pagination } from "../../../components/Pagination";
import { SeverityDistributionChart } from "../components/DashboardCharts";

export function DashboardPage() {
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const offset = (page - 1) * pageSize;

  const { data, isLoading, error, refetch } = useGlobalDashboard(pageSize, offset);

  if (isLoading) {
    return <LoadingState message="Loading platform security dashboard..." />;
  }

  if (error || !data) {
    return (
      <ErrorState
        title="Failed to load dashboard metrics"
        error={error}
        onRetry={() => refetch()}
      />
    );
  }

  const {
    total_assessments,
    total_targets,
    total_scans,
    total_findings,
    findings_by_severity,
    findings_by_status,
    assessments,
    pagination,
  } = data;

  const totalPages = Math.ceil((pagination?.total || assessments.length) / pageSize) || 1;

  // Unverified findings count across all assessments
  const unverifiedTotal = findings_by_status?.unverified || 0;
  const confirmedTotal = findings_by_status?.confirmed || 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-cyan-400 text-xs font-medium uppercase tracking-wider">
            <BarChart3 className="h-4 w-4" />
            <span>Platform Overview</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
            Security Assessment Dashboard
          </h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Consolidated threat posture, verification progress, and active assessment tracking.
          </p>
        </div>
      </div>

      {/* Global Unverified Banner */}
      {unverifiedTotal > 0 && (
        <div
          role="alert"
          className="rounded-lg border border-amber-800/80 bg-amber-950/40 p-4 text-amber-200 flex items-start space-x-3"
        >
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm">
            <span className="font-semibold text-amber-300">
              {unverifiedTotal} {unverifiedTotal === 1 ? "finding has" : "findings have"} not been verified.
            </span>{" "}
            They are not confirmed vulnerabilities. Review the findings verification queue before generating official reports.
          </div>
        </div>
      )}

      {/* Metric Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Total Assessments */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Assessments
            </span>
            <Layers className="h-4 w-4 text-slate-400" />
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">{total_assessments}</p>
          <span className="text-[11px] text-slate-500">Across {total_targets} targets</span>
        </div>

        {/* Total Scans */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Scans Run
            </span>
            <Shield className="h-4 w-4 text-slate-400" />
          </div>
          <p className="text-2xl font-bold text-slate-100 mt-2">{total_scans}</p>
          <span className="text-[11px] text-slate-500">Nmap, ZAP, DNS, cURL</span>
        </div>

        {/* Total Confirmed */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Confirmed
            </span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-emerald-400 mt-2">{confirmedTotal}</p>
          <span className="text-[11px] text-slate-500">Verified vulnerabilities</span>
        </div>

        {/* Unverified Queue */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Unverified
            </span>
            <Clock className="h-4 w-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold text-amber-400 mt-2">{unverifiedTotal}</p>
          <span className="text-[11px] text-slate-500">
            {confirmedTotal} of {total_findings} verified
          </span>
        </div>
      </div>

      {/* Global Severity Chart */}
      <SeverityDistributionChart confirmedBySeverity={findings_by_severity || {}} />

      {/* Assessments Overview Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <Layers className="h-4 w-4 text-cyan-400" />
            <span>Assessments Posture Overview</span>
          </h2>
          <span className="text-xs text-slate-400 font-mono">
            {assessments.length} assessment{assessments.length === 1 ? "" : "s"}
          </span>
        </div>

        {assessments.length === 0 ? (
          <EmptyState
            title="No assessments found"
            description="Create your first assessment to begin security testing and vulnerability metrics collection."
          />
        ) : (
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Assessment</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Target</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Status</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                      Findings
                    </th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                      Confirmed
                    </th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                      Progress
                    </th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {assessments.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-medium text-slate-100">
                        <Link
                          to={`/assessments/${a.id}`}
                          className="hover:text-cyan-400 hover:underline font-semibold"
                        >
                          {a.name}
                        </Link>
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {a.target_name || "—"}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          size="sm"
                          variant={a.status === "completed" ? "success" : "info"}
                        >
                          {a.status}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 text-right font-mono font-medium">
                        {a.total_findings}
                      </td>
                      <td className="py-3 px-4 text-right font-mono font-semibold text-emerald-400">
                        {a.confirmed_findings}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <span className="font-mono text-cyan-400">
                          {Math.round((a.verification_progress || 0) * 100)}%
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <Link
                          to={`/assessments/${a.id}`}
                          className="inline-flex items-center text-cyan-400 hover:text-cyan-300 font-medium"
                          title="View Assessment"
                        >
                          <span>Dashboard</span>
                          <ArrowRight className="h-3 w-3 ml-1" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {totalPages > 1 && (
              <div className="p-3 border-t border-slate-800">
                <Pagination
                  currentPage={page}
                  totalPages={totalPages}
                  onPageChange={(p) => setPage(p)}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
