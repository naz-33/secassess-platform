import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  Sparkles,
  FileText,
  Activity,
  Server,
  Radar,
  ArrowRight,
} from "lucide-react";
import { useAssessmentDashboard } from "../hooks";
import { SeverityDistributionChart, CategoryDistributionChart } from "./DashboardCharts";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import { Badge } from "../../../components/Badge";

interface AssessmentDashboardViewProps {
  assessmentId: string;
  onNavigateTab?: (tab: "overview" | "scans" | "assets" | "findings" | "reports") => void;
}

export function AssessmentDashboardView({ assessmentId, onNavigateTab }: AssessmentDashboardViewProps) {
  const { data, isLoading, error, refetch } = useAssessmentDashboard(assessmentId);

  if (isLoading) {
    return <LoadingState message="Loading assessment security dashboard..." />;
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
    findings,
    assets,
    scans,
    ai,
    recent_activity,
    reports,
  } = data;

  const totalFindings = findings.total || 0;
  const unverifiedCount = findings.unverified_count || 0;
  const confirmedCount = findings.verified_count || 0;
  const progressPercent = Math.round(findings.verification_progress * 100);

  return (
    <div className="space-y-6">
      {/* Banner when unverified findings remain */}
      {unverifiedCount > 0 && (
        <div
          role="alert"
          className="rounded-lg border border-amber-800/80 bg-amber-950/40 p-4 text-amber-200 flex items-start space-x-3"
        >
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-xs sm:text-sm">
            <span className="font-semibold text-amber-300">
              {unverifiedCount} {unverifiedCount === 1 ? "finding has" : "findings have"} not been verified.
            </span>{" "}
            They are not confirmed vulnerabilities. Verification by an authorized assessor is required before inclusion in official reports.
          </div>
        </div>
      )}

      {/* Top Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Total Findings */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
            Total Findings
          </span>
          <p className="text-2xl font-bold text-slate-100 mt-1">{totalFindings}</p>
          <span className="text-[11px] text-slate-500">Candidate + Confirmed</span>
        </div>

        {/* Confirmed */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Confirmed
            </span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <p className="text-2xl font-bold text-emerald-400 mt-1">{confirmedCount}</p>
          <span className="text-[11px] text-slate-500">Official vulnerabilities</span>
        </div>

        {/* Unverified */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Unverified
            </span>
            <Clock className="h-4 w-4 text-amber-400" />
          </div>
          <p className="text-2xl font-bold text-amber-400 mt-1">{unverifiedCount}</p>
          <span className="text-[11px] text-slate-500">Pending review</span>
        </div>

        {/* Verification Progress */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              Verification Progress
            </span>
            <span className="text-xs font-semibold text-cyan-400">{progressPercent}%</span>
          </div>
          <p className="text-sm font-semibold text-slate-200 mt-2">
            {confirmedCount} of {totalFindings} verified
          </p>
          <div className="w-full bg-slate-800 rounded-full h-1.5 mt-2 overflow-hidden">
            <div
              className="bg-cyan-500 h-1.5 rounded-full transition-all duration-300"
              style={{ width: `${progressPercent}%` }}
            />
          </div>
        </div>
      </div>

      {/* Visual Analytics Charts (Confirmed severity distribution & Category) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SeverityDistributionChart
          confirmedBySeverity={findings.confirmed_by_effective_severity || {}}
        />
        <CategoryDistributionChart
          confirmedByCategory={findings.confirmed_by_category || {}}
        />
      </div>

      {/* Assets & Scans Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Discovered Assets by Type */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Server className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">Discovered Assets</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">{assets.total} total</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-center">
            {["host", "port", "service", "endpoint"].map((type) => (
              <div
                key={type}
                className="bg-slate-800/50 p-2.5 rounded border border-slate-700/50"
              >
                <div className="text-[11px] uppercase tracking-wider text-slate-400">{type}</div>
                <div className="text-lg font-bold text-slate-100 mt-0.5">
                  {assets.by_type?.[type] || 0}
                </div>
              </div>
            ))}
          </div>

          {onNavigateTab && (
            <button
              onClick={() => onNavigateTab("assets")}
              className="text-xs text-cyan-400 hover:text-cyan-300 inline-flex items-center space-x-1 pt-1"
            >
              <span>Explore all assessment assets</span>
              <ArrowRight className="h-3 w-3" />
            </button>
          )}
        </div>

        {/* Scan Status & Tools */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Radar className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">Scan Executions</h3>
            </div>
            <span className="text-xs font-mono text-slate-400">{scans.total} total</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 text-center">
            {["nmap", "dns", "zap", "curl"].map((tool) => (
              <div
                key={tool}
                className="bg-slate-800/50 p-2.5 rounded border border-slate-700/50"
              >
                <div className="text-[11px] uppercase tracking-wider text-slate-400">{tool}</div>
                <div className="text-lg font-bold text-slate-100 mt-0.5">
                  {scans.by_tool?.[tool] || 0}
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center justify-between pt-1 text-xs text-slate-400">
            <span>
              Status: {scans.by_status?.completed || 0} completed, {scans.by_status?.failed || 0} failed
            </span>
            {onNavigateTab && (
              <button
                onClick={() => onNavigateTab("scans")}
                className="text-cyan-400 hover:text-cyan-300 inline-flex items-center space-x-1"
              >
                <span>View scan logs</span>
                <ArrowRight className="h-3 w-3" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* AI Summary & Latest Report */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* AI Summary Card */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <Sparkles className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">AI Analysis Posture</h3>
            </div>
            <Badge variant={ai.has_approved_executive_summary ? "success" : "neutral"}>
              {ai.has_approved_executive_summary ? "Summary Approved" : "No Approved Summary"}
            </Badge>
          </div>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Total Analyses Performed:</span>
              <span className="font-semibold text-slate-200">{ai.total}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">Approved Analyses:</span>
              <span className="font-semibold text-slate-200">{ai.approved_count}</span>
            </div>
            <div className="flex justify-between py-1 border-b border-slate-800/60">
              <span className="text-slate-400">AI-Promoted Findings:</span>
              <span className="font-semibold text-slate-200">
                {ai.ai_promoted_findings_count} ({ai.ai_promoted_confirmed_count} confirmed)
              </span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-slate-400">Executive Summary Ready:</span>
              <span className="font-semibold text-slate-200">
                {ai.has_approved_executive_summary ? "Yes" : "No"}
              </span>
            </div>
          </div>
        </div>

        {/* Latest Report Card */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center space-x-2">
              <FileText className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">Latest Report</h3>
            </div>
            {reports && (
              <Badge variant={reports.status === "completed" ? "success" : "info"}>
                v{reports.version} ({reports.format.toUpperCase()})
              </Badge>
            )}
          </div>

          {reports ? (
            <div className="space-y-2 text-xs">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Status:</span>
                <span className="font-semibold text-slate-200 capitalize">{reports.status}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Generated At:</span>
                <span className="font-mono text-slate-300">
                  {reports.generated_at ? new Date(reports.generated_at).toLocaleString() : "In progress"}
                </span>
              </div>
              {reports.sha256 && (
                <div className="py-1">
                  <span className="text-slate-400 block mb-0.5">SHA-256 Digest:</span>
                  <span className="font-mono text-[10px] text-slate-400 truncate block bg-slate-950 p-1.5 rounded border border-slate-800">
                    {reports.sha256}
                  </span>
                </div>
              )}
              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab("reports")}
                  className="text-xs text-cyan-400 hover:text-cyan-300 inline-flex items-center space-x-1 pt-1"
                >
                  <span>Go to Assessment Reports tab</span>
                  <ArrowRight className="h-3 w-3" />
                </button>
              )}
            </div>
          ) : (
            <div className="py-6 text-center text-xs text-slate-500">
              <p>No report has been compiled yet for this assessment.</p>
              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab("reports")}
                  className="text-cyan-400 hover:text-cyan-300 underline mt-2 block mx-auto"
                >
                  Generate First Report
                </button>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Recent Activity List */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
        <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
          <Activity className="h-4 w-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100">Recent Assessment Activity</h3>
        </div>

        {recent_activity && recent_activity.length > 0 ? (
          <div className="divide-y divide-slate-800/60 text-xs">
            {recent_activity.slice(0, 8).map((act) => (
              <div key={act.id} className="py-2.5 flex items-center justify-between">
                <div>
                  <span className="font-mono text-cyan-400 font-medium">{act.action}</span>
                  {act.user_id && (
                    <span className="text-slate-500 ml-2">by user {act.user_id.slice(0, 8)}</span>
                  )}
                </div>
                <span className="text-slate-500 font-mono text-[11px]">
                  {new Date(act.created_at).toLocaleString()}
                </span>
              </div>
            ))}
          </div>
        ) : (
          <div className="py-4 text-center text-xs text-slate-500">
            No recent activity recorded.
          </div>
        )}
      </div>
    </div>
  );
}
