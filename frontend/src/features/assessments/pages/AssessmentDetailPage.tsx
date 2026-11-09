import { useState, useEffect } from "react";
import { useParams, useNavigate, useSearchParams, Link } from "react-router-dom";
import {
  ArrowLeft,
  Radar,
  Server,
  Layers,
  FileText,
  Activity,
  Terminal,
} from "lucide-react";
import { useAssessment, useAssessmentScans, useAssessmentAssets } from "../hooks";
import { useTarget } from "../../targets/hooks";
import { Badge } from "../../../components/Badge";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import { ScanLauncher } from "../../scans/components/ScanLauncher";
import { ScansList } from "../../scans/components/ScansList";
import { AssetsTable } from "../../assets/components/AssetsTable";
import { RequireRole } from "../../../auth/RequireRole";
import { FindingsListPage } from "../../findings/pages/FindingsListPage";
import { useFindingsSummary } from "../../findings/hooks";
import { AssessmentDashboardView } from "../../dashboard/components/AssessmentDashboardView";
import { AssessmentReportsView } from "../../reports/components/AssessmentReportsView";

export function AssessmentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  type TabType = "overview" | "scans" | "assets" | "findings" | "reports";
  const requestedTab = (searchParams.get("tab") as TabType) || "overview";
  const [activeTab, setActiveTab] = useState<TabType>(requestedTab);

  useEffect(() => {
    if (requestedTab && ["overview", "scans", "assets", "findings", "reports"].includes(requestedTab)) {
      setActiveTab(requestedTab);
    }
  }, [requestedTab]);

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab);
    const p = new URLSearchParams(searchParams);
    if (tab === "overview") {
      p.delete("tab");
    } else {
      p.set("tab", tab);
    }
    setSearchParams(p);
  };

  const { data: assessment, isLoading, error, refetch } = useAssessment(id);
  const { data: target } = useTarget(assessment?.target_id);
  const { data: scans } = useAssessmentScans(id);
  const { data: assets } = useAssessmentAssets(id);
  const { data: findingsSummary } = useFindingsSummary(id);


  if (isLoading) return <LoadingState message="Loading assessment..." />;
  if (error || !assessment) {
    return <ErrorState title="Failed to load assessment" error={error} onRetry={() => refetch()} />;
  }

  const activeScanCount = (scans || []).filter(
    (s) => s.status === "pending" || s.status === "running"
  ).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <button
          onClick={() => navigate("/assessments")}
          className="inline-flex items-center text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 mb-3"
        >
          <ArrowLeft className="h-4 w-4 mr-1.5" />
          Back to Assessments
        </button>

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">{assessment.name}</h1>
              <Badge variant={assessment.status === "completed" ? "success" : "info"}>
                {assessment.status.toUpperCase()}
              </Badge>
              {activeScanCount > 0 && (
                <Badge variant="warning" icon={<Activity className="h-3 w-3 animate-spin" />}>
                  {activeScanCount} scan{activeScanCount > 1 ? "s" : ""} active
                </Badge>
              )}
            </div>
            {target && (
              <p className="text-xs text-slate-400 mt-1 flex items-center space-x-1.5">
                <span>Target:</span>
                <Link
                  to={`/targets/${target.id}`}
                  className="font-medium text-cyan-400 hover:text-cyan-300 hover:underline"
                >
                  {target.name}
                </Link>
                <span className="font-mono text-slate-500">({target.base_url})</span>
              </p>
            )}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-800">
        <nav className="flex space-x-6 text-sm font-medium">
          <button
            onClick={() => handleTabChange("overview")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${
              activeTab === "overview"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <Layers className="h-4 w-4" />
            <span>Overview</span>
          </button>

          <button
            onClick={() => handleTabChange("scans")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${
              activeTab === "scans"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <Radar className="h-4 w-4" />
            <span>Scans ({scans?.length || 0})</span>
            {activeScanCount > 0 && (
              <span className="h-2 w-2 rounded-full bg-amber-400 animate-ping" />
            )}
          </button>

          <button
            onClick={() => handleTabChange("assets")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${
              activeTab === "assets"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <Server className="h-4 w-4" />
            <span>Assets ({assets?.length || 0})</span>
          </button>

          <button
            onClick={() => handleTabChange("findings")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${
              activeTab === "findings"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <Terminal className="h-4 w-4" />
            <span>Findings ({findingsSummary?.total ?? 0})</span>
            {findingsSummary?.unverified_count ? (
              <span className="text-[10px] bg-amber-950 text-amber-300 border border-amber-800 px-1.5 py-0.2 rounded">
                {findingsSummary.unverified_count} unverified
              </span>
            ) : null}
          </button>

          <button
            onClick={() => handleTabChange("reports")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${
              activeTab === "reports"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
            }`}
          >
            <FileText className="h-4 w-4" />
            <span>Reports</span>
          </button>
        </nav>
      </div>

      {/* Tab Content */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* Quick Scan Launcher Card */}
          <RequireRole roles={["admin", "assessor"]}>
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6">
              <h2 className="text-base font-bold text-slate-100 mb-4 flex items-center space-x-2">
                <Radar className="h-5 w-5 text-cyan-400" />
                <span>Launch Assessment Scans</span>
              </h2>
              <ScanLauncher assessmentId={assessment.id} defaultTarget={target?.base_url} />
            </div>
          </RequireRole>

          {/* Consolidated Assessment Dashboard */}
          <AssessmentDashboardView
            assessmentId={assessment.id}
            onNavigateTab={handleTabChange}
          />
        </div>
      )}

      {activeTab === "scans" && (
        <div className="space-y-6">
          <RequireRole roles={["admin", "assessor"]}>
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6">
              <h2 className="text-base font-bold text-slate-100 mb-4 flex items-center space-x-2">
                <Radar className="h-5 w-5 text-cyan-400" />
                <span>Trigger New Scan</span>
              </h2>
              <ScanLauncher assessmentId={assessment.id} defaultTarget={target?.base_url} />
            </div>
          </RequireRole>
          <ScansList assessmentId={assessment.id} />
        </div>
      )}

      {activeTab === "assets" && (
        <div className="space-y-6">
          <AssetsTable assessmentId={assessment.id} />
        </div>
      )}

      {activeTab === "findings" && (
        <div className="space-y-6">
          <FindingsListPage assessmentId={assessment.id} />
        </div>
      )}

      {activeTab === "reports" && (
        <div className="space-y-6">
          <AssessmentReportsView assessmentId={assessment.id} />
        </div>
      )}
    </div>
  );
}
