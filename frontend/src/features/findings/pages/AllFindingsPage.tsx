import { useState, useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Terminal, Layers, ArrowRight, Clock, CheckCircle2 } from "lucide-react";
import { useAssessments } from "../../assessments/hooks";
import { useFindings } from "../hooks";
import { FindingsFilters, FindingsFilterValues } from "../components/FindingsFilters";
import { FindingsTable } from "../components/FindingsTable";
import { LoadingState, ErrorState, EmptyState } from "../../../components/StatusStates";
import { Badge } from "../../../components/Badge";
import type { FindingSeverity, FindingStatus, FindingSource, FindingRead, AssessmentRead } from "../../../api/types";

export function AllFindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<"assessments" | "all">("assessments");

  // Fetch assessments for filter dropdown and assessment cards
  const { data: assessments, isLoading: isLoadingAssessments, error: assessmentsError } = useAssessments();

  // Sync filters from URL query parameters
  const filterValues: FindingsFilterValues = {
    assessment_id: searchParams.get("assessment_id") || "",
    status: (searchParams.get("status") as FindingStatus) || "",
    effective_severity: (searchParams.get("effective_severity") as FindingSeverity) || "",
    category: searchParams.get("category") || "",
    source: (searchParams.get("source") as FindingSource) || "",
  };

  const updateFilters = (newVals: FindingsFilterValues) => {
    const params = new URLSearchParams(searchParams);

    if (newVals.assessment_id) params.set("assessment_id", newVals.assessment_id);
    else params.delete("assessment_id");

    if (newVals.status) params.set("status", newVals.status);
    else params.delete("status");

    if (newVals.effective_severity) params.set("effective_severity", newVals.effective_severity);
    else params.delete("effective_severity");

    if (newVals.category) params.set("category", newVals.category);
    else params.delete("category");

    if (newVals.source) params.set("source", newVals.source);
    else params.delete("source");

    setSearchParams(params);
  };

  const { data: findings, isLoading: isLoadingFindings, error: findingsError, refetch } = useFindings(
    undefined,
    {
      assessment_id: filterValues.assessment_id || undefined,
      status: filterValues.status || undefined,
      effective_severity: filterValues.effective_severity || undefined,
      category: filterValues.category || undefined,
      source: filterValues.source || undefined,
    }
  );

  const categories = Array.from(new Set((findings || []).map((f: FindingRead) => f.category))).filter(Boolean) as string[];

  const assessmentOptions = (assessments || []).map((a: AssessmentRead) => ({
    id: a.id,
    name: a.name,
  }));

  // Calculate unverified and confirmed counts per assessment from all loaded findings
  const countsPerAssessment = useMemo(() => {
    const counts: Record<string, { unverified: number; confirmed: number; total: number }> = {};
    (assessments || []).forEach((a: AssessmentRead) => {
      counts[a.id] = { unverified: 0, confirmed: 0, total: 0 };
    });
    (findings || []).forEach((f: FindingRead) => {
      if (!counts[f.assessment_id]) {
        counts[f.assessment_id] = { unverified: 0, confirmed: 0, total: 0 };
      }
      counts[f.assessment_id].total += 1;
      if (f.status === "unverified") {
        counts[f.assessment_id].unverified += 1;
      } else if (f.status === "confirmed") {
        counts[f.assessment_id].confirmed += 1;
      }
    });
    return counts;
  }, [assessments, findings]);

  if (isLoadingAssessments && isLoadingFindings) {
    return <LoadingState message="Loading findings and assessment queues..." />;
  }

  if (assessmentsError || findingsError) {
    return (
      <ErrorState
        title="Failed to load findings data"
        error={assessmentsError || findingsError}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-cyan-400 text-xs font-medium uppercase tracking-wider">
            <Terminal className="h-4 w-4" />
            <span>Vulnerability Management</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100">Findings & Verification</h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Track unverified candidate findings, triage vulnerability severities, and record verified results.
          </p>
        </div>
      </div>

      {/* View Switcher Tabs */}
      <div className="border-b border-slate-800">
        <nav className="flex space-x-6 text-sm font-medium">
          <button
            onClick={() => setActiveTab("assessments")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${activeTab === "assessments"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
              }`}
          >
            <Layers className="h-4 w-4" />
            <span>Assessments Queue</span>
          </button>

          <button
            onClick={() => setActiveTab("all")}
            className={`flex items-center space-x-2 border-b-2 py-3 px-1 transition-colors ${activeTab === "all"
                ? "border-cyan-500 text-cyan-400"
                : "border-transparent text-slate-400 hover:border-slate-700 hover:text-slate-200"
              }`}
          >
            <Terminal className="h-4 w-4" />
            <span>All Findings Feed ({findings?.length || 0})</span>
          </button>
        </nav>
      </div>

      {/* Tab 1: Assessments Verification Queue */}
      {activeTab === "assessments" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-100">
              Assessments with Unverified & Confirmed Finding Counts
            </h2>
          </div>

          {(assessments || []).length === 0 ? (
            <EmptyState
              title="No assessments found"
              description="Create an assessment and launch scans to start discovering findings."
            />
          ) : (
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                    <tr>
                      <th className="py-3 px-4 font-semibold uppercase tracking-wider">Assessment</th>
                      <th className="py-3 px-4 font-semibold uppercase tracking-wider">Status</th>
                      <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                        Unverified
                      </th>
                      <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                        Confirmed
                      </th>
                      <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                        Total
                      </th>
                      <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {(assessments || []).map((a: AssessmentRead) => {
                      const counts = countsPerAssessment[a.id] || { unverified: 0, confirmed: 0, total: 0 };
                      return (
                        <tr key={a.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-3 px-4 font-medium text-slate-100">
                            <Link
                              to={`/assessments/${a.id}?tab=findings`}
                              className="font-semibold hover:text-cyan-400 hover:underline"
                            >
                              {a.name}
                            </Link>
                          </td>
                          <td className="py-3 px-4">
                            <Badge
                              size="sm"
                              variant={a.status === "completed" ? "success" : "info"}
                            >
                              {a.status}
                            </Badge>
                          </td>
                          <td className="py-3 px-4 text-right">
                            {counts.unverified > 0 ? (
                              <span className="inline-flex items-center space-x-1 font-mono text-amber-400 bg-amber-950/60 border border-amber-800 px-2 py-0.5 rounded">
                                <Clock className="h-3 w-3 mr-1" />
                                {counts.unverified} unverified
                              </span>
                            ) : (
                              <span className="font-mono text-slate-500">0</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right">
                            {counts.confirmed > 0 ? (
                              <span className="inline-flex items-center space-x-1 font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800 px-2 py-0.5 rounded">
                                <CheckCircle2 className="h-3 w-3 mr-1" />
                                {counts.confirmed} confirmed
                              </span>
                            ) : (
                              <span className="font-mono text-slate-500">0</span>
                            )}
                          </td>
                          <td className="py-3 px-4 text-right font-mono font-medium text-slate-200">
                            {counts.total}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <Link
                              to={`/assessments/${a.id}?tab=findings`}
                              className="inline-flex items-center text-cyan-400 hover:text-cyan-300 font-medium"
                            >
                              <span>View Findings</span>
                              <ArrowRight className="h-3.5 w-3.5 ml-1" />
                            </Link>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: All Findings Aggregate Feed */}
      {activeTab === "all" && (
        <div className="space-y-6">
          <FindingsFilters
            values={filterValues}
            onChange={updateFilters}
            categories={categories}
            assessments={assessmentOptions}
          />
          <FindingsTable findings={findings || []} />
        </div>
      )}
    </div>
  );
}
