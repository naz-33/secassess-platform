import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Terminal, Sparkles, AlertCircle, RefreshCw } from "lucide-react";
import { useFindings, useFindingsSummary } from "../hooks";
import { FindingsSummaryStrip } from "../components/FindingsSummaryStrip";
import { FindingsFilters, FindingsFilterValues } from "../components/FindingsFilters";
import { FindingsTable } from "../components/FindingsTable";
import { Button } from "../../../components/Button";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import { PrioritizeResult } from "../../ai/components/PrioritizeResult";
import { ExecutiveSummaryResult } from "../../ai/components/ExecutiveSummaryResult";
import { usePrioritizeFindings, useSummarizeAssessment, useAIStatus } from "../../ai/hooks";
import { RequireRole } from "../../../auth/RequireRole";
import { useToast } from "../../../components/Toast";
import type { FindingSeverity, FindingStatus, FindingSource, AIAnalysisRead } from "../../../api/types";
import { ApiError } from "../../../api/client";

interface FindingsListPageProps {
  assessmentId: string;
}

export function FindingsListPage({ assessmentId }: FindingsListPageProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const { success } = useToast();

  const { data: aiStatus } = useAIStatus();
  const isAiConfigured = Boolean(aiStatus?.configured && aiStatus?.enabled);

  const prioritizeMutation = usePrioritizeFindings(assessmentId);
  const summarizeMutation = useSummarizeAssessment(assessmentId);

  const [activePrioritizeAnalysis, setActivePrioritizeAnalysis] = useState<AIAnalysisRead | null>(null);
  const [activeSummaryAnalysis, setActiveSummaryAnalysis] = useState<AIAnalysisRead | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  // Sync filters from URL query parameters
  const filterValues: FindingsFilterValues = {
    status: (searchParams.get("status") as FindingStatus) || "",
    effective_severity: (searchParams.get("effective_severity") as FindingSeverity) || "",
    category: searchParams.get("category") || "",
    source: (searchParams.get("source") as FindingSource) || "",
    scan_id: searchParams.get("scan_id") || "",
    verified_by: searchParams.get("verified_by") || "",
  };

  const updateFilters = (newVals: FindingsFilterValues) => {
    const params = new URLSearchParams(searchParams);
    if (newVals.status) params.set("status", newVals.status);
    else params.delete("status");

    if (newVals.effective_severity) params.set("effective_severity", newVals.effective_severity);
    else params.delete("effective_severity");

    if (newVals.category) params.set("category", newVals.category);
    else params.delete("category");

    if (newVals.source) params.set("source", newVals.source);
    else params.delete("source");

    if (newVals.scan_id) params.set("scan_id", newVals.scan_id);
    else params.delete("scan_id");

    if (newVals.verified_by) params.set("verified_by", newVals.verified_by);
    else params.delete("verified_by");

    setSearchParams(params);
  };

  const { data: findings, isLoading, error, refetch } = useFindings(assessmentId, {
    status: filterValues.status || undefined,
    effective_severity: filterValues.effective_severity || undefined,
    category: filterValues.category || undefined,
    source: filterValues.source || undefined,
    scan_id: filterValues.scan_id || undefined,
    verified_by: filterValues.verified_by || undefined,
  });

  const { data: summary, isLoading: summaryLoading } = useFindingsSummary(assessmentId);

  const categories = Array.from(new Set((findings || []).map((f) => f.category))).filter(Boolean);

  const handlePrioritize = async (force = false) => {
    try {
      setAiError(null);
      const res = await prioritizeMutation.mutateAsync({ force });
      setActivePrioritizeAnalysis(res);
      success(force ? "Prioritization rerun triggered." : "AI risk prioritization ready.");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setAiError(err.message);
      } else {
        setAiError("Failed to prioritize findings.");
      }
    }
  };

  const handleSummarize = async (force = false) => {
    try {
      setAiError(null);
      const res = await summarizeMutation.mutateAsync({ force });
      setActiveSummaryAnalysis(res);
      success(force ? "Executive summary regenerated." : "AI executive summary drafted.");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setAiError(err.message);
      } else {
        setAiError("Failed to draft executive summary.");
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Assessment-Level AI Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <Terminal className="h-5 w-5 text-cyan-400" aria-hidden="true" />
            <span>Assessment Findings</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Security issues identified by automated scanners and assessor observations.
          </p>
        </div>

        {/* AI Action Buttons */}
        <RequireRole roles={["admin", "assessor"]}>
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => handlePrioritize(false)}
              disabled={!isAiConfigured || prioritizeMutation.isPending}
              isLoading={prioritizeMutation.isPending}
              title={!isAiConfigured ? "AI not configured on server" : "Prioritize findings by risk and blast radius"}
              className="text-xs h-8"
            >
              <Sparkles className="h-3.5 w-3.5 text-purple-400 mr-1" />
              <span>Prioritize Risks</span>
            </Button>

            <Button
              size="sm"
              variant="outline"
              onClick={() => handleSummarize(false)}
              disabled={!isAiConfigured || summarizeMutation.isPending}
              isLoading={summarizeMutation.isPending}
              title={!isAiConfigured ? "AI not configured on server" : "Draft executive summary of confirmed findings"}
              className="text-xs h-8"
            >
              <Sparkles className="h-3.5 w-3.5 text-purple-400 mr-1" />
              <span>Executive Summary</span>
            </Button>
          </div>
        </RequireRole>
      </div>

      {/* AI error alert if any */}
      {aiError && (
        <div role="alert" className="p-3 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{aiError}</span>
          </div>
          <Button size="sm" variant="ghost" onClick={() => setAiError(null)} className="h-6 text-xs text-rose-300">
            Dismiss
          </Button>
        </div>
      )}

      {/* Active AI Prioritize Panel */}
      {activePrioritizeAnalysis && (
        <div className="space-y-2">
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handlePrioritize(true)}
              className="text-xs h-7 gap-1 text-purple-300 hover:text-white"
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              <span>Rerun Prioritization (force=true)</span>
            </Button>
          </div>
          <PrioritizeResult analysis={activePrioritizeAnalysis} assessmentId={assessmentId} />
        </div>
      )}

      {/* Active AI Summary Panel */}
      {activeSummaryAnalysis && (
        <div className="space-y-2">
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handleSummarize(true)}
              className="text-xs h-7 gap-1 text-purple-300 hover:text-white"
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              <span>Regenerate Summary (force=true)</span>
            </Button>
          </div>
          <ExecutiveSummaryResult analysis={activeSummaryAnalysis} />
        </div>
      )}

      {/* Summary strip with verification progress */}
      <FindingsSummaryStrip summary={summary} isLoading={summaryLoading} />

      {/* Filter toolbar */}
      <FindingsFilters
        values={filterValues}
        onChange={updateFilters}
        categories={categories}
      />

      {/* Table & states */}
      {isLoading ? (
        <LoadingState message="Loading assessment findings..." />
      ) : error ? (
        <ErrorState title="Failed to load findings" error={error} onRetry={() => refetch()} />
      ) : (
        <FindingsTable findings={findings || []} assessmentId={assessmentId} />
      )}
    </div>
  );
}
