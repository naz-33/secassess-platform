import { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import {
  ArrowLeft,
  Bot,
  Sparkles,
  AlertCircle,
  RefreshCw,
} from "lucide-react";
import { useFinding, useFindingVerifications, useFindingSeverityHistory } from "../hooks";
import { SeverityBadge, StatusBadge, SourceBadge } from "../components/FindingBadges";
import { VerificationForm } from "../components/VerificationForm";
import { VerificationTimeline } from "../components/VerificationTimeline";
import { SeverityOverrideForm } from "../components/SeverityOverrideForm";
import { SeverityHistoryTable } from "../components/SeverityHistoryTable";
import { EvidencePanel } from "../components/EvidencePanel";
import { ExplainFindingResult } from "../../ai/components/ExplainFindingResult";
import { useExplainFinding, useAIStatus } from "../../ai/hooks";
import { Button } from "../../../components/Button";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import { RequireRole } from "../../../auth/RequireRole";
import { useToast } from "../../../components/Toast";
import { ApiError } from "../../../api/client";
import type { AIAnalysisRead } from "../../../api/types";

export function FindingDetailPage() {
  const { assessmentId, findingId: routeFindingId, id } = useParams<{
    assessmentId?: string;
    findingId?: string;
    id?: string;
  }>();

  const findingId = routeFindingId || id;
  const navigate = useNavigate();
  const { success } = useToast();

  const { data: finding, isLoading, error, refetch } = useFinding(findingId);
  const { data: verifications } = useFindingVerifications(findingId);
  const { data: severityHistory } = useFindingSeverityHistory(findingId);

  const { data: aiStatus } = useAIStatus();
  const isAiConfigured = Boolean(aiStatus?.configured && aiStatus?.enabled);

  const explainMutation = useExplainFinding(findingId || "");
  const [explainAnalysis, setExplainAnalysis] = useState<AIAnalysisRead | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);

  if (isLoading) return <LoadingState message="Loading finding details..." />;
  if (error || !finding) {
    return <ErrorState title="Failed to load finding" error={error} onRetry={() => refetch()} />;
  }

  const effectiveAssessmentId = assessmentId || finding.assessment_id;
  const isAiProposed = finding.source === "ai";

  const handleExplain = async (force = false) => {
    try {
      setAiError(null);
      const res = await explainMutation.mutateAsync({ force });
      setExplainAnalysis(res);
      success(force ? "Explanation rerun triggered." : "AI explanation generated.");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setAiError(err.message);
      } else {
        setAiError("Failed to generate AI explanation.");
      }
    }
  };

  return (
    <div className="space-y-6">
      {/* Back button & Breadcrumbs */}
      <div>
        <button
          onClick={() => navigate(`/assessments/${effectiveAssessmentId}`)}
          className="inline-flex items-center text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 mb-2"
        >
          <ArrowLeft className="h-4 w-4 mr-1.5" />
          Back to Assessment
        </button>

        <nav className="flex items-center space-x-2 text-xs text-slate-400" aria-label="Breadcrumb">
          <Link to={`/assessments/${effectiveAssessmentId}`} className="hover:text-slate-200 hover:underline">
            Assessment
          </Link>
          <span>/</span>
          <span>Findings</span>
          <span>/</span>
          <span className="font-mono text-cyan-400">{finding.id.slice(0, 8)}...</span>
        </nav>
      </div>

      {/* Header Banner if AI-Sourced */}
      {isAiProposed && (
        <div
          role="alert"
          className="p-4 rounded-lg bg-purple-950/40 border border-purple-800/80 text-xs text-purple-200 flex items-start gap-3"
        >
          <Bot className="h-5 w-5 text-purple-400 shrink-0 mt-0.5" aria-hidden="true" />
          <div className="space-y-1">
            <p className="font-bold uppercase tracking-wider text-purple-300">
              This finding was proposed by AI.
            </p>
            <p className="text-purple-200/90 font-medium">
              It is not a confirmed vulnerability until an assessor verifies it against technical evidence.
              {finding.ai_analysis_id && (
                <span className="block mt-1 font-mono text-[11px] text-purple-400">
                  Originating Analysis ID: {finding.ai_analysis_id}
                </span>
              )}
            </p>
          </div>
        </div>
      )}

      {/* Finding Header */}
      <div className="border-b border-slate-800 pb-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="space-y-2">
            <h1 className="text-2xl font-bold tracking-tight text-slate-100">
              {finding.title}
            </h1>
            <div className="flex flex-wrap items-center gap-2">
              <StatusBadge status={finding.status} />
              <SeverityBadge severity={finding.effective_severity} />
              <SourceBadge source={finding.source} />
              <span className="text-xs text-slate-500 font-mono">
                Category: <span className="text-slate-300">{finding.category}</span>
              </span>
            </div>
          </div>

          {/* AI Explain Action */}
          <RequireRole roles={["admin", "assessor"]}>
            <Button
              size="sm"
              variant="outline"
              onClick={() => handleExplain(false)}
              disabled={!isAiConfigured || explainMutation.isPending}
              isLoading={explainMutation.isPending}
              title={!isAiConfigured ? "AI not configured on server" : "Generate deep technical explanation and remediation steps"}
              className="text-xs h-8"
            >
              <Sparkles className="h-3.5 w-3.5 text-purple-400 mr-1" />
              <span>Explain Finding</span>
            </Button>
          </RequireRole>
        </div>
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

      {/* AI Explanation Panel */}
      {explainAnalysis && (
        <div className="space-y-2">
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handleExplain(true)}
              className="text-xs h-7 gap-1 text-purple-300 hover:text-white"
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              <span>Rerun Explanation (force=true)</span>
            </Button>
          </div>
          <ExplainFindingResult analysis={explainAnalysis} />
        </div>
      )}

      {/* Details Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2/3): Details, Remediation, Evidence */}
        <div className="lg:col-span-2 space-y-6">
          {/* Finding Details Card */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400">
              Technical Description
            </h2>
            <p className="text-xs text-slate-200 whitespace-pre-wrap leading-relaxed font-sans">
              {finding.description}
            </p>

            {/* Standard vulnerability tags */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-3 border-t border-slate-800/80 text-xs">
              <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-mono">WSTG ID</span>
                <span className="font-mono text-slate-300 font-medium">{finding.wstg_id || "—"}</span>
              </div>
              <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-mono">OWASP Top 10</span>
                <span className="font-mono text-slate-300 font-medium">{finding.owasp_top10 || "—"}</span>
              </div>
              <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-mono">CWE</span>
                <span className="font-mono text-slate-300 font-medium">{finding.cwe || "—"}</span>
              </div>
              <div className="p-2 rounded bg-slate-950/60 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase block font-mono">Fingerprint</span>
                <span className="font-mono text-slate-300 font-medium truncate block" title={finding.fingerprint || ""}>
                  {finding.fingerprint ? `${finding.fingerprint.slice(0, 10)}...` : "—"}
                </span>
              </div>
            </div>

            {/* Affected URL */}
            <div className="pt-2 text-xs">
              <span className="text-slate-500 uppercase text-[10px] font-mono block">Affected Asset / Endpoint:</span>
              <p className="font-mono text-cyan-400 break-all bg-slate-950/70 p-2 rounded mt-1 border border-slate-800">
                {finding.affected_url || "Target-wide or unassigned"}
              </p>
            </div>

            {/* Suggested Remediation */}
            {finding.remediation && (
              <div className="p-3.5 rounded-md bg-slate-950/70 border border-slate-800 text-xs space-y-1">
                <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider">
                  Suggested Remediation:
                </span>
                <p className="text-slate-300 whitespace-pre-wrap font-sans leading-relaxed">
                  {finding.remediation}
                </p>
              </div>
            )}
          </div>

          {/* Evidence Panel (Upload, Note, Safe Preview, Download) */}
          <EvidencePanel findingId={finding.id} evidences={finding.evidences} />

          {/* Verification Timeline */}
          <VerificationTimeline verifications={verifications || []} />
        </div>

        {/* Right Column (1/3): Verification Actions & Severity */}
        <div className="space-y-6">
          {/* Verification Decision Form (Assessor/Admin only) */}
          <RequireRole
            roles={["admin", "assessor"]}
            fallback={
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
                <p className="font-semibold text-slate-300">Read-Only Mode</p>
                <p className="text-[11px] mt-1">
                  You are logged in as a Viewer. Only Assessors and Administrators can record verification decisions or change severities.
                </p>
              </div>
            }
          >
            <VerificationForm finding={finding} />
          </RequireRole>

          {/* Severity & CVSS Override Form (Assessor/Admin only) */}
          <RequireRole roles={["admin", "assessor"]}>
            <SeverityOverrideForm finding={finding} />
          </RequireRole>

          {/* Severity Override History */}
          <SeverityHistoryTable history={severityHistory || []} />
        </div>
      </div>
    </div>
  );
}
