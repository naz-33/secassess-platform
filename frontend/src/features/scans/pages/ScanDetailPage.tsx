import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Terminal, ShieldAlert, CheckCircle, Clock, AlertCircle, Sparkles, RefreshCw } from "lucide-react";
import { useScanDetail } from "../../assessments/hooks";
import { Badge } from "../../../components/Badge";
import { Button } from "../../../components/Button";
import { CodeBlock } from "../../../components/CodeBlock";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import { RequireRole } from "../../../auth/RequireRole";
import { useInterpretScan, useAIAnalysis, useAIStatus } from "../../ai/hooks";
import { InterpretScanResult } from "../../ai/components/InterpretScanResult";
import { useToast } from "../../../components/Toast";
import { ApiError } from "../../../api/client";
import type { AIAnalysisRead } from "../../../api/types";

export function ScanDetailPage() {
  const { assessmentId, scanId } = useParams<{ assessmentId: string; scanId: string }>();
  const navigate = useNavigate();
  const { success } = useToast();

  const { data: scan, isLoading, error, refetch } = useScanDetail(assessmentId, scanId);

  const { data: aiStatus } = useAIStatus();
  const isAiConfigured = Boolean(aiStatus?.configured && aiStatus?.enabled);

  const interpretMutation = useInterpretScan(assessmentId || "", scanId || "");
  const [interpretAnalysis, setInterpretAnalysis] = useState<AIAnalysisRead | null>(null);
  const [aiError, setAiError] = useState<string | null>(null);
  const { data: updatedInterpretAnalysis } = useAIAnalysis(interpretAnalysis?.id);
  const displayedInterpretAnalysis = updatedInterpretAnalysis || interpretAnalysis;

  if (isLoading) return <LoadingState message="Loading scan execution details..." />;
  if (error || !scan) {
    return <ErrorState title="Failed to load scan" error={error} onRetry={() => refetch()} />;
  }

  const handleInterpret = async (force = false) => {
    if (!assessmentId || !scanId) return;
    try {
      setAiError(null);
      const res = await interpretMutation.mutateAsync({ force });
      setInterpretAnalysis(res);
      success(force ? "Scan interpretation rerun started." : "AI scan interpretation started.");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setAiError(err.message);
      } else {
        setAiError("Failed to interpret scan.");
      }
    }
  };

  const getStatusBadge = () => {
    switch (scan.status) {
      case "completed":
        return (
          <Badge variant="success" icon={<CheckCircle className="h-3.5 w-3.5" />}>
            COMPLETED
          </Badge>
        );
      case "running":
        return (
          <Badge variant="info" icon={<Clock className="h-3.5 w-3.5 animate-spin" />}>
            RUNNING
          </Badge>
        );
      case "pending":
        return (
          <Badge variant="warning" icon={<Clock className="h-3.5 w-3.5" />}>
            PENDING
          </Badge>
        );
      case "rejected":
        return (
          <Badge variant="danger" icon={<ShieldAlert className="h-3.5 w-3.5" />}>
            REJECTED: OUT OF SCOPE
          </Badge>
        );
      case "failed":
        return (
          <Badge variant="danger" icon={<AlertCircle className="h-3.5 w-3.5" />}>
            FAILED
          </Badge>
        );
      default:
        return <Badge variant="neutral">{scan.status}</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <button
          onClick={() => navigate(`/assessments/${assessmentId}`)}
          className="inline-flex items-center text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 mb-3"
        >
          <ArrowLeft className="h-4 w-4 mr-1.5" />
          Back to Assessment
        </button>

        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold tracking-tight text-slate-100 uppercase">
                {scan.tool} Scan Execution
              </h1>
              {getStatusBadge()}
            </div>
            <p className="text-xs font-mono text-slate-400 mt-1">ID: {scan.id}</p>
          </div>

          {/* AI Interpret Action */}
          <RequireRole roles={["admin", "assessor"]}>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                onClick={() => handleInterpret(false)}
                disabled={!isAiConfigured || interpretMutation.isPending || scan.status !== "completed"}
                isLoading={interpretMutation.isPending}
                title={
                  !isAiConfigured
                    ? "AI not configured on server"
                    : scan.status !== "completed"
                    ? "Scan must be completed to interpret"
                    : "Interpret scan results and extract candidate findings"
                }
                className="text-xs h-8"
              >
                <Sparkles className="h-3.5 w-3.5 text-purple-400 mr-1" />
                <span>Interpret Scan</span>
              </Button>
            </div>
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

      {/* AI Interpretation Result */}
      {displayedInterpretAnalysis?.status === "pending" && (
        <p role="status" className="text-xs text-purple-300">
          AI interpretation is running. Results will appear here when complete.
        </p>
      )}
      {displayedInterpretAnalysis?.status === "failed" && (
        <div role="alert" className="p-3 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300">
          AI interpretation failed: {displayedInterpretAnalysis.error || "The provider returned no usable result. Check the key, quota, and connection, then retry."}
        </div>
      )}
      {displayedInterpretAnalysis?.status === "completed" && assessmentId && (
        <div className="space-y-2">
          <div className="flex justify-end">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => handleInterpret(true)}
              className="text-xs h-7 gap-1 text-purple-300 hover:text-white"
            >
              <RefreshCw className="h-3 w-3 mr-1" />
              <span>Rerun Interpret (force=true)</span>
            </Button>
          </div>
          <InterpretScanResult analysis={displayedInterpretAnalysis} assessmentId={assessmentId} />
        </div>
      )}

      {/* Scope Rejection Alert */}
      {scan.status === "rejected" && (
        <div className="rounded-lg border border-rose-800/80 bg-rose-950/40 p-5 text-rose-200 space-y-2">
          <div className="flex items-center space-x-2 text-rose-400 font-bold">
            <ShieldAlert className="h-5 w-5" />
            <span>Scope Rejection: Unauthorized Target Asset</span>
          </div>
          <p className="text-sm">
            This scan request was denied by the security engine because the candidate asset is out-of-scope
            or matches an active blacklist rule.
          </p>
          <div className="rounded border border-rose-900 bg-rose-950/80 p-3 font-mono text-xs text-rose-300">
            <strong>Reason: </strong> {scan.error || "Candidate asset is not in target authorized scope."}
          </div>
          <p className="text-xs text-rose-400/80">
            * This unauthorized execution attempt has been logged to the immutable audit trail with user identity and timestamp.
          </p>
        </div>
      )}

      {/* Metadata cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Command Executed</span>
          <pre className="text-xs font-mono text-cyan-400 mt-1.5 whitespace-pre-wrap break-all">
            {scan.command || "(No shell command recorded)"}
          </pre>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Timestamps</span>
          <div className="mt-1.5 space-y-1 text-xs font-mono text-slate-300">
            <p>Started: {scan.started_at ? new Date(scan.started_at).toLocaleString() : "Pending"}</p>
            <p>Finished: {scan.finished_at ? new Date(scan.finished_at).toLocaleString() : "In progress"}</p>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">Status & Error</span>
          <p className="text-xs text-slate-300 mt-1.5 font-medium">Status: {scan.status}</p>
          {scan.error && (
            <p className="text-xs text-rose-400 mt-1 break-words">
              {scan.error}
            </p>
          )}
        </div>
      </div>

      {/* Raw Output Block */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 flex items-center space-x-2">
            <Terminal className="h-4 w-4 text-cyan-400" />
            <span>Raw Tool Output</span>
          </h2>
          <span className="text-xs text-slate-500">Rendered safely as plain text</span>
        </div>
        <CodeBlock
          content={scan.raw_output}
          filename={`${scan.tool}-scan-${scan.id.slice(0, 8)}.txt`}
        />
      </div>
    </div>
  );
}
