import { useState } from "react";
import { Check, X, AlertCircle } from "lucide-react";
import { Button } from "../../../components/Button";
import { AIResultFrame } from "./AIResultFrame";
import { useReviewAnalysis } from "../hooks";
import { useToast } from "../../../components/Toast";
import { RequireRole } from "../../../auth/RequireRole";
import { ApiError } from "../../../api/client";
import type { AIAnalysisRead, AIReviewStatus } from "../../../api/types";

interface ExecutiveSummaryResultProps {
  analysis: AIAnalysisRead;
}

export function ExecutiveSummaryResult({ analysis }: ExecutiveSummaryResultProps) {
  const { success } = useToast();
  const reviewMutation = useReviewAnalysis(analysis.id);

  const res = analysis.response_json || {};
  const originalSummary = (res.executive_summary as string) || "No summary text generated.";
  const scopeMethod = (res.scope_and_method as string) || "";
  const keyRisks = (res.key_risks as string) || "";
  const nextSteps = (res.recommended_next_steps as string) || "";

  const [activeTab, setActiveTab] = useState<"original" | "edited">("original");
  const [editedText, setEditedText] = useState(analysis.edited_text || originalSummary);
  const [reviewNotes, setReviewNotes] = useState(analysis.review_notes || "");
  const [reviewError, setReviewError] = useState<string | null>(null);

  const reviewStatus: AIReviewStatus = analysis.review_status || "not_reviewed";

  const handleReview = async (decision: "approved" | "rejected") => {
    try {
      setReviewError(null);
      await reviewMutation.mutateAsync({
        review_status: decision,
        edited_text: decision === "approved" ? editedText : null,
        notes: reviewNotes.trim() || null,
      });
      success(
        decision === "approved"
          ? "Executive summary approved for report inclusion."
          : "Executive summary draft marked as rejected."
      );
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setReviewError(err.message);
      } else {
        setReviewError("Failed to update summary review status.");
      }
    }
  };

  return (
    <AIResultFrame analysis={analysis} title="AI Executive Summary Draft">
      {/* Review Status & Gate Notice */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-md bg-slate-900/80 border border-slate-800">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-300">Review Status:</span>
          <span
            className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${
              reviewStatus === "approved"
                ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                : reviewStatus === "rejected"
                ? "bg-rose-950 text-rose-300 border-rose-800"
                : "bg-amber-950 text-amber-300 border-amber-800"
            }`}
          >
            {reviewStatus.replace("_", " ")}
          </span>
          <span className="text-[11px] text-slate-400">
            • Note: Only approved executive summaries will appear in final report generation.
          </span>
        </div>
      </div>

      {reviewError && (
        <div role="alert" className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 shrink-0" />
          <span>{reviewError}</span>
        </div>
      )}

      {/* Side-by-Side / Tabbed Original vs Edited View */}
      <div className="space-y-3">
        <div className="flex border-b border-slate-800 text-xs font-semibold">
          <button
            type="button"
            onClick={() => setActiveTab("original")}
            className={`py-2 px-4 border-b-2 transition-colors ${
              activeTab === "original"
                ? "border-purple-400 text-purple-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Original AI Draft (Preserved)
          </button>
          <button
            type="button"
            onClick={() => setActiveTab("edited")}
            className={`py-2 px-4 border-b-2 transition-colors ${
              activeTab === "edited"
                ? "border-cyan-400 text-cyan-300"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Assessor Edited Version
          </button>
        </div>

        {activeTab === "original" ? (
          <div className="p-4 rounded-md bg-slate-900/60 border border-slate-800 space-y-3 text-xs">
            <div>
              <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
                Executive Narrative
              </span>
              <p className="text-slate-200 whitespace-pre-wrap leading-relaxed font-sans">
                {originalSummary}
              </p>
            </div>
            {scopeMethod && (
              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
                  Scope & Methodology
                </span>
                <p className="text-slate-300 whitespace-pre-wrap font-sans">{scopeMethod}</p>
              </div>
            )}
            {keyRisks && (
              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
                  Key Identified Risks
                </span>
                <p className="text-slate-300 whitespace-pre-wrap font-sans">{keyRisks}</p>
              </div>
            )}
            {nextSteps && (
              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-1">
                  Recommended Next Steps
                </span>
                <p className="text-slate-300 whitespace-pre-wrap font-sans">{nextSteps}</p>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            <textarea
              rows={8}
              value={editedText}
              onChange={(e) => setEditedText(e.target.value)}
              placeholder="Refine and edit executive summary narrative..."
              className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 font-sans leading-relaxed"
            />
            <p className="text-[11px] text-slate-500">
              The original AI generated draft remains immutable in the audit log.
            </p>
          </div>
        )}
      </div>

      {/* Assessor Review Form Controls */}
      <RequireRole roles={["admin", "assessor"]}>
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
          <label htmlFor="summary-review-notes" className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
            Assessor Review Rationale / Notes (Optional)
          </label>
          <textarea
            id="summary-review-notes"
            rows={2}
            value={reviewNotes}
            onChange={(e) => setReviewNotes(e.target.value)}
            placeholder="Document auditor sign-off or grounds for rejection..."
            className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />

          <div className="flex flex-wrap items-center justify-end gap-2.5 pt-1">
            <Button
              type="button"
              variant="danger"
              size="sm"
              onClick={() => handleReview("rejected")}
              disabled={reviewMutation.isPending}
              isLoading={reviewMutation.isPending}
            >
              <X className="h-3.5 w-3.5 mr-1" />
              <span>Reject Draft</span>
            </Button>
            <Button
              type="button"
              variant="primary"
              size="sm"
              onClick={() => handleReview("approved")}
              disabled={reviewMutation.isPending}
              isLoading={reviewMutation.isPending}
            >
              <Check className="h-3.5 w-3.5 mr-1" />
              <span>{activeTab === "edited" ? "Save Edits & Approve" : "Approve Summary"}</span>
            </Button>
          </div>
        </div>
      </RequireRole>
    </AIResultFrame>
  );
}
