import React, { useState } from "react";
import { CheckCircle2, XCircle, HelpCircle, AlertCircle, ShieldAlert } from "lucide-react";
import { Button } from "../../../components/Button";
import { ConfirmDialog } from "../../../components/Modal";
import { useToast } from "../../../components/Toast";
import { useVerifyFinding } from "../hooks";
import type { FindingRead, VerificationDecision } from "../../../api/types";
import { ApiError } from "../../../api/client";

interface VerificationFormProps {
  finding: FindingRead;
}

export function VerificationForm({ finding }: VerificationFormProps) {
  const { success } = useToast();
  const verifyMutation = useVerifyFinding(finding.id);

  const [decision, setDecision] = useState<VerificationDecision>("confirmed");
  const [notes, setNotes] = useState("");
  const [evidenceReviewed, setEvidenceReviewed] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const evidenceCount = finding.evidences?.length || 0;
  const isAlreadyVerified = finding.status !== "unverified";

  const cannotConfirmDueToEvidence = decision === "confirmed" && evidenceCount === 0;

  const validate = (): boolean => {
    setFieldError(null);
    if (decision === "confirmed") {
      if (!evidenceReviewed) {
        setFieldError("Confirmation requires explicit verification that you have reviewed the evidence.");
        return false;
      }
      if (evidenceCount === 0) {
        setFieldError("Cannot confirm finding without at least one supporting evidence item.");
        return false;
      }
    } else {
      if (!notes.trim() || notes.trim().length < 10) {
        setFieldError("Decision requires explanatory notes of at least 10 characters.");
        return false;
      }
    }
    return true;
  };

  const handlePreSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validate()) {
      setConfirmOpen(true);
    }
  };

  const handleConfirmedSubmit = async () => {
    try {
      await verifyMutation.mutateAsync({
        decision,
        notes: notes.trim() || null,
        evidence_reviewed: evidenceReviewed,
      });
      success(
        isAlreadyVerified
          ? "New verification decision recorded successfully."
          : `Finding status changed to ${decision.replace("_", " ")}.`
      );
      setNotes("");
      setEvidenceReviewed(false);
      setConfirmOpen(false);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setFieldError(err.message);
      } else {
        setFieldError("Failed to record verification decision.");
      }
      setConfirmOpen(false);
    }
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-base font-bold text-slate-100">
            {isAlreadyVerified ? "Record a New Decision (Re-open)" : "Verification Decision"}
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            {isAlreadyVerified
              ? "This finding is already verified. Recording a decision creates a new immutable entry in the audit history."
              : "Assessors must evaluate raw evidence before marking findings as confirmed."}
          </p>
        </div>
      </div>

      <form onSubmit={handlePreSubmit} className="space-y-4">
        {/* Decision Radio Group */}
        <fieldset className="space-y-2">
          <legend className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Assessor Decision
          </legend>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
            <label
              className={`flex items-start p-3 rounded-lg border cursor-pointer transition-colors ${
                decision === "confirmed"
                  ? "bg-emerald-950/40 border-emerald-600/80 text-emerald-200"
                  : "bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700"
              }`}
            >
              <input
                type="radio"
                name="decision"
                value="confirmed"
                checked={decision === "confirmed"}
                onChange={() => {
                  setDecision("confirmed");
                  setFieldError(null);
                }}
                className="mt-0.5 mr-2.5 text-emerald-500 focus:ring-emerald-500"
              />
              <div>
                <div className="flex items-center gap-1.5 font-semibold text-xs text-slate-200">
                  <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                  <span>Confirmed</span>
                </div>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Verified security vulnerability with real evidence.
                </span>
              </div>
            </label>

            <label
              className={`flex items-start p-3 rounded-lg border cursor-pointer transition-colors ${
                decision === "false_positive"
                  ? "bg-slate-800/80 border-slate-600 text-slate-200"
                  : "bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700"
              }`}
            >
              <input
                type="radio"
                name="decision"
                value="false_positive"
                checked={decision === "false_positive"}
                onChange={() => {
                  setDecision("false_positive");
                  setFieldError(null);
                }}
                className="mt-0.5 mr-2.5 text-slate-400 focus:ring-slate-400"
              />
              <div>
                <div className="flex items-center gap-1.5 font-semibold text-xs text-slate-200">
                  <XCircle className="h-3.5 w-3.5 text-slate-400" />
                  <span>False Positive</span>
                </div>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Scanner artifact or intentional security control.
                </span>
              </div>
            </label>

            <label
              className={`flex items-start p-3 rounded-lg border cursor-pointer transition-colors ${
                decision === "needs_testing"
                  ? "bg-purple-950/40 border-purple-600/80 text-purple-200"
                  : "bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700"
              }`}
            >
              <input
                type="radio"
                name="decision"
                value="needs_testing"
                checked={decision === "needs_testing"}
                onChange={() => {
                  setDecision("needs_testing");
                  setFieldError(null);
                }}
                className="mt-0.5 mr-2.5 text-purple-500 focus:ring-purple-500"
              />
              <div>
                <div className="flex items-center gap-1.5 font-semibold text-xs text-slate-200">
                  <HelpCircle className="h-3.5 w-3.5 text-purple-400" />
                  <span>Needs More Testing</span>
                </div>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Requires active manual probing or additional context.
                </span>
              </div>
            </label>
          </div>
        </fieldset>

        {/* Cannot Confirm Warning */}
        {cannotConfirmDueToEvidence && (
          <div
            role="alert"
            className="p-3 rounded bg-amber-950/30 border border-amber-800/60 text-xs text-amber-300 flex items-start gap-2"
          >
            <ShieldAlert className="h-4 w-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <p className="font-semibold">Confirmation Disabled: No Evidence Attached</p>
              <p className="text-[11px] text-amber-200/90 mt-0.5">
                The platform requires at least one attached evidence item before an assessor can confirm a finding. Please upload a screenshot, terminal log, or add an assessor note in the Evidence section below.
              </p>
            </div>
          </div>
        )}

        {/* Notes input */}
        <div>
          <label htmlFor="verification-notes" className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Verification Notes {decision !== "confirmed" ? "(Required, min 10 chars)" : "(Optional)"}
          </label>
          <textarea
            id="verification-notes"
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder={
              decision === "confirmed"
                ? "Optional technical notes regarding reproduction steps..."
                : "Required technical justification explaining why this is a false positive or needs more testing..."
            }
            className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        {/* Evidence reviewed checkbox */}
        <div className="flex items-start gap-2.5 pt-1">
          <input
            id="evidence-reviewed"
            type="checkbox"
            checked={evidenceReviewed}
            onChange={(e) => {
              setEvidenceReviewed(e.target.checked);
              setFieldError(null);
            }}
            className="mt-0.5 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500"
          />
          <label htmlFor="evidence-reviewed" className="text-xs text-slate-300 cursor-pointer">
            <span className="font-semibold text-slate-200">I have reviewed the supporting evidence.</span>
            <span className="block text-[11px] text-slate-400">
              Required for Confirmed status. Confirms you inspected the HTTP response, screenshot, or scan output.
            </span>
          </label>
        </div>

        {/* Field error banner */}
        {fieldError && (
          <div role="alert" className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{fieldError}</span>
          </div>
        )}

        <div className="pt-2 flex justify-end">
          <Button
            type="submit"
            variant="primary"
            disabled={verifyMutation.isPending || (decision === "confirmed" && (!evidenceReviewed || evidenceCount === 0))}
            isLoading={verifyMutation.isPending}
          >
            {isAlreadyVerified ? "Record New Decision" : "Submit Verification"}
          </Button>
        </div>
      </form>

      {/* Confirmation Dialog */}
      <ConfirmDialog
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleConfirmedSubmit}
        title="Confirm Verification Decision"
        itemName={`${finding.title} (${decision.toUpperCase()})`}
        description={`You are recording the decision "${decision.replace("_", " ")}" for this finding. This will be recorded permanently in the verification history.`}
        confirmText="Confirm Decision"
        isDangerous={decision !== "confirmed"}
        isLoading={verifyMutation.isPending}
      />
    </div>
  );
}
