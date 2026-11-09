import React, { useState } from "react";
import { AlertCircle, Sliders } from "lucide-react";
import { Button } from "../../../components/Button";
import { Select } from "../../../components/Select";
import { Input } from "../../../components/Input";
import { ConfirmDialog } from "../../../components/Modal";
import { useToast } from "../../../components/Toast";
import { useUpdateFindingSeverity } from "../hooks";
import type { FindingRead, FindingSeverity } from "../../../api/types";
import { ApiError } from "../../../api/client";
import { SeverityBadge } from "./FindingBadges";

interface SeverityOverrideFormProps {
  finding: FindingRead;
}

export function SeverityOverrideForm({ finding }: SeverityOverrideFormProps) {
  const { success } = useToast();
  const updateSeverityMutation = useUpdateFindingSeverity(finding.id);

  const [severity, setSeverity] = useState<FindingSeverity>(finding.effective_severity);
  const [justification, setJustification] = useState(finding.severity_justification || "");
  const [cvssScore, setCvssScore] = useState<string>(
    finding.cvss_score !== null && finding.cvss_score !== undefined ? String(finding.cvss_score) : ""
  );
  const [cvssVector, setCvssVector] = useState<string>(finding.cvss_vector || "");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const validate = (): boolean => {
    setErrorMsg(null);
    if (!justification.trim() || justification.trim().length < 10) {
      setErrorMsg("Justification is required and must be at least 10 characters long.");
      return false;
    }

    if (cvssScore !== "") {
      const num = parseFloat(cvssScore);
      if (isNaN(num) || num < 0.0 || num > 10.0) {
        setErrorMsg("CVSS score must be a number between 0.0 and 10.0.");
        return false;
      }
    }

    if (cvssVector.trim() && !cvssVector.startsWith("CVSS:3.1/") && !cvssVector.startsWith("CVSS:3.0/")) {
      setErrorMsg("CVSS vector must start with CVSS:3.1/ or CVSS:3.0/");
      return false;
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
      await updateSeverityMutation.mutateAsync({
        severity,
        justification: justification.trim(),
        cvss_score: cvssScore !== "" ? parseFloat(cvssScore) : null,
        cvss_vector: cvssVector.trim() || null,
      });
      success("Finding severity updated successfully.");
      setConfirmOpen(false);
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setErrorMsg(err.message);
      } else {
        setErrorMsg("Failed to update finding severity.");
      }
      setConfirmOpen(false);
    }
  };

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Sliders className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          <h2 className="text-sm font-bold text-slate-100">Adjust Severity & CVSS</h2>
        </div>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400">Original:</span>
          <SeverityBadge severity={finding.original_severity} />
          <span className="text-slate-400 ml-1">Current Effective:</span>
          <SeverityBadge severity={finding.effective_severity} />
        </div>
      </div>

      <form onSubmit={handlePreSubmit} className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Select
            label="New Effective Severity"
            value={severity}
            onChange={(e) => setSeverity(e.target.value as FindingSeverity)}
            options={[
              { label: "Critical", value: "critical" },
              { label: "High", value: "high" },
              { label: "Medium", value: "medium" },
              { label: "Low", value: "low" },
              { label: "Info", value: "info" },
            ]}
          />

          <Input
            label="CVSS Score (0.0 - 10.0)"
            type="number"
            step="0.1"
            min="0.0"
            max="10.0"
            value={cvssScore}
            onChange={(e) => setCvssScore(e.target.value)}
            placeholder="e.g. 7.5"
          />

          <Input
            label="CVSS v3.1 Vector"
            value={cvssVector}
            onChange={(e) => setCvssVector(e.target.value)}
            placeholder="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
          />
        </div>

        <div>
          <label htmlFor="severity-justification" className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">
            Justification (Required, min 10 chars)
          </label>
          <textarea
            id="severity-justification"
            rows={2}
            value={justification}
            onChange={(e) => setJustification(e.target.value)}
            placeholder="Explain context (e.g. Compensating network controls or internal-only deployment)..."
            className="w-full rounded-md border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        {errorMsg && (
          <div role="alert" className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        <div className="flex justify-end pt-1">
          <Button
            type="submit"
            variant="outline"
            disabled={updateSeverityMutation.isPending}
            isLoading={updateSeverityMutation.isPending}
          >
            Apply Severity Override
          </Button>
        </div>
      </form>

      <ConfirmDialog
        isOpen={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={handleConfirmedSubmit}
        title="Confirm Severity Override"
        itemName={`Severity: ${severity.toUpperCase()}`}
        description="Are you sure you want to change the effective severity? This is recorded in the severity history."
        confirmText="Confirm Override"
        isDangerous={false}
        isLoading={updateSeverityMutation.isPending}
      />
    </div>
  );
}
