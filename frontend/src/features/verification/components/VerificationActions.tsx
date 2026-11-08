import React, { useState } from "react";
import { Button } from "@/shared/components";

export const VerificationActions: React.FC = () => {
  const [notes, setNotes] = useState("");

  const handleDecision = (decision: string) => {
    alert(`Assessor decision recorded: ${decision}. Notes: ${notes}`);
  };

  return (
    <div className="space-y-3">
      <div>
        <label className="block text-xs font-semibold uppercase tracking-wider text-slate-600 mb-1">
          Assessor Review Notes
        </label>
        <textarea
          rows={3}
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="State verification findings, manual curl reproduction steps, or false-positive rationale..."
          className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-sky-500"
        />
      </div>
      <div className="flex gap-2">
        <Button size="sm" variant="primary" onClick={() => handleDecision("confirmed")}>
          Confirm Finding
        </Button>
        <Button size="sm" variant="danger" onClick={() => handleDecision("false_positive")}>
          Mark False Positive
        </Button>
        <Button size="sm" variant="secondary" onClick={() => handleDecision("needs_testing")}>
          Flag Needs Testing
        </Button>
      </div>
    </div>
  );
};
