import { History, ShieldCheck, CheckCircle2, XCircle, HelpCircle } from "lucide-react";
import type { VerificationRead } from "../../../api/types";

interface VerificationTimelineProps {
  verifications: VerificationRead[];
}

export function VerificationTimeline({ verifications }: VerificationTimelineProps) {
  // Ordered newest first
  const sorted = [...verifications].sort(
    (a, b) => new Date(b.verified_at).getTime() - new Date(a.verified_at).getTime()
  );

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <History className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          <h2 className="text-sm font-bold text-slate-100">Verification History</h2>
        </div>
        <span className="text-[11px] text-slate-400 font-medium">
          Append-only: decisions are never edited or deleted.
        </span>
      </div>

      {sorted.length === 0 ? (
        <p className="text-xs text-slate-400 py-3 italic">
          No verification decisions recorded yet. This finding is currently unverified.
        </p>
      ) : (
        <div className="space-y-4 pt-1">
          {sorted.map((item, idx) => {
            const isConfirmed = item.decision === "confirmed";
            const isFalsePos = item.decision === "false_positive";

            return (
              <div
                key={item.id || idx}
                className="relative pl-6 pb-2 border-l border-slate-800 last:border-l-transparent"
              >
                {/* Dot */}
                <div
                  className={`absolute -left-2 top-0.5 h-4 w-4 rounded-full flex items-center justify-center ${
                    isConfirmed
                      ? "bg-emerald-950 text-emerald-400 border border-emerald-600"
                      : isFalsePos
                      ? "bg-slate-800 text-slate-400 border border-slate-600"
                      : "bg-purple-950 text-purple-400 border border-purple-600"
                  }`}
                >
                  {isConfirmed ? (
                    <CheckCircle2 className="h-2.5 w-2.5" />
                  ) : isFalsePos ? (
                    <XCircle className="h-2.5 w-2.5" />
                  ) : (
                    <HelpCircle className="h-2.5 w-2.5" />
                  )}
                </div>

                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`text-xs font-semibold uppercase tracking-wider px-2 py-0.5 rounded border ${
                        isConfirmed
                          ? "bg-emerald-950/80 text-emerald-300 border-emerald-800"
                          : isFalsePos
                          ? "bg-slate-800/80 text-slate-300 border-slate-700"
                          : "bg-purple-950/80 text-purple-300 border-purple-800"
                      }`}
                    >
                      {item.decision.replace("_", " ")}
                    </span>
                    <span className="text-xs text-slate-400">
                      by Assessor <span className="font-mono text-slate-300">{item.assessor_id.slice(0, 8)}</span>
                    </span>
                    <span className="text-xs text-slate-400">
                      • {new Date(item.verified_at).toLocaleString()}
                    </span>
                  </div>

                  {item.evidence_reviewed && (
                    <div className="flex items-center gap-1 text-[11px] text-cyan-400 pt-0.5">
                      <ShieldCheck className="h-3 w-3" />
                      <span>Evidence reviewed</span>
                    </div>
                  )}

                  {item.notes ? (
                    <div className="mt-1.5 p-2 rounded bg-slate-950/70 border border-slate-800 text-xs text-slate-300 whitespace-pre-wrap font-sans">
                      {item.notes}
                    </div>
                  ) : (
                    <p className="text-[11px] text-slate-500 italic mt-0.5">No explanatory notes provided.</p>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
