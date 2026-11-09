import { AlertTriangle, CheckCircle, ShieldCheck } from "lucide-react";
import type { FindingsSummary } from "../../../api/types";

interface FindingsSummaryStripProps {
  summary?: FindingsSummary;
  isLoading?: boolean;
}

export function FindingsSummaryStrip({ summary, isLoading }: FindingsSummaryStripProps) {
  if (isLoading || !summary) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 animate-pulse">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-20 bg-slate-900/60 rounded-lg border border-slate-800" />
        ))}
      </div>
    );
  }

  const total = summary.total || 0;
  const verifiedCount = summary.verified_count || 0;
  const unverifiedCount = summary.unverified_count || 0;
  const confirmedCount = summary.by_status?.confirmed || 0;
  const percent = total > 0 ? Math.round((verifiedCount / total) * 100) : 100;

  const confirmedBySev = summary.confirmed_by_effective_severity || {};
  const critical = confirmedBySev.critical || 0;
  const high = confirmedBySev.high || 0;
  const medium = confirmedBySev.medium || 0;
  const low = confirmedBySev.low || 0;
  const info = confirmedBySev.info || 0;

  return (
    <div className="space-y-3">
      {unverifiedCount > 0 && (
        <div
          role="alert"
          className="flex items-center gap-2.5 px-4 py-3 rounded-lg bg-amber-950/40 border border-amber-800/60 text-amber-200 text-xs font-medium"
        >
          <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" aria-hidden="true" />
          <span>
            <strong>{unverifiedCount}</strong> finding{unverifiedCount === 1 ? "" : "s"} have not been verified. They are not confirmed vulnerabilities.
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Verification Progress */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-semibold uppercase tracking-wider">Verification Progress</span>
            <ShieldCheck className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          </div>
          <div className="mt-2">
            <div className="flex items-baseline justify-between mb-1.5">
              <span className="text-xl font-bold text-slate-100">{verifiedCount} of {total} verified</span>
              <span className="text-xs font-mono text-cyan-400 font-semibold">{percent}%</span>
            </div>
            <div
              className="w-full bg-slate-800 rounded-full h-2 overflow-hidden"
              role="progressbar"
              aria-valuenow={percent}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Verification progress"
            >
              <div
                className="bg-cyan-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${percent}%` }}
              />
            </div>
          </div>
        </div>

        {/* Status Breakdown */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-semibold uppercase tracking-wider">Status Breakdown</span>
            <CheckCircle className="h-4 w-4 text-emerald-400" aria-hidden="true" />
          </div>
          <div className="mt-2 grid grid-cols-3 gap-1 text-center">
            <div className="bg-slate-950/60 p-1.5 rounded border border-slate-800/80">
              <span className="text-[10px] uppercase text-emerald-400 block font-medium">Confirmed</span>
              <span className="text-base font-bold text-slate-100">{confirmedCount}</span>
            </div>
            <div className="bg-slate-950/60 p-1.5 rounded border border-slate-800/80">
              <span className="text-[10px] uppercase text-amber-400 block font-medium">Unverified</span>
              <span className="text-base font-bold text-slate-100">{unverifiedCount}</span>
            </div>
            <div className="bg-slate-950/60 p-1.5 rounded border border-slate-800/80">
              <span className="text-[10px] uppercase text-slate-400 block font-medium">False Pos</span>
              <span className="text-base font-bold text-slate-100">
                {(summary.by_status?.false_positive || 0)}
              </span>
            </div>
          </div>
        </div>

        {/* Confirmed Severities */}
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3.5 lg:col-span-2 flex flex-col justify-between">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span className="font-semibold uppercase tracking-wider">Confirmed by Effective Severity</span>
            <span className="text-[11px] text-slate-400 font-medium">Total Confirmed: {confirmedCount}</span>
          </div>
          <div className="mt-2 grid grid-cols-5 gap-1.5 text-center">
            <div className="bg-rose-950/40 p-1.5 rounded border border-rose-900/60">
              <span className="text-[10px] uppercase text-rose-300 font-bold block">Crit</span>
              <span className="text-base font-bold text-rose-200">{critical}</span>
            </div>
            <div className="bg-orange-950/40 p-1.5 rounded border border-orange-900/60">
              <span className="text-[10px] uppercase text-orange-300 font-bold block">High</span>
              <span className="text-base font-bold text-orange-200">{high}</span>
            </div>
            <div className="bg-amber-950/40 p-1.5 rounded border border-amber-900/60">
              <span className="text-[10px] uppercase text-amber-300 font-bold block">Med</span>
              <span className="text-base font-bold text-amber-200">{medium}</span>
            </div>
            <div className="bg-blue-950/40 p-1.5 rounded border border-blue-900/60">
              <span className="text-[10px] uppercase text-blue-300 font-bold block">Low</span>
              <span className="text-base font-bold text-blue-200">{low}</span>
            </div>
            <div className="bg-slate-800/40 p-1.5 rounded border border-slate-700/60">
              <span className="text-[10px] uppercase text-slate-300 font-bold block">Info</span>
              <span className="text-base font-bold text-slate-200">{info}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
