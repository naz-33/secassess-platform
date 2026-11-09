import { GitCommit } from "lucide-react";
import type { SeverityChangeRead } from "../../../api/types";
import { SeverityBadge } from "./FindingBadges";

interface SeverityHistoryTableProps {
  history: SeverityChangeRead[];
}

export function SeverityHistoryTable({ history }: SeverityHistoryTableProps) {
  // Chronological order: newest first
  const sorted = [...history].sort(
    (a, b) => new Date(b.changed_at).getTime() - new Date(a.changed_at).getTime()
  );

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <GitCommit className="h-4 w-4 text-cyan-400" aria-hidden="true" />
          <h2 className="text-sm font-bold text-slate-100">Severity Override History</h2>
        </div>
        <span className="text-[11px] text-slate-400 font-medium">
          Chronological record of manual severity adjustments
        </span>
      </div>

      {sorted.length === 0 ? (
        <p className="text-xs text-slate-400 py-3 italic">
          No manual severity overrides recorded. Effective severity matches original finding severity.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase tracking-wider font-semibold">
                <th scope="col" className="py-2.5 px-3">Timestamp</th>
                <th scope="col" className="py-2.5 px-3">Assessor</th>
                <th scope="col" className="py-2.5 px-3">Transition</th>
                <th scope="col" className="py-2.5 px-3">CVSS Change</th>
                <th scope="col" className="py-2.5 px-3">Justification</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {sorted.map((row) => (
                <tr key={row.id} className="hover:bg-slate-800/30">
                  <td className="py-2.5 px-3 whitespace-nowrap text-slate-400">
                    {new Date(row.changed_at).toLocaleString()}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap font-mono text-slate-300">
                    {row.changed_by ? row.changed_by.slice(0, 8) : "System"}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <div className="flex items-center gap-1.5">
                      <SeverityBadge severity={row.old_severity} />
                      <span className="text-slate-500">→</span>
                      <SeverityBadge severity={row.new_severity} />
                    </div>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap font-mono text-slate-300">
                    {row.old_cvss !== null || row.new_cvss !== null
                      ? `${row.old_cvss ?? "—"} → ${row.new_cvss ?? "—"}`
                      : "—"}
                  </td>
                  <td className="py-2.5 px-3 max-w-sm whitespace-pre-wrap font-sans text-slate-300">
                    {row.justification}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
