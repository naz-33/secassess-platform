import { Link } from "react-router-dom";
import { ExternalLink, ShieldCheck } from "lucide-react";
import type { FindingRead } from "../../../api/types";
import { SeverityBadge, StatusBadge, SourceBadge } from "./FindingBadges";

interface FindingsTableProps {
  findings: FindingRead[];
  assessmentId?: string;
  showAssessmentColumn?: boolean;
}

export function FindingsTable({ findings, assessmentId, showAssessmentColumn = false }: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-slate-800 bg-slate-900/40 p-12 text-center">
        <ShieldCheck className="h-10 w-10 text-slate-500 mx-auto mb-3" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-slate-200">No findings found</h3>
        <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
          No vulnerabilities match the selected filters or have been discovered yet.
        </p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/60">
      <table className="w-full text-left border-collapse text-xs">
        <thead>
          <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold">
            <th scope="col" className="py-3 px-4">Title & Category</th>
            {showAssessmentColumn && <th scope="col" className="py-3 px-4">Assessment</th>}
            <th scope="col" className="py-3 px-4">Effective Severity</th>
            <th scope="col" className="py-3 px-4">Status</th>
            <th scope="col" className="py-3 px-4">Source</th>
            <th scope="col" className="py-3 px-4">Affected Asset / URL</th>
            <th scope="col" className="py-3 px-4">Created</th>
            <th scope="col" className="py-3 px-4 text-right">Action</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800/60 text-slate-300">
          {findings.map((f) => {
            const effectiveAid = assessmentId || f.assessment_id;
            const targetUrl = `/assessments/${effectiveAid}/findings/${f.id}`;
            return (
              <tr key={f.id} className="hover:bg-slate-800/40 transition-colors">
                <td className="py-3 px-4 max-w-xs">
                  <Link
                    to={targetUrl}
                    className="font-semibold text-slate-100 hover:text-cyan-400 transition-colors line-clamp-1 block text-sm"
                  >
                    {f.title}
                  </Link>
                  <span className="text-[11px] text-slate-400 font-mono mt-0.5 block">{f.category}</span>
                </td>
                {showAssessmentColumn && (
                  <td className="py-3 px-4 whitespace-nowrap">
                    <Link
                      to={`/assessments/${f.assessment_id}`}
                      className="text-cyan-400 hover:underline font-medium block truncate max-w-[150px]"
                      title={(f as any).assessment_name || f.assessment_id}
                    >
                      {(f as any).assessment_name || "Assessment"}
                    </Link>
                  </td>
                )}
                <td className="py-3 px-4 whitespace-nowrap">
                  <SeverityBadge severity={f.effective_severity} />
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  <StatusBadge status={f.status} />
                </td>
                <td className="py-3 px-4 whitespace-nowrap">
                  <SourceBadge source={f.source} />
                </td>
                <td className="py-3 px-4 max-w-[200px] truncate font-mono text-slate-400" title={f.affected_url || "N/A"}>
                  {f.affected_url || "—"}
                </td>
                <td className="py-3 px-4 whitespace-nowrap text-slate-400">
                  {new Date(f.created_at).toLocaleDateString()}
                </td>
                <td className="py-3 px-4 text-right whitespace-nowrap">
                  <Link
                    to={targetUrl}
                    className="inline-flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium hover:underline text-xs"
                  >
                    <span>Review</span>
                    <ExternalLink className="h-3 w-3" aria-hidden="true" />
                  </Link>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
