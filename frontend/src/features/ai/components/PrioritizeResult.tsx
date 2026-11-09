import { Link } from "react-router-dom";
import { ListOrdered } from "lucide-react";
import { AIResultFrame } from "./AIResultFrame";
import { SeverityBadge } from "../../findings/components/FindingBadges";
import type { AIAnalysisRead } from "../../../api/types";

interface PrioritizeResultProps {
  analysis: AIAnalysisRead;
  assessmentId: string;
}

export function PrioritizeResult({ analysis, assessmentId }: PrioritizeResultProps) {
  const res = analysis.response_json || {};
  const narrative = (res.overall_risk_narrative as string) || "No risk narrative generated.";
  const prioritized = (res.prioritized_findings as Array<{
    rank: number;
    finding_id: string;
    rationale: string;
    likely_impact: string;
    exploitability_notes: string;
    suggested_severity: string;
    remediation_steps?: string;
    references?: string[];
  }>) || [];

  return (
    <AIResultFrame analysis={analysis} title="AI Risk Prioritization">
      {/* Overall Strategic Risk Narrative */}
      <div className="space-y-1.5 bg-slate-900/60 p-4 rounded-md border border-slate-800">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Executive Risk Narrative
        </h3>
        <p className="text-xs text-slate-200 whitespace-pre-wrap leading-relaxed font-sans">
          {narrative}
        </p>
      </div>

      {/* Prioritized Findings List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <ListOrdered className="h-4 w-4 text-purple-400" />
            <span>Remediation Priority Sequence ({prioritized.length})</span>
          </h3>
          <span className="text-[10px] text-amber-400 font-medium">
            AI suggested severity is advisory only and never applied automatically.
          </span>
        </div>

        {prioritized.length === 0 ? (
          <p className="text-xs text-slate-400 italic py-2">No findings prioritized.</p>
        ) : (
          <div className="space-y-3">
            {prioritized.map((item) => (
              <div
                key={item.finding_id || item.rank}
                className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2.5"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-2">
                  <div className="flex items-center gap-2">
                    <span className="flex h-6 w-6 items-center justify-center rounded-full bg-purple-900/60 border border-purple-700/80 text-xs font-bold text-purple-200">
                      #{item.rank}
                    </span>
                    <Link
                      to={`/assessments/${assessmentId}/findings/${item.finding_id}`}
                      className="font-mono text-cyan-400 hover:text-cyan-300 hover:underline text-xs font-semibold"
                    >
                      Finding ID: {item.finding_id.slice(0, 8)}...
                    </Link>
                  </div>

                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-slate-400">AI Suggested:</span>
                    <SeverityBadge severity={item.suggested_severity} isAdvisory />
                  </div>
                </div>

                <div className="space-y-1.5 text-xs">
                  <div>
                    <span className="text-slate-400 font-semibold">Priority Rationale: </span>
                    <span className="text-slate-200">{item.rationale}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 font-semibold">Likely Impact: </span>
                    <span className="text-slate-300">{item.likely_impact}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 font-semibold">Exploitability Notes: </span>
                    <span className="text-slate-300">{item.exploitability_notes}</span>
                  </div>
                </div>

                {item.remediation_steps && (
                  <div className="p-2.5 rounded bg-slate-950/70 border border-slate-800 text-xs text-slate-300">
                    <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-0.5">
                      Remediation Sequence:
                    </span>
                    <p className="whitespace-pre-wrap font-sans">{item.remediation_steps}</p>
                  </div>
                )}

                {item.references && item.references.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 text-[11px] pt-1">
                    <span className="text-slate-500 font-mono uppercase text-[10px]">References:</span>
                    {item.references.map((ref, idx) => (
                      <span
                        key={idx}
                        className="font-mono text-[10px] bg-slate-950 text-slate-300 px-1.5 py-0.5 rounded border border-slate-800"
                      >
                        {ref}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </AIResultFrame>
  );
}
