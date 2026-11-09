import { AIResultFrame } from "./AIResultFrame";
import { SeverityBadge } from "../../findings/components/FindingBadges";
import type { AIAnalysisRead } from "../../../api/types";

interface ExplainFindingResultProps {
  analysis: AIAnalysisRead;
}

export function ExplainFindingResult({ analysis }: ExplainFindingResultProps) {
  const res = analysis.response_json || {};
  const explanation = (res.explanation as string) || "No detailed explanation generated.";
  const likelyImpact = (res.likely_impact as string) || "—";
  const exploitability = (res.exploitability_notes as string) || "—";
  const remediation = (res.remediation_steps as string) || "";
  const suggestedSev = (res.suggested_severity as string) || "";
  const references = (res.references as string[]) || [];

  return (
    <AIResultFrame analysis={analysis} title="AI Deep Explanation & Remediation">
      {/* Technical Mechanism */}
      <div className="space-y-1.5 bg-slate-900/60 p-4 rounded-md border border-slate-800">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Vulnerability Mechanism
          </h3>
          {suggestedSev && (
            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-slate-400">Advisory Severity:</span>
              <SeverityBadge severity={suggestedSev} isAdvisory />
            </div>
          )}
        </div>
        <p className="text-xs text-slate-200 whitespace-pre-wrap leading-relaxed font-sans mt-2">
          {explanation}
        </p>
      </div>

      {/* Impact and exploitability */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
        <div className="p-3.5 rounded-md bg-slate-900/40 border border-slate-800 space-y-1">
          <span className="text-[10px] uppercase font-semibold text-slate-400 block">
            Likely Impact
          </span>
          <p className="text-slate-200 whitespace-pre-wrap font-sans">{likelyImpact}</p>
        </div>

        <div className="p-3.5 rounded-md bg-slate-900/40 border border-slate-800 space-y-1">
          <span className="text-[10px] uppercase font-semibold text-slate-400 block">
            Exploitability & Prerequisites
          </span>
          <p className="text-slate-200 whitespace-pre-wrap font-sans">{exploitability}</p>
        </div>
      </div>

      {/* Remediation code / config steps */}
      {remediation && (
        <div className="space-y-1.5 bg-slate-900/60 p-4 rounded-md border border-slate-800">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Concrete Remediation Advice
          </h3>
          <p className="text-xs text-slate-200 whitespace-pre-wrap leading-relaxed font-sans">
            {remediation}
          </p>
        </div>
      )}

      {/* References */}
      {references.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] pt-1">
          <span className="text-slate-500 font-mono uppercase text-[10px]">Authoritative Standards:</span>
          {references.map((ref, idx) => (
            <span
              key={idx}
              className="font-mono text-[10px] bg-slate-950 text-slate-300 px-1.5 py-0.5 rounded border border-slate-800"
            >
              {ref}
            </span>
          ))}
        </div>
      )}
    </AIResultFrame>
  );
}
