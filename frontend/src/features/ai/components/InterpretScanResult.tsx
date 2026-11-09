import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowUpRight, CheckCircle2, AlertCircle } from "lucide-react";
import { Button } from "../../../components/Button";
import { AIResultFrame } from "./AIResultFrame";
import { SeverityBadge } from "../../findings/components/FindingBadges";
import { usePromoteSuggestion } from "../hooks";
import { useToast } from "../../../components/Toast";
import { RequireRole } from "../../../auth/RequireRole";
import { ApiError } from "../../../api/client";
import type { AIAnalysisRead } from "../../../api/types";

interface InterpretScanResultProps {
  analysis: AIAnalysisRead;
  assessmentId: string;
}

export function InterpretScanResult({ analysis, assessmentId }: InterpretScanResultProps) {
  const { success } = useToast();
  const promoteMutation = usePromoteSuggestion(analysis.id);

  const [promotedMap, setPromotedMap] = useState<Record<number, string>>({});
  const [promotingIndex, setPromotingIndex] = useState<number | null>(null);
  const [promoteError, setPromoteError] = useState<string | null>(null);

  const res = analysis.response_json || {};
  const summary = (res.summary as string) || "No summary provided.";
  const keyObservations = (res.key_observations as Array<{
    observation: string;
    why_it_matters: string;
    evidence_ids?: string[];
  }>) || [];
  const candidateFindings = (res.suggested_candidate_findings as Array<{
    title: string;
    category: string;
    description: string;
    explanation?: string;
    evidence_excerpt?: string;
    suggested_severity: string;
    confidence: string;
    evidence_ids?: string[];
    wstg_id?: string;
    remediation?: string;
    recommended_fix?: string;
  }>) || [];

  const handlePromote = async (index: number) => {
    try {
      setPromoteError(null);
      setPromotingIndex(index);
      const newFinding = await promoteMutation.mutateAsync({
        suggestion_index: index,
      });
      setPromotedMap((prev) => ({ ...prev, [index]: newFinding.id }));
      success("Candidate suggestion promoted to unverified finding.");
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setPromoteError(err.message);
      } else {
        setPromoteError("Failed to promote suggestion.");
      }
    } finally {
      setPromotingIndex(null);
    }
  };

  return (
    <AIResultFrame analysis={analysis} title="AI Scan Interpretation">
      {/* Plain text summary */}
      <div className="space-y-1.5 bg-slate-900/60 p-4 rounded-md border border-slate-800">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Technical Summary
        </h3>
        <p className="text-xs text-slate-200 whitespace-pre-wrap leading-relaxed font-sans">
          {summary}
        </p>
      </div>

      {/* Key Observations with cited evidence links */}
      {keyObservations.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Key Observations ({keyObservations.length})
          </h3>
          <div className="space-y-2">
            {keyObservations.map((obs, i) => (
              <div key={i} className="p-3 rounded-md bg-slate-900/40 border border-slate-800 text-xs space-y-1">
                <p className="font-semibold text-slate-100">{obs.observation}</p>
                <p className="text-slate-400 text-[11px]">{obs.why_it_matters}</p>
                {obs.evidence_ids && obs.evidence_ids.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[10px] text-slate-500 uppercase font-mono">Cited Evidence:</span>
                    {obs.evidence_ids.map((eid) => (
                      <a
                        key={eid}
                        href={`#evidence-${eid}`}
                        className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 hover:underline bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800"
                      >
                        {eid.slice(0, 8)}
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Suggested Candidate Findings */}
      <div className="space-y-2.5 pt-2">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Suggested Candidate Findings ({candidateFindings.length})
          </h3>
          <span className="text-[10px] text-slate-500">
            Promotion creates an unverified finding requiring assessor confirmation.
          </span>
        </div>

        {promoteError && (
          <div role="alert" className="p-2.5 rounded bg-rose-950/50 border border-rose-800 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0" />
            <span>{promoteError}</span>
          </div>
        )}

        {candidateFindings.length === 0 ? (
          <p className="text-xs text-slate-400 italic py-2">No candidate findings suggested by AI.</p>
        ) : (
          <div className="space-y-3">
            {candidateFindings.map((cf, idx) => {
              const promotedFindingId = promotedMap[idx];

              return (
                <div
                  key={idx}
                  className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3"
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-xs text-slate-100">{cf.title}</span>
                        <SeverityBadge severity={cf.suggested_severity} isAdvisory />
                      </div>
                      <span className="text-[11px] text-slate-400 font-mono mt-0.5 block">
                        Category: {cf.category} {cf.wstg_id && `• WSTG: ${cf.wstg_id}`}
                      </span>
                      <span className="text-[10px] text-slate-500 mt-1 block">
                        Candidate confidence: {cf.confidence}
                      </span>
                    </div>

                    <RequireRole roles={["admin", "assessor"]}>
                      {promotedFindingId ? (
                        <div className="flex items-center gap-1.5 text-xs text-emerald-400 font-medium">
                          <CheckCircle2 className="h-4 w-4 shrink-0" />
                          <span>Created as unverified finding:</span>
                          <Link
                            to={`/assessments/${assessmentId}/findings/${promotedFindingId}`}
                            className="font-mono underline text-cyan-400 hover:text-cyan-300 ml-1"
                          >
                            View Finding
                          </Link>
                        </div>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => handlePromote(idx)}
                          disabled={promoteMutation.isPending && promotingIndex === idx}
                          isLoading={promoteMutation.isPending && promotingIndex === idx}
                          className="text-xs h-7 gap-1"
                        >
                          <ArrowUpRight className="h-3 w-3 mr-1" />
                          <span>Promote to Finding</span>
                        </Button>
                      )}
                    </RequireRole>
                  </div>

                  <p className="text-xs text-slate-300 whitespace-pre-wrap font-sans">
                    {cf.explanation || cf.description}
                  </p>

                  {cf.evidence_excerpt && (
                    <blockquote className="border-l-2 border-cyan-700 pl-3 text-xs text-cyan-200/90 whitespace-pre-wrap font-mono">
                      Evidence excerpt: {cf.evidence_excerpt}
                    </blockquote>
                  )}

                  {(cf.recommended_fix || cf.remediation) && (
                    <div className="p-2 rounded bg-slate-950/70 border border-slate-800 text-xs text-slate-300">
                      <span className="text-[10px] uppercase font-semibold text-slate-400 block mb-0.5">
                        Suggested Remediation:
                      </span>
                      <p className="whitespace-pre-wrap font-sans">{cf.recommended_fix || cf.remediation}</p>
                    </div>
                  )}

                  {cf.evidence_ids && cf.evidence_ids.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                      <span className="text-slate-500 font-mono uppercase text-[10px]">Supporting Evidence:</span>
                      {cf.evidence_ids.map((eid) => (
                        <a
                          key={eid}
                          href={`#evidence-${eid}`}
                          className="font-mono text-cyan-400 hover:underline text-[10px] bg-slate-950 px-1 py-0.5 rounded border border-slate-800"
                        >
                          {eid.slice(0, 8)}
                        </a>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </AIResultFrame>
  );
}
