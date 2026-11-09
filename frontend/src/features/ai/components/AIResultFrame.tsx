import React, { useState } from "react";
import { Sparkles, ShieldAlert, Cpu, CheckCircle2, AlertTriangle, ChevronDown, ChevronUp } from "lucide-react";
import type { AIAnalysisRead } from "../../../api/types";

interface AIResultFrameProps {
  analysis: AIAnalysisRead;
  title: string;
  children: React.ReactNode;
}

export function AIResultFrame({ analysis, title, children }: AIResultFrameProps) {
  const [showRedactions, setShowRedactions] = useState(false);

  const redactionReport = analysis.redaction_report || {};
  const redactionEntries = Object.entries(redactionReport);

  const confidence = (analysis.response_json?.confidence as string) || "medium";
  const caveats = (analysis.response_json?.caveats as string[]) || [];

  return (
    <div className="rounded-lg border border-purple-800/60 bg-purple-950/20 p-5 space-y-4">
      {/* Top Advisory Disclaimer (NON-NEGOTIABLE) */}
      <div
        role="alert"
        className="flex items-start gap-2.5 p-3 rounded-md bg-purple-900/30 border border-purple-700/60 text-xs text-purple-200"
      >
        <ShieldAlert className="h-4 w-4 shrink-0 text-purple-400 mt-0.5" aria-hidden="true" />
        <div>
          <span className="font-bold tracking-wide uppercase text-purple-300">
            AI-generated, requires assessor verification
          </span>
          <p className="text-[11px] text-purple-200/90 mt-0.5 font-medium">
            Must be verified by a qualified security assessor against technical evidence. AI ratings and candidate findings do not constitute confirmed vulnerabilities.
          </p>
        </div>
      </div>

      {/* Frame Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-purple-800/40 pb-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-5 w-5 text-purple-400" aria-hidden="true" />
          <h2 className="text-base font-bold text-slate-100">{title}</h2>
          <span className="text-[10px] font-mono uppercase bg-purple-900/40 text-purple-300 border border-purple-800/80 px-2 py-0.5 rounded">
            {analysis.function}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
          <div className="flex items-center gap-1 font-mono text-[11px]">
            <Cpu className="h-3.5 w-3.5 text-purple-400" />
            <span>{analysis.model}</span>
          </div>

          <span className="text-slate-600">•</span>

          <span className="text-[11px]">
            Prompt: <span className="font-mono text-slate-300">{analysis.prompt_version}</span>
          </span>

          <span className="text-slate-600">•</span>

          <span
            className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider border ${
              confidence === "high"
                ? "bg-emerald-950 text-emerald-300 border-emerald-800"
                : confidence === "low"
                ? "bg-amber-950 text-amber-300 border-amber-800"
                : "bg-blue-950 text-blue-300 border-blue-800"
            }`}
          >
            Confidence: {confidence}
          </span>
        </div>
      </div>

      {/* Body: Main Tool/Function Specific Content */}
      <div className="space-y-4">{children}</div>

      {/* Caveats section */}
      {caveats.length > 0 && (
        <div className="p-3 rounded-md bg-slate-900/70 border border-slate-800 text-xs text-slate-300 space-y-1.5">
          <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-[11px] uppercase tracking-wider">
            <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
            <span>AI Caveats & Limitations</span>
          </div>
          <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px]">
            {caveats.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Collapsible Redaction Report */}
      <div className="border-t border-purple-800/30 pt-3">
        <button
          type="button"
          onClick={() => setShowRedactions(!showRedactions)}
          className="flex items-center justify-between w-full text-xs text-slate-400 hover:text-slate-200 transition-colors"
        >
          <div className="flex items-center gap-1.5">
            <CheckCircle2 className="h-3.5 w-3.5 text-cyan-400" />
            <span>Target Data Redaction Report ({redactionEntries.length} rules checked)</span>
          </div>
          {showRedactions ? (
            <ChevronUp className="h-3.5 w-3.5" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" />
          )}
        </button>

        {showRedactions && (
          <div className="mt-2.5 p-3 rounded bg-slate-950/80 border border-slate-800 text-[11px] text-slate-400 font-mono space-y-1">
            <p className="text-slate-500 font-sans pb-1">
              Confidential credentials, auth tokens, and session cookies masked before LLM transmission:
            </p>
            {redactionEntries.length === 0 ? (
              <p className="text-slate-500 italic">No sensitive tokens required masking.</p>
            ) : (
              redactionEntries.map(([k, v]) => (
                <div key={k} className="flex justify-between border-b border-slate-800/40 py-0.5">
                  <span className="text-slate-300">{k}:</span>
                  <span className="text-cyan-400 font-semibold">{String(v)} redactions</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
