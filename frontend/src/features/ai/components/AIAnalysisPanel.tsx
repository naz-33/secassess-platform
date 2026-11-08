import React from "react";
import { Card, Badge } from "@/shared/components";

interface AIAnalysisPanelProps {
  functionType: "interpret" | "prioritize" | "remediate" | "summarize";
  model: string;
  content: string;
}

export const AIAnalysisPanel: React.FC<AIAnalysisPanelProps> = ({
  functionType,
  model,
  content,
}) => {
  return (
    <Card className="border-sky-200 bg-sky-50/30">
      <div className="flex items-center justify-between mb-3 border-b border-sky-100 pb-2">
        <div className="flex items-center gap-2">
          <Badge variant="info">AI-generated</Badge>
          <span className="text-xs font-semibold uppercase text-slate-700 tracking-wider">
            {functionType}
          </span>
        </div>
        <span className="text-xs text-slate-500 font-mono">Model: {model}</span>
      </div>
      <div className="text-sm text-slate-800 leading-relaxed whitespace-pre-line">
        {content}
      </div>
      <div className="mt-4 pt-2 border-t border-sky-100 text-[11px] text-slate-400 italic">
        Caution: AI suggestions are advisory and require verification by an authorized security assessor.
      </div>
    </Card>
  );
};
