import { Sparkles, AlertCircle, Cpu } from "lucide-react";
import { useAIStatus } from "../hooks";

export function AIStatusIndicator() {
  const { data: status, isLoading, error } = useAIStatus();

  if (isLoading) {
    return (
      <div className="flex items-center gap-1.5 text-xs text-slate-400">
        <Sparkles className="h-3.5 w-3.5 animate-pulse text-purple-400" />
        <span>Checking AI engine...</span>
      </div>
    );
  }

  if (error || !status || !status.configured) {
    return (
      <div
        className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-950/40 border border-amber-800/60 text-xs text-amber-300"
        title="AI features are disabled because no LLM provider or API key is configured on the backend."
      >
        <AlertCircle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
        <span className="font-medium">AI not configured</span>
      </div>
    );
  }

  const budget = status.remaining_budget;
  const callsRemaining = budget ? Object.values(budget)[0] : undefined;

  return (
    <div className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-purple-950/40 border border-purple-800/60 text-xs text-purple-300">
      <Cpu className="h-3.5 w-3.5 text-purple-400 shrink-0" />
      <span className="font-semibold text-purple-200">AI configured</span>
      <span className="font-mono text-[11px] text-slate-400">({status.model})</span>
      {!status.enabled && <span className="text-[10px] text-amber-300">(disabled)</span>}
      {callsRemaining !== undefined && (
        <span className="text-[10px] bg-purple-900/60 text-purple-200 px-1.5 py-0.2 rounded font-mono">
          {callsRemaining} calls left
        </span>
      )}
    </div>
  );
}
