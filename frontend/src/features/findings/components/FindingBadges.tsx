import {
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Bot,
  Wrench,
  ShieldAlert,
} from "lucide-react";
import type { FindingSeverity, FindingStatus, FindingSource } from "../../../api/types";

interface SeverityBadgeProps {
  severity: FindingSeverity | string;
  isAdvisory?: boolean;
}

export function SeverityBadge({ severity, isAdvisory = false }: SeverityBadgeProps) {
  const sev = (severity || "info").toLowerCase();

  let styles = "bg-slate-800 text-slate-300 border-slate-700";
  let icon = <Info className="h-3 w-3 shrink-0" aria-hidden="true" />;
  let label = "Info";

  switch (sev) {
    case "critical":
      styles = "bg-rose-950/80 text-rose-300 border-rose-800/80";
      icon = <AlertOctagonIcon className="h-3 w-3 shrink-0" />;
      label = "Critical";
      break;
    case "high":
      styles = "bg-orange-950/80 text-orange-300 border-orange-800/80";
      icon = <AlertTriangle className="h-3 w-3 shrink-0" aria-hidden="true" />;
      label = "High";
      break;
    case "medium":
      styles = "bg-amber-950/80 text-amber-300 border-amber-800/80";
      icon = <AlertCircle className="h-3 w-3 shrink-0" aria-hidden="true" />;
      label = "Medium";
      break;
    case "low":
      styles = "bg-blue-950/80 text-blue-300 border-blue-800/80";
      icon = <Info className="h-3 w-3 shrink-0" aria-hidden="true" />;
      label = "Low";
      break;
    case "info":
    default:
      styles = "bg-slate-800/80 text-slate-300 border-slate-700/80";
      icon = <Info className="h-3 w-3 shrink-0" aria-hidden="true" />;
      label = "Info";
      break;
  }

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${styles}`}
      role="status"
      aria-label={`Severity: ${label}${isAdvisory ? " (Advisory)" : ""}`}
    >
      {icon}
      <span>{label}</span>
      {isAdvisory && <span className="text-[10px] uppercase font-semibold text-amber-400/90 ml-0.5">[Advisory]</span>}
    </span>
  );
}

function AlertOctagonIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
      <line x1="12" y1="8" x2="12" y2="12" />
      <line x1="12" y1="16" x2="12.01" y2="16" />
    </svg>
  );
}

interface StatusBadgeProps {
  status: FindingStatus | string;
}

export function StatusBadge({ status }: StatusBadgeProps) {
  const st = (status || "unverified").toLowerCase();

  switch (st) {
    case "confirmed":
      return (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-emerald-950/80 text-emerald-300 border border-emerald-800/80"
          role="status"
          aria-label="Status: Confirmed"
        >
          <CheckCircle2 className="h-3 w-3 shrink-0" aria-hidden="true" />
          <span>Confirmed</span>
        </span>
      );
    case "false_positive":
      return (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-800/80 text-slate-400 border border-slate-700/80"
          role="status"
          aria-label="Status: False Positive"
        >
          <XCircle className="h-3 w-3 shrink-0" aria-hidden="true" />
          <span>False Positive</span>
        </span>
      );
    case "needs_testing":
      return (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-purple-950/80 text-purple-300 border border-purple-800/80"
          role="status"
          aria-label="Status: Needs Testing"
        >
          <HelpCircle className="h-3 w-3 shrink-0" aria-hidden="true" />
          <span>Needs Testing</span>
        </span>
      );
    case "unverified":
    default:
      return (
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-amber-950/80 text-amber-300 border border-amber-800/80"
          role="status"
          aria-label="Status: Unverified"
        >
          <ShieldAlert className="h-3 w-3 shrink-0" aria-hidden="true" />
          <span>Unverified</span>
        </span>
      );
  }
}

interface SourceBadgeProps {
  source: FindingSource | string;
}

export function SourceBadge({ source }: SourceBadgeProps) {
  const isAi = (source || "").toLowerCase() === "ai";

  if (isAi) {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-purple-950/60 text-purple-300 border border-purple-800/60"
        role="status"
        aria-label="Source: AI-generated"
      >
        <Bot className="h-3 w-3 shrink-0" aria-hidden="true" />
        <span>AI-generated</span>
      </span>
    );
  }

  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700"
      role="status"
      aria-label="Source: Tool"
    >
      <Wrench className="h-3 w-3 shrink-0" aria-hidden="true" />
      <span>Tool</span>
    </span>
  );
}
