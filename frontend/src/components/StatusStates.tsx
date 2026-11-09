import { AlertCircle, FolderOpen, RefreshCw } from "lucide-react";
import { Button } from "./Button";

export function LoadingState({ message = "Loading data..." }: { message?: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-cyan-500 border-t-transparent mb-3" />
      <p className="text-sm text-slate-400">{message}</p>
    </div>
  );
}

export function EmptyState({
  title = "No data found",
  description = "No records match the current view.",
  action,
}: {
  title?: string;
  description?: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-slate-800 py-12 px-4 text-center bg-slate-900/50">
      <FolderOpen className="h-10 w-10 text-slate-600 mb-3" />
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm mt-1">{description}</p>
      {action && (
        <div className="mt-4">
          <Button size="sm" onClick={action.onClick}>
            {action.label}
          </Button>
        </div>
      )}
    </div>
  );
}

export function ErrorState({
  title = "Failed to load data",
  error,
  onRetry,
}: {
  title?: string;
  error?: unknown;
  onRetry?: () => void;
}) {
  const message = error instanceof Error ? error.message : "An unexpected error occurred.";
  const status = (error as any)?.status;
  const details = (error as any)?.details;

  return (
    <div className="rounded-lg border border-rose-900/50 bg-rose-950/20 p-6 text-slate-200">
      <div className="flex items-start space-x-3">
        <AlertCircle className="h-6 w-6 text-rose-400 shrink-0 mt-0.5" />
        <div className="flex-1 space-y-2">
          <h3 className="text-sm font-semibold text-rose-300">{title}</h3>
          <p className="text-xs text-slate-300">{message}</p>
          {(status || details) && (
            <details className="mt-2 text-xs text-slate-400">
              <summary className="cursor-pointer hover:text-slate-300 font-mono">
                Technical Details {status ? `(HTTP ${status})` : ""}
              </summary>
              <pre className="mt-1 rounded bg-slate-950 p-2 font-mono text-[11px] text-slate-400 overflow-x-auto whitespace-pre-wrap">
                {typeof details === "string" ? details : JSON.stringify(details, null, 2)}
              </pre>
            </details>
          )}
          {onRetry && (
            <div className="pt-2">
              <Button size="sm" variant="outline" onClick={onRetry}>
                <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
                Retry
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

