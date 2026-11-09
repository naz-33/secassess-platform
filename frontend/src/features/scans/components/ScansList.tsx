import { Link } from "react-router-dom";
import { Clock, ShieldAlert, CheckCircle, AlertCircle, Loader2 } from "lucide-react";
import { useAssessmentScans } from "../../assessments/hooks";
import { Badge } from "../../../components/Badge";
import { Button } from "../../../components/Button";
import { LoadingState, EmptyState, ErrorState } from "../../../components/StatusStates";
import type { ScanRead, ScanStatus } from "../../../api/types";

export interface ScansListProps {
  assessmentId: string;
}

export function ScansList({ assessmentId }: ScansListProps) {
  const { data: scans, isLoading, error, refetch } = useAssessmentScans(assessmentId);

  if (isLoading) return <LoadingState message="Loading scan history..." />;
  if (error) return <ErrorState title="Failed to load scans" error={error} onRetry={() => refetch()} />;

  if (!scans || scans.length === 0) {
    return (
      <EmptyState
        title="No scans executed yet"
        description="Launch an Nmap reconnaissance scan, DNS query, or Web assessment above to gather data."
      />
    );
  }

  const getStatusBadge = (status: ScanStatus) => {
    switch (status) {
      case "completed":
        return (
          <Badge variant="success" size="sm" icon={<CheckCircle className="h-3 w-3" />}>
            COMPLETED
          </Badge>
        );
      case "running":
        return (
          <Badge variant="info" size="sm" icon={<Loader2 className="h-3 w-3 animate-spin" />}>
            RUNNING
          </Badge>
        );
      case "pending":
        return (
          <Badge variant="warning" size="sm" icon={<Clock className="h-3 w-3" />}>
            PENDING
          </Badge>
        );
      case "rejected":
        return (
          <Badge variant="danger" size="sm" icon={<ShieldAlert className="h-3 w-3" />}>
            REJECTED: OUT OF SCOPE
          </Badge>
        );
      case "failed":
        return (
          <Badge variant="danger" size="sm" icon={<AlertCircle className="h-3 w-3" />}>
            FAILED
          </Badge>
        );
      default:
        return <Badge variant="neutral">{status}</Badge>;
    }
  };

  const calculateDuration = (scan: ScanRead) => {
    if (!scan.started_at) return "—";
    const start = new Date(scan.started_at).getTime();
    const end = scan.finished_at ? new Date(scan.finished_at).getTime() : Date.now();
    const sec = Math.max(0, Math.floor((end - start) / 1000));
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    return `${min}m ${sec % 60}s`;
  };

  return (
    <div className="space-y-4">
      <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/60 shadow">
        <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
          <thead className="bg-slate-900 text-xs font-semibold uppercase tracking-wider text-slate-400">
            <tr>
              <th className="px-6 py-3.5">Tool</th>
              <th className="px-6 py-3.5">Status</th>
              <th className="px-6 py-3.5">Started</th>
              <th className="px-6 py-3.5">Duration</th>
              <th className="px-6 py-3.5">Command / Notes</th>
              <th className="px-6 py-3.5 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 text-slate-300">
            {scans.map((scan) => (
              <tr key={scan.id} className="hover:bg-slate-850/50">
                <td className="px-6 py-4 font-semibold text-slate-100 uppercase tracking-wide">
                  {scan.tool}
                </td>
                <td className="px-6 py-4">{getStatusBadge(scan.status)}</td>
                <td className="px-6 py-4 font-mono text-xs text-slate-400">
                  {scan.started_at ? new Date(scan.started_at).toLocaleTimeString() : "Queued"}
                </td>
                <td className="px-6 py-4 text-xs text-slate-400">{calculateDuration(scan)}</td>
                <td className="px-6 py-4 font-mono text-xs text-slate-300 max-w-xs truncate">
                  {scan.status === "rejected" ? (
                    <span className="text-rose-400 font-sans text-xs">
                      {scan.error || "Attempt logged: Target asset is outside authorized scope."}
                    </span>
                  ) : (
                    scan.command || "Executing..."
                  )}
                </td>
                <td className="px-6 py-4 text-right whitespace-nowrap">
                  <Link to={`/assessments/${assessmentId}/scans/${scan.id}`}>
                    <Button size="sm" variant="ghost">
                      View Output
                    </Button>
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

