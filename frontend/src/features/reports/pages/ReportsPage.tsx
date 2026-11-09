import { Link } from "react-router-dom";
import { FileText, ArrowRight, Layers } from "lucide-react";
import { useAssessments } from "../../assessments/hooks";
import { LoadingState, ErrorState, EmptyState } from "../../../components/StatusStates";
import { Badge } from "../../../components/Badge";

export function ReportsPage() {
  const { data: assessments, isLoading, error, refetch } = useAssessments();

  if (isLoading) {
    return <LoadingState message="Loading assessments for report compilation..." />;
  }

  if (error || !assessments) {
    return (
      <ErrorState
        title="Failed to load assessments"
        error={error}
        onRetry={() => refetch()}
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-cyan-400 text-xs font-medium uppercase tracking-wider">
            <FileText className="h-4 w-4" />
            <span>Reporting Hub</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
            Assessment Reports
          </h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Compile immutable assessment deliverables (DOCX / PDF), inspect generation history, and download reports.
          </p>
        </div>
      </div>

      {/* Assessment Reports Navigator */}
      <div className="space-y-4">
        <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
          <Layers className="h-4 w-4 text-cyan-400" />
          <span>Select Assessment to View or Generate Reports</span>
        </h2>

        {assessments.length === 0 ? (
          <EmptyState
            title="No assessments available"
            description="Create an assessment first to compile reports."
          />
        ) : (
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Assessment</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Status</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Created</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {assessments.map((a) => (
                    <tr key={a.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-semibold text-slate-100">
                        {a.name}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          size="sm"
                          variant={a.status === "completed" ? "success" : "info"}
                        >
                          {a.status}
                        </Badge>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {new Date(a.created_at).toLocaleDateString()}
                      </td>
                      <td className="py-3 px-4 text-right">
                        <Link
                          to={`/assessments/${a.id}?tab=reports`}
                          className="inline-flex items-center text-cyan-400 hover:text-cyan-300 font-medium"
                        >
                          <span>Manage Reports</span>
                          <ArrowRight className="h-3.5 w-3.5 ml-1" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
