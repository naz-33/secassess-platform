import { useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Search, ShieldCheck, ExternalLink, Calendar } from "lucide-react";
import { useAssessments } from "../hooks";
import { useTargets } from "../../targets/hooks";
import { Button } from "../../../components/Button";
import { Badge } from "../../../components/Badge";
import { LoadingState, EmptyState, ErrorState } from "../../../components/StatusStates";
import { RequireRole } from "../../../auth/RequireRole";

export function AssessmentsPage() {
  const { data: assessments, isLoading, error, refetch } = useAssessments();
  const { data: targets } = useTargets();

  const [search, setSearch] = useState("");
  const [targetFilter, setTargetFilter] = useState<string>("all");

  const targetMap = new Map((targets || []).map((t) => [t.id, t]));

  const filteredAssessments = (assessments || []).filter((a) => {
    const matchesTarget = targetFilter === "all" || a.target_id === targetFilter;
    const targetName = targetMap.get(a.target_id)?.name || "";
    const q = search.toLowerCase();
    const matchesSearch = a.name.toLowerCase().includes(q) || targetName.toLowerCase().includes(q);
    return matchesTarget && matchesSearch;
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">Security Assessments</h1>
          <p className="text-sm text-slate-400 mt-1">
            Reconnaissance cycles, vulnerability evaluations, and test executions across approved targets.
          </p>
        </div>
        <RequireRole roles={["admin", "assessor"]}>
          <Link to="/assessments/new">
            <Button>
              <Plus className="h-4 w-4 mr-1.5" />
              New Assessment
            </Button>
          </Link>
        </RequireRole>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search assessments by name or target..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-md border border-slate-700 bg-slate-900 pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>
        <select
          value={targetFilter}
          onChange={(e) => setTargetFilter(e.target.value)}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
        >
          <option value="all">All Targets</option>
          {targets?.map((t) => (
            <option key={t.id} value={t.id}>
              {t.name}
            </option>
          ))}
        </select>
      </div>

      {isLoading && <LoadingState message="Loading assessments..." />}
      {error && <ErrorState title="Failed to load assessments" error={error} onRetry={() => refetch()} />}

      {!isLoading && !error && filteredAssessments.length === 0 && (
        <EmptyState
          title={search || targetFilter !== "all" ? "No matching assessments" : "No assessments created"}
          description={
            search || targetFilter !== "all"
              ? "Try adjusting your search query or target filter."
              : "Launch a new security assessment cycle on an approved target."
          }
        />
      )}

      {!isLoading && !error && filteredAssessments.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/60 shadow">
          <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
            <thead className="bg-slate-900 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-6 py-3.5">Assessment Name</th>
                <th className="px-6 py-3.5">Associated Target</th>
                <th className="px-6 py-3.5">Status</th>
                <th className="px-6 py-3.5">Created At</th>
                <th className="px-6 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {filteredAssessments.map((a) => {
                const targetObj = targetMap.get(a.target_id);
                const statusVariant =
                  a.status === "completed"
                    ? "success"
                    : a.status === "in_progress" || a.status === "running"
                    ? "info"
                    : "neutral";

                return (
                  <tr key={a.id} className="hover:bg-slate-850/50 transition-colors">
                    <td className="px-6 py-4 font-medium text-slate-100">
                      <Link
                        to={`/assessments/${a.id}`}
                        className="text-cyan-400 hover:text-cyan-300 hover:underline"
                      >
                        {a.name}
                      </Link>
                    </td>
                    <td className="px-6 py-4">
                      {targetObj ? (
                        <div>
                          <Link
                            to={`/targets/${targetObj.id}`}
                            className="text-xs font-medium text-slate-300 hover:text-cyan-300 flex items-center space-x-1"
                          >
                            <ShieldCheck className="h-3.5 w-3.5 text-cyan-500 shrink-0" />
                            <span>{targetObj.name}</span>
                          </Link>
                          <p className="text-[11px] font-mono text-slate-500 truncate max-w-xs">
                            {targetObj.base_url}
                          </p>
                        </div>
                      ) : (
                        <span className="text-xs text-slate-500 font-mono">{a.target_id}</span>
                      )}
                    </td>
                    <td className="px-6 py-4">
                      <Badge variant={statusVariant} size="sm">
                        {a.status.toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400 font-mono">
                      <span className="flex items-center space-x-1.5">
                        <Calendar className="h-3.5 w-3.5 text-slate-500" />
                        <span>{new Date(a.created_at).toLocaleDateString()}</span>
                      </span>
                    </td>
                    <td className="px-6 py-4 text-right">
                      <Link to={`/assessments/${a.id}`}>
                        <Button size="sm" variant="ghost" title="Open assessment workspace">
                          <ExternalLink className="h-4 w-4 mr-1.5" />
                          Open
                        </Button>
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
