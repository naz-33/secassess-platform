import { useState } from "react";
import { Filter, ChevronDown, ChevronRight, Shield } from "lucide-react";
import { useAuditLogs, useUsers } from "../../dashboard/hooks";
import { LoadingState, ErrorState, EmptyState } from "../../../components/StatusStates";
import { Button } from "../../../components/Button";
import type { AuditLogRead, UserRead } from "../../../api/types";

export function AuditLogPage() {
  const [actionInput, setActionInput] = useState("");
  const [userInput, setUserInput] = useState("");
  const [startDateInput, setStartDateInput] = useState("");
  const [endDateInput, setEndDateInput] = useState("");

  const [appliedFilters, setAppliedFilters] = useState<{
    action?: string;
    user_id?: string;
    start_date?: string;
    end_date?: string;
  }>({});

  const [page, setPage] = useState(1);
  const pageSize = 20;

  // Track expanded row ids
  const [expandedIds, setExpandedIds] = useState<Record<string, boolean>>({});

  const { data: users } = useUsers();

  const { data: logs, isLoading, error, refetch } = useAuditLogs({
    action: appliedFilters.action,
    user_id: appliedFilters.user_id,
    start_date: appliedFilters.start_date,
    end_date: appliedFilters.end_date,
    limit: pageSize,
    offset: (page - 1) * pageSize,
  });

  const toggleExpand = (id: string) => {
    setExpandedIds((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const handleApplyFilters = () => {
    setAppliedFilters({
      action: actionInput.trim() || undefined,
      user_id: userInput || undefined,
      start_date: startDateInput ? new Date(startDateInput).toISOString() : undefined,
      end_date: endDateInput ? new Date(endDateInput).toISOString() : undefined,
    });
    setPage(1);
  };

  const handleResetFilters = () => {
    setActionInput("");
    setUserInput("");
    setStartDateInput("");
    setEndDateInput("");
    setAppliedFilters({});
    setPage(1);
  };

  if (isLoading) return <LoadingState message="Loading immutable security audit trail..." />;
  if (error) {
    return <ErrorState title="Failed to load audit logs" error={error} onRetry={() => refetch()} />;
  }

  // Pre-calculate user map
  const userMap = new Map<string, UserRead>((users || []).map((u: UserRead) => [u.id, u]));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-cyan-400 text-xs font-medium uppercase tracking-wider">
            <Shield className="h-4 w-4" />
            <span>Compliance & Administration</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100">
            Security Audit Trail
          </h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Tamper-evident system activity log recording authentication, scan dispatches, and verification decisions.
          </p>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-4 space-y-4">
        <div className="flex items-center space-x-2 text-xs font-semibold uppercase tracking-wider text-slate-400">
          <Filter className="h-3.5 w-3.5 text-cyan-400" />
          <span>Filter Audit Trail</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
          <div>
            <label htmlFor="audit-action-filter" className="block text-slate-400 font-medium mb-1">Action Type</label>
            <input
              id="audit-action-filter"
              type="text"
              placeholder="e.g. login, verify, scan"
              value={actionInput}
              onChange={(e) => setActionInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Actor User</label>
            <select
              value={userInput}
              onChange={(e) => setUserInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="">All Users</option>
              {(users || []).map((u: UserRead) => (
                <option key={u.id} value={u.id}>
                  {u.name} ({u.email})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">From Date</label>
            <input
              type="date"
              value={startDateInput}
              onChange={(e) => setStartDateInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">To Date</label>
            <input
              type="date"
              value={endDateInput}
              onChange={(e) => setEndDateInput(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

          <div className="flex items-center space-x-2">
            <Button
              size="sm"
              variant="outline"
              onClick={handleApplyFilters}
            >
              Apply Filter
            </Button>
            {(appliedFilters.action || appliedFilters.user_id || appliedFilters.start_date || appliedFilters.end_date || actionInput || userInput || startDateInput || endDateInput) && (
              <Button size="sm" variant="ghost" onClick={handleResetFilters}>
                Clear Filters
              </Button>
            )}
          </div>
      </div>

      {/* Logs Table (Read-Only) */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
        {logs && logs.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                <tr>
                  <th className="w-8 py-3 px-3"></th>
                  <th className="py-3 px-4 font-semibold uppercase tracking-wider">Timestamp</th>
                  <th className="py-3 px-4 font-semibold uppercase tracking-wider">Action</th>
                  <th className="py-3 px-4 font-semibold uppercase tracking-wider">User</th>
                  <th className="py-3 px-4 font-semibold uppercase tracking-wider">Audit Details Preview</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {logs.map((log: AuditLogRead) => {
                  const isExpanded = expandedIds[log.id];
                  const actor = log.user_id ? userMap.get(log.user_id) : null;

                  return (
                    <tr
                      key={log.id}
                      onClick={() => toggleExpand(log.id)}
                      className="hover:bg-slate-800/40 transition-colors cursor-pointer"
                    >
                      <td className="py-3 px-3 text-slate-500">
                        {isExpanded ? (
                          <ChevronDown className="h-4 w-4" />
                        ) : (
                          <ChevronRight className="h-4 w-4" />
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400 whitespace-nowrap">
                        {new Date(log.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4 font-mono font-semibold text-cyan-400">
                        {log.action}
                      </td>
                      <td className="py-3 px-4">
                        {actor ? (
                          <span className="font-medium text-slate-200">
                            {actor.name} <span className="font-mono text-slate-500 text-[11px]">({actor.email})</span>
                          </span>
                        ) : log.user_id ? (
                          <span className="font-mono text-slate-500 text-[11px]">
                            {log.user_id}
                          </span>
                        ) : (
                          <span className="text-slate-500 italic">System</span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400 truncate max-w-md">
                        {/* Untrusted content rendered purely as text */}
                        <span>{log.detail || "—"}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No audit logs matched"
            description="No security audit events match the specified filter criteria."
          />
        )}
      </div>
    </div>
  );
}
