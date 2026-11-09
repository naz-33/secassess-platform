import { useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Search, ShieldCheck, ExternalLink, Trash2 } from "lucide-react";
import { useTargets, useDeleteTarget } from "../hooks";
import { Button } from "../../../components/Button";
import { Badge } from "../../../components/Badge";
import { LoadingState, EmptyState, ErrorState } from "../../../components/StatusStates";
import { ConfirmDialog } from "../../../components/Modal";
import { RequireRole } from "../../../auth/RequireRole";
import type { TargetRead } from "../../../api/types";

export function TargetsPage() {
  const { data: targets, isLoading, error, refetch } = useTargets();
  const deleteMutation = useDeleteTarget();

  const [search, setSearch] = useState("");
  const [targetToDelete, setTargetToDelete] = useState<TargetRead | null>(null);

  const filteredTargets = (targets || []).filter((t) => {
    const q = search.toLowerCase();
    return (
      t.name.toLowerCase().includes(q) ||
      t.base_url.toLowerCase().includes(q) ||
      (t.description && t.description.toLowerCase().includes(q))
    );
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-100">Assessment Targets</h1>
          <p className="text-sm text-slate-400 mt-1">
            Approved infrastructure and domain boundaries for automated reconnaissance and security testing.
          </p>
        </div>
        <RequireRole roles={["admin", "assessor"]}>
          <Link to="/targets/new">
            <Button>
              <Plus className="h-4 w-4 mr-1.5" />
              New Target
            </Button>
          </Link>
        </RequireRole>
      </div>

      {/* Guidance box */}
      <div className="rounded-lg border border-amber-900/40 bg-amber-950/20 p-4 text-xs text-amber-200/90 flex items-start space-x-3">
        <ShieldCheck className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-amber-300">Authorized Testing Boundary Notice: </span>
          Only configure instructor-approved testing targets (e.g. synthetic local environments, designated test ranges).
          Do not target public domain endpoints or unauthorized production servers.
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex items-center space-x-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input
            type="text"
            placeholder="Search targets by name, URL, or description..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-md border border-slate-700 bg-slate-900 pl-9 pr-4 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>
      </div>

      {isLoading && <LoadingState message="Loading registered targets..." />}
      {error && <ErrorState title="Failed to load targets" error={error} onRetry={() => refetch()} />}

      {!isLoading && !error && filteredTargets.length === 0 && (
        <EmptyState
          title={search ? "No matching targets" : "No targets configured"}
          description={
            search
              ? "No targets match your current search criteria."
              : "Create your first authorized security assessment target to define scope rules."
          }
        />
      )}

      {!isLoading && !error && filteredTargets.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/60 shadow">
          <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
            <thead className="bg-slate-900 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-6 py-3.5">Target Name</th>
                <th className="px-6 py-3.5">Base URL</th>
                <th className="px-6 py-3.5">Scope Rules</th>
                <th className="px-6 py-3.5">Authorization Note</th>
                <th className="px-6 py-3.5 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {filteredTargets.map((target) => (
                <tr key={target.id} className="hover:bg-slate-850/50 transition-colors">
                  <td className="px-6 py-4 font-medium text-slate-100">
                    <Link
                      to={`/targets/${target.id}`}
                      className="text-cyan-400 hover:text-cyan-300 hover:underline"
                    >
                      {target.name}
                    </Link>
                    {target.description && (
                      <p className="text-xs text-slate-400 font-normal line-clamp-1 mt-0.5">
                        {target.description}
                      </p>
                    )}
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-300">
                    <span className="break-all">{target.base_url}</span>
                  </td>
                  <td className="px-6 py-4">
                    <Badge variant="neutral" size="sm">
                      {target.scope_items?.length || 0} items
                    </Badge>
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-400 max-w-xs truncate">
                    {target.authorization_note || "—"}
                  </td>
                  <td className="px-6 py-4 text-right space-x-2 whitespace-nowrap">
                    <Link to={`/targets/${target.id}`}>
                      <Button size="sm" variant="ghost" title="View details and scope">
                        <ExternalLink className="h-4 w-4" />
                      </Button>
                    </Link>
                    <RequireRole roles={["admin", "assessor"]}>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setTargetToDelete(target)}
                        className="text-rose-400 hover:text-rose-300"
                        title="Delete target"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </RequireRole>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {targetToDelete && (
        <ConfirmDialog
          isOpen={!!targetToDelete}
          onClose={() => setTargetToDelete(null)}
          onConfirm={() => {
            deleteMutation.mutate(targetToDelete.id, {
              onSettled: () => setTargetToDelete(null),
            });
          }}
          title="Delete Target"
          itemName={`${targetToDelete.name} (${targetToDelete.base_url})`}
          description="Are you sure you want to permanently delete this target? All associated scope rules and assessments will also be deleted."
          isLoading={deleteMutation.isPending}
        />
      )}
    </div>
  );
}
