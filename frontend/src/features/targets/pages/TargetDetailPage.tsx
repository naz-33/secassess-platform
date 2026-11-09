import React, { useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import {
  ArrowLeft,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Plus,
  Trash2,
  CheckCircle2,
  XCircle,
  HelpCircle,
} from "lucide-react";
import {
  useTarget,
  useAddScopeItem,
  useDeleteScopeItem,
  useScopeValidator,
} from "../hooks";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import { Badge } from "../../../components/Badge";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import { ConfirmDialog } from "../../../components/Modal";
import { RequireRole } from "../../../auth/RequireRole";
import type { ScopeItemCreate, ScopeItemRead } from "../../../api/types";

export function TargetDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const { data: target, isLoading, error, refetch } = useTarget(id);
  const addScopeMutation = useAddScopeItem(id!);
  const deleteScopeMutation = useDeleteScopeItem(id!);
  const scopeValidatorMutation = useScopeValidator(id!);

  // New Scope Item Form State
  const [newAsset, setNewAsset] = useState("");
  const [newInScope, setNewInScope] = useState(true);
  const [newNotes, setNewNotes] = useState("");
  const [showAddScope, setShowAddScope] = useState(false);

  // Scope Validation Tool State
  const [candidateAsset, setCandidateAsset] = useState("");
  const [itemToDelete, setItemToDelete] = useState<ScopeItemRead | null>(null);

  if (isLoading) return <LoadingState message="Loading target details..." />;
  if (error || !target) {
    return <ErrorState title="Failed to load target" error={error} onRetry={() => refetch()} />;
  }

  const handleAddScope = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newAsset.trim()) return;

    const payload: ScopeItemCreate = {
      asset: newAsset.trim(),
      in_scope: newInScope,
      notes: newNotes.trim() || null,
    };

    addScopeMutation.mutate(payload, {
      onSuccess: () => {
        setNewAsset("");
        setNewNotes("");
        setShowAddScope(false);
      },
    });
  };

  const handleValidateScope = (e: React.FormEvent) => {
    e.preventDefault();
    if (!candidateAsset.trim()) return;
    scopeValidatorMutation.mutate(candidateAsset.trim());
  };

  return (
    <div className="space-y-8">
      {/* Back and Title Header */}
      <div>
        <button
          onClick={() => navigate("/targets")}
          className="inline-flex items-center text-xs font-semibold uppercase tracking-wider text-slate-400 hover:text-slate-200 mb-3"
        >
          <ArrowLeft className="h-4 w-4 mr-1.5" />
          Back to Targets
        </button>
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-bold tracking-tight text-slate-100">{target.name}</h1>
              <Badge variant="info">Active Target</Badge>
            </div>
            <p className="text-sm font-mono text-cyan-400 mt-1">{target.base_url}</p>
          </div>
          <div className="flex items-center space-x-3">
            <RequireRole roles={["admin", "assessor"]}>
              <Link to={`/assessments/new?target_id=${target.id}`}>
                <Button size="sm">Create Assessment Here</Button>
              </Link>
            </RequireRole>
          </div>
        </div>
      </div>

      {/* Target Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Target Metadata</h2>
          <div>
            <span className="text-xs text-slate-500">Description:</span>
            <p className="text-sm text-slate-200 mt-0.5 whitespace-pre-wrap">{target.description || "No description provided."}</p>
          </div>
          <div>
            <span className="text-xs text-slate-500">Created At:</span>
            <p className="text-sm text-slate-300 font-mono mt-0.5">
              {new Date(target.created_at).toLocaleString()}
            </p>
          </div>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">Authorization Agreement</h2>
          <div>
            <span className="text-xs text-slate-500">Recorded Documentation:</span>
            <div className="rounded-md border border-slate-700 bg-slate-950 p-3 mt-1 text-xs text-slate-200 font-mono">
              {target.authorization_note || "No authorization documentation recorded."}
            </div>
          </div>
        </div>
      </div>

      {/* Scope Management Section */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
              <Shield className="h-5 w-5 text-cyan-400" />
              <span>Scope Boundaries ({target.scope_items?.length || 0})</span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Granular URL prefixes, hostnames, IP addresses, CIDR ranges, and blacklist rules.
            </p>
          </div>
          <RequireRole roles={["admin", "assessor"]}>
            <Button
              size="sm"
              variant={showAddScope ? "secondary" : "primary"}
              onClick={() => setShowAddScope(!showAddScope)}
            >
              <Plus className="h-4 w-4 mr-1.5" />
              {showAddScope ? "Cancel" : "Add Scope Rule"}
            </Button>
          </RequireRole>
        </div>

        {/* Add Scope Item Inline Form */}
        {showAddScope && (
          <form
            onSubmit={handleAddScope}
            className="rounded-lg border border-cyan-800/50 bg-slate-900 p-5 space-y-4 animate-in fade-in duration-150"
          >
            <h3 className="text-sm font-semibold text-cyan-300">New Scope Boundary Rule</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="md:col-span-2">
                <Input
                  label="Asset Rule / Pattern"
                  required
                  placeholder="e.g. 192.168.1.0/24, api.local, /admin, http://localhost:8080"
                  value={newAsset}
                  onChange={(e) => setNewAsset(e.target.value)}
                  hint="Supports URLs, hostname, IP, CIDR block, or path prefix."
                />
              </div>
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
                  Scope Type
                </label>
                <div className="flex items-center space-x-4 mt-2">
                  <label className="inline-flex items-center text-xs text-emerald-300 cursor-pointer">
                    <input
                      type="radio"
                      name="inScope"
                      checked={newInScope === true}
                      onChange={() => setNewInScope(true)}
                      className="mr-1.5 text-cyan-600 focus:ring-cyan-500"
                    />
                    In-Scope (Allowed)
                  </label>
                  <label className="inline-flex items-center text-xs text-rose-300 cursor-pointer">
                    <input
                      type="radio"
                      name="inScope"
                      checked={newInScope === false}
                      onChange={() => setNewInScope(false)}
                      className="mr-1.5 text-rose-600 focus:ring-rose-500"
                    />
                    Out-of-Scope (Forbidden)
                  </label>
                </div>
              </div>
            </div>

            <Input
              label="Boundary Notes"
              placeholder="e.g. Exclude sensitive billing endpoint, payment gateway"
              value={newNotes}
              onChange={(e) => setNewNotes(e.target.value)}
            />

            <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
              <Button type="button" size="sm" variant="ghost" onClick={() => setShowAddScope(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" isLoading={addScopeMutation.isPending}>
                Save Scope Rule
              </Button>
            </div>
          </form>
        )}

        {/* Scope Items Table */}
        {(!target.scope_items || target.scope_items.length === 0) ? (
          <div className="rounded-lg border border-dashed border-slate-800 p-8 text-center bg-slate-900/40">
            <p className="text-sm text-slate-400">
              No scope rules defined yet. By default, only the target's base URL will be permitted.
            </p>
          </div>
        ) : (
          <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/60 shadow">
            <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
              <thead className="bg-slate-900 text-xs font-semibold uppercase tracking-wider text-slate-400">
                <tr>
                  <th className="px-6 py-3.5">Asset Rule</th>
                  <th className="px-6 py-3.5">Boundary Status</th>
                  <th className="px-6 py-3.5">Notes</th>
                  <th className="px-6 py-3.5 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800 text-slate-300">
                {target.scope_items.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-850/50">
                    <td className="px-6 py-4 font-mono text-xs font-medium text-slate-200">
                      {item.asset}
                    </td>
                    <td className="px-6 py-4">
                      {item.in_scope ? (
                        <Badge variant="success" size="sm" icon={<ShieldCheck className="h-3.5 w-3.5" />}>
                          IN-SCOPE (Allowed)
                        </Badge>
                      ) : (
                        <div className="flex flex-col items-start gap-1">
                          <Badge variant="danger" size="sm" icon={<ShieldAlert className="h-3.5 w-3.5" />}>
                            OUT-OF-SCOPE (Blacklist)
                          </Badge>
                          <span className="text-[11px] text-rose-400 font-mono">
                            Blocked (blacklist wins over in-scope rules)
                          </span>
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-4 text-xs text-slate-400 max-w-xs truncate">
                      {item.notes || "—"}
                    </td>
                    <td className="px-6 py-4 text-right">
                      <RequireRole roles={["admin", "assessor"]}>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setItemToDelete(item)}
                          className="text-rose-400 hover:text-rose-300"
                          title="Delete scope rule"
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
      </div>

      {/* Scope Check Tool (Demo and Oral-Defense feature) */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <HelpCircle className="h-5 w-5 text-cyan-400" />
            <span>Scope Check Verification Tool</span>
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Test candidate URLs, hostnames, IP addresses, or path prefixes against the backend's scope decision engine
            (`POST /api/v1/targets/{"{id}"}/scope/validate`).
          </p>
        </div>

        <form onSubmit={handleValidateScope} className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <input
              type="text"
              placeholder="e.g. http://localhost:8080/admin or 192.168.1.50"
              value={candidateAsset}
              onChange={(e) => setCandidateAsset(e.target.value)}
              className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          </div>
          <Button type="submit" isLoading={scopeValidatorMutation.isPending}>
            Check Scope
          </Button>
        </form>

        {scopeValidatorMutation.data && (
          <div
            className={`rounded-lg border p-4 text-sm animate-in fade-in duration-200 ${
              scopeValidatorMutation.data.in_scope
                ? "border-emerald-800/80 bg-emerald-950/30 text-emerald-200"
                : "border-rose-800/80 bg-rose-950/30 text-rose-200"
            }`}
          >
            <div className="flex items-start space-x-3">
              {scopeValidatorMutation.data.in_scope ? (
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <XCircle className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
              )}
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-sm">
                    {scopeValidatorMutation.data.in_scope ? "AUTHORIZED / IN-SCOPE" : "REJECTED / OUT-OF-SCOPE"}
                  </span>
                  <Badge variant={scopeValidatorMutation.data.in_scope ? "success" : "danger"} size="sm">
                    {scopeValidatorMutation.data.in_scope ? "Permitted" : "Prohibited"}
                  </Badge>
                </div>
                <p className="text-xs font-mono break-all text-slate-300">
                  Asset: {scopeValidatorMutation.data.asset}
                </p>
                <p className="text-xs mt-1">
                  <span className="font-semibold">Backend Decision Reason: </span>
                  {scopeValidatorMutation.data.reason}
                </p>
              </div>
            </div>
          </div>
        )}

        {scopeValidatorMutation.isError && (
          <div className="rounded-lg border border-rose-900/50 bg-rose-950/20 p-4 text-xs text-rose-300">
            Validation check failed: {scopeValidatorMutation.error?.message}
          </div>
        )}
      </div>

      {/* Delete Scope Confirmation */}
      {itemToDelete && (
        <ConfirmDialog
          isOpen={!!itemToDelete}
          onClose={() => setItemToDelete(null)}
          onConfirm={() => {
            deleteScopeMutation.mutate(itemToDelete.id, {
              onSettled: () => setItemToDelete(null),
            });
          }}
          title="Delete Scope Rule"
          itemName={itemToDelete.asset}
          description="Are you sure you want to remove this scope boundary rule from the target configuration?"
          isLoading={deleteScopeMutation.isPending}
        />
      )}
    </div>
  );
}
