import React, { useState } from "react";
import { Shield } from "lucide-react";
import { useUsers, useCreateUser, useUpdateUser } from "../../dashboard/hooks";
import { useAuth } from "../../../auth/AuthContext";
import { Button } from "../../../components/Button";
import { Badge } from "../../../components/Badge";
import { Select } from "../../../components/Select";
import { Modal } from "../../../components/Modal";
import { LoadingState, ErrorState } from "../../../components/StatusStates";
import type { UserRead, UserRole } from "../../../api/types";

export function UsersPage() {
  const { user: currentUser } = useAuth();
  const { data: users, isLoading, error, refetch } = useUsers(100, 0);

  const createUserMutation = useCreateUser();
  const updateUserMutation = useUpdateUser();

  // Create Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<UserRole>("assessor");
  const [createError, setCreateError] = useState<string | null>(null);

  // Status Change Confirmation Modal State
  const [statusUser, setStatusUser] = useState<UserRead | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  // Role Change Modal State
  const [roleUser, setRoleUser] = useState<UserRead | null>(null);
  const [selectedRole, setSelectedRole] = useState<UserRole>("assessor");
  const [roleError, setRoleError] = useState<string | null>(null);

  const handleOpenCreate = () => {
    setNewName("");
    setNewEmail("");
    setNewPassword("");
    setNewRole("assessor");
    setCreateError(null);
    setIsCreateOpen(true);
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);

    if (newPassword.length < 12) {
      setCreateError("Password must be at least 12 characters.");
      return;
    }

    try {
      await createUserMutation.mutateAsync({
        name: newName.trim(),
        email: newEmail.trim(),
        password: newPassword,
        role: newRole,
      });
      setIsCreateOpen(false);
      await refetch();
    } catch (err: any) {
      console.error("Create user error:", err);
      setCreateError(err.message || "Failed to create user.");
    }
  };

  const handleToggleActive = async () => {
    if (!statusUser) return;
    setStatusError(null);

    // Self-protection hint
    if (statusUser.id === currentUser?.id) {
      setStatusError("You cannot deactivate your own administrative account.");
      return;
    }

    try {
      await updateUserMutation.mutateAsync({
        userId: statusUser.id,
        payload: {
          is_active: !statusUser.is_active,
        },
      });
      setStatusUser(null);
    } catch (err: any) {
      setStatusError(err.message || "Failed to update user status.");
    }
  };

  const handleChangeRole = async () => {
    if (!roleUser) return;
    setRoleError(null);

    // Self-demotion hint
    if (roleUser.id === currentUser?.id && selectedRole !== "admin") {
      setRoleError("You cannot demote yourself from the admin role.");
      return;
    }

    try {
      await updateUserMutation.mutateAsync({
        userId: roleUser.id,
        payload: {
          role: selectedRole,
        },
      });
      setRoleUser(null);
    } catch (err: any) {
      setRoleError(err.message || "Failed to update user role.");
    }
  };

  if (isLoading) return <LoadingState message="Loading platform users..." />;
  if (error) {
    return <ErrorState title="Failed to load users" error={error} onRetry={() => refetch()} />;
  }

  const roleBadge = (r: UserRole) => {
    switch (r) {
      case "admin":
        return <Badge variant="purple">ADMIN</Badge>;
      case "assessor":
        return <Badge variant="info">ASSESSOR</Badge>;
      default:
        return <Badge variant="neutral">VIEWER</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-cyan-400 text-xs font-medium uppercase tracking-wider">
            <Shield className="h-4 w-4" />
            <span>Administration</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-slate-100">User Management</h1>
          <p className="text-xs sm:text-sm text-slate-400">
            Provision user accounts, configure role access privileges, and manage account statuses.
          </p>
        </div>
        <Button onClick={handleOpenCreate} data-testid="open-create-user-modal">
          Create User
        </Button>
      </div>

      {/* Users Table */}
      <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
              <tr>
                <th className="py-3 px-4 font-semibold uppercase tracking-wider">Name</th>
                <th className="py-3 px-4 font-semibold uppercase tracking-wider">Email</th>
                <th className="py-3 px-4 font-semibold uppercase tracking-wider">Role</th>
                <th className="py-3 px-4 font-semibold uppercase tracking-wider">Status</th>
                <th className="py-3 px-4 font-semibold uppercase tracking-wider">Created</th>
                <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {(users || []).map((u: UserRead) => {
                const isSelf = u.id === currentUser?.id;
                return (
                  <tr key={u.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-medium text-slate-100">
                      {/* Untrusted content rendered purely as text */}
                      <span>{u.name}</span>
                      {isSelf && (
                        <span className="ml-2 text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 px-1.5 py-0.5 rounded">
                          You
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">{u.email}</td>
                    <td className="py-3 px-4">{roleBadge(u.role)}</td>
                    <td className="py-3 px-4">
                      {u.is_active ? (
                        <Badge size="sm" variant="success">Active</Badge>
                      ) : (
                        <Badge size="sm" variant="danger">Deactivated</Badge>
                      )}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-500">
                      {new Date(u.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4 text-right space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          setRoleUser(u);
                          setSelectedRole(u.role);
                          setRoleError(null);
                        }}
                      >
                        Change Role
                      </Button>
                      <Button
                        size="sm"
                        variant={u.is_active ? "ghost" : "primary"}
                        onClick={() => {
                          setStatusUser(u);
                          setStatusError(null);
                        }}
                      >
                        {u.is_active ? "Deactivate" : "Activate"}
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create User Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Create New User Account"
      >
        <form onSubmit={handleCreateSubmit} className="space-y-4">
          {createError && (
            <div role="alert" className="p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-200 text-xs">
              {createError}
            </div>
          )}

          <div className="space-y-3">
            <div>
              <label htmlFor="user-name-input" className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Full Name <span className="text-rose-400">*</span>
              </label>
              <input
                id="user-name-input"
                aria-label="Full Name"
                type="text"
                placeholder="Jane Doe"
                required
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="block w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 shadow-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>

            <div>
              <label htmlFor="user-email-input" className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Email Address <span className="text-rose-400">*</span>
              </label>
              <input
                id="user-email-input"
                aria-label="Email Address"
                type="email"
                placeholder="jane@example.com"
                required
                value={newEmail}
                onChange={(e) => setNewEmail(e.target.value)}
                className="block w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 shadow-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
            </div>

            <div>
              <label htmlFor="user-password-input" className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1">
                Password (min 12 characters) <span className="text-rose-400">*</span>
              </label>
              <input
                id="user-password-input"
                data-testid="user-password-input"
                type="password"
                placeholder="••••••••••••"
                required
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="block w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 shadow-sm focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              <p className="mt-1 text-[11px] text-slate-500">Must be at least 12 characters long.</p>
            </div>
          </div>

          <Select
            label="Platform Role"
            value={newRole}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setNewRole(e.target.value as UserRole)}
            options={[
              { label: "Assessor (Launch scans, verify findings, generate reports)", value: "assessor" },
              { label: "Admin (Full platform and user administration)", value: "admin" },
              { label: "Viewer (Read-only access across findings and reports)", value: "viewer" },
            ]}
          />

          <div className="flex justify-end space-x-3 pt-3">
            <Button type="button" variant="ghost" onClick={() => setIsCreateOpen(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              data-testid="submit-create-user"
              onClick={handleCreateSubmit}
              isLoading={createUserMutation.isPending}
            >
              Submit Create User
            </Button>
          </div>
        </form>
      </Modal>

      {/* Role Change Modal */}
      {roleUser && (
        <Modal
          isOpen={Boolean(roleUser)}
          onClose={() => setRoleUser(null)}
          title={`Change Role: ${roleUser.name}`}
        >
          <div className="space-y-4 text-xs">
            {roleError && (
              <div role="alert" className="p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-200">
                {roleError}
              </div>
            )}

            {roleUser.id === currentUser?.id && (
              <div className="p-2.5 rounded bg-amber-950/40 border border-amber-800 text-amber-200">
                Note: Demoting your own account from Admin will revoke your administrative access.
              </div>
            )}

            <Select
              label="Select New Role"
              value={selectedRole}
              onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setSelectedRole(e.target.value as UserRole)}
              options={[
                { label: "Admin", value: "admin" },
                { label: "Assessor", value: "assessor" },
                { label: "Viewer", value: "viewer" },
              ]}
            />

            <div className="flex justify-end space-x-3 pt-3">
              <Button type="button" variant="ghost" onClick={() => setRoleUser(null)}>
                Cancel
              </Button>
              <Button
                type="button"
                isLoading={updateUserMutation.isPending}
                onClick={handleChangeRole}
              >
                Save Role
              </Button>
            </div>
          </div>
        </Modal>
      )}

      {/* Status Confirmation Modal */}
      {statusUser && (
        <Modal
          isOpen={Boolean(statusUser)}
          onClose={() => setStatusUser(null)}
          title={statusUser.is_active ? "Deactivate User Account" : "Activate User Account"}
        >
          <div className="space-y-4 text-xs">
            {statusError && (
              <div role="alert" className="p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-200">
                {statusError}
              </div>
            )}

            <p className="text-slate-300">
              Are you sure you want to {statusUser.is_active ? "deactivate" : "activate"} user{" "}
              <strong className="text-slate-100 font-semibold">{statusUser.name}</strong> ({statusUser.email})?
            </p>

            {statusUser.is_active && (
              <p className="text-amber-400">
                Deactivated users cannot authenticate or access platform API services.
              </p>
            )}

            <div className="flex justify-end space-x-3 pt-3">
              <Button type="button" variant="ghost" onClick={() => setStatusUser(null)}>
                Cancel
              </Button>
              <Button
                type="button"
                variant={statusUser.is_active ? "danger" : "primary"}
                isLoading={updateUserMutation.isPending}
                onClick={handleToggleActive}
              >
                {statusUser.is_active ? "Confirm Deactivation" : "Confirm Activation"}
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
}
