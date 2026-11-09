import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, AlertCircle } from "lucide-react";
import { useCreateTarget } from "../hooks";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import type { TargetCreate } from "../../../api/types";

export function TargetCreatePage() {
  const navigate = useNavigate();
  const createMutation = useCreateTarget();

  const [formData, setFormData] = useState<TargetCreate>({
    name: "",
    base_url: "",
    description: "",
    authorization_note: "",
  });

  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const errs: Record<string, string> = {};
    if (!formData.name.trim()) errs.name = "Target name is required.";
    if (!formData.base_url.trim()) {
      errs.base_url = "Base URL is required.";
    } else {
      try {
        const parsed = new URL(formData.base_url.trim());
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
          errs.base_url = "URL protocol must be http:// or https://.";
        }
      } catch {
        errs.base_url = "Invalid URL format. Include http:// or https://.";
      }
    }
    if (!formData.authorization_note?.trim()) {
      errs.authorization_note = "Authorization documentation note is required.";
    }
    setValidationErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    createMutation.mutate(
      {
        ...formData,
        name: formData.name.trim(),
        base_url: formData.base_url.trim(),
        description: formData.description?.trim() || null,
        authorization_note: formData.authorization_note?.trim() || null,
      },
      {
        onSuccess: (data) => {
          navigate(`/targets/${data.id}`);
        },
      }
    );
  };

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Create Assessment Target</h1>
        <p className="text-sm text-slate-400 mt-1">
          Register an approved environment and establish initial authorization bounds.
        </p>
      </div>

      <div className="rounded-lg border border-cyan-900/40 bg-cyan-950/20 p-4 text-xs text-cyan-200/90 flex items-start space-x-3">
        <Shield className="h-5 w-5 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-cyan-300">Policy Guidance: </span>
          Only configure instructor-approved targets or sandbox services. Scans targeting unauthorized domain
          infrastructure will be blocked by backend scope policy.
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5 rounded-lg border border-slate-800 bg-slate-900/60 p-6">
        <Input
          label="Target Name"
          required
          placeholder="e.g. Testbed Banking WebApp"
          value={formData.name}
          onChange={(e) => setFormData({ ...formData, name: e.target.value })}
          error={validationErrors.name}
          hint="Human-readable identifier for this target scope."
        />

        <Input
          label="Base URL / Host"
          required
          placeholder="e.g. http://localhost:8080 or http://127.0.0.1:8000"
          value={formData.base_url}
          onChange={(e) => setFormData({ ...formData, base_url: e.target.value })}
          error={validationErrors.base_url}
          hint="Primary address with scheme (http:// or https://)."
        />

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
            Description
          </label>
          <textarea
            rows={3}
            className="block w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:border-cyan-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
            placeholder="Target tech stack, port ranges, deployment topology..."
            value={formData.description || ""}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          />
        </div>

        <Input
          label="Authorization Note"
          required
          placeholder="e.g. Authorized by Prof. Smith under Course Capstone Policy 2026-A"
          value={formData.authorization_note || ""}
          onChange={(e) => setFormData({ ...formData, authorization_note: e.target.value })}
          error={validationErrors.authorization_note}
          hint="Record formal consent reference or agreement ID."
        />

        {createMutation.isError && (
          <div className="rounded-md border border-rose-900/50 bg-rose-950/20 p-3 text-xs text-rose-300 flex items-center space-x-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{createMutation.error?.message || "Failed to create target."}</span>
          </div>
        )}

        <div className="flex items-center justify-end space-x-3 pt-4 border-t border-slate-800">
          <Button type="button" variant="secondary" onClick={() => navigate("/targets")}>
            Cancel
          </Button>
          <Button type="submit" isLoading={createMutation.isPending}>
            Create Target
          </Button>
        </div>
      </form>
    </div>
  );
}

