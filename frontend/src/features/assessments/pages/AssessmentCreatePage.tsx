import React, { useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { AlertCircle } from "lucide-react";
import { useCreateAssessment } from "../hooks";
import { useTargets } from "../../targets/hooks";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import { Select } from "../../../components/Select";
import { LoadingState } from "../../../components/StatusStates";

export function AssessmentCreatePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const preselectedTarget = searchParams.get("target_id") || "";

  const { data: targets, isLoading: targetsLoading } = useTargets();
  const createMutation = useCreateAssessment();

  const [name, setName] = useState("");
  const [targetId, setTargetId] = useState(preselectedTarget);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const errs: Record<string, string> = {};
    if (!name.trim()) errs.name = "Assessment name is required.";
    if (!targetId) errs.targetId = "An authorized target must be selected.";
    setErrors(errs);
    return Object.keys(errs).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    createMutation.mutate(
      {
        name: name.trim(),
        target_id: targetId,
        status: "draft",
      },
      {
        onSuccess: (data) => {
          navigate(`/assessments/${data.id}`);
        },
      }
    );
  };

  if (targetsLoading) {
    return <LoadingState message="Loading available targets..." />;
  }

  const targetOptions = [
    { label: "-- Select Target --", value: "" },
    ...(targets || []).map((t) => ({
      label: `${t.name} (${t.base_url})`,
      value: t.id,
    })),
  ];

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      <div className="border-b border-slate-800 pb-4">
        <h1 className="text-2xl font-bold tracking-tight text-slate-100">Initialize New Assessment</h1>
        <p className="text-sm text-slate-400 mt-1">
          Create an assessment cycle linked to an approved target environment.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5 rounded-lg border border-slate-800 bg-slate-900/60 p-6">
        <Input
          label="Assessment Name"
          required
          placeholder="e.g. Q4 Web Security Review"
          value={name}
          onChange={(e) => setName(e.target.value)}
          error={errors.name}
          hint="Identifier for this testing cycle."
        />

        <Select
          label="Authorized Target"
          required
          options={targetOptions}
          value={targetId}
          onChange={(e) => setTargetId(e.target.value)}
          error={errors.targetId}
          hint="Target boundary governing all scan tool executions for this assessment."
        />

        {createMutation.isError && (
          <div className="rounded-md border border-rose-900/50 bg-rose-950/20 p-3 text-xs text-rose-300 flex items-center space-x-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{createMutation.error?.message || "Failed to create assessment."}</span>
          </div>
        )}

        <div className="flex items-center justify-end space-x-3 pt-4 border-t border-slate-800">
          <Button type="button" variant="secondary" onClick={() => navigate("/assessments")}>
            Cancel
          </Button>
          <Button type="submit" isLoading={createMutation.isPending}>
            Create Assessment
          </Button>
        </div>
      </form>
    </div>
  );
}
