import { Filter, RotateCcw } from "lucide-react";
import { Select } from "../../../components/Select";
import { Button } from "../../../components/Button";
import type { FindingSeverity, FindingStatus, FindingSource } from "../../../api/types";

export interface FindingsFilterValues {
  assessment_id?: string;
  status?: FindingStatus | "";
  effective_severity?: FindingSeverity | "";
  category?: string;
  source?: FindingSource | "";
  scan_id?: string;
  verified_by?: string;
}

interface FindingsFiltersProps {
  values: FindingsFilterValues;
  onChange: (newValues: FindingsFilterValues) => void;
  categories: string[];
  assessments?: { id: string; name: string }[];
}

export function FindingsFilters({ values, onChange, categories, assessments }: FindingsFiltersProps) {
  const handleQuickFilter = (patch: Partial<FindingsFilterValues>) => {
    onChange({ ...values, ...patch });
  };

  const handleReset = () => {
    onChange({
      assessment_id: "",
      status: "",
      effective_severity: "",
      category: "",
      source: "",
      scan_id: "",
      verified_by: "",
    });
  };

  const hasActiveFilters = Boolean(
    values.assessment_id ||
    values.status ||
    values.effective_severity ||
    values.category ||
    values.source ||
    values.scan_id ||
    values.verified_by
  );

  return (
    <div className="space-y-3 bg-slate-900/60 p-4 rounded-lg border border-slate-800">
      {/* Quick Filter Chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 mr-1">
          <Filter className="h-3.5 w-3.5" aria-hidden="true" /> Quick Filters:
        </span>

        <button
          type="button"
          onClick={() => handleQuickFilter({ status: "unverified" })}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
            values.status === "unverified"
              ? "bg-amber-950/80 text-amber-300 border-amber-700"
              : "bg-slate-800/60 text-slate-400 border-slate-700/60 hover:text-slate-200 hover:bg-slate-800"
          }`}
        >
          Needs my review (Unverified)
        </button>

        <button
          type="button"
          onClick={() => handleQuickFilter({ status: "confirmed" })}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
            values.status === "confirmed"
              ? "bg-emerald-950/80 text-emerald-300 border-emerald-700"
              : "bg-slate-800/60 text-slate-400 border-slate-700/60 hover:text-slate-200 hover:bg-slate-800"
          }`}
        >
          Confirmed Vulnerabilities
        </button>

        <button
          type="button"
          onClick={() => handleQuickFilter({ source: "ai" })}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
            values.source === "ai"
              ? "bg-purple-950/80 text-purple-300 border-purple-700"
              : "bg-slate-800/60 text-slate-400 border-slate-700/60 hover:text-slate-200 hover:bg-slate-800"
          }`}
        >
          AI-sourced
        </button>

        {hasActiveFilters && (
          <Button
            size="sm"
            variant="ghost"
            onClick={handleReset}
            className="text-xs h-7 text-slate-400 hover:text-slate-200 gap-1 ml-auto"
          >
            <RotateCcw className="h-3 w-3" />
            Clear Filters
          </Button>
        )}
      </div>

      {/* Structured Selects */}
      <div className={`grid grid-cols-1 sm:grid-cols-2 ${assessments ? "md:grid-cols-5" : "md:grid-cols-4"} gap-3 pt-2 border-t border-slate-800/60`}>
        {assessments && (
          <Select
            label="Assessment"
            value={values.assessment_id || ""}
            onChange={(e) => onChange({ ...values, assessment_id: e.target.value })}
            options={[
              { label: "All Assessments", value: "" },
              ...assessments.map((a) => ({ label: a.name, value: a.id })),
            ]}
          />
        )}

        <Select
          label="Status"
          value={values.status || ""}
          onChange={(e) => onChange({ ...values, status: (e.target.value as FindingStatus) || "" })}
          options={[
            { label: "All Statuses", value: "" },
            { label: "Unverified", value: "unverified" },
            { label: "Confirmed", value: "confirmed" },
            { label: "False Positive", value: "false_positive" },
            { label: "Needs Testing", value: "needs_testing" },
          ]}
        />

        <Select
          label="Effective Severity"
          value={values.effective_severity || ""}
          onChange={(e) =>
            onChange({ ...values, effective_severity: (e.target.value as FindingSeverity) || "" })
          }
          options={[
            { label: "All Severities", value: "" },
            { label: "Critical", value: "critical" },
            { label: "High", value: "high" },
            { label: "Medium", value: "medium" },
            { label: "Low", value: "low" },
            { label: "Info", value: "info" },
          ]}
        />

        <Select
          label="Category"
          value={values.category || ""}
          onChange={(e) => onChange({ ...values, category: e.target.value })}
          options={[
            { label: "All Categories", value: "" },
            ...categories.map((cat) => ({ label: cat, value: cat })),
          ]}
        />

        <Select
          label="Source"
          value={values.source || ""}
          onChange={(e) => onChange({ ...values, source: (e.target.value as FindingSource) || "" })}
          options={[
            { label: "All Sources", value: "" },
            { label: "Tool", value: "tool" },
            { label: "AI-generated", value: "ai" },
          ]}
        />
      </div>
    </div>
  );
}
