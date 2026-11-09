import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  FileText,
  Download,
  Copy,
  Check,
  RefreshCw,
  FileSpreadsheet,
  ShieldAlert,
} from "lucide-react";
import {
  useAssessmentReports,
  useGenerateReport,
  useReportPoller,
  useAssessmentDashboard,
} from "../../dashboard/hooks";
import { reportsApi } from "../../dashboard/api";
import { useAuth } from "../../../auth/AuthContext";
import { RequireRole } from "../../../auth/RequireRole";
import { Button } from "../../../components/Button";
import { Badge } from "../../../components/Badge";
import { Input } from "../../../components/Input";
import { LoadingState, ErrorState, EmptyState } from "../../../components/StatusStates";
import type { ReportRead } from "../../../api/types";

interface AssessmentReportsViewProps {
  assessmentId: string;
}

export function AssessmentReportsView({ assessmentId }: AssessmentReportsViewProps) {
  const { role } = useAuth();
  const canGenerate = role === "admin" || role === "assessor";

  // Data fetching
  const {
    data: reports,
    isLoading: isLoadingReports,
    error: reportsError,
    refetch: refetchReports,
  } = useAssessmentReports(assessmentId);

  const { data: dashboardData } = useAssessmentDashboard(assessmentId);

  // Form states
  const [format, setFormat] = useState<"docx" | "pdf">("docx");
  const [includeAppendix, setIncludeAppendix] = useState(true);
  const [title, setTitle] = useState("");
  const [notes, setNotes] = useState("");

  // Generation status states
  const [activeReportId, setActiveReportId] = useState<string | null>(null);
  const [conflictError, setConflictError] = useState<string | null>(null);
  const [pdfUnavailableError, setPdfUnavailableError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(null);
  const [copiedSha, setCopiedSha] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [exportingType, setExportingType] = useState<"csv" | "json" | null>(null);

  const generateMutation = useGenerateReport(assessmentId);

  // Poll active generation
  const { isPolling, durationExceeded } = useReportPoller(
    activeReportId,
    {
      onCompleted: () => {
        refetchReports();
      },
      onFailed: (rep: ReportRead) => {
        setGeneralError(rep.error || "Report generation failed on backend.");
      },
    }
  );

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setConflictError(null);
    setPdfUnavailableError(null);
    setGeneralError(null);

    try {
      const result = await generateMutation.mutateAsync({
        format,
        include_unverified_appendix: includeAppendix,
        title: title.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      setActiveReportId(result.id);
    } catch (err: any) {
      if (err.status === 409) {
        setConflictError(
          err.message || "A report compilation is already running for this assessment. Please wait for it to finish."
        );
      } else if (err.status === 501 || (err.status === 422 && /pdf/i.test(err.message))) {
        setPdfUnavailableError(
          "PDF conversion not available: LibreOffice is not installed or configured on the server. Please select DOCX format instead."
        );
      } else {
        setGeneralError(err.message || "Failed to start report generation.");
      }
    }
  };

  const handleDownload = async (report: ReportRead) => {
    try {
      setDownloadingId(report.id);
      const { blob, filename } = await reportsApi.downloadReport(report.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `report_${report.version}.${report.format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      alert(`Download failed: ${err.message}`);
    } finally {
      setDownloadingId(null);
    }
  };

  const handleExportFindings = async (fmt: "csv" | "json") => {
    try {
      setExportingType(fmt);
      const { blob, filename } = await reportsApi.exportFindings(assessmentId, fmt, "confirmed");
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `findings_export_${assessmentId}.${fmt}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      alert(`Findings export failed: ${err.message}`);
    } finally {
      setExportingType(null);
    }
  };

  const copySha = (sha: string) => {
    navigator.clipboard.writeText(sha);
    setCopiedSha(sha);
    setTimeout(() => setCopiedSha(null), 2500);
  };

  if (isLoadingReports) {
    return <LoadingState message="Loading assessment reports..." />;
  }

  if (reportsError) {
    return (
      <ErrorState
        title="Failed to load reports"
        error={reportsError}
        onRetry={() => refetchReports()}
      />
    );
  }

  // Pre-generation readiness checklist data
  const unverifiedCount = dashboardData?.findings?.unverified_count ?? 0;
  const confirmedCount = dashboardData?.findings?.verified_count ?? 0;
  const hasApprovedExecutiveSummary = dashboardData?.ai?.has_approved_executive_summary ?? false;

  return (
    <div className="space-y-8">
      {/* Export Section */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 p-4 rounded-lg border border-slate-800 bg-slate-900/60">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
            <FileSpreadsheet className="h-4 w-4 text-cyan-400" />
            <span>Raw Finding Exports (Authenticated)</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Export confirmed assessment findings directly via authenticated stream download.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <Button
            size="sm"
            variant="outline"
            isLoading={exportingType === "csv"}
            onClick={() => handleExportFindings("csv")}
          >
            <Download className="h-3.5 w-3.5 mr-1.5" />
            Export CSV
          </Button>
          <Button
            size="sm"
            variant="outline"
            isLoading={exportingType === "json"}
            onClick={() => handleExportFindings("json")}
          >
            <Download className="h-3.5 w-3.5 mr-1.5" />
            Export JSON
          </Button>
        </div>
      </div>

      {/* Generation Form & Readiness Checklist (Assessor/Admin) */}
      <RequireRole roles={["admin", "assessor"]}>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Readiness Checklist */}
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <div className="flex items-center space-x-2 border-b border-slate-800 pb-3">
              <ShieldAlert className="h-4 w-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Report Readiness Checklist
              </h3>
            </div>

            <div className="space-y-3 text-xs">
              {/* Unverified Findings Notice */}
              <div className="p-2.5 rounded border border-slate-800 bg-slate-950/60 space-y-1">
                <div className="flex items-center justify-between font-medium">
                  <span className="text-slate-300">Unverified Findings:</span>
                  <Badge variant={unverifiedCount > 0 ? "warning" : "success"} size="sm">
                    {unverifiedCount}
                  </Badge>
                </div>
                {unverifiedCount > 0 ? (
                  <p className="text-amber-400/90 text-[11px] leading-tight">
                    Warning: Report will be marked as "Draft" because unverified candidate findings remain.
                  </p>
                ) : (
                  <p className="text-emerald-400/90 text-[11px] leading-tight">
                    All findings have been verified by an assessor.
                  </p>
                )}
              </div>

              {/* Confirmed Findings Count */}
              <div className="p-2.5 rounded border border-slate-800 bg-slate-950/60 space-y-1">
                <div className="flex items-center justify-between font-medium">
                  <span className="text-slate-300">Confirmed Findings:</span>
                  <Badge variant={confirmedCount > 0 ? "success" : "neutral"} size="sm">
                    {confirmedCount}
                  </Badge>
                </div>
                {confirmedCount === 0 && (
                  <p className="text-slate-400 text-[11px] leading-tight">
                    Notice: Zero confirmed findings recorded. The report will reflect a clean or pending posture.
                  </p>
                )}
              </div>

              {/* Approved Executive Summary */}
              <div className="p-2.5 rounded border border-slate-800 bg-slate-950/60 space-y-1">
                <div className="flex items-center justify-between font-medium">
                  <span className="text-slate-300">Executive Summary:</span>
                  <Badge variant={hasApprovedExecutiveSummary ? "success" : "warning"} size="sm">
                    {hasApprovedExecutiveSummary ? "Approved" : "Missing"}
                  </Badge>
                </div>
                {!hasApprovedExecutiveSummary ? (
                  <p className="text-amber-400/90 text-[11px] leading-tight">
                    No approved AI executive summary exists. You can review and approve a draft in the{" "}
                    <Link
                      to={`/assessments/${assessmentId}`}
                      className="underline text-cyan-400 hover:text-cyan-300"
                    >
                      AI Summary section
                    </Link>
                    .
                  </p>
                ) : (
                  <p className="text-emerald-400/90 text-[11px] leading-tight">
                    Approved executive narrative ready for inclusion.
                  </p>
                )}
              </div>
            </div>
          </div>

          {/* Report Generation Form */}
          <div className="lg:col-span-2 rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-2">
                <FileText className="h-4 w-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-100">
                  Compile New Assessment Report
                </h3>
              </div>
            </div>

            {/* Error alerts */}
            {conflictError && (
              <div role="alert" className="p-3 rounded bg-amber-950/60 border border-amber-800 text-amber-200 text-xs">
                {conflictError}
              </div>
            )}
            {pdfUnavailableError && (
              <div role="alert" className="p-3 rounded bg-amber-950/60 border border-amber-800 text-amber-200 text-xs">
                {pdfUnavailableError}
              </div>
            )}
            {generalError && (
              <div role="alert" className="p-3 rounded bg-rose-950/60 border border-rose-800 text-rose-200 text-xs">
                {generalError}
              </div>
            )}

            <form onSubmit={handleGenerate} className="space-y-4 text-xs">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block font-medium text-slate-300 mb-1">
                    Output Format
                  </label>
                  <select
                    value={format}
                    onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFormat(e.target.value as "docx" | "pdf")}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="docx">Microsoft Word (DOCX)</option>
                    <option value="pdf">Adobe PDF (PDF)</option>
                  </select>
                </div>

                <div className="flex items-center pt-5">
                  <label className="flex items-center space-x-2 cursor-pointer text-slate-300">
                    <input
                      type="checkbox"
                      checked={includeAppendix}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) => setIncludeAppendix(e.target.checked)}
                      className="rounded border-slate-700 bg-slate-950 text-cyan-600 focus:ring-0"
                    />
                    <span>Include Unverified Findings Appendix</span>
                  </label>
                </div>
              </div>

              <div>
                <Input
                  label="Custom Report Title (Optional)"
                  placeholder="e.g. Q4 Web Application Security Assessment"
                  value={title}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTitle(e.target.value)}
                />
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">
                  Report Executive Notes / Scope Addendum (Optional)
                </label>
                <textarea
                  rows={2}
                  value={notes}
                  onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) => setNotes(e.target.value)}
                  placeholder="Additional context or notes for report stakeholders..."
                  className="w-full bg-slate-950 border border-slate-800 rounded p-2.5 text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="pt-2 flex items-center justify-between">
                <div className="text-[11px] text-slate-400">
                  {isPolling && (
                    <span className="flex items-center text-cyan-400">
                      <RefreshCw className="h-3 w-3 animate-spin mr-1.5" />
                      Compiling report... polling status.
                    </span>
                  )}
                  {durationExceeded && (
                    <span className="text-amber-400">
                      Report compilation is taking longer than expected. Check the reports table below shortly.
                    </span>
                  )}
                </div>

                <Button
                  type="submit"
                  isLoading={generateMutation.isPending || isPolling}
                  disabled={generateMutation.isPending || isPolling}
                >
                  Generate Report
                </Button>
              </div>
            </form>
          </div>
        </div>
      </RequireRole>

      {/* Generated Reports Table */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-slate-100 flex items-center space-x-2">
            <FileText className="h-4 w-4 text-cyan-400" />
            <span>Generated Reports</span>
          </h2>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => refetchReports()}
            title="Refresh list"
          >
            <RefreshCw className="h-3.5 w-3.5 mr-1" />
            Refresh
          </Button>
        </div>

        {reports && reports.length > 0 ? (
          <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400">
                  <tr>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Version</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Format</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Status</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Generated At</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Confirmed / Unverified</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">Size</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider">SHA-256 Digest</th>
                    <th className="py-3 px-4 font-semibold uppercase tracking-wider text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 text-slate-300">
                  {reports.map((report: ReportRead) => (
                    <tr key={report.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 font-mono font-medium text-slate-100">
                        v{report.version}
                      </td>
                      <td className="py-3 px-4 uppercase font-semibold text-slate-300">
                        {report.format}
                      </td>
                      <td className="py-3 px-4">
                        <Badge
                          size="sm"
                          variant={
                            report.status === "completed"
                              ? "success"
                              : report.status === "failed"
                              ? "danger"
                              : "warning"
                          }
                        >
                          {report.status}
                        </Badge>
                        {report.error && (
                          <span className="block text-[10px] text-rose-400 truncate max-w-xs mt-0.5">
                            {report.error}
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {report.generated_at
                          ? new Date(report.generated_at).toLocaleString()
                          : "In progress"}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        <span className="text-emerald-400">
                          {report.confirmed_count_at_generation}
                        </span>{" "}
                        /{" "}
                        <span className="text-amber-400">
                          {report.unverified_count_at_generation}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-400">
                        {report.size_bytes
                          ? `${(report.size_bytes / 1024).toFixed(1)} KB`
                          : "—"}
                      </td>
                      <td className="py-3 px-4 font-mono">
                        {report.sha256 ? (
                          <div className="flex items-center space-x-1.5">
                            <span className="text-[10px] text-slate-400 truncate max-w-[120px]">
                              {report.sha256}
                            </span>
                            <button
                              onClick={() => copySha(report.sha256!)}
                              className="text-slate-400 hover:text-cyan-400 p-1 rounded"
                              title="Copy SHA-256 Digest"
                            >
                              {copiedSha === report.sha256 ? (
                                <Check className="h-3 w-3 text-emerald-400" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </button>
                          </div>
                        ) : (
                          <span className="text-slate-500">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right">
                        {report.status === "completed" && (
                          <Button
                            size="sm"
                            variant="primary"
                            isLoading={downloadingId === report.id}
                            onClick={() => handleDownload(report)}
                            title="Download Report (Authenticated)"
                          >
                            <Download className="h-3.5 w-3.5 mr-1" />
                            Download
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        ) : (
          <EmptyState
            title="No reports compiled yet"
            description={
              canGenerate
                ? "Configure the parameters above to compile your first assessment report."
                : "No assessment reports have been generated yet."
            }
          />
        )}
      </div>
    </div>
  );
}
