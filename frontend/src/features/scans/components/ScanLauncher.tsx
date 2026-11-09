import React, { useState } from "react";
import { ShieldCheck, Play, AlertTriangle } from "lucide-react";
import { useTriggerReconScan, useTriggerWebAssessment, useAssessmentScans } from "../../assessments/hooks";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import { Select } from "../../../components/Select";
import type { ScanTool } from "../../../api/types";

export interface ScanLauncherProps {
  assessmentId: string;
  defaultTarget?: string;
}

export function ScanLauncher({ assessmentId, defaultTarget = "" }: ScanLauncherProps) {
  const [launcherMode, setLauncherMode] = useState<"recon" | "web">("recon");

  // Recon scan state
  const [reconTool, setReconTool] = useState<ScanTool>("nmap");
  const [customTarget, setCustomTarget] = useState(defaultTarget);
  const [topPorts, setTopPorts] = useState(100);
  const [timing, setTiming] = useState("-T3");
  const [serviceVersion, setServiceVersion] = useState(true);
  const [dnsRecordTypes, setDnsRecordTypes] = useState<string[]>(["A", "AAAA", "MX", "NS"]);

  // Web scan state
  const [selectedCategories, setSelectedCategories] = useState<string[]>([
    "security_headers",
    "exposed_files",
    "information_disclosure",
    "session_management",
  ]);
  const [includeZap, setIncludeZap] = useState(false);
  const [spiderMaxDepth, setSpiderMaxDepth] = useState(2);
  const [spiderMaxDuration, setSpiderMaxDuration] = useState(2);

  const { data: scans } = useAssessmentScans(assessmentId);
  const isAnyScanRunning = (scans || []).some(
    (s) => s.status === "pending" || s.status === "running"
  );

  const reconMutation = useTriggerReconScan(assessmentId);
  const webMutation = useTriggerWebAssessment(assessmentId);

  const handleReconSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isAnyScanRunning) return;

    const options: Record<string, any> = {};
    if (reconTool === "nmap") {
      options.top_ports = Number(topPorts);
      options.timing = timing;
      options.service_version = serviceVersion;
    } else if (reconTool === "dns") {
      options.record_types = dnsRecordTypes;
    }

    reconMutation.mutate({
      tool: reconTool,
      target: customTarget.trim() || undefined,
      options,
    });
  };

  const handleWebSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isAnyScanRunning) return;

    webMutation.mutate({
      categories: selectedCategories,
      include_zap: includeZap,
      zap_options: includeZap
        ? {
            spider_max_depth: Number(spiderMaxDepth),
            spider_duration_mins: Number(spiderMaxDuration),
            run_active_scan: false, // Strict safety constraint: active scanning disabled
          }
        : {},
      options: {
        delay_ms: 100,
        max_requests: 50,
      },
    });
  };

  const isSubmitting = reconMutation.isPending || webMutation.isPending;

  return (
    <div className="space-y-5">
      {/* 409 Conflict Banner if scan is currently running */}
      {isAnyScanRunning && (
        <div className="rounded-lg border border-amber-900/60 bg-amber-950/30 p-4 text-xs text-amber-200 flex items-center space-x-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0" />
          <div>
            <span className="font-semibold text-amber-300">Scan execution locked: </span>
            A scan is currently running for this assessment. Concurrent scans on the same assessment target
            are restricted to prevent load issues and race conditions.
          </div>
        </div>
      )}

      {/* Mode Selector */}
      <div className="flex border-b border-slate-800">
        <button
          type="button"
          onClick={() => setLauncherMode("recon")}
          className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors ${
            launcherMode === "recon"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Reconnaissance (Nmap / DNS)
        </button>
        <button
          type="button"
          onClick={() => setLauncherMode("web")}
          className={`px-4 py-2 text-xs font-semibold uppercase tracking-wider border-b-2 transition-colors ${
            launcherMode === "web"
              ? "border-cyan-500 text-cyan-400"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          Web Security Assessment (Headers / Files / ZAP)
        </button>
      </div>

      {/* RECON LAUNCHER */}
      {launcherMode === "recon" && (
        <form onSubmit={handleReconSubmit} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Select
              label="Reconnaissance Tool"
              options={[
                { label: "Nmap Port & Service Scanner", value: "nmap" },
                { label: "DNS Record Resolver", value: "dns" },
              ]}
              value={reconTool}
              onChange={(e) => setReconTool(e.target.value as ScanTool)}
            />

            <Input
              label="Target Hostname / IP (Defaults to Target Base)"
              placeholder={defaultTarget || "e.g. 127.0.0.1 or localhost"}
              value={customTarget}
              onChange={(e) => setCustomTarget(e.target.value)}
              hint="Scope enforcement verified on backend before dispatch."
            />
          </div>

          {reconTool === "nmap" && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 rounded-md border border-slate-800 bg-slate-950/40 p-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                  Top Ports Count (1-1000)
                </label>
                <input
                  type="number"
                  min={1}
                  max={1000}
                  value={topPorts}
                  onChange={(e) => setTopPorts(Number(e.target.value))}
                  className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-sm text-slate-100 focus:border-cyan-500 focus:outline-none"
                />
              </div>

              <Select
                label="Timing Template"
                options={[
                  { label: "-T0 (Paranoid)", value: "-T0" },
                  { label: "-T1 (Sneaky)", value: "-T1" },
                  { label: "-T2 (Polite)", value: "-T2" },
                  { label: "-T3 (Normal - Recommended)", value: "-T3" },
                  { label: "-T4 (Aggressive)", value: "-T4" },
                ]}
                value={timing}
                onChange={(e) => setTiming(e.target.value)}
                hint="-T5 strictly disallowed by policy."
              />

              <div className="flex flex-col justify-center">
                <label className="inline-flex items-center text-xs text-slate-300 cursor-pointer pt-3">
                  <input
                    type="checkbox"
                    checked={serviceVersion}
                    onChange={(e) => setServiceVersion(e.target.checked)}
                    className="mr-2 rounded text-cyan-600 focus:ring-cyan-500"
                  />
                  Service Version Detection (-sV)
                </label>
              </div>
            </div>
          )}

          {reconTool === "dns" && (
            <div className="rounded-md border border-slate-800 bg-slate-950/40 p-4">
              <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">
                Allowed DNS Query Types
              </label>
              <div className="flex flex-wrap gap-4 text-xs text-slate-300">
                {["A", "AAAA", "MX", "NS", "TXT", "CNAME"].map((type) => (
                  <label key={type} className="inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      checked={dnsRecordTypes.includes(type)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setDnsRecordTypes([...dnsRecordTypes, type]);
                        } else {
                          setDnsRecordTypes(dnsRecordTypes.filter((t) => t !== type));
                        }
                      }}
                      className="mr-1.5 rounded text-cyan-600 focus:ring-cyan-500"
                    />
                    {type}
                  </label>
                ))}
              </div>
            </div>
          )}

          <div className="flex justify-end pt-2">
            <Button
              type="submit"
              disabled={isAnyScanRunning || isSubmitting}
              isLoading={isSubmitting}
            >
              <Play className="h-4 w-4 mr-1.5" />
              Launch {reconTool.toUpperCase()} Scan
            </Button>
          </div>
        </form>
      )}

      {/* WEB ASSESSMENT LAUNCHER */}
      {launcherMode === "web" && (
        <form onSubmit={handleWebSubmit} className="space-y-4">
          <div className="rounded-md border border-cyan-900/40 bg-cyan-950/20 p-3 text-xs text-cyan-200/90 flex items-start space-x-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400 shrink-0 mt-0.5" />
            <span>
              <strong>Safety Guardrail: </strong>
              Active exploitation and destructive payloads are strictly disabled. Only non-destructive checks
              and passive vulnerability analysis run against approved targets.
            </span>
          </div>

          <div className="rounded-md border border-slate-800 bg-slate-950/40 p-4 space-y-3">
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-400">
              Evaluation Categories
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs text-slate-300">
              {[
                { id: "security_headers", label: "Security configuration and HTTPS headers" },
                { id: "exposed_files", label: "Exposed files and sensitive directories" },
                { id: "information_disclosure", label: "Information disclosure & server banners" },
                { id: "session_management", label: "Session management (cookies, flags)" },
              ].map((cat) => (
                <label key={cat.id} className="inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedCategories.includes(cat.id)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setSelectedCategories([...selectedCategories, cat.id]);
                      } else {
                        setSelectedCategories(selectedCategories.filter((c) => c !== cat.id));
                      }
                    }}
                    className="mr-2 rounded text-cyan-600 focus:ring-cyan-500"
                  />
                  {cat.label}
                </label>
              ))}
            </div>
          </div>

          {/* Optional ZAP Spider & Passive Scanner */}
          <div className="rounded-md border border-slate-800 bg-slate-950/40 p-4 space-y-3">
            <label className="inline-flex items-center text-xs font-semibold text-slate-200 cursor-pointer">
              <input
                type="checkbox"
                checked={includeZap}
                onChange={(e) => setIncludeZap(e.target.checked)}
                className="mr-2 rounded text-cyan-600 focus:ring-cyan-500"
              />
              Include OWASP ZAP Passive Scanner & Spider
            </label>

            {includeZap && (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-slate-800 animate-in fade-in duration-150">
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Spider Max Depth (1-3)</label>
                  <input
                    type="number"
                    min={1}
                    max={3}
                    value={spiderMaxDepth}
                    onChange={(e) => setSpiderMaxDepth(Number(e.target.value))}
                    className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100"
                  />
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">Spider Max Duration (Minutes)</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={spiderMaxDuration}
                    onChange={(e) => setSpiderMaxDuration(Number(e.target.value))}
                    className="w-full rounded-md border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs text-slate-100"
                  />
                </div>
              </div>
            )}
          </div>

          <div className="flex justify-end pt-2">
            <Button
              type="submit"
              disabled={isAnyScanRunning || isSubmitting || selectedCategories.length === 0}
              isLoading={isSubmitting}
            >
              <Play className="h-4 w-4 mr-1.5" />
              Launch Web Assessment
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

