import { Construction, Sparkles } from "lucide-react";

export interface PlaceholderPageProps {
  title: string;
  phase: string;
  description: string;
  badge?: string;
}

export function PlaceholderPage({ title, phase, description, badge }: PlaceholderPageProps) {
  return (
    <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
      <div className="rounded-full bg-slate-800/80 p-4 border border-slate-700 mb-4">
        <Construction className="h-8 w-8 text-cyan-400" />
      </div>
      <div className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800 text-xs font-semibold text-cyan-300 mb-3">
        <Sparkles className="h-3.5 w-3.5" />
        <span>{phase}</span>
      </div>
      <h1 className="text-2xl font-bold tracking-tight text-slate-100">{title}</h1>
      <p className="text-sm text-slate-400 max-w-md mt-2 leading-relaxed">{description}</p>
      {badge && (
        <span className="mt-4 text-xs font-mono text-slate-500 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
          Role Required: {badge}
        </span>
      )}
    </div>
  );
}

export function FindingsPlaceholderPage() {
  return (
    <PlaceholderPage
      title="Findings & Vulnerability Analysis"
      phase="Phase 8 Feature"
      description="Interactive vulnerability triaging, CVSS v3.1 calculator, evidence uploads, AI-assisted analysis via Gemini, and human verification workflows will be available in Phase 8."
    />
  );
}

export function DashboardPlaceholderPage() {
  return (
    <PlaceholderPage
      title="Security Metrics Dashboard"
      phase="Phase 9 Feature"
      description="Visual threat analytics, risk trends, severity distribution charts, and executive posture summaries using Recharts will arrive in Phase 9."
    />
  );
}

export function ReportsPlaceholderPage() {
  return (
    <PlaceholderPage
      title="Executive & Technical Reports"
      phase="Phase 9 Feature"
      description="Full DOCX report generation, assessment summary downloads, remediation roadmaps, and stakeholder exports will arrive in Phase 9."
    />
  );
}

export function UsersPlaceholderPage() {
  return (
    <PlaceholderPage
      title="User Management"
      phase="Phase 9 Admin Screen"
      badge="Admin"
      description="Administrative user provisioning, role assignments (admin / assessor / viewer), and account lifecycle management will be enabled in Phase 9."
    />
  );
}

export function AuditLogPlaceholderPage() {
  return (
    <PlaceholderPage
      title="Security Audit Trail"
      phase="Phase 9 Admin Screen"
      badge="Admin"
      description="Tamper-evident audit logs tracking all logins, scan dispatches, scope rejections, and target modifications will be visible in Phase 9."
    />
  );
}

