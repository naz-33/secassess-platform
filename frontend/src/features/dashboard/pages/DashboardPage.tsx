import React from "react";
import { Card, Badge } from "@/shared/components";
import { SeverityBarChart } from "../components/SeverityBarChart";

export const DashboardPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Security Dashboard</h1>
          <p className="text-sm text-slate-500">
            Overview of assessment targets, scan posture, and identified vulnerabilities.
          </p>
        </div>
        <Badge variant="success">Workspace Active</Badge>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <div className="text-xs font-medium text-slate-500 uppercase">Targets</div>
          <div className="text-2xl font-bold text-slate-800 mt-1">1</div>
          <div className="text-xs text-emerald-600 mt-1">OWASP Juice Shop</div>
        </Card>
        <Card>
          <div className="text-xs font-medium text-slate-500 uppercase">Assessments</div>
          <div className="text-2xl font-bold text-slate-800 mt-1">1</div>
          <div className="text-xs text-slate-500 mt-1">Cycle 2026-Q1</div>
        </Card>
        <Card>
          <div className="text-xs font-medium text-slate-500 uppercase">Active Scans</div>
          <div className="text-2xl font-bold text-slate-800 mt-1">2</div>
          <div className="text-xs text-sky-600 mt-1">Nmap / ZAP</div>
        </Card>
        <Card>
          <div className="text-xs font-medium text-slate-500 uppercase">Total Findings</div>
          <div className="text-2xl font-bold text-slate-800 mt-1">22</div>
          <div className="text-xs text-rose-600 mt-1">2 Critical, 5 High</div>
        </Card>
      </div>

      <Card title="Findings by Severity" subtitle="Vulnerability distribution across active assessments">
        <SeverityBarChart />
      </Card>
    </div>
  );
};
