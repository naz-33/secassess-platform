import React from "react";
import { Card, Button } from "@/shared/components";
import { ScopeList } from "../components/ScopeList";

export const TargetsPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Targets & Scope Enforcement</h1>
          <p className="text-sm text-slate-500">
            Configure authorized target applications and strict boundary assets.
          </p>
        </div>
        <Button>+ Register Target</Button>
      </div>

      <Card title="Active Target: OWASP Juice Shop" subtitle="Base URL: http://juice-shop:3000">
        <p className="text-sm text-slate-600 mb-4">
          Intentionally vulnerable target authorized for security assessments. All automated scans enforce ScopeManager boundary checks prior to tool execution.
        </p>
        <ScopeList />
      </Card>
    </div>
  );
};
