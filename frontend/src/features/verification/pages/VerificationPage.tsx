import React from "react";
import { Card, Badge } from "@/shared/components";
import { VerificationActions } from "../components/VerificationActions";

export const VerificationPage: React.FC = () => {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-800">Assessor Verification Workflow</h1>
        <p className="text-sm text-slate-500">
          Human-in-the-loop review queue to validate vulnerability candidates before final reporting.
        </p>
      </div>

      <Card title="Pending Review: SQL Injection in Login Endpoint" subtitle="Discovered by automated web scan">
        <div className="space-y-4">
          <div className="bg-slate-50 p-4 rounded-lg border border-slate-200">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold uppercase text-slate-600">Candidate Evidence</span>
              <Badge variant="warning">Awaiting Assessor Decision</Badge>
            </div>
            <pre className="text-xs font-mono text-slate-700 overflow-x-auto p-2 bg-white rounded border border-slate-200">
              {`POST /rest/user/login HTTP/1.1\nPayload: {"email": "' OR 1=1--", "password": "x"}`}
            </pre>
          </div>

          <VerificationActions />
        </div>
      </Card>
    </div>
  );
};
