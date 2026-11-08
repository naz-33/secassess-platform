import React, { useState } from "react";
import { Card, Badge, Button } from "@/shared/components";
import { FindingSeverityBadge } from "../components/FindingSeverityBadge";
import { Severity } from "@/shared/types";

export const FindingsPage: React.FC = () => {
  const [selectedFinding, setSelectedFinding] = useState<string | null>("f1");

  const findings: Array<{
    id: string;
    title: string;
    category: string;
    severity: Severity;
    status: string;
    description: string;
    remediation: string;
  }> = [
    {
      id: "f1",
      title: "SQL Injection in Login Endpoint",
      category: "A03:2021-Injection",
      severity: "critical",
      status: "unverified",
      description: "User input supplied to the 'email' field is concatenated directly into SQL queries without parameterization.",
      remediation: "Use parameterized queries or ORM query abstractions.",
    },
    {
      id: "f2",
      title: "Cross-Site Scripting (Reflected)",
      category: "A03:2021-Injection",
      severity: "high",
      status: "confirmed",
      description: "Search parameter reflected unsanitized in response HTML context.",
      remediation: "Context-aware HTML entity encoding on user input rendering.",
    },
    {
      id: "f3",
      title: "Missing Content Security Policy (CSP)",
      category: "A05:2021-Security Misconfiguration",
      severity: "medium",
      status: "unverified",
      description: "HTTP response headers do not contain a Content-Security-Policy header directive.",
      remediation: "Implement a restrictive Content-Security-Policy header.",
    },
  ];

  const current = findings.find((f) => f.id === selectedFinding) || findings[0];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Vulnerability Findings</h1>
          <p className="text-sm text-slate-500">
            Detected security weaknesses across automated and AI-assisted scanning.
          </p>
        </div>
        <Button>+ Ingest Finding</Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-1 space-y-3">
          <h2 className="text-sm font-semibold uppercase text-slate-500 tracking-wider">Findings List</h2>
          {findings.map((f) => (
            <div
              key={f.id}
              onClick={() => setSelectedFinding(f.id)}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                selectedFinding === f.id
                  ? "bg-white border-sky-500 shadow-sm ring-1 ring-sky-500"
                  : "bg-white border-slate-200 hover:border-slate-300"
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <FindingSeverityBadge severity={f.severity} />
                <Badge variant="neutral">{f.status}</Badge>
              </div>
              <h4 className="text-sm font-semibold text-slate-800">{f.title}</h4>
              <p className="text-xs text-slate-500 mt-1">{f.category}</p>
            </div>
          ))}
        </div>

        <div className="lg:col-span-2">
          <Card title="Finding Detail">
            <div className="space-y-4">
              <div className="flex items-center justify-between border-b border-slate-100 pb-3">
                <div>
                  <h3 className="text-lg font-bold text-slate-800">{current.title}</h3>
                  <p className="text-xs text-slate-500">{current.category}</p>
                </div>
                <div className="flex items-center gap-2">
                  <FindingSeverityBadge severity={current.severity} />
                  <Badge variant="info">{current.status}</Badge>
                </div>
              </div>

              <div>
                <h4 className="text-xs font-semibold uppercase text-slate-500 mb-1">Description</h4>
                <p className="text-sm text-slate-700">{current.description}</p>
              </div>

              <div>
                <h4 className="text-xs font-semibold uppercase text-slate-500 mb-1">Recommended Remediation</h4>
                <p className="text-sm text-slate-700 bg-slate-50 p-3 rounded-lg border border-slate-200">
                  {current.remediation}
                </p>
              </div>

              <div className="pt-2 flex gap-2">
                <Button size="sm">Request AI Analysis</Button>
                <Button size="sm" variant="outline">Verify Finding</Button>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
