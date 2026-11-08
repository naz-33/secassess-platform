import React from "react";
import { Card, Button } from "@/shared/components";
import { ScanStatusBadge } from "../components/ScanStatusBadge";

export const ScansPage: React.FC = () => {
  const scans = [
    { id: "s1", tool: "Nmap", command: "nmap -sV -p 80,443,3000 juice-shop", status: "completed" as const, started: "10 mins ago" },
    { id: "s2", tool: "OWASP ZAP", command: "zap-baseline.py -t http://juice-shop:3000", status: "running" as const, started: "2 mins ago" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-800">Automated Tool Scans</h1>
          <p className="text-sm text-slate-500">
            Monitor and execute background security tool jobs (Nmap, ZAP, DNS, TLS).
          </p>
        </div>
        <Button>+ Launch Scan</Button>
      </div>

      <Card title="Recent Scan Jobs">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-slate-200 text-sm">
            <thead>
              <tr className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
                <th className="px-4 py-3">Tool</th>
                <th className="px-4 py-3">Command</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Started</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {scans.map((s) => (
                <tr key={s.id} className="hover:bg-slate-50/50">
                  <td className="px-4 py-3 font-semibold text-slate-800">{s.tool}</td>
                  <td className="px-4 py-3 font-mono text-xs text-slate-600">{s.command}</td>
                  <td className="px-4 py-3">
                    <ScanStatusBadge status={s.status} />
                  </td>
                  <td className="px-4 py-3 text-slate-500 text-xs">{s.started}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
