import React from "react";
import { Badge, Button } from "@/shared/components";

export const ReportList: React.FC = () => {
  const reports = [
    { id: "r1", title: "Comprehensive Assessment Report - Juice Shop", format: "PDF", generated: "2026-11-08 10:45" },
    { id: "r2", title: "Executive Technical Summary - DOCX", format: "DOCX", generated: "2026-11-08 10:47" },
  ];

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead>
          <tr className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
            <th className="px-4 py-3">Report Document</th>
            <th className="px-4 py-3">Format</th>
            <th className="px-4 py-3">Generated At</th>
            <th className="px-4 py-3 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {reports.map((r) => (
            <tr key={r.id} className="hover:bg-slate-50/50">
              <td className="px-4 py-3 font-medium text-slate-800">{r.title}</td>
              <td className="px-4 py-3">
                <Badge variant="info">{r.format}</Badge>
              </td>
              <td className="px-4 py-3 text-slate-500 text-xs">{r.generated}</td>
              <td className="px-4 py-3 text-right">
                <Button size="sm" variant="outline">Download</Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
