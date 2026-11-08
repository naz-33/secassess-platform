import React from "react";
import { Badge } from "@/shared/components";

export const ScopeList: React.FC = () => {
  const scopeItems = [
    { id: "1", asset: "http://juice-shop:3000", in_scope: true, notes: "Web application UI and REST API" },
    { id: "2", asset: "http://juice-shop:3000/ftp", in_scope: true, notes: "Exposed FTP directory challenge" },
    { id: "3", asset: "*.secassess.local", in_scope: true, notes: "Internal Docker network domain" },
  ];

  return (
    <div className="overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-200 text-sm">
        <thead>
          <tr className="bg-slate-50 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">
            <th className="px-4 py-3">Asset</th>
            <th className="px-4 py-3">Scope Boundary</th>
            <th className="px-4 py-3">Notes</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {scopeItems.map((item) => (
            <tr key={item.id} className="hover:bg-slate-50/50">
              <td className="px-4 py-3 font-mono text-xs text-slate-800">{item.asset}</td>
              <td className="px-4 py-3">
                <Badge variant={item.in_scope ? "success" : "danger"}>
                  {item.in_scope ? "In Scope" : "Out of Scope"}
                </Badge>
              </td>
              <td className="px-4 py-3 text-slate-600">{item.notes}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
