import React from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell,
} from "recharts";

const sampleData = [
  { severity: "Critical", count: 2, color: "#e11d48" },
  { severity: "High", count: 5, color: "#ea580c" },
  { severity: "Medium", count: 8, color: "#eab308" },
  { severity: "Low", count: 4, color: "#3b82f6" },
  { severity: "Info", count: 3, color: "#64748b" },
];

export const SeverityBarChart: React.FC = () => {
  return (
    <div className="w-full h-72">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={sampleData} margin={{ top: 10, right: 20, left: 0, bottom: 20 }}>
          <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e2e8f0" />
          <XAxis dataKey="severity" stroke="#64748b" tick={{ fontSize: 12 }} />
          <YAxis stroke="#64748b" allowDecimals={false} tick={{ fontSize: 12 }} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#ffffff",
              borderColor: "#e2e8f0",
              borderRadius: "0.5rem",
              boxShadow: "0 4px 6px -1px rgb(0 0 0 / 0.1)",
            }}
          />
          <Bar dataKey="count" radius={[6, 6, 0, 0]}>
            {sampleData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
