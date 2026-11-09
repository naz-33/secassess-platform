import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  PieChart,
  Pie,
} from "recharts";

interface SeverityChartProps {
  confirmedBySeverity: Record<string, number>;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444", // red-500
  high: "#f97316", // orange-500
  medium: "#eab308", // yellow-500
  low: "#3b82f6", // blue-500
  info: "#94a3b8", // slate-400
};

export function SeverityDistributionChart({ confirmedBySeverity }: SeverityChartProps) {
  // Always include all 5 severity levels, including 0s
  const levels = ["critical", "high", "medium", "low", "info"];
  const data = levels.map((lvl) => ({
    severity: lvl.toUpperCase(),
    key: lvl,
    count: confirmedBySeverity?.[lvl] || 0,
  }));

  const total = data.reduce((acc, d) => acc + d.count, 0);

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Confirmed Severity Distribution
          </h2>
          <p className="text-xs text-slate-400">
            Strictly confirmed vulnerabilities only ({total} total)
          </p>
        </div>
      </div>

      <div className="h-48 w-full" aria-hidden="true">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis
              dataKey="severity"
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: "#334155" }}
            />
            <YAxis
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: "#334155" }}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#0f172a",
                borderColor: "#334155",
                borderRadius: "0.375rem",
                color: "#f8fafc",
                fontSize: "12px",
              }}
              formatter={(value: any) => [`${value} findings`, "Count"]}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry) => (
                <Cell key={entry.key} fill={SEVERITY_COLORS[entry.key] || "#94a3b8"} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Accessible Table / Text Fallback (Non-color reliant) */}
      <div className="mt-3">
        <span className="sr-only">Confirmed Findings Severity Distribution Table</span>
        <div className="grid grid-cols-5 gap-2 text-center text-xs">
          {data.map((d) => (
            <div
              key={d.key}
              className="rounded bg-slate-800/60 p-2 border border-slate-700/60"
            >
              <div className="text-[11px] font-medium text-slate-400">{d.severity}</div>
              <div className="text-base font-bold text-slate-100 mt-0.5">{d.count}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

interface CategoryChartProps {
  confirmedByCategory: Record<string, number>;
}

const CATEGORY_COLORS = [
  "#06b6d4", // cyan-500
  "#8b5cf6", // violet-500
  "#3b82f6", // blue-500
  "#10b981", // emerald-500
  "#f59e0b", // amber-500
  "#ec4899", // pink-500
  "#64748b", // slate-500
];

export function CategoryDistributionChart({ confirmedByCategory }: CategoryChartProps) {
  const entries = Object.entries(confirmedByCategory || {});
  const data = entries.map(([category, count]) => ({
    category,
    count,
  }));

  const total = data.reduce((acc, d) => acc + d.count, 0);

  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-100">
            Confirmed Findings by Category
          </h2>
          <p className="text-xs text-slate-400">
            Breakdown across vulnerability categories
          </p>
        </div>
      </div>

      {data.length === 0 ? (
        <div className="flex h-48 items-center justify-center text-xs text-slate-500">
          No confirmed category data recorded yet.
        </div>
      ) : (
        <>
          <div className="h-48 w-full" aria-hidden="true">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={data}
                  dataKey="count"
                  nameKey="category"
                  cx="50%"
                  cy="50%"
                  outerRadius={70}
                  innerRadius={35}
                  paddingAngle={2}
                >
                  {data.map((_, index) => (
                    <Cell
                      key={`cat-cell-${index}`}
                      fill={CATEGORY_COLORS[index % CATEGORY_COLORS.length]}
                    />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#0f172a",
                    borderColor: "#334155",
                    borderRadius: "0.375rem",
                    color: "#f8fafc",
                    fontSize: "12px",
                  }}
                  formatter={(val: any) => [`${val} findings`, "Count"]}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Accessible Table Fallback */}
          <div className="max-h-32 overflow-y-auto border border-slate-800 rounded bg-slate-950/40 p-2 text-xs">
            <table className="w-full text-left">
              <thead>
                <tr className="text-slate-400 border-b border-slate-800">
                  <th className="pb-1 font-medium">Category</th>
                  <th className="pb-1 text-right font-medium">Confirmed Count</th>
                  <th className="pb-1 text-right font-medium">Percentage</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {data.map((item) => (
                  <tr key={item.category}>
                    <td className="py-1 font-mono text-[11px] truncate max-w-[140px]">
                      {item.category}
                    </td>
                    <td className="py-1 text-right font-semibold">{item.count}</td>
                    <td className="py-1 text-right text-slate-400">
                      {total > 0 ? `${Math.round((item.count / total) * 100)}%` : "0%"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
