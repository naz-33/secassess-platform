import { useState, useMemo } from "react";
import { Server, Globe, Cpu, Hash } from "lucide-react";
import { useAssessmentAssets } from "../../assessments/hooks";
import { Badge } from "../../../components/Badge";
import { Pagination } from "../../../components/Pagination";
import { LoadingState, EmptyState, ErrorState } from "../../../components/StatusStates";
import type { AssetType } from "../../../api/types";

export interface AssetsTableProps {
  assessmentId: string;
}

export function AssetsTable({ assessmentId }: AssetsTableProps) {
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  const { data: assets, isLoading, error, refetch } = useAssessmentAssets(assessmentId, {
    type: typeFilter !== "all" ? typeFilter : undefined,
  });

  const countsByType = useMemo(() => {
    const counts: Record<string, number> = { host: 0, port: 0, service: 0, endpoint: 0 };
    (assets || []).forEach((a) => {
      if (counts[a.type] !== undefined) counts[a.type]++;
    });
    return counts;
  }, [assets]);

  const totalPages = Math.ceil((assets?.length || 0) / pageSize);
  const paginatedAssets = useMemo(() => {
    if (!assets) return [];
    const start = (currentPage - 1) * pageSize;
    return assets.slice(start, start + pageSize);
  }, [assets, currentPage, pageSize]);

  if (isLoading) return <LoadingState message="Loading discovered assets..." />;
  if (error) return <ErrorState title="Failed to load assets" error={error} onRetry={() => refetch()} />;

  const getTypeBadge = (type: AssetType) => {
    switch (type) {
      case "host":
        return (
          <Badge variant="info" size="sm" icon={<Server className="h-3 w-3" />}>
            HOST
          </Badge>
        );
      case "port":
        return (
          <Badge variant="purple" size="sm" icon={<Hash className="h-3 w-3" />}>
            PORT
          </Badge>
        );
      case "service":
        return (
          <Badge variant="success" size="sm" icon={<Cpu className="h-3 w-3" />}>
            SERVICE
          </Badge>
        );
      case "endpoint":
        return (
          <Badge variant="warning" size="sm" icon={<Globe className="h-3 w-3" />}>
            ENDPOINT
          </Badge>
        );
      default:
        return <Badge variant="neutral">{type}</Badge>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Asset Type Metric Pills */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { type: "host", label: "Hosts", icon: <Server className="h-4 w-4 text-cyan-400" /> },
          { type: "port", label: "Open Ports", icon: <Hash className="h-4 w-4 text-purple-400" /> },
          { type: "service", label: "Services", icon: <Cpu className="h-4 w-4 text-emerald-400" /> },
          { type: "endpoint", label: "Web Endpoints", icon: <Globe className="h-4 w-4 text-amber-400" /> },
        ].map((item) => (
          <button
            key={item.type}
            type="button"
            onClick={() => {
              setTypeFilter(typeFilter === item.type ? "all" : item.type);
              setCurrentPage(1);
            }}
            className={`flex items-center justify-between p-3 rounded-lg border text-left transition-all ${
              typeFilter === item.type
                ? "border-cyan-500 bg-cyan-950/30 text-white"
                : "border-slate-800 bg-slate-900/60 text-slate-300 hover:border-slate-700"
            }`}
          >
            <div className="flex items-center space-x-2">
              {item.icon}
              <span className="text-xs font-medium">{item.label}</span>
            </div>
            <span className="font-mono text-sm font-bold text-slate-100">
              {countsByType[item.type] || 0}
            </span>
          </button>
        ))}
      </div>

      {/* Asset Table */}
      {(!assets || assets.length === 0) ? (
        <EmptyState
          title="No assets cataloged"
          description="Discovered network hosts, open ports, application banners, and endpoints will appear here after running scans."
        />
      ) : (
        <div className="overflow-hidden rounded-lg border border-slate-800 bg-slate-900/60 shadow">
          <table className="min-w-full divide-y divide-slate-800 text-left text-sm">
            <thead className="bg-slate-900 text-xs font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-6 py-3.5">Type</th>
                <th className="px-6 py-3.5">Asset Value</th>
                <th className="px-6 py-3.5">Discovered Details</th>
                <th className="px-6 py-3.5">Discovered At</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800 text-slate-300">
              {paginatedAssets.map((asset) => (
                <tr key={asset.id} className="hover:bg-slate-850/50">
                  <td className="px-6 py-4">{getTypeBadge(asset.type)}</td>
                  <td className="px-6 py-4 font-mono text-xs font-medium text-slate-100 break-all">
                    {asset.value}
                  </td>
                  <td className="px-6 py-4 text-xs text-slate-300">
                        {asset.details && typeof asset.details === "object" && Object.keys(asset.details).length > 0 ? (
                      <div className="space-y-0.5">
                        {"product" in asset.details && asset.details.product ? (
                          <p>
                            <span className="text-slate-500">Product: </span>
                            <span className="font-semibold text-slate-200">{String(asset.details.product)}</span>
                          </p>
                        ) : null}
                        {"version" in asset.details && asset.details.version ? (
                          <p>
                            <span className="text-slate-500">Version: </span>
                            <span className="font-mono text-cyan-300">{String(asset.details.version)}</span>
                          </p>
                        ) : null}
                        {"extra_info" in asset.details && asset.details.extra_info ? (
                          <p className="text-slate-400 text-[11px]">{String(asset.details.extra_info)}</p>
                        ) : null}
                        {!("product" in asset.details) && !("version" in asset.details) && (
                          <span className="font-mono text-[11px] text-slate-400 truncate block max-w-sm">
                            {JSON.stringify(asset.details)}
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-600">—</span>
                    )}
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-slate-400">
                    {new Date(asset.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            onPageChange={setCurrentPage}
            totalItems={assets.length}
            pageSize={pageSize}
          />
        </div>
      )}
    </div>
  );
}
