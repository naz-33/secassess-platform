import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import apiClient from "@/shared/api/client";
import { HealthStatus } from "@/shared/types";

interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const location = useLocation();
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [healthError, setHealthError] = useState<boolean>(false);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await apiClient.get<HealthStatus>("/health");
        setHealth(response.data);
        setHealthError(false);
      } catch {
        setHealthError(true);
      }
    };

    checkHealth();
    const interval = setInterval(checkHealth, 30000);
    return () => clearInterval(interval);
  }, []);

  const navItems = [
    { label: "Dashboard", path: "/" },
    { label: "Targets & Scope", path: "/targets" },
    { label: "Assessments", path: "/assessments" },
    { label: "Scans", path: "/scans" },
    { label: "Findings", path: "/findings" },
    { label: "Verification", path: "/verification" },
    { label: "AI Analysis", path: "/ai" },
    { label: "Reports", path: "/reports" },
  ];

  return (
    <div className="min-h-screen flex bg-slate-50">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 text-slate-300 flex flex-col justify-between shrink-0 shadow-lg">
        <div>
          {/* Brand header */}
          <div className="h-16 flex items-center px-6 border-b border-slate-800 bg-slate-950/50">
            <span className="text-lg font-bold tracking-tight text-white flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-500 ring-4 ring-sky-500/20"></span>
              SecAssess
            </span>
          </div>

          {/* Navigation Links */}
          <nav className="p-4 space-y-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    isActive
                      ? "bg-sky-600 text-white shadow-sm"
                      : "text-slate-400 hover:text-white hover:bg-slate-800/60"
                  }`}
                >
                  {item.label}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Sidebar Footer: Health Check Indicator & Auth */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/40 space-y-3">
          {/* API Status indicator */}
          <div className="flex items-center justify-between text-xs px-2 py-1.5 rounded bg-slate-800/70 border border-slate-700/50">
            <span className="text-slate-400 font-mono">API Status</span>
            <div className="flex items-center gap-1.5">
              <span
                className={`w-2 h-2 rounded-full ${
                  health?.status === "ok"
                    ? "bg-emerald-400 ring-2 ring-emerald-400/20 animate-pulse"
                    : healthError
                    ? "bg-rose-500"
                    : "bg-amber-400"
                }`}
              ></span>
              <span
                className={`font-semibold capitalize ${
                  health?.status === "ok"
                    ? "text-emerald-400"
                    : healthError
                    ? "text-rose-400"
                    : "text-amber-400"
                }`}
              >
                {health?.status || (healthError ? "Offline" : "Checking...")}
              </span>
            </div>
          </div>

          <Link
            to="/login"
            className="block text-center w-full py-1.5 px-3 rounded text-xs font-medium text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            Assessor Login
          </Link>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 overflow-y-auto">
        <header className="h-16 bg-white border-b border-slate-200 flex items-center justify-between px-8">
          <div className="text-xs text-slate-500 uppercase tracking-wider font-semibold">
            AI-Assisted Security Assessment Platform
          </div>
          <div className="text-xs text-slate-400">
            University Capstone Project
          </div>
        </header>

        <div className="p-8 max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
};
