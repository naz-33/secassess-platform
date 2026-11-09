import { useState } from "react";
import { Link, useLocation, Outlet } from "react-router-dom";
import {
  Shield,
  Layers,
  Terminal,
  BarChart3,
  FileText,
  Users,
  ScrollText,
  LogOut,
  Menu,
  X,
  AlertOctagon,
} from "lucide-react";
import { useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { RequireRole } from "../auth/RequireRole";
import { AIStatusIndicator } from "../features/ai/components/AIStatusIndicator";

export function AppShell() {
  const { user, role, logout } = useAuth();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { label: "Targets & Scope", path: "/targets", icon: <Shield className="h-4 w-4" /> },
    { label: "Assessments", path: "/assessments", icon: <Layers className="h-4 w-4" /> },
    { label: "Findings", path: "/findings", icon: <Terminal className="h-4 w-4" /> },
    { label: "Dashboard", path: "/dashboard", icon: <BarChart3 className="h-4 w-4" /> },
    { label: "Reports", path: "/reports", icon: <FileText className="h-4 w-4" /> },
  ];

  const adminNavItems = [
    { label: "Users", path: "/users", icon: <Users className="h-4 w-4" /> },
    { label: "Audit Log", path: "/audit", icon: <ScrollText className="h-4 w-4" /> },
  ];

  const getRoleBadgeVariant = (r?: string | null) => {
    switch (r) {
      case "admin":
        return "purple";
      case "assessor":
        return "info";
      default:
        return "neutral";
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden">
      {/* Sidebar for Desktop */}
      <aside className="hidden md:flex md:w-64 md:flex-col md:inset-y-0 border-r border-slate-800 bg-slate-900/80 backdrop-blur">
        <div className="flex flex-col flex-1 min-h-0">
          {/* Logo / Header */}
          <div className="flex items-center h-16 shrink-0 px-5 border-b border-slate-800">
            <div className="flex items-center space-x-2.5">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-600/20 border border-cyan-500/40 text-cyan-400">
                <Shield className="h-5 w-5" />
              </div>
              <span className="font-bold text-base tracking-tight text-white">SecAssess</span>
            </div>
          </div>

          {/* Navigation Links */}
          <div className="flex-1 flex flex-col justify-between overflow-y-auto px-3 py-4">
            <nav className="space-y-1">
              <span className="px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Assessment Core
              </span>
              <div className="mt-2 space-y-1">
                {navItems.map((item) => {
                  const isActive = location.pathname.startsWith(item.path);
                  return (
                    <Link
                      key={item.path}
                      to={item.path}
                      className={`flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${isActive
                          ? "bg-cyan-600/15 text-cyan-400 font-semibold border-l-2 border-cyan-400"
                          : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                        }`}
                    >
                      <div className="flex items-center space-x-2.5">
                        {item.icon}
                        <span>{item.label}</span>
                      </div>
                    </Link>
                  );
                })}
              </div>

              {/* Admin Placeholders */}
              <RequireRole roles={["admin"]}>
                <div className="pt-6">
                  <span className="px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                    Administration
                  </span>
                  <div className="mt-2 space-y-1">
                    {adminNavItems.map((item) => {
                      const isActive = location.pathname.startsWith(item.path);
                      return (
                        <Link
                          key={item.path}
                          to={item.path}
                          className={`flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${isActive
                              ? "bg-cyan-600/15 text-cyan-400 font-semibold border-l-2 border-cyan-400"
                              : "text-slate-400 hover:bg-slate-800 hover:text-slate-200"
                            }`}
                        >
                          <div className="flex items-center space-x-2.5">
                            {item.icon}
                            <span>{item.label}</span>
                          </div>
                        </Link>
                      );
                    })}
                  </div>
                </div>
              </RequireRole>
            </nav>

            {/* Bottom User Profile */}
            <div className="pt-4 border-t border-slate-800 space-y-3">
              <div className="px-3">
                <p className="text-xs font-semibold text-slate-200 truncate">{user?.name || "User"}</p>
                <div className="flex items-center justify-between mt-1">
                  <Badge variant={getRoleBadgeVariant(role)} size="sm">
                    {role?.toUpperCase() || "VIEWER"}
                  </Badge>
                  <button
                    onClick={logout}
                    className="text-slate-400 hover:text-rose-400 text-xs flex items-center space-x-1"
                    title="Sign out"
                  >
                    <LogOut className="h-3.5 w-3.5" />
                    <span>Sign Out</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Top Header Notice Bar */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/60 px-4 sm:px-6 flex items-center justify-between shrink-0">
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden text-slate-400 hover:text-white p-1"
              aria-label="Toggle navigation"
            >
              {mobileMenuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            {/* Mandatory authorized testing notice */}
            <div className="flex items-center space-x-2 text-xs font-medium text-amber-400/90 bg-amber-950/30 px-3 py-1 rounded border border-amber-900/50">
              <AlertOctagon className="h-3.5 w-3.5 shrink-0" />
              <span>Authorized testing only: synthetic data on approved targets</span>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <AIStatusIndicator />
            <span className="hidden sm:inline-block text-xs text-slate-400 font-mono">
              {user?.email}
            </span>
            <Badge variant={getRoleBadgeVariant(role)} size="sm">
              {role?.toUpperCase() || "VIEWER"}
            </Badge>
          </div>
        </header>

        {/* Mobile menu dropdown */}
        {mobileMenuOpen && (
          <div className="md:hidden bg-slate-900 border-b border-slate-800 px-4 py-3 space-y-1">
            {navItems.map((item) => (
              <Link
                key={item.path}
                to={item.path}
                onClick={() => setMobileMenuOpen(false)}
                className="block px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 rounded"
              >
                {item.label}
              </Link>
            ))}
            <RequireRole roles={["admin"]}>
              {adminNavItems.map((item) => (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => setMobileMenuOpen(false)}
                  className="block px-3 py-2 text-xs font-medium text-slate-300 hover:bg-slate-800 rounded"
                >
                  {item.label}
                </Link>
              ))}
            </RequireRole>
            <div className="pt-2 border-t border-slate-800">
              <button
                onClick={logout}
                className="w-full text-left px-3 py-2 text-xs text-rose-400 hover:bg-slate-800 rounded"
              >
                Sign Out
              </button>
            </div>
          </div>
        )}

        {/* Main Routed Page Content */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
