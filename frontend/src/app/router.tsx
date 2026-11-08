import React from "react";
import { createBrowserRouter, Navigate } from "react-router-dom";
import { AppShell } from "./layout/AppShell";
import { LoginPage } from "@/features/auth";
import { DashboardPage } from "@/features/dashboard";
import { TargetsPage } from "@/features/targets";
import { AssessmentsPage } from "@/features/assessments";
import { ScansPage } from "@/features/scans";
import { FindingsPage } from "@/features/findings";
import { VerificationPage } from "@/features/verification";
import { AIPage } from "@/features/ai";
import { ReportsPage } from "@/features/reports";

interface ShellRouteProps {
  element: React.ReactNode;
}

const WithShell: React.FC<ShellRouteProps> = ({ element }) => {
  return <AppShell>{element}</AppShell>;
};

export const router = createBrowserRouter([
  {
    path: "/",
    element: <WithShell element={<DashboardPage />} />,
  },
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/targets",
    element: <WithShell element={<TargetsPage />} />,
  },
  {
    path: "/assessments",
    element: <WithShell element={<AssessmentsPage />} />,
  },
  {
    path: "/scans",
    element: <WithShell element={<ScansPage />} />,
  },
  {
    path: "/findings",
    element: <WithShell element={<FindingsPage />} />,
  },
  {
    path: "/verification",
    element: <WithShell element={<VerificationPage />} />,
  },
  {
    path: "/ai",
    element: <WithShell element={<AIPage />} />,
  },
  {
    path: "/reports",
    element: <WithShell element={<ReportsPage />} />,
  },
  {
    path: "*",
    element: <Navigate to="/" replace />,
  },
]);
