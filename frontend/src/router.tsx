import { lazy, Suspense } from "react";
import { createBrowserRouter, Navigate } from "react-router-dom";
import { ProtectedRoute } from "./auth/ProtectedRoute";
import { RequireRole } from "./auth/RequireRole";
import { AppShell } from "./layouts/AppShell";
import { NotFoundPage } from "./layouts/ErrorBoundary";
import { LoadingState } from "./components/StatusStates";

// Lazy-loaded pages
const LoginPage = lazy(() =>
  import("./features/auth/pages/LoginPage").then((m) => ({ default: m.LoginPage }))
);
const TargetsPage = lazy(() =>
  import("./features/targets/pages/TargetsPage").then((m) => ({ default: m.TargetsPage }))
);
const TargetCreatePage = lazy(() =>
  import("./features/targets/pages/TargetCreatePage").then((m) => ({ default: m.TargetCreatePage }))
);
const TargetDetailPage = lazy(() =>
  import("./features/targets/pages/TargetDetailPage").then((m) => ({ default: m.TargetDetailPage }))
);
const AssessmentsPage = lazy(() =>
  import("./features/assessments/pages/AssessmentsPage").then((m) => ({ default: m.AssessmentsPage }))
);
const AssessmentCreatePage = lazy(() =>
  import("./features/assessments/pages/AssessmentCreatePage").then((m) => ({ default: m.AssessmentCreatePage }))
);
const AssessmentDetailPage = lazy(() =>
  import("./features/assessments/pages/AssessmentDetailPage").then((m) => ({ default: m.AssessmentDetailPage }))
);
const ScanDetailPage = lazy(() =>
  import("./features/scans/pages/ScanDetailPage").then((m) => ({ default: m.ScanDetailPage }))
);
const FindingDetailPage = lazy(() =>
  import("./features/findings/pages/FindingDetailPage").then((m) => ({ default: m.FindingDetailPage }))
);
const AllFindingsPage = lazy(() =>
  import("./features/findings/pages/AllFindingsPage").then((m) => ({ default: m.AllFindingsPage }))
);
const DashboardPage = lazy(() =>
  import("./features/dashboard/pages/DashboardPage").then((m) => ({ default: m.DashboardPage }))
);
const ReportsPage = lazy(() =>
  import("./features/reports/pages/ReportsPage").then((m) => ({ default: m.ReportsPage }))
);
const UsersPage = lazy(() =>
  import("./features/admin/pages/UsersPage").then((m) => ({ default: m.UsersPage }))
);
const AuditLogPage = lazy(() =>
  import("./features/admin/pages/AuditLogPage").then((m) => ({ default: m.AuditLogPage }))
);

export const router = createBrowserRouter([
  {
    path: "/login",
    element: (
      <Suspense fallback={<LoadingState />}>
        <LoginPage />
      </Suspense>
    ),
  },
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <AppShell />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: <Navigate to="/targets" replace />,
      },
      {
        path: "targets",
        children: [
          {
            index: true,
            element: (
              <Suspense fallback={<LoadingState />}>
                <TargetsPage />
              </Suspense>
            ),
          },
          {
            path: "new",
            element: (
              <RequireRole roles={["admin", "assessor"]} fallback={<Navigate to="/targets" replace />}>
                <Suspense fallback={<LoadingState />}>
                  <TargetCreatePage />
                </Suspense>
              </RequireRole>
            ),
          },
          {
            path: ":id",
            element: (
              <Suspense fallback={<LoadingState />}>
                <TargetDetailPage />
              </Suspense>
            ),
          },
        ],
      },
      {
        path: "assessments",
        children: [
          {
            index: true,
            element: (
              <Suspense fallback={<LoadingState />}>
                <AssessmentsPage />
              </Suspense>
            ),
          },
          {
            path: "new",
            element: (
              <RequireRole roles={["admin", "assessor"]} fallback={<Navigate to="/assessments" replace />}>
                <Suspense fallback={<LoadingState />}>
                  <AssessmentCreatePage />
                </Suspense>
              </RequireRole>
            ),
          },
          {
            path: ":id",
            element: (
              <Suspense fallback={<LoadingState />}>
                <AssessmentDetailPage />
              </Suspense>
            ),
          },
          {
            path: ":assessmentId/scans/:scanId",
            element: (
              <Suspense fallback={<LoadingState />}>
                <ScanDetailPage />
              </Suspense>
            ),
          },
          {
            path: ":assessmentId/findings/:findingId",
            element: (
              <Suspense fallback={<LoadingState />}>
                <FindingDetailPage />
              </Suspense>
            ),
          },
        ],
      },
      // Direct finding route
      {
        path: "findings/:id",
        element: (
          <Suspense fallback={<LoadingState />}>
            <FindingDetailPage />
          </Suspense>
        ),
      },
      // Findings top-level nav route -> All Findings aggregate view
      {
        path: "findings",
        element: (
          <Suspense fallback={<LoadingState />}>
            <AllFindingsPage />
          </Suspense>
        ),
      },
      // Top-level Dashboard and Reports
      {
        path: "dashboard",
        element: (
          <Suspense fallback={<LoadingState />}>
            <DashboardPage />
          </Suspense>
        ),
      },
      {
        path: "reports",
        element: (
          <Suspense fallback={<LoadingState />}>
            <ReportsPage />
          </Suspense>
        ),
      },
      // Admin screens protected by RequireRole
      {
        path: "users",
        element: (
          <RequireRole roles={["admin"]} fallback={<Navigate to="/targets" replace />}>
            <Suspense fallback={<LoadingState />}>
              <UsersPage />
            </Suspense>
          </RequireRole>
        ),
      },
      {
        path: "audit",
        element: (
          <RequireRole roles={["admin"]} fallback={<Navigate to="/targets" replace />}>
            <Suspense fallback={<LoadingState />}>
              <AuditLogPage />
            </Suspense>
          </RequireRole>
        ),
      },
      {
        path: "*",
        element: <NotFoundPage />,
      },
    ],
  },
  {
    path: "*",
    element: <NotFoundPage />,
  },
]);
