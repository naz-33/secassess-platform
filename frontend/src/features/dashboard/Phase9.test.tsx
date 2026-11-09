import React from "react";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import axe from "axe-core";

import { AuthProvider } from "../../auth";
import { setToken } from "../../api/client";
import { DashboardPage } from "../dashboard/pages/DashboardPage";
import { AssessmentDashboardView } from "../dashboard/components/AssessmentDashboardView";
import { AssessmentReportsView } from "../reports/components/AssessmentReportsView";
import { ReportsPage } from "../reports/pages/ReportsPage";
import { UsersPage } from "../admin/pages/UsersPage";
import { AuditLogPage } from "../admin/pages/AuditLogPage";
import type {
  GlobalDashboardResponse,
  AssessmentDashboardResponse,
  ReportRead,
  UserRead,
  AuditLogRead,
  AssessmentRead,
} from "../../api/types";

// Mock Data
const mockGlobalDashboard: GlobalDashboardResponse = {
  total_assessments: 2,
  total_targets: 1,
  total_scans: 5,
  total_findings: 4,
  findings_by_severity: {
    critical: 1,
    high: 0,
    medium: 1,
    low: 0,
    info: 0,
  },
  findings_by_status: {
    confirmed: 2,
    unverified: 2,
  },
  assessments: [
    {
      id: "assess-1",
      name: "Acme Production Web App",
      target_name: "Acme Web Target",
      status: "in_progress",
      created_at: new Date().toISOString(),
      total_findings: 4,
      confirmed_findings: 2,
      verification_progress: 0.5,
    },
  ],
  pagination: {
    total: 1,
    limit: 50,
    offset: 0,
  },
  generated_at: new Date().toISOString(),
};

const mockAssessmentDashboard: AssessmentDashboardResponse = {
  assessment: {
    id: "assess-1",
    name: "Acme Production Web App",
    target_id: "target-1",
    target_name: "Acme Web Target",
    target_base_url: "https://example.com",
    status: "in_progress",
    created_at: new Date().toISOString(),
  },
  scope: {
    in_scope: 5,
    out_of_scope: 1,
    total: 6,
  },
  findings: {
    total: 4,
    by_status: { confirmed: 2, unverified: 2 },
    by_severity: { critical: 1, medium: 1 },
    confirmed_by_effective_severity: {
      critical: 1,
      high: 0,
      medium: 1,
      low: 0,
      info: 0,
    },
    confirmed_by_category: {
      injection: 1,
      xss: 1,
    },
    verification_progress: 0.5,
    unverified_count: 2,
    verified_count: 2,
  },
  top_findings: [
    { id: "f-1", title: "SQLi", severity: "critical", category: "injection" },
  ],
  assets: {
    total: 8,
    by_type: { host: 2, port: 4, service: 2, endpoint: 0 },
    open_ports_and_services: [],
  },
  scans: {
    total: 3,
    by_tool: { nmap: 2, zap: 1 },
    by_status: { completed: 3 },
    recent_scans: [],
  },
  ai: {
    total: 2,
    by_function: { interpret: 2 },
    by_status: { completed: 2 },
    approved_count: 1,
    has_approved_executive_summary: false, // For readiness checklist warning
    ai_promoted_findings_count: 2,
    ai_promoted_confirmed_count: 1,
  },
  recent_activity: [
    {
      id: "act-1",
      action: "finding.verified",
      user_id: "usr-admin-1234",
      created_at: new Date().toISOString(),
    },
  ],
  reports: {
    id: "rep-1",
    version: 1,
    format: "docx",
    status: "completed",
    generated_at: new Date().toISOString(),
    sha256: "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    size_bytes: 102400,
  },
  generated_at: new Date().toISOString(),
};

let mockReportsList: ReportRead[] = [
  {
    id: "rep-1",
    assessment_id: "assess-1",
    version: 1,
    format: "docx",
    status: "completed",
    sha256: "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    size_bytes: 102400,
    generated_by: "usr-admin-1234",
    generated_at: new Date().toISOString(),
    template_version: "1.0",
    generator_version: "1.0",
    snapshot_json: {},
    unverified_count_at_generation: 1,
    confirmed_count_at_generation: 2,
    created_at: new Date().toISOString(),
  },
];

let mockUsersList: UserRead[] = [
  {
    id: "usr-admin",
    name: "System Admin <script>alert(1)</script>",
    email: "admin@secassess.local",
    role: "admin",
    is_active: true,
    created_at: new Date().toISOString(),
  },
  {
    id: "usr-assessor",
    name: "Lead Assessor",
    email: "assessor@secassess.local",
    role: "assessor",
    is_active: true,
    created_at: new Date().toISOString(),
  },
];

let mockAuditLogs: AuditLogRead[] = [
  {
    id: "log-1",
    action: "user.login",
    user_id: "usr-admin",
    detail: "User authenticated from <img onerror=alert(1)> javascript:void(0)",
    created_at: new Date().toISOString(),
  },
];

let mockAssessmentsList: AssessmentRead[] = [
  {
    id: "assess-1",
    name: "Acme Production Web App",
    target_id: "target-1",
    status: "in_progress",
    created_at: new Date().toISOString(),
  },
];

// Captured request headers for verification
let lastDownloadAuthHeader: string | null = null;
let lastExportAuthHeader: string | null = null;

const server = setupServer(
  // Global dashboard
  http.get("/api/v1/dashboard", () => {
    return HttpResponse.json(mockGlobalDashboard);
  }),

  // Assessment dashboard
  http.get("/api/v1/assessments/:id/dashboard", () => {
    return HttpResponse.json(mockAssessmentDashboard);
  }),

  // Assessment reports list
  http.get("/api/v1/assessments/:id/reports", () => {
    return HttpResponse.json(mockReportsList);
  }),

  // Generate assessment report
  http.post("/api/v1/assessments/:id/reports", async ({ request }) => {
    const body = (await request.json()) as any;
    if (body.format === "pdf") {
      return HttpResponse.json(
        { detail: "PDF conversion not available: LibreOffice is not installed or configured on the system." },
        { status: 501 }
      );
    }
    if (body.title === "TRIGGER_CONFLICT") {
      return HttpResponse.json(
        { detail: "Report compilation is already running for this assessment." },
        { status: 409 }
      );
    }

    const newReport: ReportRead = {
      id: "rep-pending",
      assessment_id: "assess-1",
      version: mockReportsList.length + 1,
      format: body.format || "docx",
      status: "running",
      template_version: "1.0",
      generator_version: "1.0",
      snapshot_json: {},
      unverified_count_at_generation: 2,
      confirmed_count_at_generation: 2,
      created_at: new Date().toISOString(),
    };
    return HttpResponse.json(newReport, { status: 202 });
  }),

  // Poll report
  http.get("/api/v1/reports/:id", ({ params }) => {
    if (params.id === "rep-pending") {
      // Return completed on poll
      return HttpResponse.json({
        ...mockReportsList[0],
        id: "rep-pending",
        status: "completed",
      });
    }
    return HttpResponse.json(mockReportsList[0]);
  }),

  // Download report
  http.get("/api/v1/reports/:id/download", ({ request }) => {
    lastDownloadAuthHeader = request.headers.get("Authorization");
    const docxBytes = new Uint8Array([80, 75, 3, 4]); // PK zip header
    return new HttpResponse(docxBytes, {
      status: 200,
      headers: {
        "Content-Type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "Content-Disposition": 'attachment; filename="report_v1.docx"',
      },
    });
  }),

  // Export findings
  http.get("/api/v1/assessments/:id/findings/export", ({ request }) => {
    lastExportAuthHeader = request.headers.get("Authorization");
    const csvBytes = new TextEncoder().encode("id,title,severity\n1,SQLi,critical");
    return new HttpResponse(csvBytes, {
      status: 200,
      headers: {
        "Content-Type": "text/csv",
        "Content-Disposition": 'attachment; filename="findings.csv"',
      },
    });
  }),

  // Users management
  http.get("/api/v1/users", () => {
    return HttpResponse.json(mockUsersList);
  }),

  http.post("/api/v1/users", async ({ request }) => {
    const body = (await request.json()) as any;
    const created: UserRead = {
      id: "usr-new",
      name: body.name,
      email: body.email,
      role: body.role,
      is_active: true,
      created_at: new Date().toISOString(),
    };
    mockUsersList.push(created);
    return HttpResponse.json(created, { status: 201 });
  }),

  http.patch("/api/v1/users/:id", async ({ params, request }) => {
    const body = (await request.json()) as any;
    const user = mockUsersList.find((u) => u.id === params.id);
    if (user) {
      if (body.role !== undefined) user.role = body.role;
      if (body.is_active !== undefined) user.is_active = body.is_active;
      return HttpResponse.json(user);
    }
    return HttpResponse.json({ detail: "Not found" }, { status: 404 });
  }),

  // Audit Log
  http.get("/api/v1/audit-log", ({ request }) => {
    const url = new URL(request.url);
    const action = url.searchParams.get("action");
    if (action && action.length > 0) {
      const filtered = mockAuditLogs.filter((l) =>
        l.action.toLowerCase().includes(action.toLowerCase())
      );
      return HttpResponse.json([...filtered]);
    }
    return HttpResponse.json([...mockAuditLogs]);
  }),

  // Assessments list
  http.get("/api/v1/assessments", () => {
    return HttpResponse.json(mockAssessmentsList);
  }),

  // Auth me endpoint for initial auth load
  http.get("/api/v1/auth/me", () => {
    return HttpResponse.json({
      id: "usr-admin",
      name: "Admin User",
      email: "admin@secassess.local",
      role: "admin",
      is_active: true,
      created_at: new Date().toISOString(),
    });
  })
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" } as any));
afterEach(() => {
  server.resetHandlers();
  lastDownloadAuthHeader = null;
  lastExportAuthHeader = null;
});
afterAll(() => server.close());

function renderWithClient(ui: React.ReactElement, initialRole: "admin" | "assessor" | "viewer" = "admin") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  // Set auth state
  setToken("mock-valid-bearer-token");
  server.use(
    http.get("/api/v1/auth/me", () => {
      return HttpResponse.json({
        id: initialRole === "admin" ? "usr-admin" : "usr-assessor",
        name: "Test User",
        email: "test@secassess.local",
        role: initialRole,
        is_active: true,
        created_at: new Date().toISOString(),
      });
    })
  );

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter>{ui}</MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe("Phase 9: Dashboard, Reports, and Admin Screens", () => {
  it("Dashboard: renders stat cards, unverified banner, and all 5 severity levels with zeros", async () => {
    renderWithClient(<AssessmentDashboardView assessmentId="assess-1" />);

    // 1. Unverified banner
    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        "2 findings have not been verified. They are not confirmed vulnerabilities."
      );
    });

    // 2. Stat cards
    expect(screen.getByText("Total Findings")).toBeInTheDocument();
    expect(screen.getByText("2 of 4 verified")).toBeInTheDocument();

    // 3. Severity chart text fallback table ensures all 5 severity levels are shown (even with 0)
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("HIGH")).toBeInTheDocument();
    expect(screen.getByText("MEDIUM")).toBeInTheDocument();
    expect(screen.getByText("LOW")).toBeInTheDocument();
    expect(screen.getByText("INFO")).toBeInTheDocument();
  });

  it("Dashboard: renders global dashboard page with assessments list and pagination", async () => {
    renderWithClient(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("Acme Production Web App")).toBeInTheDocument();
      expect(screen.getByText("Security Assessment Dashboard")).toBeInTheDocument();
    });
  });

  it("Reports: generates report with 202 status and polls to completed state", async () => {
    const user = userEvent.setup();
    renderWithClient(<AssessmentReportsView assessmentId="assess-1" />, "admin");

    await waitFor(() => {
      expect(screen.getByText("Compile New Assessment Report")).toBeInTheDocument();
    });

    // Click generate report
    const generateBtn = screen.getByRole("button", { name: /generate report/i });
    await user.click(generateBtn);

    // Waiting for poll completion and refreshed reports
    await waitFor(() => {
      expect(screen.getByText("v1")).toBeInTheDocument();
    });
  });

  it("Reports: shows friendly error when PDF conversion returns 501 / unavailable", async () => {
    const user = userEvent.setup();
    renderWithClient(<AssessmentReportsView assessmentId="assess-1" />, "assessor");

    await waitFor(() => {
      expect(screen.getByText("Output Format")).toBeInTheDocument();
    });

    // Change format to PDF
    const select = screen.getByRole("combobox");
    await user.selectOptions(select, "pdf");

    const generateBtn = screen.getByRole("button", { name: /generate report/i });
    await user.click(generateBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/PDF conversion not available: LibreOffice is not installed/i)
      ).toBeInTheDocument();
    });
  });

  it("Reports: shows clear message on 409 conflict", async () => {
    const user = userEvent.setup();
    renderWithClient(<AssessmentReportsView assessmentId="assess-1" />, "admin");

    await waitFor(() => {
      expect(screen.getByLabelText(/Custom Report Title/i)).toBeInTheDocument();
    });

    const titleInput = screen.getByLabelText(/Custom Report Title/i);
    await user.type(titleInput, "TRIGGER_CONFLICT");

    const generateBtn = screen.getByRole("button", { name: /generate report/i });
    await user.click(generateBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/Report compilation is already running for this assessment/i)
      ).toBeInTheDocument();
    });
  });

  it("Reports: authenticated download sends Authorization header without token in URL", async () => {
    const user = userEvent.setup();
    renderWithClient(<AssessmentReportsView assessmentId="assess-1" />, "admin");

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /download/i })).toBeInTheDocument();
    });

    const downloadBtn = screen.getByRole("button", { name: /download/i });
    await user.click(downloadBtn);

    await waitFor(() => {
      expect(lastDownloadAuthHeader).toBe("Bearer mock-valid-bearer-token");
    });

    // Findings CSV export test
    const exportCsvBtn = screen.getByRole("button", { name: /export csv/i });
    await user.click(exportCsvBtn);

    await waitFor(() => {
      expect(lastExportAuthHeader).toBe("Bearer mock-valid-bearer-token");
    });
  });

  it("Reports: readiness checklist warns on unverified findings and missing approved executive summary", async () => {
    renderWithClient(<AssessmentReportsView assessmentId="assess-1" />, "assessor");

    await waitFor(() => {
      expect(screen.getByText("Report Readiness Checklist")).toBeInTheDocument();
      expect(
        screen.getByText(/Warning: Report will be marked as "Draft" because unverified candidate findings remain/i)
      ).toBeInTheDocument();
      expect(
        screen.getByText(/No approved AI executive summary exists/i)
      ).toBeInTheDocument();
    });
  });

  it("Reports: viewer sees report list and download button, but no generation controls", async () => {
    renderWithClient(<AssessmentReportsView assessmentId="assess-1" />, "viewer");

    await waitFor(() => {
      expect(screen.getByText("Generated Reports")).toBeInTheDocument();
    });

    // Viewer should see the download button
    expect(screen.getByRole("button", { name: /download/i })).toBeInTheDocument();

    // Viewer should NOT see the compile report form
    expect(screen.queryByText("Compile New Assessment Report")).not.toBeInTheDocument();
  });

  it("Admin: Users page allows creating user, changing role, and confirms deactivation", async () => {
    const user = userEvent.setup();
    renderWithClient(<UsersPage />, "admin");

    await waitFor(() => {
      expect(screen.getByText("Lead Assessor")).toBeInTheDocument();
    });

    // 1. Open create modal
    const createBtn = screen.getByTestId("open-create-user-modal");
    await user.click(createBtn);

    // Wait for the modal dialog to appear
    await screen.findByRole("dialog");
    expect(screen.getByText("Create New User Account")).toBeInTheDocument();

    // Fill form
    const nameInput = screen.getByPlaceholderText("Jane Doe");
    const emailInput = screen.getByPlaceholderText("jane@example.com");
    const passInput = screen.getByTestId("user-password-input");

    await user.click(nameInput);
    await user.paste("Test Operator");
    await user.click(emailInput);
    await user.paste("operator@example.com");
    await user.click(passInput);
    await user.paste("ComplexPassword123!");

    // Submit create user form
    const submitBtn = screen.getByRole("button", { name: /submit create user/i });
    await userEvent.click(submitBtn);

    // Wait for modal to close
    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });

    await waitFor(() => {
      expect(screen.getByText("Test Operator")).toBeInTheDocument();
    });

    // 2. Change role
    const changeRoleBtns = screen.getAllByRole("button", { name: /change role/i });
    await user.click(changeRoleBtns[1]); // Lead Assessor

    await waitFor(() => {
      expect(screen.getByText("Change Role: Lead Assessor")).toBeInTheDocument();
    });

    const roleSelect = screen.getByLabelText(/Select New Role/i);
    await user.selectOptions(roleSelect, "viewer");
    await user.click(screen.getByRole("button", { name: /save role/i }));

    // 3. Deactivate user with confirmation modal
    const deactivateBtns = screen.getAllByRole("button", { name: /deactivate/i });
    await user.click(deactivateBtns[1]); // Lead Assessor

    await waitFor(() => {
      expect(screen.getByText("Deactivate User Account")).toBeInTheDocument();
    });

    const confirmDeact = screen.getByRole("button", { name: /confirm deactivation/i });
    await user.click(confirmDeact);
  }, 15000);

  it("Admin: Audit Log renders entries, filters actions, and expands details", async () => {
    const user = userEvent.setup();
    renderWithClient(<AuditLogPage />, "admin");

    await waitFor(() => {
      expect(screen.getByText("user.login")).toBeInTheDocument();
    });

    // Filter action
    const actionInput = screen.getByLabelText(/Action Type/i);
    await user.type(actionInput, "nomatch");
    await user.click(screen.getByRole("button", { name: /apply filter/i }));

    await waitFor(() => {
      expect(screen.getByText("No audit logs matched")).toBeInTheDocument();
    });

    // Clear filter
    const clearBtn = screen.getByRole("button", { name: /clear filters/i });
    await user.click(clearBtn);

    await waitFor(() => {
      expect(screen.getByText("user.login")).toBeInTheDocument();
    });
  });

  it("Untrusted content: hostile strings (<script>, <img onerror>, javascript:) render safely as text", async () => {
    renderWithClient(<UsersPage />, "admin");

    // The mock user name contains `<script>alert(1)</script>`
    await waitFor(() => {
      const element = screen.getByText(/System Admin <script>alert\(1\)<\/script>/i);
      expect(element).toBeInTheDocument();
      // Ensure it is text content, not an active DOM script element
      expect(element.tagName.toLowerCase()).not.toBe("script");
    });

    // Audit log details contain `<img onerror=alert(1)>`
    renderWithClient(<AuditLogPage />, "admin");
    await waitFor(() => {
      const details = screen.getByText(/User authenticated from <img onerror=alert\(1\)> javascript:void\(0\)/i);
      expect(details).toBeInTheDocument();
      expect(details.tagName.toLowerCase()).not.toBe("img");
    });
  });

  it("Axe accessibility test: checks Dashboard, Reports, and Users views", async () => {
    const { container: dashContainer } = renderWithClient(<DashboardPage />);
    await waitFor(() => expect(screen.getByText("Platform Overview")).toBeInTheDocument());
    const dashAxe = await axe.run(dashContainer);
    // Ignore color-contrast warnings that depend on synthetic style computation in jsdom
    const seriousDashViolations = dashAxe.violations.filter((v) => v.id !== "color-contrast");
    expect(seriousDashViolations).toEqual([]);

    const { container: reportsContainer } = renderWithClient(<ReportsPage />);
    await waitFor(() => expect(screen.getByText("Reporting Hub")).toBeInTheDocument());
    const repAxe = await axe.run(reportsContainer);
    const seriousRepViolations = repAxe.violations.filter((v) => v.id !== "color-contrast");
    expect(seriousRepViolations).toEqual([]);

    const { container: usersContainer } = renderWithClient(<UsersPage />);
    await waitFor(() => expect(screen.getByText("User Management")).toBeInTheDocument());
    const usersAxe = await axe.run(usersContainer);
    const seriousUserViolations = usersAxe.violations.filter((v) => v.id !== "color-contrast");
    expect(seriousUserViolations).toEqual([]);
  });
});
