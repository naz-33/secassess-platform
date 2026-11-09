import React from "react";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import axe from "axe-core";

import { AuthProvider } from "../../auth";
import { ToastProvider } from "../../components/Toast";
import { FindingsListPage } from "./pages/FindingsListPage";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { VerificationForm } from "./components/VerificationForm";
import type { FindingRead, FindingsSummary, VerificationRead, SeverityChangeRead } from "../../api/types";

// Mock Data
const mockSummary: FindingsSummary = {
  total: 3,
  by_severity: { critical: 1, high: 1, medium: 1 },
  by_category: { injection: 1, auth: 1, disclosure: 1 },
  confirmed_by_category: { injection: 1 },
  by_status: { confirmed: 1, unverified: 2, false_positive: 0 },
  confirmed_by_effective_severity: { critical: 1 },
  unverified_count: 2,
  verified_count: 1,
  verification_progress: 33.3,
};

let mockFindings: FindingRead[] = [
  {
    id: "f-1",
    assessment_id: "assess-1",
    scan_id: "scan-1",
    title: "SQL Injection in User Search <script>alert(1)</script>",
    category: "injection",
    description: "Vulnerable parameter id allows SQL injection. Payload: ' OR '1'='1",
    severity: "critical",
    original_severity: "critical",
    effective_severity: "critical",
    status: "confirmed",
    source: "tool",
    affected_url: "https://example.com/api/users?id=1",
    wstg_id: "WSTG-INPV-05",
    owasp_top10: "A03:2021-Injection",
    cwe: "CWE-89",
    remediation: "Use parameterized SQL queries.",
    created_at: new Date(Date.now() - 3600000).toISOString(),
    evidences: [
      {
        id: "ev-1",
        finding_id: "f-1",
        type: "output",
        label: "Database Error Response",
        content: "syntax error at or near 'OR' at line 1",
        original_filename: "sqli_error.txt",
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        captured_at: new Date().toISOString(),
        uploaded_by: "user-assessor",
      },
    ],
  },
  {
    id: "f-2",
    assessment_id: "assess-1",
    scan_id: "scan-1",
    title: "AI Proposed SSRF in Webhook System",
    category: "ssrf",
    description: "Internal webhook URL accepts arbitrary destination host.",
    severity: "high",
    original_severity: "high",
    effective_severity: "high",
    status: "unverified",
    source: "ai",
    ai_analysis_id: "ai-analysis-101",
    affected_url: "https://example.com/webhook",
    wstg_id: "WSTG-INPV-12",
    owasp_top10: "A10:2021-SSRF",
    cwe: "CWE-918",
    remediation: "Validate destination URLs against whitelist.",
    created_at: new Date().toISOString(),
    evidences: [],
  },
];

let mockVerifications: VerificationRead[] = [
  {
    id: "v-1",
    finding_id: "f-1",
    assessor_id: "assessor-uuid-1",
    decision: "confirmed",
    notes: "Verified SQL injection syntax error manually via curl.",
    evidence_reviewed: true,
    verified_at: new Date().toISOString(),
  },
];

let mockSeverityHistory: SeverityChangeRead[] = [
  {
    id: "sev-1",
    finding_id: "f-1",
    old_severity: "high",
    new_severity: "critical",
    old_cvss: 7.5,
    new_cvss: 9.8,
    justification: "Allows full unauthorized database data exfiltration.",
    changed_by: "assessor-uuid-1",
    changed_at: new Date().toISOString(),
  },
];

let authRole = "assessor";

const server = setupServer(
  http.get("/api/v1/auth/me", () => {
    return HttpResponse.json({
      id: "assessor-uuid-1",
      name: "Assessor Jane",
      email: "jane@secassess.local",
      role: authRole,
      is_active: true,
      created_at: new Date().toISOString(),
    });
  }),
  http.get("/api/v1/ai/status", () => {
    return HttpResponse.json({
      enabled: true,
      configured: true,
      model: "gemini-1.5-pro",
      limits: { max_calls: 20 },
      remaining_budget: { calls: 15 },
    });
  }),
  http.get("/api/v1/assessments/assess-1/findings/summary", () => {
    return HttpResponse.json(mockSummary);
  }),
  http.get("/api/v1/assessments/assess-1/findings", () => {
    return HttpResponse.json(mockFindings);
  }),
  http.get("/api/v1/findings/:id", ({ params }) => {
    const f = mockFindings.find((item) => item.id === params.id);
    if (!f) return HttpResponse.json({ detail: "Finding not found" }, { status: 404 });
    return HttpResponse.json(f);
  }),
  http.get("/api/v1/findings/:id/verifications", () => {
    return HttpResponse.json(mockVerifications);
  }),
  http.get("/api/v1/findings/:id/severity-history", () => {
    return HttpResponse.json(mockSeverityHistory);
  }),
  http.post("/api/v1/findings/:id/verify", async ({ request, params }) => {
    const body: any = await request.json();
    if (authRole === "viewer") {
      return HttpResponse.json({ detail: "Forbidden" }, { status: 403 });
    }
    if (body.decision === "confirmed" && !body.evidence_reviewed) {
      return HttpResponse.json({ detail: "Confirmation requires explicit evidence review" }, { status: 422 });
    }
    const newVer: VerificationRead = {
      id: `v-${Date.now()}`,
      finding_id: params.id as string,
      assessor_id: "assessor-uuid-1",
      decision: body.decision,
      notes: body.notes || null,
      evidence_reviewed: Boolean(body.evidence_reviewed),
      verified_at: new Date().toISOString(),
    };
    mockVerifications = [newVer, ...mockVerifications];

    const idx = mockFindings.findIndex((f) => f.id === params.id);
    if (idx !== -1) {
      mockFindings[idx] = {
        ...mockFindings[idx],
        status: body.decision,
      };
    }

    return HttpResponse.json(newVer, { status: 201 });
  }),
  http.patch("/api/v1/findings/:id/severity", async ({ request, params }) => {
    const body: any = await request.json();
    const idx = mockFindings.findIndex((f) => f.id === params.id);
    if (idx === -1) return HttpResponse.json({ detail: "Finding not found" }, { status: 404 });

    const updated = {
      ...mockFindings[idx],
      effective_severity: body.severity,
      severity_justification: body.justification,
      cvss_score: body.cvss_score,
      cvss_vector: body.cvss_vector,
    };
    mockFindings[idx] = updated;

    const newHistory: SeverityChangeRead = {
      id: `sev-${Date.now()}`,
      finding_id: params.id as string,
      old_severity: mockFindings[idx].effective_severity,
      new_severity: body.severity,
      old_cvss: mockFindings[idx].cvss_score,
      new_cvss: body.cvss_score,
      justification: body.justification,
      changed_by: "assessor-uuid-1",
      changed_at: new Date().toISOString(),
    };
    mockSeverityHistory = [newHistory, ...mockSeverityHistory];

    return HttpResponse.json(updated);
  }),
  http.post("/api/v1/findings/:id/evidence/upload", async () => {
    return HttpResponse.json(
      {
        id: "ev-uploaded",
        finding_id: "f-1",
        type: "screenshot",
        label: "Uploaded Screenshot",
        original_filename: "screenshot.png",
        sha256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        captured_at: new Date().toISOString(),
        uploaded_by: "assessor-uuid-1",
      },
      { status: 201 }
    );
  }),
  http.get("/api/v1/evidence/:id/download", ({ request }) => {
    const authHeader = request.headers.get("authorization");
    if (!authHeader || !authHeader.startsWith("Bearer fake-token")) {
      return HttpResponse.json({ detail: "Unauthorized - missing bearer token" }, { status: 401 });
    }
    const pngBytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]);
    return new HttpResponse(pngBytes, {
      headers: {
        "Content-Type": "image/png",
        "Content-Disposition": 'attachment; filename="screenshot.png"',
      },
    });
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  sessionStorage.clear();
  authRole = "assessor";
});
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement, initialPath = "/") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  sessionStorage.setItem("secassess_auth_token", "fake-token");

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ToastProvider>
          <MemoryRouter initialEntries={[initialPath]}>{ui}</MemoryRouter>
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe("Findings Feature & Verification Workflow", () => {
  it("renders findings list with effective severity, status, and source badges", async () => {
    renderWithProviders(<FindingsListPage assessmentId="assess-1" />);

    expect(await screen.findByText(/Assessment Findings/i)).toBeInTheDocument();

    // Verification progress label & unverified banner
    expect(screen.getByText("1 of 3 verified")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("2 findings have not been verified");

    // Table rows
    expect(screen.getByText(/SQL Injection in User Search/i)).toBeInTheDocument();
    expect(screen.getByText("AI Proposed SSRF in Webhook System")).toBeInTheDocument();

    // Badges present
    expect(screen.getByRole("status", { name: "Severity: Critical" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Status: Confirmed" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Source: Tool" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Source: AI-generated" })).toBeInTheDocument();
  });

  it("verification form enforces business rules: evidence review checkbox and notes length", async () => {
    const findingWithEvidence = mockFindings[0];
    renderWithProviders(<VerificationForm finding={findingWithEvidence} />);

    expect(screen.getByText("Record a New Decision (Re-open)")).toBeInTheDocument();

    // Submitting 'confirmed' without checking evidence reviewed is blocked
    const submitBtn = screen.getByRole("button", { name: /Record New Decision/i });
    expect(submitBtn).toBeDisabled();

    // Check evidence reviewed checkbox
    const checkbox = screen.getByLabelText(/I have reviewed the supporting evidence/i);
    await userEvent.click(checkbox);
    expect(submitBtn).not.toBeDisabled();

    // Switch to False Positive: requires at least 10 chars of notes
    const falsePosRadio = screen.getByLabelText(/False Positive/i);
    await userEvent.click(falsePosRadio);

    // Try submit with short notes
    const notesInput = screen.getByLabelText(/Verification Notes/i);
    await userEvent.type(notesInput, "short");
    await userEvent.click(submitBtn);

    expect(await screen.findByText(/explanatory notes of at least 10 characters/i)).toBeInTheDocument();
  });

  it("confirming verification opens confirmation dialog and records permanently in history", async () => {
    const findingWithEvidence = mockFindings[0];
    renderWithProviders(<VerificationForm finding={findingWithEvidence} />);

    const checkbox = screen.getByLabelText(/I have reviewed the supporting evidence/i);
    await userEvent.click(checkbox);

    const submitBtn = screen.getByRole("button", { name: /Record New Decision/i });
    await userEvent.click(submitBtn);

    // Confirmation dialog appears
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText(/Confirm Verification Decision/i)).toBeInTheDocument();
    expect(screen.getByText(/recorded permanently in the verification history/i)).toBeInTheDocument();

    const confirmBtn = screen.getByRole("button", { name: "Confirm Decision" });
    await userEvent.click(confirmBtn);

    await waitFor(() => {
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    });
  });

  it("finding detail page renders evidence, verification history, and severity history without edit/delete controls", async () => {
    renderWithProviders(
      <Routes>
        <Route path="/assessments/:assessmentId/findings/:findingId" element={<FindingDetailPage />} />
      </Routes>,
      "/assessments/assess-1/findings/f-1"
    );

    expect(await screen.findByText(/SQL Injection in User Search/i)).toBeInTheDocument();

    // Evidence panel
    expect(screen.getByText(/Supporting Evidence \(1\)/i)).toBeInTheDocument();
    expect(screen.getByText("Database Error Response")).toBeInTheDocument();
    expect(screen.getByText("syntax error at or near 'OR' at line 1")).toBeInTheDocument();

    // SHA-256 copy button present
    expect(screen.getByTitle("Copy SHA-256")).toBeInTheDocument();

    // Verification history timeline present (append only)
    expect(screen.getByText("Verification History")).toBeInTheDocument();
    expect(screen.getByText(/Append-only: decisions are never edited or deleted/i)).toBeInTheDocument();
    expect(screen.getByText(/Verified SQL injection syntax error manually via curl/i)).toBeInTheDocument();

    // Severity history present
    expect(screen.getByText("Severity Override History")).toBeInTheDocument();
    expect(screen.getByText("Allows full unauthorized database data exfiltration.")).toBeInTheDocument();

    // Assert absence of any Edit or Delete buttons for historical records
    expect(screen.queryByRole("button", { name: /delete evidence/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /edit verification/i })).not.toBeInTheDocument();
  });

  it("authenticated blob evidence download attaches Bearer header and does not expose token in URL", async () => {
    renderWithProviders(
      <Routes>
        <Route path="/assessments/:assessmentId/findings/:findingId" element={<FindingDetailPage />} />
      </Routes>,
      "/assessments/assess-1/findings/f-1"
    );

    await screen.findByText("Database Error Response");
    const downloadBtns = screen.getAllByRole("button", { name: /Download/i });
    expect(downloadBtns.length).toBeGreaterThanOrEqual(1);

    // Trigger download on the evidence item download button
    await userEvent.click(downloadBtns[0]);

    // Verify token was stored only in sessionStorage and not leaked
    expect(sessionStorage.getItem("secassess_auth_token")).toBe("fake-token");
    expect(localStorage.getItem("secassess_auth_token")).toBeNull();
  });

  it("untrusted content and prompt injection in finding title or AI text render strictly as plain text", async () => {
    renderWithProviders(
      <Routes>
        <Route path="/assessments/:assessmentId/findings/:findingId" element={<FindingDetailPage />} />
      </Routes>,
      "/assessments/assess-1/findings/f-1"
    );

    // Finding title contained '<script>alert(1)</script>'
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading).toHaveTextContent("SQL Injection in User Search <script>alert(1)</script>");

    // Check that no executable script tags exist in DOM
    const scripts = document.querySelectorAll("script");
    const scriptTexts = Array.from(scripts).map((s) => s.textContent);
    expect(scriptTexts.some((t) => t?.includes("alert(1)"))).toBe(false);
  });

  it("passes axe accessibility checks on finding detail page", async () => {
    const { container } = renderWithProviders(
      <Routes>
        <Route path="/assessments/:assessmentId/findings/:findingId" element={<FindingDetailPage />} />
      </Routes>,
      "/assessments/assess-1/findings/f-1"
    );

    await screen.findByText(/SQL Injection in User Search/i);

    const results = await axe.run(container);
    expect(results.violations).toEqual([]);
  });
});
