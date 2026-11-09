import React from "react";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { ScanLauncher } from "./components/ScanLauncher";
import { ScansList } from "./components/ScansList";
import { CodeBlock } from "../../components/CodeBlock";
import { AuthProvider } from "../../auth";
import { ToastProvider } from "../../components/Toast";
import type { ScanRead } from "../../api/types";

let scanStateList: ScanRead[] = [
  {
    id: "scan-completed-1",
    assessment_id: "assess-1",
    tool: "nmap",
    status: "completed",
    command: "nmap -sV -oX - -T3 127.0.0.1",
    started_at: new Date(Date.now() - 60000).toISOString(),
    finished_at: new Date().toISOString(),
    raw_output: "Starting Nmap 7.94\nNmap scan report for 127.0.0.1\nPORT 80/tcp OPEN http\n",
    error: null,
    created_at: new Date(Date.now() - 60000).toISOString(),
  },
  {
    id: "scan-rejected-2",
    assessment_id: "assess-1",
    tool: "dns",
    status: "rejected",
    command: "dig unauthorized.internal A",
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    raw_output: "",
    error: "Scope violation: Asset 'unauthorized.internal' is OUT OF SCOPE",
    created_at: new Date().toISOString(),
  },
];

const server = setupServer(
  http.get("/api/v1/auth/me", () => {
    return HttpResponse.json({
      id: "user-1",
      name: "Assessor",
      email: "assessor@test.com",
      role: "assessor",
      is_active: true,
      created_at: new Date().toISOString(),
    });
  }),
  http.get("/api/v1/assessments/assess-1/scans", () => {
    return HttpResponse.json(scanStateList);
  }),
  http.post("/api/v1/assessments/assess-1/scans", async ({ request }) => {
    const body: any = await request.json();
    if (body.target && body.target.includes("evil.com")) {
      return HttpResponse.json(
        { detail: "Asset 'evil.com' is OUT OF SCOPE or unauthorized" },
        { status: 403 }
      );
    }
    const newScan: ScanRead = {
      id: "scan-new-pending",
      assessment_id: "assess-1",
      tool: body.tool || "nmap",
      status: "pending",
      command: `nmap ${body.target || "127.0.0.1"}`,
      started_at: null,
      finished_at: null,
      raw_output: null,
      error: null,
      created_at: new Date().toISOString(),
    };
    scanStateList = [newScan, ...scanStateList];
    return HttpResponse.json(newScan, { status: 202 });
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  sessionStorage.clear();
});
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  sessionStorage.setItem("secassess_auth_token", "fake-token");

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ToastProvider>
          <MemoryRouter>{ui}</MemoryRouter>
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe("Scans Feature", () => {
  beforeEach(() => {
    scanStateList = [
      {
        id: "scan-completed-1",
        assessment_id: "assess-1",
        tool: "nmap",
        status: "completed",
        command: "nmap -sV -oX - -T3 127.0.0.1",
        started_at: new Date(Date.now() - 60000).toISOString(),
        finished_at: new Date().toISOString(),
        raw_output: "Starting Nmap 7.94\nNmap scan report for 127.0.0.1\nPORT 80/tcp OPEN http\n",
        error: null,
        created_at: new Date(Date.now() - 60000).toISOString(),
      },
      {
        id: "scan-rejected-2",
        assessment_id: "assess-1",
        tool: "dns",
        status: "rejected",
        command: "dig unauthorized.internal A",
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        raw_output: "",
        error: "Scope violation: Asset 'unauthorized.internal' is OUT OF SCOPE",
        created_at: new Date().toISOString(),
      },
    ];
  });

  it("renders scan list with completed and rejected statuses", async () => {
    renderWithProviders(<ScansList assessmentId="assess-1" />);

    expect(await screen.findByText("COMPLETED")).toBeInTheDocument();
    expect(screen.getByText("REJECTED: OUT OF SCOPE")).toBeInTheDocument();
    expect(
      screen.getByText(/Scope violation: Asset 'unauthorized.internal' is OUT OF SCOPE/i)
    ).toBeInTheDocument();
  });

  it("launches an Nmap scan returning 202 and updates list", async () => {
    renderWithProviders(
      <div>
        <ScanLauncher assessmentId="assess-1" defaultTarget="127.0.0.1" />
        <ScansList assessmentId="assess-1" />
      </div>
    );

    const launchBtn = await screen.findByRole("button", { name: /Launch NMAP Scan/i });
    await userEvent.click(launchBtn);

    await waitFor(() => {
      expect(screen.getByText("PENDING")).toBeInTheDocument();
    });
  });

  it("handles out-of-scope scan dispatch 403 clearly in UI", async () => {
    renderWithProviders(
      <div>
        <ScanLauncher assessmentId="assess-1" defaultTarget="127.0.0.1" />
        <ScansList assessmentId="assess-1" />
      </div>
    );

    const targetInput = await screen.findByLabelText(/Target Hostname \/ IP/i);
    await userEvent.clear(targetInput);
    await userEvent.type(targetInput, "evil.com");

    const launchBtn = screen.getByRole("button", { name: /Launch NMAP Scan/i });
    await userEvent.click(launchBtn);

    await waitFor(() => {
      expect(screen.getByText("Scope Rejected (403)")).toBeInTheDocument();
      expect(
        screen.getByText(/Asset 'evil.com' is OUT OF SCOPE or unauthorized/i)
      ).toBeInTheDocument();
    });
  });

  it("untrusted content test: malicious payloads render as safe plain text", () => {
    const maliciousPayload =
      "<script>alert('xss')</script><img src='x' onerror='alert(2)'><style>body{display:none}</style>";

    const { container } = render(
      <CodeBlock content={maliciousPayload} filename="untrusted.txt" />
    );

    // Assert script or img elements were NOT injected into the DOM
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("style")).toBeNull();

    // Assert text is displayed safely as literal text node
    expect(screen.getByText(new RegExp("<script>alert\\('xss'\\)<\\/script>", "i"))).toBeInTheDocument();
  });
});
