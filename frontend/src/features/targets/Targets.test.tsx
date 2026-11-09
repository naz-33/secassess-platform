import React from "react";
import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { TargetsPage } from "./pages/TargetsPage";
import { TargetDetailPage } from "./pages/TargetDetailPage";
import { AuthProvider } from "../../auth";
import { ToastProvider } from "../../components/Toast";

const mockTarget = {
  id: "target-123",
  name: "Local Test Server",
  base_url: "http://localhost:8080",
  description: "Testbed for authorized vulnerability scanning",
  authorization_note: "Authorized by Lab Policy #101",
  created_at: new Date().toISOString(),
  scope_items: [
    {
      id: "scope-1",
      target_id: "target-123",
      asset: "http://localhost:8080",
      in_scope: true,
      notes: "Base service allowed",
      created_at: new Date().toISOString(),
    },
    {
      id: "scope-2",
      target_id: "target-123",
      asset: "http://localhost:8080/admin",
      in_scope: false,
      notes: "Blacklisted admin console",
      created_at: new Date().toISOString(),
    },
  ],
};

const server = setupServer(
  http.get("/api/v1/auth/me", () => {
    return HttpResponse.json({
      id: "user-assessor",
      name: "Assessor User",
      email: "assessor@test.com",
      role: "assessor",
      is_active: true,
      created_at: new Date().toISOString(),
    });
  }),
  http.get("/api/v1/targets", () => {
    return HttpResponse.json([mockTarget]);
  }),
  http.get("/api/v1/targets/target-123", () => {
    return HttpResponse.json(mockTarget);
  }),
  http.post("/api/v1/targets/target-123/scope/validate", async ({ request }) => {
    const body: any = await request.json();
    if (body.asset.includes("/admin")) {
      return HttpResponse.json({
        asset: body.asset,
        target_id: "target-123",
        in_scope: false,
        reason: "Matched explicit out-of-scope blacklist rule 'http://localhost:8080/admin'",
      });
    }
    return HttpResponse.json({
      asset: body.asset,
      target_id: "target-123",
      in_scope: true,
      reason: "Asset matches authorized target base URL prefix rule",
    });
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  sessionStorage.clear();
});
afterAll(() => server.close());

function renderWithProviders(ui: React.ReactElement, initialRoute = "/targets") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  sessionStorage.setItem("secassess_auth_token", "fake-valid-token");

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ToastProvider>
          <MemoryRouter initialEntries={[initialRoute]}>{ui}</MemoryRouter>
        </ToastProvider>
      </AuthProvider>
    </QueryClientProvider>
  );
}

describe("Targets and Scope Feature", () => {
  it("renders targets list with scope rule count and guidance box", async () => {
    renderWithProviders(<TargetsPage />);

    expect(await screen.findByText("Local Test Server")).toBeInTheDocument();
    expect(screen.getByText("http://localhost:8080")).toBeInTheDocument();
    expect(screen.getByText("2 items")).toBeInTheDocument();
    expect(
      screen.getByText(/Only configure instructor-approved testing targets/i)
    ).toBeInTheDocument();
  });

  it("renders target detail with in-scope and out-of-scope visual distinction", async () => {
    renderWithProviders(
      <Routes>
        <Route path="/targets/:id" element={<TargetDetailPage />} />
      </Routes>,
      "/targets/target-123"
    );

    expect(await screen.findByText("Local Test Server")).toBeInTheDocument();
    expect(screen.getByText("IN-SCOPE (Allowed)")).toBeInTheDocument();
    expect(screen.getByText("OUT-OF-SCOPE (Blacklist)")).toBeInTheDocument();
    expect(
      screen.getByText("Blocked (blacklist wins over in-scope rules)")
    ).toBeInTheDocument();
  });

  it("scope check tool demonstrates both authorized and rejected results with backend reason", async () => {
    renderWithProviders(
      <Routes>
        <Route path="/targets/:id" element={<TargetDetailPage />} />
      </Routes>,
      "/targets/target-123"
    );

    const input = await screen.findByPlaceholderText(/e.g. http:\/\/localhost:8080\/admin/i);
    const checkBtn = screen.getByRole("button", { name: /Check Scope/i });

    // Test 1: In-scope asset
    await userEvent.clear(input);
    await userEvent.type(input, "http://localhost:8080/api/v1/users");
    await userEvent.click(checkBtn);

    await waitFor(() => {
      expect(screen.getByText("AUTHORIZED / IN-SCOPE")).toBeInTheDocument();
      expect(
        screen.getByText(/Asset matches authorized target base URL prefix rule/i)
      ).toBeInTheDocument();
    });

    // Test 2: Out-of-scope blacklisted asset
    await userEvent.clear(input);
    await userEvent.type(input, "http://localhost:8080/admin/settings");
    await userEvent.click(checkBtn);

    await waitFor(() => {
      expect(screen.getByText("REJECTED / OUT-OF-SCOPE")).toBeInTheDocument();
      expect(
        screen.getByText(/Matched explicit out-of-scope blacklist rule/i)
      ).toBeInTheDocument();
    });
  });
});

