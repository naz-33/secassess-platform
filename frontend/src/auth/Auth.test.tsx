import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { BrowserRouter } from "react-router-dom";
import { AuthProvider, useAuth } from "./AuthContext";
import { LoginPage } from "../features/auth/pages/LoginPage";
import { RequireRole } from "./RequireRole";
import { getToken } from "../api/client";

const mockUser = {
  id: "user-1",
  name: "Alice Assessor",
  email: "alice@example.com",
  role: "assessor",
  is_active: true,
  created_at: new Date().toISOString(),
};

const server = setupServer(
  http.post("/api/v1/auth/login", async ({ request }) => {
    const body: any = await request.json();
    if (body.email === "alice@example.com" && body.password === "ValidPass1234!") {
      return HttpResponse.json({
        access_token: "jwt-token-xyz-123",
        token_type: "bearer",
        user: mockUser,
      });
    }
    if (body.email === "locked@example.com") {
      return HttpResponse.json(
        { detail: "Account temporarily locked. Retry after 15 minutes." },
        { status: 400 }
      );
    }
    return HttpResponse.json({ detail: "Invalid credentials" }, { status: 401 });
  }),
  http.get("/api/v1/auth/me", ({ request }) => {
    const auth = request.headers.get("Authorization");
    if (auth === "Bearer valid-saved-token") {
      return HttpResponse.json(mockUser);
    }
    return HttpResponse.json({ detail: "Unauthorized" }, { status: 401 });
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  sessionStorage.clear();
  localStorage.clear();
});
afterAll(() => server.close());

function TestAuthConsumer() {
  const { user, isAuthenticated, role, logout } = useAuth();
  return (
    <div>
      <div data-testid="auth-status">{isAuthenticated ? "authenticated" : "anonymous"}</div>
      <div data-testid="user-role">{role || "none"}</div>
      <div data-testid="user-name">{user?.name || "none"}</div>
      <button onClick={logout}>Sign Out Button</button>
    </div>
  );
}

describe("Authentication & Token Security", () => {
  it("successful login sets token in sessionStorage, never localStorage, and populates AuthContext", async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <LoginPage />
          <TestAuthConsumer />
        </AuthProvider>
      </BrowserRouter>
    );

    const emailInput = screen.getByLabelText(/Email Address/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitBtn = screen.getByRole("button", { name: /Sign In to Platform/i });

    await userEvent.type(emailInput, "alice@example.com");
    await userEvent.type(passwordInput, "ValidPass1234!");
    await userEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("authenticated");
    });

    expect(screen.getByTestId("user-name")).toHaveTextContent("Alice Assessor");
    expect(screen.getByTestId("user-role")).toHaveTextContent("assessor");

    // Token security assertions
    expect(sessionStorage.getItem("secassess_auth_token")).toBe("jwt-token-xyz-123");
    expect(localStorage.getItem("secassess_auth_token")).toBeNull();
    expect(localStorage.length).toBe(0);
  });

  it("failed login presents generic error display without leaking user existence", async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </BrowserRouter>
    );

    const emailInput = screen.getByLabelText(/Email Address/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitBtn = screen.getByRole("button", { name: /Sign In to Platform/i });

    await userEvent.type(emailInput, "unknown@example.com");
    await userEvent.type(passwordInput, "WrongPassword!");
    await userEvent.click(submitBtn);

    await waitFor(() => {
      expect(screen.getByText("Invalid email or password.")).toBeInTheDocument();
    });
  });

  it("handles locked account response with clear countdown notice", async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </BrowserRouter>
    );

    const emailInput = screen.getByLabelText(/Email Address/i);
    const passwordInput = screen.getByLabelText(/Password/i);
    const submitBtn = screen.getByRole("button", { name: /Sign In to Platform/i });

    await userEvent.type(emailInput, "locked@example.com");
    await userEvent.type(passwordInput, "SomePass12345");
    await userEvent.click(submitBtn);

    await waitFor(() => {
      expect(
        screen.getByText(/Account temporarily locked. Retry after 15 minutes./i)
      ).toBeInTheDocument();
    });
  });

  it("restores session via GET /auth/me on mount from sessionStorage", async () => {
    sessionStorage.setItem("secassess_auth_token", "valid-saved-token");

    render(
      <AuthProvider>
        <TestAuthConsumer />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("authenticated");
      expect(screen.getByTestId("user-name")).toHaveTextContent("Alice Assessor");
    });
  });

  it("clears token on logout", async () => {
    sessionStorage.setItem("secassess_auth_token", "valid-saved-token");

    render(
      <AuthProvider>
        <TestAuthConsumer />
      </AuthProvider>
    );

    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("authenticated");
    });

    await userEvent.click(screen.getByText("Sign Out Button"));

    expect(screen.getByTestId("auth-status")).toHaveTextContent("anonymous");
    expect(getToken()).toBeNull();
    expect(sessionStorage.getItem("secassess_auth_token")).toBeNull();
  });
});

describe("RequireRole Component", () => {
  it("hides privileged actions from unauthorized role", () => {
    render(
      <AuthProvider>
        <RequireRole roles={["admin"]} fallback={<div>Fallback No Permission</div>}>
          <button>Admin Only Action</button>
        </RequireRole>
      </AuthProvider>
    );
    expect(screen.queryByText("Admin Only Action")).not.toBeInTheDocument();
    expect(screen.getByText("Fallback No Permission")).toBeInTheDocument();
  });
});
