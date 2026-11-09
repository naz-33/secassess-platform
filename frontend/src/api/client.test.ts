import { describe, it, expect, afterEach, vi, beforeAll, afterAll } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  apiClient,
  ApiError,
  setToken,
  getToken,
  clearToken,
  registerUnauthorizedHandler,
} from "./client";

const server = setupServer(
  http.get("/api/v1/test-success", ({ request }) => {
    const authHeader = request.headers.get("Authorization");
    return HttpResponse.json({ status: "ok", auth: authHeader });
  }),
  http.get("/api/v1/test-401", () => {
    return HttpResponse.json({ detail: "Token invalid or expired" }, { status: 401 });
  }),
  http.get("/api/v1/test-403", () => {
    return HttpResponse.json({ detail: "Permission denied" }, { status: 403 });
  }),
  http.post("/api/v1/test-validation", () => {
    return HttpResponse.json(
      {
        detail: [
          { loc: ["body", "email"], msg: "Invalid email", type: "value_error" },
          { loc: ["body", "password"], msg: "Too short", type: "value_error" },
        ],
      },
      { status: 422 }
    );
  }),
  http.get("/api/v1/test-delay", async () => {
    await new Promise((resolve) => setTimeout(resolve, 300));
    return HttpResponse.json({ delayed: true });
  })
);

beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  clearToken();
});
afterAll(() => server.close());

describe("API Client (fetch wrapper)", () => {
  it("attaches Authorization header when token is set", async () => {
    setToken("test-jwt-token-12345");
    const res = await apiClient<{ status: string; auth: string }>("/api/v1/test-success");
    expect(res.status).toBe("ok");
    expect(res.auth).toBe("Bearer test-jwt-token-12345");
  });

  it("handles 401 response: clears token, invokes unauthorized callback, throws ApiError", async () => {
    setToken("expired-token");
    const onUnauthorized = vi.fn();
    registerUnauthorizedHandler(onUnauthorized);

    await expect(apiClient("/api/v1/test-401")).rejects.toThrow(ApiError);
    expect(getToken()).toBeNull();
    expect(onUnauthorized).toHaveBeenCalled();
  });

  it("formats FastAPI 422 validation errors into readable message", async () => {
    try {
      await apiClient("/api/v1/test-validation", { method: "POST" });
      expect.fail("Should have thrown ApiError");
    } catch (err: any) {
      expect(err).toBeInstanceOf(ApiError);
      expect(err.status).toBe(422);
      expect(err.message).toContain("body.email: Invalid email");
      expect(err.message).toContain("body.password: Too short");
    }
  });

  it("supports timeout and abort signal", async () => {
    await expect(
      apiClient("/api/v1/test-delay", { timeoutMs: 50 })
    ).rejects.toThrow(/timed out|aborted/i);
  });
});
