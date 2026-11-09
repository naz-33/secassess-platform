/**
 * Custom application error class representing backend API errors.
 */
export class ApiError extends Error {
  public status: number;
  public details?: unknown;

  constructor(status: number, message: string, details?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.details = details;
  }
}

// In-memory token storage (module-level)
let inMemoryToken: string | null = null;
const SESSION_STORAGE_KEY = "secassess_auth_token";

export function setToken(token: string | null): void {
  inMemoryToken = token;
  if (token) {
    sessionStorage.setItem(SESSION_STORAGE_KEY, token);
  } else {
    sessionStorage.removeItem(SESSION_STORAGE_KEY);
  }
}

export function getToken(): string | null {
  if (inMemoryToken) {
    return inMemoryToken;
  }
  const saved = sessionStorage.getItem(SESSION_STORAGE_KEY);
  if (saved) {
    inMemoryToken = saved;
  }
  return inMemoryToken;
}

export function clearToken(): void {
  inMemoryToken = null;
  sessionStorage.removeItem(SESSION_STORAGE_KEY);
}

// Callback registered by AuthProvider when a 401 occurs
let onUnauthorizedHandler: (() => void) | null = null;

export function registerUnauthorizedHandler(handler: () => void): void {
  onUnauthorizedHandler = handler;
}

export interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

/**
 * Base fetch client with authentication header injection, timeout, abort, and normalized ApiError parsing.
 */
export async function apiClient<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = 15000, headers, ...customConfig } = options;

  // Base URL configuration (empty string if using Vite proxy, or configured baseUrl)
  const baseUrl = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  const url = `${baseUrl}${cleanEndpoint}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  if (options.signal) {
    options.signal.addEventListener("abort", () => controller.abort());
  }

  const token = getToken();
  const requestHeaders = new Headers(headers);

  if (!requestHeaders.has("Content-Type") && !(options.body instanceof FormData)) {
    requestHeaders.set("Content-Type", "application/json");
  }

  if (token && !requestHeaders.has("Authorization")) {
    requestHeaders.set("Authorization", `Bearer ${token}`);
  }

  try {
    const response = await fetch(url, {
      ...customConfig,
      headers: requestHeaders,
      signal: controller.signal,
    });

    if (response.status === 204) {
      return {} as T;
    }

    let data: any = null;
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      try {
        data = await response.json();
      } catch {
        data = null;
      }
    } else {
      const text = await response.text();
      data = text ? { message: text } : null;
    }

    if (!response.ok) {
      if (response.status === 401) {
        clearToken();
        if (onUnauthorizedHandler) {
          onUnauthorizedHandler();
        }
      }

      let errorMessage = "An error occurred with the request.";
      if (data && typeof data === "object") {
        if (typeof data.detail === "string") {
          errorMessage = data.detail;
        } else if (Array.isArray(data.detail)) {
          // Format FastAPI validation error details
          errorMessage = data.detail
            .map((item: any) => `${item.loc ? item.loc.join(".") + ": " : ""}${item.msg}`)
            .join("; ");
        } else if (data.message) {
          errorMessage = data.message;
        }
      }

      throw new ApiError(response.status, errorMessage, data?.detail || data);
    }

    return data as T;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(408, "Request timed out or was aborted by the client.");
    }
    throw new ApiError(0, err instanceof Error ? err.message : "Network error");
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Authenticated binary/blob download helper.
 * Token is sent strictly via Authorization header and never appears in URLs.
 */
export async function downloadBlob(endpoint: string, options: RequestOptions = {}): Promise<{ blob: Blob; filename?: string }> {
  const { timeoutMs = 30000, headers, ...customConfig } = options;

  const baseUrl = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/+$/, "");
  const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  const url = `${baseUrl}${cleanEndpoint}`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  if (options.signal) {
    options.signal.addEventListener("abort", () => controller.abort());
  }

  const token = getToken();
  const requestHeaders = new Headers(headers);

  if (token && !requestHeaders.has("Authorization")) {
    requestHeaders.set("Authorization", `Bearer ${token}`);
  }

  try {
    const response = await fetch(url, {
      ...customConfig,
      headers: requestHeaders,
      signal: controller.signal,
    });

    if (!response.ok) {
      if (response.status === 401) {
        clearToken();
        if (onUnauthorizedHandler) {
          onUnauthorizedHandler();
        }
      }
      let errorMsg = `Download failed with status ${response.status}`;
      try {
        const errJson = await response.json();
        if (errJson?.detail) {
          errorMsg = typeof errJson.detail === "string" ? errJson.detail : JSON.stringify(errJson.detail);
        }
      } catch {
        // Fallback to text or default message
      }
      throw new ApiError(response.status, errorMsg);
    }

    // Extract filename from Content-Disposition header if available
    let filename: string | undefined;
    const disposition = response.headers.get("content-disposition");
    if (disposition && disposition.includes("filename=")) {
      const match = disposition.match(/filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/);
      if (match && match[1]) {
        filename = match[1].replace(/['"]/g, "").trim();
      }
    }

    const blob = await response.blob();
    return { blob, filename };
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(408, "Download request timed out or was aborted.");
    }
    throw new ApiError(0, err instanceof Error ? err.message : "Network error during download");
  } finally {
    clearTimeout(timeoutId);
  }
}


