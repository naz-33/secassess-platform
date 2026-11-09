import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { apiClient, clearToken, getToken, registerUnauthorizedHandler, setToken } from "../api/client";
import type { UserRead, UserRole, TokenResponse, UserLogin } from "../api/types";

interface AuthContextValue {
  user: UserRead | null;
  role: UserRole | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  sessionExpired: boolean;
  login: (credentials: UserLogin) => Promise<void>;
  logout: () => void;
  clearSessionExpired: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserRead | null>(null);
  const [tokenState, setTokenState] = useState<string | null>(() => getToken());
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [sessionExpired, setSessionExpired] = useState<boolean>(false);

  const logout = useCallback(() => {
    clearToken();
    setTokenState(null);
    setUser(null);
  }, []);

  const handleUnauthorized = useCallback(() => {
    logout();
    setSessionExpired(true);
  }, [logout]);

  useEffect(() => {
    registerUnauthorizedHandler(handleUnauthorized);
  }, [handleUnauthorized]);

  // Restore session on mount via GET /api/v1/auth/me if token exists in sessionStorage
  useEffect(() => {
    const existingToken = getToken();
    if (!existingToken) {
      setIsLoading(false);
      return;
    }

    let isMounted = true;
    apiClient<UserRead>("/api/v1/auth/me")
      .then((profile) => {
        if (isMounted) {
          setUser(profile);
          setTokenState(existingToken);
        }
      })
      .catch(() => {
        if (isMounted) {
          logout();
        }
      })
      .finally(() => {
        if (isMounted) {
          setIsLoading(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [logout]);

  const login = async (credentials: UserLogin) => {
    const res = await apiClient<TokenResponse>("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    });

    setToken(res.access_token);
    setTokenState(res.access_token);
    setUser(res.user);
    setSessionExpired(false);
  };

  const clearSessionExpired = () => {
    setSessionExpired(false);
  };

  const value: AuthContextValue = {
    user,
    role: user?.role || null,
    token: tokenState,
    isAuthenticated: !!user && !!tokenState,
    isLoading,
    sessionExpired,
    login,
    logout,
    clearSessionExpired,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

