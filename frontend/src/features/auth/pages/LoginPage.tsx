import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { ShieldCheck, Lock, AlertCircle, Clock } from "lucide-react";
import { useAuth } from "../../../auth";
import { Button } from "../../../components/Button";
import { Input } from "../../../components/Input";
import { ApiError } from "../../../api/client";

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, sessionExpired, clearSessionExpired } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [lockedInfo, setLockedInfo] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const from = (location.state as any)?.from?.pathname || "/targets";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setLockedInfo(null);
    clearSessionExpired();

    if (!email.trim() || !password) {
      setErrorMessage("Please enter both email and password.");
      return;
    }

    setIsSubmitting(true);
    try {
      await login({
        email: email.trim(),
        password,
      });
      navigate(from, { replace: true });
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        // Account lock handling
        if (err.message && err.message.toLowerCase().includes("locked")) {
          setLockedInfo(err.message);
        } else if (err.status === 400 || err.status === 401) {
          // Generic secure error message without revealing user existence vs invalid password
          setErrorMessage("Invalid email or password.");
        } else {
          setErrorMessage(err.message || "Authentication failed. Please try again.");
        }
      } else {
        setErrorMessage("An unexpected network error occurred.");
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col justify-center bg-slate-950 px-6 py-12 lg:px-8 text-slate-100">
      <div className="sm:mx-auto sm:w-full sm:max-w-md">
        <div className="flex justify-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-600/20 border border-cyan-500/40 text-cyan-400">
            <ShieldCheck className="h-7 w-7" />
          </div>
        </div>
        <h2 className="mt-4 text-center text-2xl font-bold tracking-tight text-slate-100">
          SecAssess Platform
        </h2>
        <p className="mt-1 text-center text-xs text-slate-400">
          AI-Assisted Security Assessment and Vulnerability Analysis
        </p>

        {/* Mandatory Policy Warning */}
        <div className="mt-4 rounded-md border border-amber-900/60 bg-amber-950/30 p-2.5 text-center text-xs text-amber-300">
          Authorized testing only: synthetic data on approved targets.
        </div>
      </div>

      <div className="mt-6 sm:mx-auto sm:w-full sm:max-w-md">
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-8 shadow-2xl backdrop-blur">
          {sessionExpired && (
            <div className="mb-4 rounded-md border border-amber-800/80 bg-amber-950/40 p-3 text-xs text-amber-200 flex items-center space-x-2">
              <Clock className="h-4 w-4 shrink-0 text-amber-400" />
              <span>Your session has expired. Please log in again to continue.</span>
            </div>
          )}

          {lockedInfo && (
            <div className="mb-4 rounded-md border border-rose-800 bg-rose-950/50 p-3 text-xs text-rose-200 flex items-start space-x-2">
              <Lock className="h-4 w-4 shrink-0 text-rose-400 mt-0.5" />
              <span>{lockedInfo}</span>
            </div>
          )}

          {errorMessage && (
            <div className="mb-4 rounded-md border border-rose-800 bg-rose-950/50 p-3 text-xs text-rose-200 flex items-center space-x-2">
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
              <span>{errorMessage}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-5">
            <Input
              label="Email Address"
              type="email"
              required
              autoComplete="email"
              placeholder="assessor@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />

            <Input
              label="Password"
              type="password"
              required
              autoComplete="current-password"
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />

            <Button
              type="submit"
              className="w-full mt-2"
              isLoading={isSubmitting}
              disabled={isSubmitting}
            >
              Sign In to Platform
            </Button>
          </form>

          <div className="mt-6 border-t border-slate-800 pt-4 text-center text-xs text-slate-500">
            Role-Based Access: Admin, Assessor, Viewer.
          </div>
        </div>
      </div>
    </div>
  );
}
