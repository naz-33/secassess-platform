import React from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, Home } from "lucide-react";
import { Button } from "../components/Button";

export function NotFoundPage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] text-center px-4">
      <div className="rounded-full bg-slate-800/80 p-4 border border-slate-700 mb-4">
        <AlertTriangle className="h-8 w-8 text-amber-400" />
      </div>
      <h1 className="text-3xl font-bold tracking-tight text-slate-100">404 - Page Not Found</h1>
      <p className="text-sm text-slate-400 max-w-md mt-2">
        The security console resource you requested does not exist or may have been deleted.
      </p>
      <div className="mt-6">
        <Link to="/targets">
          <Button variant="outline">
            <Home className="h-4 w-4 mr-2" />
            Back to Targets
          </Button>
        </Link>
      </div>
    </div>
  );
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends React.Component<{ children: React.ReactNode }, ErrorBoundaryState> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error("ErrorBoundary caught an unhandled error:", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center min-h-screen bg-slate-950 text-slate-100 p-6 text-center">
          <div className="max-w-md w-full rounded-lg border border-rose-900 bg-rose-950/20 p-6">
            <AlertTriangle className="h-10 w-10 text-rose-400 mx-auto mb-3" />
            <h2 className="text-lg font-bold text-rose-300">Application Error</h2>
            <p className="text-xs text-slate-300 mt-2">
              A frontend rendering error occurred in this view.
            </p>
            <div className="mt-4 rounded bg-slate-950 p-3 text-left font-mono text-[11px] text-slate-400 overflow-x-auto">
              {this.state.error?.message || "Unknown error"}
            </div>
            <div className="mt-4">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  this.setState({ hasError: false, error: null });
                  window.location.href = "/targets";
                }}
              >
                Reload Console
              </Button>
            </div>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

