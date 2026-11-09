import React from "react";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  hint?: string;
}

export const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, hint, id, name, className = "", ...props }, ref) => {
    const generatedId = React.useId();
    const inputId = id || name || generatedId;

    return (
      <div className="w-full">
        {label && (
          <label htmlFor={inputId} className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
            {label}
            {props.required && <span className="text-rose-400 ml-1">*</span>}
          </label>
        )}
        <input
          ref={ref}
          id={inputId}
          name={name}
          aria-invalid={!!error}
          aria-describedby={error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined}
          className={`block w-full rounded-md border bg-slate-900 px-3 py-2 text-sm text-slate-100 placeholder-slate-500 shadow-sm transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:bg-slate-800 ${
            error ? "border-rose-500 focus:border-rose-500 focus:ring-rose-500" : "border-slate-700 hover:border-slate-600"
          } ${className}`}
          {...props}
        />
        {hint && !error && (
          <p id={`${inputId}-hint`} className="mt-1 text-xs text-slate-400">
            {hint}
          </p>
        )}
        {error && (
          <p id={`${inputId}-error`} className="mt-1 text-xs font-medium text-rose-400">
            {error}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";

