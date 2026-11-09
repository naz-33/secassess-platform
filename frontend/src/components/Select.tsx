import React from "react";

export interface SelectOption {
  label: string;
  value: string;
}

export interface SelectProps extends React.SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  options: SelectOption[];
  error?: string;
  hint?: string;
}

export const Select = React.forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, options, error, hint, id, name, className = "", ...props }, ref) => {
    const generatedId = React.useId();
    const selectId = id || name || generatedId;

    return (
      <div className="w-full">
        {label && (
          <label htmlFor={selectId} className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-1.5">
            {label}
            {props.required && <span className="text-rose-400 ml-1">*</span>}
          </label>
        )}
        <select
          ref={ref}
          id={selectId}
          aria-invalid={!!error}
          aria-describedby={error ? `${selectId}-error` : hint ? `${selectId}-hint` : undefined}
          className={`block w-full rounded-md border bg-slate-900 px-3 py-2 text-sm text-slate-100 shadow-sm transition-colors focus:outline-none focus:ring-2 focus:ring-cyan-500 disabled:opacity-50 disabled:bg-slate-800 ${
            error ? "border-rose-500 focus:border-rose-500 focus:ring-rose-500" : "border-slate-700 hover:border-slate-600"
          } ${className}`}
          {...props}
        >
          {options.map((opt) => (
            <option key={opt.value} value={opt.value} className="bg-slate-900 text-slate-100">
              {opt.label}
            </option>
          ))}
        </select>
        {hint && !error && (
          <p id={`${selectId}-hint`} className="mt-1 text-xs text-slate-400">
            {hint}
          </p>
        )}
        {error && (
          <p id={`${selectId}-error`} className="mt-1 text-xs font-medium text-rose-400">
            {error}
          </p>
        )}
      </div>
    );
  }
);

Select.displayName = "Select";

