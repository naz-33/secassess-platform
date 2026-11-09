import React from "react";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost" | "outline";
  size?: "sm" | "md" | "lg";
  isLoading?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      children,
      variant = "primary",
      size = "md",
      isLoading = false,
      disabled,
      className = "",
      ...props
    },
    ref
  ) => {
    const baseStyles =
      "inline-flex items-center justify-center font-medium rounded-md transition-colors focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed select-none";

    const variantStyles = {
      primary:
        "bg-cyan-600 text-white hover:bg-cyan-500 focus:ring-cyan-500 focus:ring-offset-slate-900 border border-transparent",
      secondary:
        "bg-slate-700 text-slate-100 hover:bg-slate-600 focus:ring-slate-400 focus:ring-offset-slate-900 border border-slate-600",
      danger:
        "bg-rose-600 text-white hover:bg-rose-500 focus:ring-rose-500 focus:ring-offset-slate-900 border border-transparent",
      outline:
        "border border-slate-600 text-slate-300 hover:bg-slate-800 hover:text-white focus:ring-slate-500 focus:ring-offset-slate-900",
      ghost:
        "text-slate-400 hover:text-white hover:bg-slate-800 focus:ring-slate-500 focus:ring-offset-slate-900 border border-transparent",
    };

    const sizeStyles = {
      sm: "px-2.5 py-1.5 text-xs gap-1.5",
      md: "px-3.5 py-2 text-sm gap-2",
      lg: "px-5 py-2.5 text-base gap-2.5",
    };

    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={`${baseStyles} ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
        {...props}
      >
        {isLoading && (
          <span
            data-testid="loading-spinner"
            className="h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
          />
        )}
        {children}
      </button>
    );
  }
);

Button.displayName = "Button";

