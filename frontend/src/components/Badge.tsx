import React from "react";

export interface BadgeProps {
  children: React.ReactNode;
  variant?: "success" | "danger" | "warning" | "info" | "neutral" | "purple";
  size?: "sm" | "md";
  className?: string;
  icon?: React.ReactNode;
}

export function Badge({
  children,
  variant = "neutral",
  size = "md",
  className = "",
  icon,
}: BadgeProps) {
  const variantStyles = {
    success: "bg-emerald-950/70 text-emerald-300 border-emerald-700/60",
    danger: "bg-rose-950/70 text-rose-300 border-rose-700/60",
    warning: "bg-amber-950/70 text-amber-300 border-amber-700/60",
    info: "bg-cyan-950/70 text-cyan-300 border-cyan-700/60",
    purple: "bg-purple-950/70 text-purple-300 border-purple-700/60",
    neutral: "bg-slate-800 text-slate-300 border-slate-700",
  };

  const sizeStyles = {
    sm: "px-2 py-0.5 text-xs font-medium gap-1",
    md: "px-2.5 py-1 text-xs font-semibold gap-1.5",
  };

  return (
    <span
      className={`inline-flex items-center rounded-full border ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
    >
      {icon && <span className="shrink-0">{icon}</span>}
      <span>{children}</span>
    </span>
  );
}

