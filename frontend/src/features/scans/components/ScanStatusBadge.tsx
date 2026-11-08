import React from "react";
import { Badge } from "@/shared/components";

interface ScanStatusBadgeProps {
  status: "pending" | "running" | "completed" | "failed";
}

export const ScanStatusBadge: React.FC<ScanStatusBadgeProps> = ({ status }) => {
  const variant = {
    pending: "neutral" as const,
    running: "info" as const,
    completed: "success" as const,
    failed: "danger" as const,
  }[status];

  return <Badge variant={variant}>{status.toUpperCase()}</Badge>;
};
