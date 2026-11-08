import React from "react";
import { Badge } from "@/shared/components";
import { Severity } from "@/shared/types";

interface FindingSeverityBadgeProps {
  severity: Severity;
}

export const FindingSeverityBadge: React.FC<FindingSeverityBadgeProps> = ({ severity }) => {
  const variant = {
    critical: "danger" as const,
    high: "warning" as const,
    medium: "warning" as const,
    low: "info" as const,
    info: "neutral" as const,
  }[severity];

  return <Badge variant={variant}>{severity.toUpperCase()}</Badge>;
};
