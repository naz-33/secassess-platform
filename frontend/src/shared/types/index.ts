export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus = "unverified" | "confirmed" | "false_positive" | "needs_testing";

export interface HealthStatus {
  status: string;
  database: string;
  version: string;
}
