import type { components, paths } from "./schema";

export type Schemas = components["schemas"];

export type UserRole = Schemas["UserRole"];
export type UserRead = Schemas["UserRead"];
export type UserLogin = Schemas["UserLogin"];
export type TokenResponse = Schemas["TokenResponse"];

export type TargetRead = Schemas["TargetRead"];
export type TargetCreate = Schemas["TargetCreate"];
export type TargetUpdate = Schemas["TargetUpdate"];

export type ScopeItemRead = Schemas["ScopeItemRead"];
export type ScopeItemCreate = Schemas["ScopeItemCreate"];
export type ScopeValidationRequest = Schemas["ScopeValidationRequest"];
export type ScopeValidationResponse = Schemas["ScopeValidationResponse"];

export type AssessmentRead = Schemas["AssessmentRead"];
export type AssessmentCreate = Schemas["AssessmentCreate"];

export type ScanRead = Schemas["ScanRead"];
export type ScanCreate = Schemas["ScanCreate"];
export type ScanTool = Schemas["ScanTool"];
export type ScanStatus = Schemas["ScanStatus"];

export type WebAssessmentRequest = Schemas["WebAssessmentRequest"];

export type AssetRead = Schemas["AssetRead"];
export type AssetType = Schemas["AssetType"];

// Phase 8: Findings, Verification, Evidence, and AI Types
export type FindingRead = Schemas["FindingRead"];
export type FindingSeverity = Schemas["FindingSeverity"];
export type FindingStatus = Schemas["FindingStatus"];
export type FindingSource = Schemas["FindingSource"];
export type FindingsSummary = Schemas["FindingsSummary"];

export type VerificationRead = Schemas["VerificationRead"];
export type VerificationCreate = Schemas["VerificationCreate"];
export type VerificationDecision = Schemas["VerificationDecision"];

export type SeverityUpdateRequest = Schemas["SeverityUpdateRequest"];
export type SeverityChangeRead = Schemas["SeverityChangeRead"];

export type EvidenceRead = Schemas["EvidenceRead"];
export type EvidenceType = Schemas["EvidenceType"];
export type NoteEvidenceCreate = Schemas["NoteEvidenceCreate"];

export type AIStatusRead = Schemas["AIStatusRead"];
export type AIAnalysisRead = Schemas["AIAnalysisRead"];
export type AIFunction = Schemas["AIFunction"];
export type AIAnalysisStatus = Schemas["AIAnalysisStatus"];
export type AIReviewStatus = Schemas["AIReviewStatus"];
export type PromoteSuggestionRequest = Schemas["PromoteSuggestionRequest"];
export type ReviewAnalysisRequest = Schemas["ReviewAnalysisRequest"];

// Phase 9: Dashboard, Reports, Users, and Audit Log Types
export type AssessmentDashboardResponse = Schemas["AssessmentDashboardResponse"];
export type GlobalDashboardResponse = Schemas["GlobalDashboardResponse"];
export type DashboardMetrics = Schemas["DashboardMetrics"];
export type ReportRead = Schemas["ReportRead"];
export type ReportGenerateRequest = Schemas["ReportGenerateRequest"];
export type LatestReportMetadata = Schemas["LatestReportMetadata"];
export type UserCreate = Schemas["UserCreate"];
export type UserUpdate = Schemas["UserUpdate"];
export type AuditLogRead = Schemas["AuditLogRead"];
export type AssessmentOverviewItem = Schemas["AssessmentOverviewItem"];

export type Paths = paths;


