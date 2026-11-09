import { apiClient } from "../../api/client";
import type {
  TargetRead,
  TargetCreate,
  TargetUpdate,
  ScopeItemRead,
  ScopeItemCreate,
  ScopeValidationResponse,
} from "../../api/types";

export async function fetchTargets(limit = 100, offset = 0): Promise<TargetRead[]> {
  return apiClient<TargetRead[]>(`/api/v1/targets?limit=${limit}&offset=${offset}`);
}

export async function fetchTarget(id: string): Promise<TargetRead> {
  return apiClient<TargetRead>(`/api/v1/targets/${id}`);
}

export async function createTarget(payload: TargetCreate): Promise<TargetRead> {
  return apiClient<TargetRead>("/api/v1/targets", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function updateTarget(id: string, payload: TargetUpdate): Promise<TargetRead> {
  return apiClient<TargetRead>(`/api/v1/targets/${id}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}

export async function deleteTarget(id: string): Promise<void> {
  return apiClient<void>(`/api/v1/targets/${id}`, {
    method: "DELETE",
  });
}

export async function fetchTargetScope(targetId: string): Promise<ScopeItemRead[]> {
  return apiClient<ScopeItemRead[]>(`/api/v1/targets/${targetId}/scope`);
}

export async function addScopeItem(targetId: string, payload: ScopeItemCreate): Promise<ScopeItemRead> {
  return apiClient<ScopeItemRead>(`/api/v1/targets/${targetId}/scope`, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function deleteScopeItem(targetId: string, scopeItemId: string): Promise<void> {
  return apiClient<void>(`/api/v1/targets/${targetId}/scope/${scopeItemId}`, {
    method: "DELETE",
  });
}

export async function validateScope(
  targetId: string,
  asset: string
): Promise<ScopeValidationResponse> {
  return apiClient<ScopeValidationResponse>(`/api/v1/targets/${targetId}/scope/validate`, {
    method: "POST",
    body: JSON.stringify({ asset }),
  });
}
