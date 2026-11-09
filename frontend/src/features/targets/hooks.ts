import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import * as api from "./api";
import type { TargetCreate, TargetUpdate, ScopeItemCreate } from "../../api/types";
import { useToast } from "../../components/Toast";

export function useTargets(limit = 100, offset = 0) {
  return useQuery({
    queryKey: ["targets", { limit, offset }],
    queryFn: () => api.fetchTargets(limit, offset),
  });
}

export function useTarget(id: string | undefined) {
  return useQuery({
    queryKey: ["target", id],
    queryFn: () => (id ? api.fetchTarget(id) : Promise.reject("No ID provided")),
    enabled: !!id,
  });
}

export function useCreateTarget() {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (payload: TargetCreate) => api.createTarget(payload),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      toast.success("Target created", `Target "${data.name}" was successfully registered.`);
    },
    onError: (err: any) => {
      toast.error("Failed to create target", err?.message || "An unexpected error occurred.");
    },
  });
}

export function useUpdateTarget(id: string) {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (payload: TargetUpdate) => api.updateTarget(id, payload),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      queryClient.invalidateQueries({ queryKey: ["target", id] });
      toast.success("Target updated", `Target "${data.name}" has been updated.`);
    },
    onError: (err: any) => {
      toast.error("Failed to update target", err?.message || "An unexpected error occurred.");
    },
  });
}

export function useDeleteTarget() {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      toast.success("Target deleted", "Target and its scope items have been deleted.");
    },
    onError: (err: any) => {
      toast.error("Failed to delete target", err?.message || "Action prohibited.");
    },
  });
}

export function useAddScopeItem(targetId: string) {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (payload: ScopeItemCreate) => api.addScopeItem(targetId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["target", targetId] });
      toast.success("Scope item added", "The scope boundary item has been created.");
    },
    onError: (err: any) => {
      toast.error("Failed to add scope item", err?.message || "Validation error.");
    },
  });
}

export function useDeleteScopeItem(targetId: string) {
  const queryClient = useQueryClient();
  const toast = useToast();

  return useMutation({
    mutationFn: (scopeItemId: string) => api.deleteScopeItem(targetId, scopeItemId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["target", targetId] });
      toast.success("Scope item deleted", "The scope boundary has been removed.");
    },
    onError: (err: any) => {
      toast.error("Failed to delete scope item", err?.message || "Action prohibited.");
    },
  });
}

export function useScopeValidator(targetId: string) {
  return useMutation({
    mutationFn: (asset: string) => api.validateScope(targetId, asset),
  });
}

