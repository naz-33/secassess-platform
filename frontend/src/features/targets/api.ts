import apiClient from "@/shared/api/client";

export const targetsApi = {
  listTargets: async () => {
    const response = await apiClient.get("/targets/");
    return response.data;
  },
};
