import apiClient from "@/shared/api/client";

export const aiApi = {
  getStatus: async () => {
    const response = await apiClient.get("/ai-analysis/");
    return response.data;
  },
};
