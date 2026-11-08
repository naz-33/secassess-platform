import apiClient from "@/shared/api/client";

export const findingsApi = {
  listFindings: async () => {
    const response = await apiClient.get("/findings/");
    return response.data;
  },
};
