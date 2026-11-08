import apiClient from "@/shared/api/client";

export const authApi = {
  getProfile: async () => {
    const response = await apiClient.get("/auth/me");
    return response.data;
  },
};
