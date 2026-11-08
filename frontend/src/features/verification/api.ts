import apiClient from "@/shared/api/client";

export const verificationApi = {
  listVerifications: async () => {
    const response = await apiClient.get("/verification/");
    return response.data;
  },
};
