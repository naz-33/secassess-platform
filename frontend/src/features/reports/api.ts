import apiClient from "@/shared/api/client";

export const reportsApi = {
  listReports: async () => {
    const response = await apiClient.get("/reports/");
    return response.data;
  },
};
