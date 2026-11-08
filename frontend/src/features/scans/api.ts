import apiClient from "@/shared/api/client";

export const scansApi = {
  listScans: async () => {
    const response = await apiClient.get("/scans/");
    return response.data;
  },
};
