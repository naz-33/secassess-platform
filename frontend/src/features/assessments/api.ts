import apiClient from "@/shared/api/client";

export const assessmentsApi = {
  listAssessments: async () => {
    const response = await apiClient.get("/assessments/");
    return response.data;
  },
};
