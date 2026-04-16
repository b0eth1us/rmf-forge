import axios from "axios";

export const api = axios.create({
  baseURL: "/api",
  headers: { "Content-Type": "application/json" },
});

export const projectsApi = {
  list: () => api.get("/projects/").then(r => r.data),
  get:  (id: string) => api.get(`/projects/${id}`).then(r => r.data),
  create: (data: { name: string; system_name?: string; description?: string }) =>
    api.post("/projects/", data).then(r => r.data),
  delete: (id: string) => api.delete(`/projects/${id}`),
};

export const findingsApi = {
  list: (projectId: string, params?: { status?: string; source_tool?: string }) =>
    api.get(`/findings/project/${projectId}`, { params }).then(r => r.data),
  summary: (projectId: string) =>
    api.get(`/findings/project/${projectId}/summary`).then(r => r.data),
  update: (id: string, data: { status?: string; justification?: string; vuln_id?: string }) =>
    api.patch(`/findings/${id}`, data).then(r => r.data),
};
