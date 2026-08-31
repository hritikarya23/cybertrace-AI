export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export type ApiError = {
  success: false;
  error: { code: string; message: string };
};

export type LoginResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: { id: number; email: string; full_name: string; role: "admin" | "analyst" | "viewer" };
};

async function request<T>(path: string, init: RequestInit = {}, token?: string): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (!(init.body instanceof FormData)) headers.set("Content-Type", "application/json");

  const response = await fetch(`${API_BASE_URL}${path}`, { ...init, headers });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(body?.error?.message ?? body?.detail ?? `HTTP ${response.status}`);
  }
  return body as T;
}

export const api = {
  login: (email: string, password: string) =>
    request<LoginResponse>("/api/v1/auth/login", {
      method: "POST", body: JSON.stringify({ email, password }),
    }),
  me: (token: string) => request("/api/v1/auth/me", {}, token),
  uploadEmail: (file: File, token: string) => {
    const form = new FormData(); form.append("file", file);
    return request("/api/v1/emails/upload", { method: "POST", body: form }, token);
  },
  startAnalysis: (emailId: number, token: string) =>
    request("/api/v1/analysis", { method: "POST", body: JSON.stringify({ email_id: emailId }) }, token),
  analysis: (id: number, token: string) => request(`/api/v1/analysis/${id}`, {}, token),
  investigations: (query: string, token: string) => request(`/api/v1/investigations?${query}`, {}, token),
  investigation: (id: number, token: string) => request(`/api/v1/investigations/${id}`, {}, token),
  graph: (id: number, token: string) => request(`/api/v1/investigations/${id}/graph`, {}, token),
};
