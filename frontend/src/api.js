const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000'

async function request(path, options = {}, token, responseType = 'json') {
  const headers = new Headers(options.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  if (options.body && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(`${API_BASE_URL}${path}`, { ...options, headers })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.error?.message ?? body?.detail ?? `Request failed (${response.status})`)
  }
  if (response.status === 204) return null
  return responseType === 'blob' ? response.blob() : response.json()
}

export const api = {
  register: (payload) => request('/api/v1/auth/register', { method: 'POST', body: JSON.stringify(payload) }),
  login: (email, password) => request('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  me: (token) => request('/api/v1/auth/me', {}, token),
  changePassword: (currentPassword, newPassword, token) => request('/api/v1/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }) }, token),
  uploadEmail: (file, token) => {
    const form = new FormData()
    form.append('file', file)
    return request('/api/v1/emails/upload', { method: 'POST', body: form }, token)
  },
  startAnalysis: (emailId, token) => request('/api/v1/analysis', { method: 'POST', body: JSON.stringify({ email_id: emailId }) }, token),
  investigations: (token) => request('/api/v1/investigations?page_size=100', {}, token),
  investigation: (analysisId, token) => request(`/api/v1/investigations/${analysisId}`, {}, token),
  report: (analysisId, token) => request(`/api/v1/investigations/${analysisId}/report/pdf`, {}, token, 'blob'),
}
