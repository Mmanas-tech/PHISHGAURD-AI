const API_BASE_URL = "http://localhost:8000";
const MAX_RETRIES = 3;

export async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const config = {
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
    ...options,
  };

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(url, config);

      if (response.status === 429) {
        const waitTime = Math.pow(2, attempt) * 1000;
        await new Promise((r) => setTimeout(r, waitTime));
        continue;
      }

      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.detail || `HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      if (attempt === MAX_RETRIES - 1) throw error;
      const waitTime = Math.pow(2, attempt) * 500;
      await new Promise((r) => setTimeout(r, waitTime));
    }
  }
}

export async function scanUrl(url, htmlContent = null) {
  const body = { url };
  if (htmlContent) body.html_content = htmlContent;

  return apiRequest("/api/v1/scan", {
    method: "POST",
    body: JSON.stringify(body),
  });
}

export async function getScanHistory(page = 1, pageSize = 20) {
  return apiRequest(`/api/v1/scan/history?page=${page}&page_size=${pageSize}`);
}

export async function login(email, password) {
  return apiRequest("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function register(email, password) {
  return apiRequest("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function refreshToken(refreshToken) {
  return apiRequest("/api/v1/auth/refresh", {
    method: "POST",
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
}

export async function getDashboardStats() {
  return apiRequest("/api/v1/dashboard/stats");
}

export async function getTimeline(days = 30) {
  return apiRequest(`/api/v1/dashboard/timeline?days=${days}`);
}

export async function getThreats(page = 1, filters = {}) {
  const params = new URLSearchParams({ page: page.toString() });
  if (filters.threat_level) params.set("threat_level", filters.threat_level);
  if (filters.threat_type) params.set("threat_type", filters.threat_type);

  return apiRequest(`/api/v1/dashboard/threats?${params.toString()}`);
}
