import axios from "axios";

const api = axios.create({
  baseURL: "/api/v1",
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
  },
});

api.interceptors.request.use((config) => {
  const stored = localStorage.getItem("phishguard-auth");
  if (stored) {
    try {
      const { state } = JSON.parse(stored);
      if (state?.token) {
        config.headers.Authorization = `Bearer ${state.token}`;
      }
    } catch {
      // ignore
    }
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        const stored = localStorage.getItem("phishguard-auth");
        if (stored) {
          const { state } = JSON.parse(stored);
          if (state?.refreshToken) {
            const response = await axios.post("/api/v1/auth/refresh", {
              refresh_token: state.refreshToken,
            });

            const { access_token, refresh_token } = response.data;
            const updated = {
              ...JSON.parse(stored),
              state: { ...state, token: access_token, refreshToken: refresh_token },
            };
            localStorage.setItem("phishguard-auth", JSON.stringify(updated));

            originalRequest.headers.Authorization = `Bearer ${access_token}`;
            return api(originalRequest);
          }
        }
      } catch {
        localStorage.removeItem("phishguard-auth");
        window.location.href = "/login";
      }
    }

    return Promise.reject(error);
  }
);

export default api;
