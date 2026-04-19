const BASE = import.meta.env?.VITE_API_URL || 'http://localhost:4000';

export const getToken  = () => localStorage.getItem('connect_token');
export const setToken  = (t) => localStorage.setItem('connect_token', t);
export const clearToken = () => {
  localStorage.removeItem('connect_token');
  localStorage.removeItem('connect_user');
};

async function req(path, options = {}) {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });

  if (res.status === 401) {
    clearToken();
    window.location.href = '/';
  }

  if (!res.ok) {
    const e = await res.json();
    throw new Error(e.error || 'Request failed');
  }

  return res.json();
}

export const api = {
  // Generic
  get:   (path)         => req(path),
  post:  (path, body)   => req(path, { method: 'POST',  body: JSON.stringify(body) }),
  patch: (path, body)   => req(path, { method: 'PATCH', body: JSON.stringify(body) }),

  // Auth
  login: (email, password) => req('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  me:    ()                => req('/api/auth/me'),

  // Dashboard
  dashboardStats:  () => req('/api/dashboard/stats'),
  dashboardCharts: () => req('/api/dashboard/charts'),

  // CBOM
  cbom:        (path = '') => req(`/api/cbom${path}`),
  cbomSummary: ()          => req('/api/cbom/summary'),
  cbomRoadmap: ()          => req('/api/cbom/migration-roadmap'),

  // Alerts
  alerts:      (path = '') => req(`/api/alerts${path}`),
  createAlert: (data)      => req('/api/alerts', { method: 'POST', body: JSON.stringify(data) }),
  updateAlert: (id, status) => req(`/api/alerts/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) }),
  correlate:   ()          => req('/api/alerts/correlate', { method: 'POST', body: '{}' }),

  // Threat Intel
  iocs:   ()              => req('/api/threat-intel/iocs'),
  cves:   ()              => req('/api/threat-intel/cves'),
  lookup: (indicator, type) => req('/api/threat-intel/lookup', { method: 'POST', body: JSON.stringify({ indicator, type }) }),

  // ML
  zscore:      (values, threshold) => req('/api/ml/zscore',        { method: 'POST', body: JSON.stringify({ values, threshold }) }),
  dnsTunneling: (queries)          => req('/api/ml/dns-tunneling', { method: 'POST', body: JSON.stringify({ queries }) }),
  mlAnomalies: ()                  => req('/api/ml/anomalies'),
};
