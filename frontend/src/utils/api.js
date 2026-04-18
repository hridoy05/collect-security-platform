const BASE = import.meta.env?.VITE_API_URL || 'http://localhost:4000';
export const getToken = () => localStorage.getItem('connect_token');
export const setToken = t => localStorage.setItem('connect_token', t);
export const clearToken = () => { localStorage.removeItem('connect_token'); localStorage.removeItem('connect_user'); };
async function req(path, options = {}) {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(options.headers || {}) }
  });
  if (res.status === 401) { clearToken(); window.location.href = '/'; }
  if (!res.ok) { const e = await res.json(); throw new Error(e.error || 'Request failed'); }
  return res.json();
}
export const api = {
  get: p => req(p), post: (p,b) => req(p,{method:'POST',body:JSON.stringify(b)}),
  patch: (p,b) => req(p,{method:'PATCH',body:JSON.stringify(b)}),
  login: (e,p) => req('/api/auth/login',{method:'POST',body:JSON.stringify({email:e,password:p})}),
  me: () => req('/api/auth/me'),
  dashboardStats: () => req('/api/dashboard/stats'),
  cbom: (p='') => req(`/api/cbom${p}`), cbomSummary: () => req('/api/cbom/summary'), cbomRoadmap: () => req('/api/cbom/migration-roadmap'),
  alerts: (p='') => req(`/api/alerts${p}`), createAlert: d => req('/api/alerts',{method:'POST',body:JSON.stringify(d)}),
  updateAlert: (id,s) => req(`/api/alerts/${id}/status`,{method:'PATCH',body:JSON.stringify({status:s})}),
  correlate: () => req('/api/alerts/correlate',{method:'POST',body:'{}'}),
  iocs: () => req('/api/threat-intel/iocs'), cves: () => req('/api/threat-intel/cves'),
  lookup: (i,t) => req('/api/threat-intel/lookup',{method:'POST',body:JSON.stringify({indicator:i,type:t})}),
  zscore: (v,t) => req('/api/ml/zscore',{method:'POST',body:JSON.stringify({values:v,threshold:t})}),
  dnsTunneling: q => req('/api/ml/dns-tunneling',{method:'POST',body:JSON.stringify({queries:q})}),
  mlAnomalies: () => req('/api/ml/anomalies'),
};
