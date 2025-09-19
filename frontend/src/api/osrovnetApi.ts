/* Lightweight API client for OSROVNet backend
   Exports async functions for the main backend features. Uses fetch and assumes
   same-origin auth (cookies) or environment manages Authorization header.

   Add or adapt headers (Authorization) if your app uses token auth.
*/

type Json = any;

// Default API base: in development we point to localhost backend; in production prefer same-origin '/api'
const API_BASE = process.env.REACT_APP_API_BASE || (process.env.NODE_ENV === 'production' ? '/api' : 'http://127.0.0.1:8000/api');

async function request(path: string, opts: RequestInit = {}) {
  const url = path.startsWith('http') ? path : `${API_BASE}${path}`;
  const defaultHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  // attach token if present
  try {
    const token = localStorage.getItem('osrovnet_token_v1');
    if (token) defaultHeaders['Authorization'] = `Token ${token}`;
  } catch (e) {}

  const init: RequestInit = {
    credentials: 'include',
    ...opts,
    headers: {
      ...defaultHeaders,
      ...(opts.headers || {}),
    },
  };

  const res = await fetch(url, init);
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  if (!res.ok) {
    const err: any = new Error(`API error ${res.status}`);
    err.status = res.status;
    err.body = data;
    throw err;
  }
  return data;
}

/* Network Security */
export const Targets = {
  list: (query?: string) => request(`/targets/${query || ''}`),
  create: (payload: Json) => request(`/targets/`, { method: 'POST', body: JSON.stringify(payload) }),
  retrieve: (id: number) => request(`/targets/${id}/`),
  update: (id: number, payload: Json) => request(`/targets/${id}/`, { method: 'PUT', body: JSON.stringify(payload) }),
  partialUpdate: (id: number, payload: Json) => request(`/targets/${id}/`, { method: 'PATCH', body: JSON.stringify(payload) }),
  delete: (id: number) => request(`/targets/${id}/`, { method: 'DELETE' }),
  startScan: (id: number) => request(`/targets/${id}/start_scan/`, { method: 'POST' }),
};

export const Scans = {
  list: (params = '') => request(`/scans/${params}`),
  retrieve: (id: number) => request(`/scans/${id}/`),
  stop: (id: number) => request(`/scans/${id}/stop_scan/`, { method: 'POST' }),
};

export const Hosts = {
  list: (params = '') => request(`/hosts/${params}`),
  retrieve: (id: number) => request(`/hosts/${id}/`),
};

export const Vulnerabilities = {
  list: (params = '') => request(`/vulnerabilities/${params}`),
  retrieve: (id: number) => request(`/vulnerabilities/${id}/`),
};

export const Alerts = {
  list: (params = '') => request(`/alerts/${params}`),
  retrieve: (id: number) => request(`/alerts/${id}/`),
  assignToMe: (id: number) => request(`/alerts/${id}/assign_to_me/`, { method: 'POST' }),
  markResolved: (id: number) => request(`/alerts/${id}/mark_resolved/`, { method: 'POST' }),
};

/* Quick scan */
export const QuickScan = (payload: Json) => request(`/quick-scan/`, { method: 'POST', body: JSON.stringify(payload) });

/* Analytics */
export const Analytics = {
  metrics: (params = '') => request(`/analytics/metrics/${params}`),
  events: (params = '') => request(`/analytics/events/${params}`),
  reports: (params = '') => request(`/analytics/reports/${params}`),
  scheduledReports: (params = '') => request(`/analytics/scheduled-reports/${params}`),
};

/* Threat Intelligence */
export const ThreatIntel = {
  feeds: (params = '') => request(`/threat-feeds/${params}`),
  iocs: (params = '') => request(`/iocs/${params}`),
  threatMatches: (params = '') => request(`/threat-matches/${params}`),
  startHunt: (payload: Json) => request(`/threat-hunts/`, { method: 'POST', body: JSON.stringify(payload) }),
};

/* Infrastructure */
export const Infrastructure = {
  components: (params = '') => request(`/components/${params}`),
  metrics: (params = '') => request(`/metrics/${params}`),
  alerts: (params = '') => request(`/alerts/${params}`),
};

/* Advanced analytics */
export const Advanced = {
  hunts: (params = '') => request(`/advanced-analytics/hunts/${params}`),
  simulations: (params = '') => request(`/advanced-analytics/simulations/${params}`),
  tamperLogs: (params = '') => request(`/advanced-analytics/tamper-logs/${params}`),
};

/* Quantum-Inspired Analytics */
export const QuantumInspired = {
  listTechniques: () => request('/api/quantum-inspired/techniques/'),
  run: (payload: Json) => request('/api/quantum-inspired/run/', { method: 'POST', body: JSON.stringify(payload) }),
};

/* Security Analytics / ML endpoints */
export const SecurityAnalytics = {
  detect: (modelId: number, payload: Json) => request(`/models/${modelId}/detect/`, { method: 'POST', body: JSON.stringify(payload) }),
  train: (payload: Json) => request(`/training/`, { method: 'POST', body: JSON.stringify(payload) }),
  behaviorAnalyze: (payload: Json) => request(`/behavior/analyze/`, { method: 'POST', body: JSON.stringify(payload) }),
};

/* SIEM */
export const SIEM = {
  logSources: (params = '') => request(`/siem/log-sources/${params}`),
  events: (params = '') => request(`/siem/events/${params}`),
  alerts: (params = '') => request(`/siem/alerts/${params}`),
};

/* Post-Quantum (PQC) */
export const PostQuantum = {
  listAlgorithms: () => request('/postquantum/algorithms/'),
  generateKeypair: (payload: Json) => request('/postquantum/generate/', { method: 'POST', body: JSON.stringify(payload) }),
};

/* Vulnerability management */
export const VulnMgmt = {
  scanners: (params = '') => request(`/vulnerability-management/scanners/${params}`),
  scanConfigs: (params = '') => request(`/vulnerability-management/scan-configs/${params}`),
  executions: (params = '') => request(`/vulnerability-management/executions/${params}`),
};

// eslint-disable-next-line import/no-anonymous-default-export
export default {
  request,
  Targets,
  Scans,
  Hosts,
  Vulnerabilities,
  Alerts,
  QuickScan,
  Analytics,
  ThreatIntel,
  Infrastructure,
  Advanced,
  SIEM,
  VulnMgmt,
  SecurityAnalytics,
  QuantumInspired,
};
