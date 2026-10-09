/**
 * VulnTriage API client — thin wrapper around fetch for the FastAPI backend.
 */

const BASE = '/api';

// Deployments that set VULNTRIAGE_API_KEY require it on write and LLM requests.
// The key is kept in this browser only and sent as X-API-Key.
const API_KEY_STORAGE = 'vulntriage_api_key';
export const getApiKey = () => {
  try { return window.localStorage.getItem(API_KEY_STORAGE) || ''; } catch { return ''; }
};
export const setApiKey = (key) => {
  try {
    if (key) window.localStorage.setItem(API_KEY_STORAGE, key);
    else window.localStorage.removeItem(API_KEY_STORAGE);
  } catch { /* storage unavailable */ }
};

async function request(path, options = {}) {
  const url = `${BASE}${path}`;
  const key = getApiKey();
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(key ? { 'X-API-Key': key } : {}),
      ...options.headers,
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `API ${res.status}: ${res.statusText}`);
  }
  return res.json();
}

/* ── Health ─────────────────────────────────────────────── */
export const getHealth = () => request('/health');

/* ── Dashboard Stats ────────────────────────────────────── */
export const getStats = () => request('/v1/stats');
export const getTopRisk = (limit = 10) =>
  request(`/v1/stats/top-risk?limit=${limit}`);

/* ── Vulnerabilities ────────────────────────────────────── */
export const getVulnerabilities = ({
  page = 1,
  perPage = 25,
  search = '',
  minCvss = null,
  maxCvss = null,
  sortBy = 'published_at',
  sortOrder = 'desc',
  hasKev = null,
} = {}) => {
  const params = new URLSearchParams({ page, per_page: perPage, sort_by: sortBy, sort_order: sortOrder });
  if (search) params.set('search', search);
  if (minCvss !== null) params.set('min_cvss', minCvss);
  if (maxCvss !== null) params.set('max_cvss', maxCvss);
  if (hasKev !== null) params.set('has_kev', hasKev);
  return request(`/v1/vulnerabilities?${params}`);
};

export const getVulnerability = (id) => request(`/v1/vulnerabilities/${id}`);

/* ── Predictions ────────────────────────────────────────── */
export const predict = (vulnId, asof = null) => {
  const q = asof ? `?asof=${asof}` : '';
  return request(`/v1/predict/${vulnId}${q}`, { method: 'POST' });
};

/* ── RAG Briefs ─────────────────────────────────────────── */
export const getBrief = (vulnId) =>
  request(`/v1/brief/${vulnId}`, { method: 'POST' });

export const getLLMBrief = (vulnId, { verify = false, refresh = false } = {}) => {
  const params = new URLSearchParams();
  if (verify) params.set('verify', 'true');
  if (refresh) params.set('refresh', 'true');
  const q = params.toString() ? `?${params}` : '';
  return request(`/v1/brief-llm/${vulnId}${q}`, { method: 'POST' });
};

/* ── Assets ─────────────────────────────────────────────── */
export const getAssets = () => request('/v1/assets');
export const createAsset = (asset) =>
  request('/v1/assets', { method: 'POST', body: JSON.stringify(asset) });
export const deleteAsset = (id) => request(`/v1/assets/${id}`, { method: 'DELETE' });
export const uploadSbom = (id, document) =>
  request(`/v1/assets/${id}/sbom`, { method: 'POST', body: JSON.stringify(document) });
export const uploadVex = (id, document) =>
  request(`/v1/assets/${id}/vex`, { method: 'POST', body: JSON.stringify(document) });
export const evaluateAsset = (id) =>
  request(`/v1/assets/${id}/evaluate`, { method: 'POST' });
export const getFindings = (id, { action = '', limit = 200 } = {}) => {
  const params = new URLSearchParams({ limit });
  if (action) params.set('action', action);
  return request(`/v1/assets/${id}/findings?${params}`);
};

/* ── Reports ────────────────────────────────────────────── */
export const getLatestReport = () => request('/v1/reports/latest');

/* ── Policy ─────────────────────────────────────────────── */
export const getPolicy = () => request('/v1/policy');
