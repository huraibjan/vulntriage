/**
 * VulnTriage API client — thin wrapper around fetch for the FastAPI backend.
 */

const BASE = '/api';

async function request(path, options = {}) {
  const url = `${BASE}${path}`;
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
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

export const getLLMBrief = (vulnId) =>
  request(`/v1/brief-llm/${vulnId}`, { method: 'POST' });

/* ── Reports ────────────────────────────────────────────── */
export const getLatestReport = () => request('/v1/reports/latest');

/* ── Policy ─────────────────────────────────────────────── */
export const getPolicy = () => request('/v1/policy');
