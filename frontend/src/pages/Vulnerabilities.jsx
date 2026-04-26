import { useEffect, useState, useCallback } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { Search, ChevronLeft, ChevronRight, Filter, X } from 'lucide-react'
import { getVulnerabilities } from '../api'
import { severityBadge, severityLabel, formatDate, truncate } from '../utils'

export default function Vulnerabilities() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const page      = parseInt(searchParams.get('page') || '1', 10)
  const search    = searchParams.get('search') || ''
  const minCvss   = searchParams.get('min_cvss') || ''
  const sortBy    = searchParams.get('sort_by') || 'published_at'
  const sortOrder = searchParams.get('sort_order') || 'desc'

  const [data, setData]         = useState({ items: [], total: 0, pages: 0 })
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [searchInput, setSearchInput] = useState(search)
  const [showFilters, setShowFilters] = useState(false)

  const load = useCallback(() => {
    setLoading(true)
    setError(null)
    getVulnerabilities({
      page, perPage: 25,
      search: search || undefined,
      minCvss: minCvss ? parseFloat(minCvss) : null,
      sortBy, sortOrder,
    })
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [page, search, minCvss, sortBy, sortOrder])

  useEffect(() => { load() }, [load])

  const setParam = (key, value) => {
    const p = new URLSearchParams(searchParams)
    if (value) p.set(key, value); else p.delete(key)
    if (key !== 'page') p.set('page', '1')
    setSearchParams(p)
  }

  const handleSearch = (e) => { e.preventDefault(); setParam('search', searchInput) }

  const handleSort = (col) => {
    if (col === sortBy) {
      setParam('sort_order', sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      const p = new URLSearchParams(searchParams)
      p.set('sort_by', col); p.set('sort_order', 'desc'); p.set('page', '1')
      setSearchParams(p)
    }
  }

  const sortIcon = (col) => {
    if (col !== sortBy) return ''
    return sortOrder === 'asc' ? ' ↑' : ' ↓'
  }

  return (
    <div className="fade-in">
      <div className="page-header">
        <h2>Vulnerabilities</h2>
        <p>{data.total.toLocaleString()} total CVEs in database</p>
      </div>

      {/* ── Toolbar ──────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.75rem', marginBottom: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <form onSubmit={handleSearch} className="search-wrapper" style={{ flex: 1, minWidth: 250 }}>
          <Search size={16} />
          <input
            type="text"
            className="input input-search"
            placeholder="Search CVE ID, title, or description…"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
          />
        </form>

        <motion.button
          className="btn btn-secondary btn-sm"
          onClick={() => setShowFilters(!showFilters)}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
        >
          <Filter size={14} /> Filters
        </motion.button>

        {search && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => { setSearchInput(''); setParam('search', '') }}
          >
            <X size={14} /> Clear
          </button>
        )}
      </div>

      {/* ── Filter bar ───────────────────────────────────── */}
      <AnimatePresence>
        {showFilters && (
          <motion.div
            className="card"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: 0.25 }}
            style={{ marginBottom: '1rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-end', padding: '1rem 1.25rem', overflow: 'hidden' }}
          >
            <div>
              <label className="detail-label">Min CVSS</label>
              <select
                className="input"
                value={minCvss}
                onChange={(e) => setParam('min_cvss', e.target.value)}
                style={{ minWidth: 140 }}
              >
                <option value="">Any</option>
                <option value="9">Critical (≥ 9.0)</option>
                <option value="7">High (≥ 7.0)</option>
                <option value="4">Medium (≥ 4.0)</option>
              </select>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {error && <div className="error-box" style={{ marginBottom: '1rem' }}>⚠ {error}</div>}

      {/* ── Table ────────────────────────────────────────── */}
      <div className="table-container stagger-in" style={{ animationDelay: '0.1s' }}>
        <table>
          <thead>
            <tr>
              <th onClick={() => handleSort('cve_id')} style={{ cursor: 'pointer' }}>CVE ID{sortIcon('cve_id')}</th>
              <th>Title</th>
              <th onClick={() => handleSort('cvss_base_score')} style={{ cursor: 'pointer' }}>CVSS{sortIcon('cvss_base_score')}</th>
              <th onClick={() => handleSort('published_at')} style={{ cursor: 'pointer' }}>Published{sortIcon('published_at')}</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              Array.from({ length: 10 }).map((_, i) => (
                <tr key={i} style={{ cursor: 'default' }}>
                  <td><div className="skeleton" style={{ height: 16, width: 130 }} /></td>
                  <td><div className="skeleton" style={{ height: 16, width: '85%' }} /></td>
                  <td><div className="skeleton" style={{ height: 22, width: 85 }} /></td>
                  <td><div className="skeleton" style={{ height: 16, width: 100 }} /></td>
                </tr>
              ))
            ) : data.items.length === 0 ? (
              <tr style={{ cursor: 'default' }}>
                <td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '3rem' }}>
                  No vulnerabilities found.
                </td>
              </tr>
            ) : (
              data.items.map((v, idx) => (
                <tr
                  key={v.id}
                  className="table-row-animated"
                  style={{ animationDelay: `${idx * 20}ms` }}
                  onClick={() => navigate(`/vuln/${v.cve_id || v.id}`)}
                >
                  <td className="mono" style={{ fontWeight: 600, whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                    {v.cve_id || v.vuldb_id || '—'}
                  </td>
                  <td style={{ maxWidth: 480 }}>
                    {truncate(v.title || v.description, 110)}
                  </td>
                  <td>
                    <span className={`badge ${severityBadge(v.cvss_base_score)}`}>
                      {v.cvss_base_score?.toFixed(1) ?? '—'} {severityLabel(v.cvss_base_score)}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {formatDate(v.published_at)}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* ── Pagination ────────────────────────────────── */}
        <div className="pagination">
          <span>Page {page} of {data.pages || 1} · {data.total.toLocaleString()} results</span>
          <div className="pagination-controls">
            <motion.button
              className="btn btn-secondary btn-sm"
              disabled={page <= 1}
              onClick={() => setParam('page', String(page - 1))}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
            >
              <ChevronLeft size={14} /> Prev
            </motion.button>
            <motion.button
              className="btn btn-secondary btn-sm"
              disabled={page >= data.pages}
              onClick={() => setParam('page', String(page + 1))}
              whileHover={{ scale: 1.04 }}
              whileTap={{ scale: 0.96 }}
            >
              Next <ChevronRight size={14} />
            </motion.button>
          </div>
        </div>
      </div>
    </div>
  )
}
