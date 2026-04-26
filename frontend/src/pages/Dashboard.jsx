import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'
import {
  ShieldAlert, AlertTriangle, Database, Zap, TrendingUp, Crosshair,
} from 'lucide-react'
import { getStats, getTopRisk, getHealth } from '../api'
import { severityBadge, severityLabel, formatDate } from '../utils'

const PIE_COLORS = ['#dc2626', '#ea580c', '#d97706', '#059669']

const CHART_TOOLTIP_STYLE = {
  background: '#ffffff',
  border: '1px solid #e2e5ee',
  borderRadius: 10,
  boxShadow: '0 4px 16px rgba(0,0,0,0.08)',
  color: '#1a1d2b',
  fontSize: 13,
  padding: '8px 12px',
}

/* ── Animated counter (uses IntersectionObserver directly) ── */
function AnimatedNumber({ value, duration = 1200 }) {
  const [display, setDisplay] = useState(0)
  const ref = useRef(null)
  const started = useRef(false)

  useEffect(() => {
    if (value == null || started.current) return
    const el = ref.current
    if (!el) return

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (!entry.isIntersecting || started.current) return
        started.current = true
        observer.disconnect()

        const num = typeof value === 'string' ? parseFloat(value.replace(/[^0-9.]/g, '')) : value
        if (isNaN(num)) { setDisplay(value); return }

        const startTime = performance.now()
        function tick(now) {
          const progress = Math.min((now - startTime) / duration, 1)
          const eased = 1 - Math.pow(1 - progress, 3)
          setDisplay(Math.floor(num * eased))
          if (progress < 1) requestAnimationFrame(tick)
        }
        requestAnimationFrame(tick)
      },
      { threshold: 0.1 }
    )
    observer.observe(el)
    return () => observer.disconnect()
  }, [value, duration])

  return <span ref={ref}>{typeof display === 'number' ? display.toLocaleString() : display}</span>
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [topRisk, setTopRisk] = useState([])
  const [health, setHealth] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    Promise.all([getStats(), getTopRisk(10), getHealth()])
      .then(([s, r, h]) => { setStats(s); setTopRisk(r); setHealth(h) })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner" />
        <span>Loading dashboard…</span>
      </div>
    )
  }

  if (error) {
    return (
      <div>
        <div className="page-header"><h2>Dashboard</h2></div>
        <div className="error-box">⚠ {error}</div>
      </div>
    )
  }

  const severity = stats?.severity || {}
  const pieData = [
    { name: 'Critical', value: severity.critical || 0 },
    { name: 'High',     value: severity.high || 0 },
    { name: 'Medium',   value: severity.medium || 0 },
    { name: 'Low',      value: severity.low || 0 },
  ]
  const yearlyData = (stats?.yearly_distribution || []).slice(-7)

  return (
    <div className="dashboard-page fade-in">
      <div className="page-header">
        <h2>Dashboard</h2>
        <p>AI-Driven Vulnerability Intelligence Overview</p>
      </div>

      {/* ── Stat Cards ──────────────────────────────────── */}
      <div className="stat-grid">
        <StatCard icon={<Database size={18} />} accent="indigo"
          iconBg="rgba(99,102,241,0.1)" iconColor="#6366f1"
          label="Total CVEs" value={stats?.total_vulnerabilities} delay={0} />
        <StatCard icon={<AlertTriangle size={18} />} accent="red"
          iconBg="rgba(220,38,38,0.08)" iconColor="#dc2626"
          label="Critical (CVSS ≥ 9)" value={severity.critical} delay={1} />
        <StatCard icon={<Crosshair size={18} />} accent="orange"
          iconBg="rgba(234,88,12,0.08)" iconColor="#ea580c"
          label="KEV Listed" value={stats?.kev_listed} delay={2} />
        <StatCard icon={<Zap size={18} />} accent="amber"
          iconBg="rgba(217,119,6,0.08)" iconColor="#d97706"
          label="PoC Available" value={stats?.poc_available} delay={3} />
        <StatCard icon={<TrendingUp size={18} />} accent="blue"
          iconBg="rgba(37,99,235,0.08)" iconColor="#2563eb"
          label="Avg EPSS Score"
          value={stats?.avg_epss_score != null ? (stats.avg_epss_score * 100).toFixed(2) + '%' : '—'}
          noAnimate delay={4} />
        <StatCard icon={<ShieldAlert size={18} />} accent="emerald"
          iconBg="rgba(5,150,105,0.08)" iconColor="#059669"
          label="Critical (Last 30d)" value={stats?.recent_critical_30d} delay={5} />
      </div>

      {/* ── Charts ──────────────────────────────────────── */}
      <div className="chart-grid">
        <div className="card stagger-in" style={{ animationDelay: '0.15s' }}>
          <div className="card-title">Severity Distribution</div>
          <div style={{ width: '100%', height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%"
                  innerRadius={65} outerRadius={105} paddingAngle={3}
                  dataKey="value" cornerRadius={4}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={{ stroke: '#94a3b8', strokeWidth: 1 }}
                >
                  {pieData.map((_, i) => <Cell key={i} fill={PIE_COLORS[i]} />)}
                </Pie>
                <Legend verticalAlign="bottom" iconType="circle" iconSize={8}
                  formatter={(v) => <span style={{ color: '#4b5068', fontSize: 12, fontWeight: 500 }}>{v}</span>}
                />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card stagger-in" style={{ animationDelay: '0.25s' }}>
          <div className="card-title">CVEs by Year</div>
          <div style={{ width: '100%', height: 300 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={yearlyData}>
                <defs>
                  <linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%"   stopColor="#6366f1" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#6366f1" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="year"
                  tick={{ fill: '#4b5068', fontSize: 12, fontWeight: 500 }}
                  axisLine={{ stroke: '#e2e5ee' }} tickLine={false}
                />
                <YAxis tick={{ fill: '#4b5068', fontSize: 12 }}
                  axisLine={false} tickLine={false} width={50}
                />
                <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                <Area type="monotone" dataKey="count"
                  stroke="#6366f1" strokeWidth={2.5} fill="url(#areaGrad)"
                  dot={{ fill: '#6366f1', strokeWidth: 0, r: 4 }}
                  activeDot={{ r: 6, fill: '#6366f1', stroke: '#ffffff', strokeWidth: 2 }}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── Top Risk Table ──────────────────────────────── */}
      <div className="card stagger-in" style={{ padding: 0, overflow: 'hidden', animationDelay: '0.35s' }}>
        <div style={{ padding: '1rem 1.25rem', borderBottom: '1px solid var(--border)' }}>
          <div className="card-title" style={{ margin: 0 }}>Top Risk Vulnerabilities</div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table>
            <thead>
              <tr>
                <th>CVE ID</th><th>Title</th><th>CVSS</th>
                <th>EPSS</th><th>Risk Score</th><th>Published</th>
              </tr>
            </thead>
            <tbody>
              {topRisk.map((v, idx) => (
                <tr key={v.cve_id}
                  className="table-row-animated"
                  style={{ animationDelay: `${idx * 40}ms`, cursor: 'pointer' }}
                  onClick={() => navigate(`/vuln/${v.cve_id}`)}
                >
                  <td className="mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                    {v.cve_id || '—'}
                  </td>
                  <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {v.title || '—'}
                  </td>
                  <td>
                    <span className={`badge ${severityBadge(v.cvss_base_score)}`}>
                      {v.cvss_base_score?.toFixed(1) ?? '—'} {severityLabel(v.cvss_base_score)}
                    </span>
                  </td>
                  <td className="mono">
                    {v.epss_score != null ? (v.epss_score * 100).toFixed(2) + '%' : '—'}
                  </td>
                  <td>
                    <span className="mono" style={{ fontWeight: 700, color: 'var(--critical)' }}>
                      {v.risk_score?.toFixed(2)}
                    </span>
                  </td>
                  <td style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {formatDate(v.published_at)}
                  </td>
                </tr>
              ))}
              {topRisk.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2.5rem' }}>No data available</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── System Status Bar ───────────────────────────── */}
      <div className="status-bar stagger-in" style={{ animationDelay: '0.45s' }}>
        <div className="status-item">
          <span className={`status-dot ${health?.db_connected ? 'status-dot-green' : 'status-dot-red'}`} />
          PostgreSQL
        </div>
        <div className="status-item">
          <span className={`status-dot ${health?.qdrant_connected ? 'status-dot-green' : 'status-dot-red'}`} />
          Qdrant
        </div>
        <div className="status-item">
          <span className={`status-dot ${stats?.openai_enabled ? 'status-dot-green' : 'status-dot-amber'}`} />
          OpenAI
        </div>
        <div style={{ marginLeft: 'auto', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Last refreshed: {new Date().toLocaleTimeString()}
        </div>
      </div>
    </div>
  )
}

/* ── Stat Card — motion only for hover ────────────────── */
function StatCard({ icon, accent, iconBg, iconColor, label, value, noAnimate, delay = 0 }) {
  return (
    <motion.div
      className={`stat-card stat-accent-${accent} stagger-in`}
      style={{ animationDelay: `${delay * 60}ms` }}
      whileHover={{ y: -3, transition: { type: 'spring', stiffness: 400, damping: 20 } }}
    >
      <div className="stat-card-header">
        <div className="card-title">{label}</div>
        <div className="stat-icon" style={{ background: iconBg, color: iconColor }}>
          {icon}
        </div>
      </div>
      <div className="card-value">
        {noAnimate || value == null || typeof value === 'string'
          ? (value ?? '—')
          : <AnimatedNumber value={value} />
        }
      </div>
    </motion.div>
  )
}
