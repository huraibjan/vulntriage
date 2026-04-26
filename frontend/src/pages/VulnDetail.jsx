import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ArrowLeft, Brain, Shield, Clock, ExternalLink, Cpu, Zap,
  CheckCircle2, XCircle, Loader2, Crosshair, Target,
} from 'lucide-react'
import { getVulnerability, predict, getLLMBrief } from '../api'
import { severityBadge, severityLabel, formatDate } from '../utils'
import AIPipeline from '../components/AIPipeline'

/* Typewriter-style text reveal */
function StreamingText({ text, speed = 12 }) {
  const [displayed, setDisplayed] = useState('')
  useEffect(() => {
    if (!text) return
    setDisplayed('')
    let i = 0
    const iv = setInterval(() => {
      i++
      setDisplayed(text.slice(0, i))
      if (i >= text.length) clearInterval(iv)
    }, speed)
    return () => clearInterval(iv)
  }, [text, speed])
  return <span>{displayed}<motion.span animate={{ opacity: [1,0] }} transition={{ duration: 0.5, repeat: Infinity }}>|</motion.span></span>
}

export default function VulnDetail() {
  const { id } = useParams()
  const navigate = useNavigate()

  const [vuln, setVuln]             = useState(null)
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState(null)
  const [prediction, setPrediction] = useState(null)
  const [predLoading, setPredLoading] = useState(false)
  const [brief, setBrief]           = useState(null)
  const [briefLoading, setBriefLoading] = useState(false)
  const [briefError, setBriefError] = useState(null)
  const [activeTab, setActiveTab]   = useState('overview')

  useEffect(() => {
    setLoading(true)
    getVulnerability(id)
      .then(setVuln)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [id])

  const handlePredict = () => {
    setPredLoading(true)
    predict(id)
      .then(setPrediction)
      .catch((e) => setError(e.message))
      .finally(() => setPredLoading(false))
  }

  const handleLLMBrief = () => {
    setBriefLoading(true)
    setBriefError(null)
    getLLMBrief(id)
      .then(setBrief)
      .catch((e) => setBriefError(e.message))
      .finally(() => setBriefLoading(false))
  }

  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner" />
        <span>Loading vulnerability…</span>
      </div>
    )
  }

  if (error && !vuln) {
    return (
      <div>
        <button className="btn btn-ghost" onClick={() => navigate(-1)}>
          <ArrowLeft size={16} /> Back
        </button>
        <div className="error-box" style={{ marginTop: '1rem' }}>⚠ {error}</div>
      </div>
    )
  }

  const cwes = vuln?.cwe_ids || []
  const refs = vuln?.references_json || []
  const products = vuln?.affected_products_json || []

  const probColor = (p) => {
    if (p > 0.7) return '#dc2626'
    if (p > 0.4) return '#d97706'
    return '#059669'
  }

  return (
    <div className="fade-in">
      {/* ── Header ────────────────────────────────────────── */}
      <div className="stagger-in" style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', marginBottom: '1.5rem' }}>
        <motion.button
          className="btn btn-ghost btn-sm"
          onClick={() => navigate(-1)}
          style={{ marginTop: 4 }}
          whileHover={{ x: -3 }}
          whileTap={{ scale: 0.92 }}
        >
          <ArrowLeft size={16} />
        </motion.button>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <h2 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.03em', color: 'var(--text-primary)' }}>
              {vuln.cve_id || vuln.vuldb_id || 'Unknown'}
            </h2>
            <span
              className={`badge ${severityBadge(vuln.cvss_base_score)}`}
              style={{ fontSize: '0.72rem', padding: '0.25rem 0.7rem' }}
            >
              CVSS {vuln.cvss_base_score?.toFixed(1) ?? 'N/A'} · {severityLabel(vuln.cvss_base_score)}
            </span>
          </div>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', marginTop: 4 }}>
            {vuln.title || 'No title'}
          </p>
        </div>
      </div>

      {/* ── Action Buttons ────────────────────────────────── */}
      <div className="stagger-in" style={{ display: 'flex', gap: '0.75rem', marginBottom: '1.5rem', animationDelay: '0.08s' }}>
        <motion.button
          className="btn btn-secondary"
          onClick={handlePredict}
          disabled={predLoading}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
        >
          {predLoading ? <Loader2 size={16} className="spin-icon" /> : <Cpu size={16} />}
          {predLoading ? 'Predicting…' : 'Run ML Prediction'}
        </motion.button>
        <motion.button
          className="btn btn-primary"
          onClick={handleLLMBrief}
          disabled={briefLoading}
          whileHover={{ scale: 1.03, boxShadow: '0 6px 20px rgba(99,102,241,0.25)' }}
          whileTap={{ scale: 0.97 }}
        >
          {briefLoading ? <Loader2 size={16} className="spin-icon" /> : <Brain size={16} />}
          {briefLoading ? 'Generating…' : 'Generate AI Brief'}
        </motion.button>
      </div>

      {/* ── Prediction Result ─────────────────────────────── */}
      <AnimatePresence>
        {prediction && (
          <motion.div
            className="prediction-bar"
            initial={{ opacity: 0, y: 12, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            transition={{ type: 'spring', stiffness: 260, damping: 22 }}
          >
            {/* Main score */}
            <div>
              <div className="detail-label">Exploitation Probability</div>
              <motion.div
                style={{ fontSize: '2rem', fontWeight: 800, color: probColor(prediction.p_final), letterSpacing: '-0.03em' }}
                initial={{ opacity: 0, scale: 0.5 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ type: 'spring', stiffness: 300, delay: 0.2 }}
              >
                {(prediction.p_final * 100).toFixed(1)}%
              </motion.div>
              {/* Visual bar */}
              <div style={{ width: '100%', height: 6, borderRadius: 3, background: '#e2e5ee', marginTop: 6, overflow: 'hidden' }}>
                <motion.div
                  style={{ height: '100%', borderRadius: 3, background: probColor(prediction.p_final) }}
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.max(prediction.p_final * 100, 1)}%` }}
                  transition={{ duration: 0.8, delay: 0.3, ease: 'easeOut' }}
                />
              </div>
            </div>

            {/* Risk label */}
            <div>
              <div className="detail-label">Risk Level</div>
              <div style={{
                fontSize: '0.95rem',
                fontWeight: 700,
                color: prediction.p_final > 0.7 ? '#dc2626' : prediction.p_final > 0.4 ? '#d97706' : prediction.p_final > 0.1 ? '#2563eb' : '#059669',
              }}>
                {prediction.p_final > 0.7 ? '🔴 Critical' : prediction.p_final > 0.4 ? '🟡 High' : prediction.p_final > 0.1 ? '🔵 Moderate' : '🟢 Low'}
              </div>
            </div>

            {/* Stage 1 score */}
            <div>
              <div className="detail-label">Stage-1 (XGBoost)</div>
              <div className="mono" style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>
                {(prediction.p_stage1 * 100).toFixed(1)}%
              </div>
            </div>

            {/* Model */}
            <div>
              <div className="detail-label">Model</div>
              <div className="mono" style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>RRF Ensemble</div>
            </div>

            {/* As-of */}
            <div>
              <div className="detail-label">As-of Date</div>
              <div style={{ color: 'var(--text-secondary)' }}>{prediction.asof}</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Tabs ──────────────────────────────────────────── */}
      <div className="tabs stagger-in" style={{ animationDelay: '0.16s' }}>
        {['overview', 'brief', 'references'].map((tab) => (
          <motion.button
            key={tab}
            className={`tab ${activeTab === tab ? 'active' : ''}`}
            onClick={() => setActiveTab(tab)}
            whileHover={{ y: -1 }}
            whileTap={{ scale: 0.97 }}
          >
            {tab === 'brief' && <Brain size={14} />}
            {tab === 'overview' ? 'Overview' : tab === 'brief' ? 'AI Brief' : 'References'}
          </motion.button>
        ))}
      </div>

      {/* ── Tab Content (Animated) ─────────────────────────── */}
      <AnimatePresence mode="wait">
        {/* ── Tab: Overview ─────────────────────────────────── */}
        {activeTab === 'overview' && (
          <motion.div key="overview" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }}>
            <div className="detail-grid">
              <div className="card">
                <div className="card-title">Vulnerability Details</div>
                <div className="detail-field">
                  <div className="detail-label">Description</div>
                  <div className="detail-value" style={{ lineHeight: 1.75, color: 'var(--text-secondary)' }}>
                    {vuln.description || 'No description available.'}
                  </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
                  <div className="detail-field">
                    <div className="detail-label">Published</div>
                    <div className="detail-value">{formatDate(vuln.published_at)}</div>
                  </div>
                  <div className="detail-field">
                    <div className="detail-label">Source</div>
                    <div className="detail-value" style={{ textTransform: 'uppercase', fontWeight: 600 }}>{vuln.source}</div>
                  </div>
                  <div className="detail-field">
                    <div className="detail-label">CVSS Vector</div>
                    <div className="detail-value mono" style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                      {vuln.cvss_vector || '—'}
                    </div>
                  </div>
                  <div className="detail-field">
                    <div className="detail-label">CVSS Version</div>
                    <div className="detail-value">{vuln.cvss_version || '—'}</div>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                <div className="card">
                  <div className="card-title">CWE Weaknesses</div>
                  {cwes.length > 0 ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {cwes.map((c) => (
                        <motion.span key={c} className="brief-tag" whileHover={{ scale: 1.06 }}>
                          <Shield size={12} /> {c}
                        </motion.span>
                      ))}
                    </div>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>None listed</span>
                  )}
                </div>

                <div className="card">
                  <div className="card-title">Affected Products</div>
                  {products.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                      {products.slice(0, 8).map((p, i) => (
                        <div key={i} style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{p.vendor}</span>
                          {' '}{p.product} {p.version && `(${p.version})`}
                        </div>
                      ))}
                      {products.length > 8 && (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                          + {products.length - 8} more…
                        </span>
                      )}
                    </div>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontSize: '0.88rem' }}>None listed</span>
                  )}
                </div>
              </div>
            </div>
          </motion.div>
        )}

        {/* ── Tab: AI Brief ─────────────────────────────────── */}
        {activeTab === 'brief' && (
          <motion.div key="brief" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }}>
            {briefError && <div className="error-box" style={{ marginBottom: '1rem' }}>⚠ {briefError}</div>}

            {/* Loading — AI Pipeline Animation */}
            {briefLoading && (
              <motion.div
                className="card"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                style={{ background: 'linear-gradient(180deg, rgba(99,102,241,0.04) 0%, var(--bg-card) 100%)' }}
              >
                <AIPipeline isRunning={true} />
                <motion.p
                  style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.82rem', marginTop: '0.5rem', paddingBottom: '1rem' }}
                  animate={{ opacity: [0.5, 1, 0.5] }}
                  transition={{ duration: 2, repeat: Infinity }}
                >
                  Retrieving ATT&CK techniques → Building context → Generating brief…
                </motion.p>
              </motion.div>
            )}

            {/* Empty state */}
            {!brief && !briefLoading && !briefError && (
              <motion.div
                className="ai-brief-empty"
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ duration: 0.4 }}
              >
                <motion.div
                  className="ai-brief-icon"
                  animate={{
                    boxShadow: [
                      '0 0 0px rgba(99,102,241,0)',
                      '0 0 20px rgba(99,102,241,0.1)',
                      '0 0 0px rgba(99,102,241,0)',
                    ],
                  }}
                  transition={{ duration: 3, repeat: Infinity }}
                >
                  <Brain size={32} />
                </motion.div>
                <h3 style={{ color: 'var(--text-primary)', marginBottom: '0.5rem', fontWeight: 700, fontSize: '1.1rem' }}>
                  AI Intelligence Brief
                </h3>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.75rem', maxWidth: 480, margin: '0 auto 1.75rem', lineHeight: 1.7, fontSize: '0.88rem' }}>
                  Generate a GPT-4o-mini powered analysis with ATT&CK technique mappings,
                  remediation steps, and risk assessment using RAG over the MITRE knowledge base.
                </p>

                {/* Mini pipeline preview */}
                <AIPipeline isRunning={false} />

                <motion.button
                  className="btn btn-primary"
                  onClick={handleLLMBrief}
                  style={{ marginTop: '1.5rem' }}
                  whileHover={{ scale: 1.04, boxShadow: '0 6px 20px rgba(99,102,241,0.25)' }}
                  whileTap={{ scale: 0.97 }}
                >
                  <Brain size={16} /> Generate AI Brief
                </motion.button>
              </motion.div>
            )}

            {/* Brief result */}
            {brief && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.4 }}
              >
                {/* Status bar */}
                <motion.div
                  className="card"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  style={{
                    marginBottom: '1.25rem', display: 'flex', gap: '1.5rem',
                    alignItems: 'center', flexWrap: 'wrap', padding: '0.85rem 1.25rem',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    {brief.verified
                      ? <CheckCircle2 size={18} style={{ color: 'var(--success)' }} />
                      : <XCircle size={18} style={{ color: 'var(--danger)' }} />
                    }
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: brief.verified ? 'var(--success)' : 'var(--danger)' }}>
                      {brief.verified ? 'Verified Safe' : 'Verification Issues'}
                    </span>
                  </div>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Model: <span className="mono">{brief.model}</span>
                  </span>
                  <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    Tokens: <span className="mono">{brief.tokens_used}</span>
                  </span>
                </motion.div>

                {/* Executive Summary */}
                {brief.llm_analysis?.executive_summary && (
                  <motion.div
                    className="card brief-section"
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.1 }}
                    style={{ marginBottom: '1rem', borderLeft: '3px solid var(--accent)' }}
                  >
                    <h3><Zap size={16} /> Executive Summary</h3>
                    <p><StreamingText text={brief.llm_analysis.executive_summary} speed={8} /></p>
                  </motion.div>
                )}

                {/* Risk Assessment */}
                {brief.llm_analysis?.risk_assessment && (
                  <motion.div
                    className="card brief-section"
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.2 }}
                    style={{ marginBottom: '1rem' }}
                  >
                    <h3><Target size={16} /> Risk Assessment</h3>
                    <p>{brief.llm_analysis.risk_assessment}</p>
                  </motion.div>
                )}

                {/* ATT&CK Mapping */}
                {brief.llm_analysis?.attck_analysis?.length > 0 && (
                  <motion.div
                    className="card brief-section"
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.3 }}
                    style={{ marginBottom: '1rem' }}
                  >
                    <h3><Crosshair size={16} /> MITRE ATT&CK Mapping</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.75rem' }}>
                      {brief.llm_analysis.attck_analysis.map((t, i) => (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, y: 8 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: 0.35 + i * 0.08 }}
                          style={{
                            padding: '0.85rem 1rem', background: 'var(--bg-elevated)',
                            borderRadius: 'var(--radius)', border: '1px solid var(--border-light)',
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
                            <span className="brief-tag" style={{ margin: 0 }}>{t.technique_id}</span>
                            <span style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text-primary)' }}>{t.technique_name}</span>
                          </div>
                          {t.relevance && (
                            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: '0.25rem 0' }}>{t.relevance}</p>
                          )}
                          {t.detection_guidance && (
                            <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                              <strong style={{ color: 'var(--text-label)' }}>Detection:</strong> {t.detection_guidance}
                            </p>
                          )}
                        </motion.div>
                      ))}
                    </div>
                  </motion.div>
                )}

                {/* Remediation Steps */}
                {brief.llm_analysis?.remediation_steps?.length > 0 && (
                  <motion.div
                    className="card brief-section"
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.4 }}
                    style={{ marginBottom: '1rem' }}
                  >
                    <h3><Clock size={16} /> Remediation Steps</h3>
                    <ol style={{ paddingLeft: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.6rem', marginTop: '0.5rem' }}>
                      {brief.llm_analysis.remediation_steps.map((s, i) => (
                        <motion.li
                          key={i}
                          initial={{ opacity: 0, x: -8 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ delay: 0.45 + i * 0.06 }}
                          style={{ color: 'var(--text-secondary)' }}
                        >
                          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{s.action}</span>
                          {s.rationale && (
                            <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}> — {s.rationale}</span>
                          )}
                          <span
                            className={`badge badge-${s.priority === 'critical' ? 'critical' : s.priority === 'high' ? 'high' : s.priority === 'medium' ? 'medium' : 'low'}`}
                            style={{ marginLeft: '0.5rem' }}
                          >
                            {s.priority}
                          </span>
                        </motion.li>
                      ))}
                    </ol>
                  </motion.div>
                )}

                {/* IOC Suggestions */}
                {brief.llm_analysis?.ioc_suggestions?.length > 0 && (
                  <motion.div
                    className="card brief-section"
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.5 }}
                    style={{ marginBottom: '1rem' }}
                  >
                    <h3>IOC Suggestions</h3>
                    <ul style={{ paddingLeft: '1.25rem', color: 'var(--text-secondary)' }}>
                      {brief.llm_analysis.ioc_suggestions.map((ioc, i) => (
                        <li key={i} style={{ marginBottom: '0.3rem' }}>{ioc}</li>
                      ))}
                    </ul>
                  </motion.div>
                )}

                {/* Confidence Notes */}
                {brief.llm_analysis?.confidence_notes && (
                  <motion.div
                    className="card brief-section"
                    initial={{ opacity: 0, x: -12 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.55 }}
                    style={{ borderLeft: '3px solid var(--warning)' }}
                  >
                    <h3>Confidence Notes</h3>
                    <p>{brief.llm_analysis.confidence_notes}</p>
                  </motion.div>
                )}
              </motion.div>
            )}
          </motion.div>
        )}

        {/* ── Tab: References ───────────────────────────────── */}
        {activeTab === 'references' && (
          <motion.div key="references" initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0 }} transition={{ duration: 0.3 }}>
            <div className="card">
              <div className="card-title">References ({refs.length})</div>
              {refs.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {refs.map((r, i) => (
                    <motion.a
                      key={i}
                      href={r.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.03 }}
                      whileHover={{ x: 4, backgroundColor: 'rgba(99,102,241,0.05)' }}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '0.5rem',
                        fontSize: '0.85rem', wordBreak: 'break-all',
                        padding: '0.5rem 0.65rem', borderRadius: 'var(--radius)',
                        transition: 'background 180ms ease',
                      }}
                    >
                      <ExternalLink size={14} style={{ flexShrink: 0, color: 'var(--accent-hover)' }} />
                      <span>{r.url}</span>
                      {r.source && <span className="badge badge-info" style={{ flexShrink: 0 }}>{r.source}</span>}
                    </motion.a>
                  ))}
                </div>
              ) : (
                <span style={{ color: 'var(--text-muted)' }}>No references available</span>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
