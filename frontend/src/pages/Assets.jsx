import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import { Server, Upload, Plus, RefreshCw, Trash2, Loader2, Globe, FileJson } from 'lucide-react'
import {
  getAssets, createAsset, deleteAsset, uploadSbom, uploadVex, evaluateAsset, getFindings,
} from '../api'
import { severityBadge, formatDate, truncate } from '../utils'

// Presentation only: actions and SLAs are decided by the backend engine.
const ACTIONS = ['patch_now', 'mitigate_now', 'patch_window', 'monitor', 'accept']
const ACTION_LABELS = {
  patch_now: 'Patch now', mitigate_now: 'Mitigate now',
  patch_window: 'Patch in window', monitor: 'Monitor', accept: 'Accept',
}
const ACTION_COLORS = {
  patch_now: '#dc2626', mitigate_now: '#dc2626', patch_window: '#d97706',
  monitor: '#2563eb', accept: '#059669',
}
const MATCH_LABELS = {
  version: 'Version confirmed',
  product_only: 'Product match, version unverified',
  not_in_range: 'Installed version not vulnerable',
}

function fmtSla(h) {
  if (h == null) return '—'
  if (h <= 48) return `${h} h`
  const d = Math.round(h / 24)
  return d >= 365 ? `${Math.round(d / 365)} yr` : `${d} days`
}

function readJsonFile(file) {
  return file.text().then((text) => {
    try { return JSON.parse(text) } catch { throw new Error(`${file.name} is not valid JSON`) }
  })
}

const EMPTY_FORM = {
  name: '', asset_type: 'server', environment: 'production',
  criticality: 'medium', is_internet_facing: false, owner: '',
}

export default function Assets() {
  const navigate = useNavigate()
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [findings, setFindings] = useState(null)
  const [actionFilter, setActionFilter] = useState('')
  const [busy, setBusy] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState(EMPTY_FORM)
  const sbomInput = useRef(null)
  const vexInput = useRef(null)

  const selected = assets.find((a) => a.id === selectedId) || null

  const loadAssets = (keepSelection = true) =>
    getAssets()
      .then((res) => {
        setAssets(res.items)
        if (!keepSelection || !res.items.some((a) => a.id === selectedId)) {
          setSelectedId(res.items[0]?.id ?? null)
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))

  useEffect(() => { loadAssets() }, [])  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selectedId) { setFindings(null); return }
    setFindings(null)
    getFindings(selectedId, { action: actionFilter })
      .then(setFindings)
      .catch((e) => setError(e.message))
  }, [selectedId, actionFilter])

  const run = (label, fn) => {
    setBusy(label); setError(null); setNotice(null)
    return fn()
      .then((msg) => { if (msg) setNotice(msg) })
      .catch((e) => setError(e.message))
      .finally(() => setBusy(''))
  }

  const refreshSelected = () =>
    Promise.all([loadAssets(), getFindings(selectedId, { action: actionFilter }).then(setFindings)])

  const handleCreate = (e) => {
    e.preventDefault()
    run('create', () =>
      createAsset({ ...form, owner: form.owner || null }).then((asset) => {
        setForm(EMPTY_FORM); setShowForm(false)
        return loadAssets().then(() => { setSelectedId(asset.id); return `Asset "${asset.name}" registered. Upload its SBOM to build the queue.` })
      }))
  }

  const describeEvaluation = (ev) =>
    `${ev.findings} matching CVEs: ${ev.urgent} urgent with asset context, ` +
    `${ev.urgent_without_asset_context} without. Asset evidence changed ${ev.decisions_changed_by_asset_context} decisions.`

  const handleSbom = (e) => {
    const file = e.target.files?.[0]; e.target.value = ''
    if (!file || !selected) return
    run('sbom', () =>
      readJsonFile(file).then((doc) => uploadSbom(selected.id, doc)).then((res) =>
        refreshSelected().then(() =>
          `Imported ${res.sbom.components} components (${res.sbom.identity_resolved} resolved to a known product). ` +
          describeEvaluation(res.evaluation))))
  }

  const handleVex = (e) => {
    const file = e.target.files?.[0]; e.target.value = ''
    if (!file || !selected) return
    run('vex', () =>
      readJsonFile(file).then((doc) => uploadVex(selected.id, doc)).then((res) =>
        refreshSelected().then(() =>
          `Imported ${res.vex.statements} VEX statements for this asset. ` + describeEvaluation(res.evaluation))))
  }

  const handleEvaluate = () =>
    run('evaluate', () =>
      evaluateAsset(selected.id).then((ev) => refreshSelected().then(() => describeEvaluation(ev))))

  const handleDelete = () => {
    if (!selected || !window.confirm(`Delete asset "${selected.name}" with its inventory and findings?`)) return
    run('delete', () => deleteAsset(selected.id).then(() => loadAssets(false).then(() => 'Asset deleted.')))
  }

  if (loading) {
    return <div className="loading-container"><div className="spinner" /><span>Loading assets…</span></div>
  }

  return (
    <div className="fade-in">
      <div className="page-header" style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 260 }}>
          <h2>Assets</h2>
          <p>
            Upload an SBOM to match installed software against known vulnerabilities by version,
            then triage each match with the asset's own context.
          </p>
        </div>
        <motion.button className="btn btn-primary" onClick={() => setShowForm(!showForm)}
          whileHover={{ scale: 1.03 }} whileTap={{ scale: 0.97 }}>
          <Plus size={16} /> Register asset
        </motion.button>
      </div>

      {error && <div className="error-box" style={{ marginBottom: '1rem' }}>⚠ {error}</div>}
      {notice && (
        <div className="card" style={{ marginBottom: '1rem', padding: '0.75rem 1rem', borderLeft: '3px solid var(--success)', fontSize: '0.88rem' }}>
          {notice}
        </div>
      )}

      {showForm && (
        <form className="card" onSubmit={handleCreate}
          style={{ marginBottom: '1rem', display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: 2, minWidth: 220 }}>
            <label className="detail-label" htmlFor="asset-name">Name</label>
            <input id="asset-name" className="input" required value={form.name} style={{ width: '100%' }}
              placeholder="payments-api (prod)"
              onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          <div>
            <label className="detail-label" htmlFor="asset-type">Type</label>
            <select id="asset-type" className="input" value={form.asset_type}
              onChange={(e) => setForm({ ...form, asset_type: e.target.value })}>
              {['server', 'container', 'application', 'endpoint'].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="detail-label" htmlFor="asset-env">Environment</label>
            <select id="asset-env" className="input" value={form.environment}
              onChange={(e) => setForm({ ...form, environment: e.target.value })}>
              {['production', 'staging', 'development'].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div>
            <label className="detail-label" htmlFor="asset-crit">Criticality</label>
            <select id="asset-crit" className="input" value={form.criticality}
              onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
              {['critical', 'high', 'medium', 'low'].map((t) => <option key={t}>{t}</option>)}
            </select>
          </div>
          <div style={{ flex: 1, minWidth: 140 }}>
            <label className="detail-label" htmlFor="asset-owner">Owner</label>
            <input id="asset-owner" className="input" value={form.owner} style={{ width: '100%' }}
              onChange={(e) => setForm({ ...form, owner: e.target.value })} />
          </div>
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.85rem', paddingBottom: '0.5rem' }}>
            <input type="checkbox" checked={form.is_internet_facing}
              onChange={(e) => setForm({ ...form, is_internet_facing: e.target.checked })} />
            Internet-facing
          </label>
          <button className="btn btn-primary" type="submit" disabled={busy === 'create'}>
            {busy === 'create' ? <Loader2 size={16} className="spin-icon" /> : <Plus size={16} />} Create
          </button>
        </form>
      )}

      {assets.length === 0 ? (
        <div className="ai-brief-empty">
          <div className="ai-brief-icon"><Server size={32} /></div>
          <h3 style={{ fontWeight: 700, fontSize: '1.1rem', marginBottom: '0.5rem' }}>No assets registered</h3>
          <p style={{ color: 'var(--text-muted)', maxWidth: 520, margin: '0 auto', lineHeight: 1.7, fontSize: '0.88rem' }}>
            Register an asset, then upload a CycloneDX or SPDX SBOM (for example from Syft or Trivy).
            Each component is matched against CVE version ranges and scored with the asset's criticality and exposure.
          </p>
        </div>
      ) : (
        <>
          {/* ── Asset list ───────────────────────────────── */}
          <div className="table-container" style={{ marginBottom: '1.25rem' }}>
            <table>
              <thead>
                <tr>
                  <th>Asset</th><th>Criticality</th><th>Exposure</th>
                  <th>Components</th><th>Urgent</th><th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a) => {
                  const total = Object.values(a.findings_by_action || {}).reduce((x, y) => x + y, 0)
                  return (
                    <tr key={a.id} onClick={() => { setSelectedId(a.id); setActionFilter('') }}
                      style={{ background: a.id === selectedId ? 'rgba(99,102,241,0.06)' : undefined }}>
                      <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        {a.name}
                        <div style={{ fontWeight: 400, fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                          {a.asset_type} · {a.environment || '—'}{a.owner ? ` · ${a.owner}` : ''}
                        </div>
                      </td>
                      <td style={{ textTransform: 'capitalize' }}>{a.criticality}</td>
                      <td>
                        {a.is_internet_facing
                          ? <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}><Globe size={13} /> Internet-facing</span>
                          : 'Internal'}
                      </td>
                      <td className="mono">{a.components}</td>
                      <td>
                        <span className="mono" style={{ fontWeight: 700, color: a.urgent > 0 ? '#dc2626' : 'var(--text-secondary)' }}>
                          {a.urgent}
                        </span>
                      </td>
                      <td className="mono">{total}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ── Selected asset ───────────────────────────── */}
          {selected && (
            <>
              <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1.05rem', fontWeight: 700, marginRight: 'auto' }}>{selected.name}</h3>
                <input ref={sbomInput} type="file" accept=".json,application/json" hidden onChange={handleSbom} />
                <input ref={vexInput} type="file" accept=".json,application/json" hidden onChange={handleVex} />
                <button className="btn btn-secondary btn-sm" disabled={!!busy} onClick={() => sbomInput.current?.click()}>
                  {busy === 'sbom' ? <Loader2 size={14} className="spin-icon" /> : <Upload size={14} />} Upload SBOM
                </button>
                <button className="btn btn-secondary btn-sm" disabled={!!busy} onClick={() => vexInput.current?.click()}>
                  {busy === 'vex' ? <Loader2 size={14} className="spin-icon" /> : <FileJson size={14} />} Upload VEX
                </button>
                <button className="btn btn-secondary btn-sm" disabled={!!busy || selected.components === 0} onClick={handleEvaluate}>
                  {busy === 'evaluate' ? <Loader2 size={14} className="spin-icon" /> : <RefreshCw size={14} />} Re-evaluate
                </button>
                <button className="btn btn-ghost btn-sm" disabled={!!busy} onClick={handleDelete} aria-label="Delete asset">
                  <Trash2 size={14} />
                </button>
              </div>

              {/* Action tier counts double as a filter */}
              <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                {ACTIONS.map((act) => {
                  const n = selected.findings_by_action?.[act] || 0
                  const active = actionFilter === act
                  return (
                    <button key={act} onClick={() => setActionFilter(active ? '' : act)}
                      className="card"
                      style={{
                        padding: '0.6rem 0.9rem', cursor: 'pointer', textAlign: 'left', minWidth: 128,
                        borderColor: active ? ACTION_COLORS[act] : undefined,
                        boxShadow: active ? `0 0 0 1px ${ACTION_COLORS[act]}` : undefined,
                      }}>
                      <div style={{ fontSize: '0.72rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: ACTION_COLORS[act] }}>
                        {ACTION_LABELS[act]}
                      </div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 800 }}>{n}</div>
                    </button>
                  )
                })}
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>CVE</th><th>Action</th><th>SLA</th><th>CVSS</th>
                      <th>Installed component</th><th>Evidence</th><th>Without asset context</th>
                    </tr>
                  </thead>
                  <tbody>
                    {!findings ? (
                      <tr style={{ cursor: 'default' }}><td colSpan={7}><div className="skeleton" style={{ height: 18 }} /></td></tr>
                    ) : findings.items.length === 0 ? (
                      <tr style={{ cursor: 'default' }}>
                        <td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2.5rem' }}>
                          {selected.components === 0
                            ? 'No software inventory yet. Upload an SBOM for this asset.'
                            : actionFilter ? 'No findings in this tier.' : 'No known CVE matches the installed software.'}
                        </td>
                      </tr>
                    ) : findings.items.map((f) => (
                      <tr key={f.cve_id} onClick={() => navigate(`/vuln/${f.cve_id}`)}>
                        <td className="mono" style={{ fontWeight: 600, whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                          {f.cve_id}
                          {f.exploitation === 'active' && (
                            <div><span className="badge badge-critical" style={{ fontSize: '0.66rem' }}>Known exploited</span></div>
                          )}
                        </td>
                        <td style={{ fontWeight: 700, color: ACTION_COLORS[f.action], whiteSpace: 'nowrap' }}>
                          {ACTION_LABELS[f.action] || f.action}
                        </td>
                        <td style={{ whiteSpace: 'nowrap' }}>{fmtSla(f.sla_hours)}</td>
                        <td>
                          <span className={`badge ${severityBadge(f.cvss_base_score)}`}>
                            {f.cvss_base_score?.toFixed(1) ?? '—'}
                          </span>
                        </td>
                        <td style={{ fontSize: '0.82rem' }}>
                          <span style={{ fontWeight: 600 }}>{f.component.product}</span>{' '}
                          <span className="mono">{f.component.installed_version || 'version unknown'}</span>
                          <div style={{ color: 'var(--text-muted)', fontSize: '0.76rem' }}>
                            {MATCH_LABELS[f.component.match_level] || f.component.match_level}
                            {f.component.vulnerable_range ? ` · vulnerable ${f.component.vulnerable_range}` : ''}
                          </div>
                        </td>
                        <td style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', maxWidth: 320 }}>
                          {truncate((f.rationale || []).slice(1).join(' · ') || (f.rationale || [])[0], 140)}
                        </td>
                        <td style={{ fontSize: '0.8rem', whiteSpace: 'nowrap', color: f.changed_by_asset_context ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                          {ACTION_LABELS[f.action_without_asset_context] || '—'}
                          {f.changed_by_asset_context && <span style={{ fontWeight: 700 }}> → changed</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {findings && findings.total > findings.items.length && (
                  <div className="pagination">
                    <span>Showing the {findings.items.length} most urgent of {findings.total} findings</span>
                  </div>
                )}
              </div>
              <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.75rem', lineHeight: 1.6 }}>
                Versions are compared with the upstream ranges NVD publishes. Distribution packages that
                backport a fix without changing the upstream version can still appear as affected; a vendor
                VEX statement resolves those. Registered {formatDate(selected.created_at)}.
              </p>
            </>
          )}
        </>
      )}
    </div>
  )
}
