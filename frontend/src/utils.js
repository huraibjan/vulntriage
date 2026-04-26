export function severityClass(cvss) {
  if (cvss == null) return 'cvss-none'
  if (cvss >= 9.0) return 'cvss-critical'
  if (cvss >= 7.0) return 'cvss-high'
  if (cvss >= 4.0) return 'cvss-medium'
  return 'cvss-low'
}

export function severityLabel(cvss) {
  if (cvss == null) return 'N/A'
  if (cvss >= 9.0) return 'Critical'
  if (cvss >= 7.0) return 'High'
  if (cvss >= 4.0) return 'Medium'
  return 'Low'
}

export function severityBadge(cvss) {
  if (cvss == null) return 'badge-info'
  if (cvss >= 9.0) return 'badge-critical'
  if (cvss >= 7.0) return 'badge-high'
  if (cvss >= 4.0) return 'badge-medium'
  return 'badge-low'
}

export function formatDate(dateStr) {
  if (!dateStr) return '—'
  const d = new Date(dateStr)
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

export function truncate(text, max = 120) {
  if (!text) return '—'
  return text.length > max ? text.slice(0, max) + '…' : text
}
