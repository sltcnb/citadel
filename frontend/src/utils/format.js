// Shared formatting helpers — bytes, dates, relative time.

/**
 * Human-readable byte size (1024 base).
 * @param {number} n  size in bytes
 * @param {string} empty  string returned for null/0/undefined input
 */
export function formatBytes(n, empty = '—') {
  if (n == null || n === 0 || Number.isNaN(n)) return empty
  if (n < 1024)        return `${n} B`
  if (n < 1048576)     return `${(n / 1024).toFixed(1)} KB`
  if (n < 1073741824)  return `${(n / 1048576).toFixed(1)} MB`
  return `${(n / 1073741824).toFixed(2)} GB`
}

/**
 * Locale-aware date/time formatting.
 * @param {string} iso  ISO date string (or anything Date accepts)
 * @param {'date'|'datetime'|'time'|'short-datetime'|'month-time'} style
 * @param {string} empty  fallback for falsy input
 */
export function formatDate(iso, style = 'datetime', empty = '-') {
  if (!iso) return empty
  const d = new Date(iso)
  switch (style) {
    case 'date':
      return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
    case 'time':
      return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    case 'short-datetime':
      return d.toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
    case 'month-time':
      return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    case 'datetime':
    default:
      return d.toLocaleString()
  }
}

/**
 * Compact relative time ("just now", "3m ago", "2h ago").
 * @param {string} iso  ISO date string
 * @param {string} empty  fallback for falsy input
 */
export function relativeTime(iso, empty = '') {
  if (!iso) return empty
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 10)   return 'just now'
  if (diff < 60)   return `${diff}s ago`
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`
  return `${Math.round(diff / 3600)}h ago`
}
