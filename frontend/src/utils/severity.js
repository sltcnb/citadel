// Shared severity/level styling. One scheme: text-X-700 bg-X-50 border-X-200 (medium=amber).

export const SEVERITY_STYLES = {
  critical:      'text-red-700 bg-red-50 border-red-200',
  high:          'text-orange-700 bg-orange-50 border-orange-200',
  medium:        'text-amber-700 bg-amber-50 border-amber-200',
  low:           'text-blue-700 bg-blue-50 border-blue-200',
  informational: 'text-gray-600 bg-gray-50 border-gray-200',
  info:          'text-gray-600 bg-gray-50 border-gray-200',
  unknown:       'text-gray-500 bg-gray-50 border-gray-200',
}

export function severityStyle(level) {
  return SEVERITY_STYLES[String(level || '').toLowerCase()] || SEVERITY_STYLES.info
}

// Canonical severity ordering — highest first. One source for every "for each
// level" loop so ordering never drifts between panels.
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational']

// Canonical level → `.badge-*` CSS class (the pill style used in run cards,
// module hits, timeline). Aliases (crit/med/info) fold onto the same classes so
// no panel needs its own map.
const LEVEL_BADGE_CLASS = {
  critical: 'badge-critical', crit: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium', med: 'badge-medium',
  low: 'badge-low',
  informational: 'badge-informational', info: 'badge-informational',
}
export function levelBadgeClass(level) {
  return LEVEL_BADGE_CLASS[String(level || '').toLowerCase()] || 'badge-generic'
}

// Richer per-risk config used by gauges (level → colors + bar + label).
export const RISK_CONFIG = {
  none:     { color: 'text-green-600',  bg: 'bg-green-100',  border: 'border-green-300',  bar: 'bg-green-500',   label: 'No Risk' },
  low:      { color: 'text-blue-600',   bg: 'bg-blue-100',   border: 'border-blue-300',   bar: 'bg-blue-500',    label: 'Low' },
  medium:   { color: 'text-amber-600',  bg: 'bg-amber-100',  border: 'border-amber-300',  bar: 'bg-amber-500',   label: 'Medium' },
  high:     { color: 'text-orange-600', bg: 'bg-orange-100', border: 'border-orange-300', bar: 'bg-orange-500',  label: 'High' },
  critical: { color: 'text-red-600',    bg: 'bg-red-100',    border: 'border-red-300',    bar: 'bg-red-500',     label: 'Critical' },
  unknown:  { color: 'text-gray-500',   bg: 'bg-gray-100',   border: 'border-gray-300',   bar: 'bg-gray-400',    label: 'Unknown' },
}
