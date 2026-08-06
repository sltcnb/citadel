import { severityStyle } from '../../utils/severity'
import { statusStyle } from '../../utils/status'

/**
 * Generic colored badge — the single base for every chip/pill. Renders the
 * shared `.badge` CSS look (flat pastel, no border, 11px semibold, rounded-md).
 * `color` is a full Tailwind class string (e.g. 'text-red-700 bg-red-50').
 * Extra classes via `className` (e.g. 'rounded-full' for a pill shape).
 */
export function Badge({ color = '', className = '', children }) {
  return (
    <span className={`badge ${color} ${className}`}>
      {children}
    </span>
  )
}

/**
 * Severity/level badge using the shared SEVERITY_STYLES scheme.
 * Renders `children` if provided, otherwise the level label.
 */
export function SeverityBadge({ level, className = '', children }) {
  return (
    <Badge color={severityStyle(level)} className={className}>
      {children ?? level}
    </Badge>
  )
}

/**
 * Run/file status badge using the shared STATUS_STYLES scheme.
 * Defaults to the canonical label; override with `children` or `label`.
 */
export function StatusBadge({ status, label, className = '', children }) {
  const s = statusStyle(status)
  return (
    <Badge color={s.cls} className={className}>
      {children ?? label ?? s.label}
    </Badge>
  )
}

export default Badge
