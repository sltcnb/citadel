import { severityStyle } from '../../utils/severity'
import { statusStyle } from '../../utils/status'

/**
 * Generic colored badge. `color` is a full Tailwind class string
 * (e.g. 'text-red-700 bg-red-50 border-red-200'). Extra classes via `className`.
 */
export function Badge({ color = '', className = '', children }) {
  return (
    <span className={`inline-flex items-center border rounded-full px-2 py-0.5 text-[10px] font-medium whitespace-nowrap ${color} ${className}`}>
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
