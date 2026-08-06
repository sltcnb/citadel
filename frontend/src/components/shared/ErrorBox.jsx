import { AlertCircle, RefreshCw } from 'lucide-react'

/**
 * ErrorBox — the one red error card. Replaces the ~80 copy-pasted
 *   text-red-600 bg-red-50 border border-red-200 rounded-lg …
 * blocks, and guarantees every error surface carries role="alert" so
 * assistive tech (and the e2e suite) can find it.
 *
 *   <ErrorBox msg={error} />
 *   <ErrorBox msg={error} onRetry={reload} />
 *   <ErrorBox>…custom children…</ErrorBox>
 *
 * `className` is appended, so callers keep layout tweaks (margins, etc.)
 * without restyling the box itself.
 */
export default function ErrorBox({ msg, children, onRetry, retryLabel = 'Retry', className = '' }) {
  return (
    <div
      role="alert"
      className={`text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5 ${className}`}
    >
      <AlertCircle size={12} className="mt-0.5 flex-shrink-0" aria-hidden="true" />
      <span className="flex-1 min-w-0">{msg ?? children}</span>
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="flex items-center gap-1 font-medium text-red-700 hover:text-red-800 hover:underline flex-shrink-0"
        >
          <RefreshCw size={11} aria-hidden="true" /> {retryLabel}
        </button>
      )}
    </div>
  )
}

/**
 * NoticeBox — amber companion to ErrorBox for non-blocking warnings and
 * informational notices (not an error, so role="status", not "alert").
 */
export function NoticeBox({ msg, children, className = '' }) {
  return (
    <div
      role="status"
      className={`text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-2 ${className}`}
    >
      {msg ?? children}
    </div>
  )
}
