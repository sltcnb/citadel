/**
 * Shared page layout primitives — match the look defined by CrossCaseSearch,
 * MitreCoverage, and Watchlist. Every top-level page should use these so the
 * app feels coherent.
 *
 *   <PageShell>
 *     <PageHeader
 *       title="Modules"
 *       subtitle="Run analysis modules against ingested files"
 *       icon={Cpu}
 *       actions={<button …>New</button>}
 *     />
 *     ...page content...
 *   </PageShell>
 */
import { ChevronRight } from 'lucide-react'

export function PageShell({ children, className = '' }) {
  return (
    <div
      className={`w-full px-4 sm:px-6 lg:px-8 py-6 lg:py-8 space-y-6 lg:space-y-8 fade-in ${className}`}
    >
      {children}
    </div>
  )
}

export function PageHeader({ title, subtitle, icon: Icon, actions, breadcrumbs }) {
  return (
    <div className="flex items-start justify-between flex-wrap gap-3">
      <div className="min-w-0 flex-1">
        {breadcrumbs && breadcrumbs.length > 0 && (
          <nav className="flex items-center gap-1 text-[11px] text-gray-500 mb-2">
            {breadcrumbs.map((b, i) => (
              <span key={i} className="flex items-center gap-1">
                {i > 0 && <ChevronRight size={11} className="text-gray-400" />}
                {b.to
                  ? <a href={b.to} className="hover:text-brand-text transition-colors">{b.label}</a>
                  : <span className="text-gray-700">{b.label}</span>}
              </span>
            ))}
          </nav>
        )}
        <h1 className="text-[28px] sm:text-[32px] font-bold text-brand-text tracking-tight leading-none flex items-center gap-2.5">
          {Icon && <Icon size={26} className="text-brand-accent flex-shrink-0" />}
          <span className="truncate">{title}</span>
        </h1>
        {subtitle && <p className="text-sm text-gray-500 mt-2">{subtitle}</p>}
      </div>
      {actions && (
        <div className="flex items-center gap-2 flex-wrap flex-shrink-0">{actions}</div>
      )}
    </div>
  )
}

/** Big numeric stat card — matches Dashboard's BigStatCard exactly. */
export function StatCard({ icon: Icon, label, value, sub, loading }) {
  return (
    <div className="card p-5 hover:border-gray-300 transition-colors duration-150">
      <div className="flex items-start justify-between gap-3 mb-3">
        <p className="text-[11px] text-gray-500 font-semibold uppercase tracking-wider">{label}</p>
        {Icon && <Icon size={14} className="text-gray-400 flex-shrink-0" />}
      </div>
      <p className="text-[30px] font-bold text-brand-text tabular-nums leading-none tracking-tight">
        {loading ? <span className="skeleton inline-block w-16 h-8 rounded" /> : value}
      </p>
      {sub && <p className="text-xs text-gray-500 mt-2 truncate font-medium">{sub}</p>}
    </div>
  )
}
