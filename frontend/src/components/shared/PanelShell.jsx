import { Loader2, X, AlertTriangle } from 'lucide-react'
import PanelHelp from './PanelHelp'

/**
 * PanelShell — the ONE standard chrome for every case side-drawer panel.
 *
 * Before this, each of the ~8 analysis panels (MITRE, Baseline, EntityGraph,
 * KillChain, Anomaly, ProcessTree, CoPilot, IOC) hand-rolled its own backdrop,
 * drawer, header, close button, and loading/error/empty markup — three
 * different widths, inconsistent spacing, one panel with no error state. That
 * is what made the product feel like a different tool per panel.
 *
 * Wrap a panel's body in <PanelShell> and you get, for free and identically
 * everywhere:
 *   • one drawer width + backdrop + click-out-to-close
 *   • a header: icon + title + optional count + an actions slot + close (X)
 *   • a collapsible "How to use this" (PanelHelp) when help props are passed
 *   • standard loading / error / empty states
 *
 * Props:
 *   icon       — a lucide icon component (e.g. Target)
 *   title      — panel title (string)
 *   count      — optional small count/subtitle node shown next to the title
 *   onClose    — close handler
 *   loading    — show the standard spinner
 *   error      — error string (shows the standard error card)
 *   empty      — truthy when there is no data (shows `emptyText`)
 *   emptyText  — message for the empty state
 *   actions    — node rendered in the header right side (export / save buttons)
 *   help       — { use, when, data, tip } → renders a PanelHelp block
 *   width      — tailwind width class; defaults to the standard drawer width
 */
export default function PanelShell({
  icon: Icon,
  title,
  count = null,
  onClose,
  loading = false,
  error = '',
  empty = false,
  emptyText = 'Nothing to show yet.',
  actions = null,
  help = null,
  width = 'md:w-[900px]',
  children,
}) {
  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div className={`panel-drawer ${width}`} onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            {Icon && <Icon size={16} className="text-brand-accent flex-shrink-0" />}
            <span className="font-semibold text-brand-text truncate">{title}</span>
            {count != null && <span className="text-[11px] text-gray-500 ml-2">{count}</span>}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {actions}
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {help && (
            <PanelHelp title={title} use={help.use} when={help.when} data={help.data} tip={help.tip} />
          )}

          {loading ? (
            <div className="card p-6 flex items-center justify-center gap-2 text-sm text-gray-500">
              <Loader2 size={16} className="animate-spin" /> Loading…
            </div>
          ) : error ? (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border border-red-200 flex items-center gap-2">
              <AlertTriangle size={14} className="flex-shrink-0" /> {error}
            </div>
          ) : empty ? (
            <div className="card p-6 text-center text-xs text-gray-500">{emptyText}</div>
          ) : (
            children
          )}
        </div>
      </div>
    </div>
  )
}
