import { useState } from 'react'
import { HelpCircle, ChevronDown, ChevronRight } from 'lucide-react'

/**
 * Collapsible "how to use this panel" block. Drop one near the top of any
 * case panel so an analyst knows, at a glance:
 *   • what the panel does (use)
 *   • when it's the right tool (when)
 *   • what data must be in the case for it to work (data)
 *
 * Usage:
 *   <PanelHelp
 *     title="Entity graph"
 *     use="Maps host ↔ user ↔ IP relationships so lateral movement is visible."
 *     when="When you suspect an account or host pivoted to others."
 *     data={['Events with host.hostname + user.name', 'network.dst_ip for IP edges']}
 *     defaultOpen
 *   />
 *
 * Collapsed by default (analysts who know the tool aren't nagged); the open
 * state is remembered per-title in localStorage so a panel you keep expanded
 * stays expanded across opens.
 */
export default function PanelHelp({ title, use, when, data = [], tip, defaultOpen = false }) {
  const storeKey = `fo_help_${(title || 'panel').replace(/\s+/g, '_').toLowerCase()}`
  const [open, setOpen] = useState(() => {
    const v = typeof localStorage !== 'undefined' ? localStorage.getItem(storeKey) : null
    return v === null ? defaultOpen : v === '1'
  })

  function toggle() {
    const next = !open
    setOpen(next)
    try { localStorage.setItem(storeKey, next ? '1' : '0') } catch { /* ignore */ }
  }

  const dataList = Array.isArray(data) ? data : [data].filter(Boolean)

  return (
    <div className="rounded-lg border border-sky-100 bg-sky-50/50 text-[11px] mb-3">
      <button
        onClick={toggle}
        className="w-full flex items-center gap-1.5 px-3 py-1.5 text-sky-700 hover:bg-sky-100/50 rounded-lg transition-colors"
        aria-expanded={open}
      >
        <HelpCircle size={12} className="flex-shrink-0" />
        <span className="font-semibold">How to use this</span>
        <span className="ml-auto">{open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
      </button>
      {open && (
        <div className="px-3 pb-2.5 pt-0.5 space-y-1.5 text-gray-700 leading-relaxed">
          {use && (
            <p><span className="font-semibold text-gray-600">What&nbsp;it&nbsp;does — </span>{use}</p>
          )}
          {when && (
            <p><span className="font-semibold text-gray-600">When&nbsp;to&nbsp;use — </span>{when}</p>
          )}
          {dataList.length > 0 && (
            <div>
              <span className="font-semibold text-gray-600">Needs in the case — </span>
              <ul className="list-disc list-inside mt-0.5 space-y-0.5">
                {dataList.map((d, i) => <li key={i} className="text-gray-600">{d}</li>)}
              </ul>
            </div>
          )}
          {tip && (
            <p className="text-gray-500 italic">Tip — {tip}</p>
          )}
        </div>
      )}
    </div>
  )
}
