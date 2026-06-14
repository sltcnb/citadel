import { useEffect, useState, useCallback } from 'react'
import {
  Crosshair, Loader2, AlertTriangle, ExternalLink, X, Search,
} from 'lucide-react'
import { api } from '../../api/client'
import { Badge } from './Badge'

/**
 * Right-side drawer: reverse kill-chain reconstruction.
 *
 *   GET /cases/{id}/killchain?fo_id=…|host=…&timestamp=…&window_minutes=…
 *
 * Given an anchor event (fo_id) or a (host, timestamp) pair, the backend walks
 * backward to first access and forward to impact, returning an ordered,
 * ATT&CK-tagged timeline. Mounted next to the other per-case panels.
 *
 * Drawer shell mirrors AnomalyPanel (panel-backdrop, right-0 w-[860px], …).
 */

// Canonical ATT&CK tactics, in enterprise kill-chain order.
const ATTACK_TACTICS = [
  { id: 'reconnaissance',        label: 'Recon' },
  { id: 'resource-development',  label: 'Resource Dev' },
  { id: 'initial-access',        label: 'Initial Access' },
  { id: 'execution',             label: 'Execution' },
  { id: 'persistence',           label: 'Persistence' },
  { id: 'privilege-escalation',  label: 'Priv Esc' },
  { id: 'defense-evasion',       label: 'Defense Evasion' },
  { id: 'credential-access',     label: 'Cred Access' },
  { id: 'discovery',             label: 'Discovery' },
  { id: 'lateral-movement',      label: 'Lateral Movement' },
  { id: 'collection',            label: 'Collection' },
  { id: 'command-and-control',   label: 'C2' },
  { id: 'exfiltration',          label: 'Exfiltration' },
  { id: 'impact',                label: 'Impact' },
]

// tactic → full tailwind class string (text/bg/border), same vocabulary as severity.js.
const TACTIC_STYLES = {
  'reconnaissance':       'text-slate-700 bg-slate-50 border-slate-200',
  'resource-development': 'text-slate-700 bg-slate-50 border-slate-200',
  'initial-access':       'text-red-700 bg-red-50 border-red-200',
  'execution':            'text-orange-700 bg-orange-50 border-orange-200',
  'persistence':          'text-amber-700 bg-amber-50 border-amber-200',
  'privilege-escalation': 'text-pink-700 bg-pink-50 border-pink-200',
  'defense-evasion':      'text-violet-700 bg-violet-50 border-violet-200',
  'credential-access':    'text-rose-700 bg-rose-50 border-rose-200',
  'discovery':            'text-cyan-700 bg-cyan-50 border-cyan-200',
  'lateral-movement':     'text-blue-700 bg-blue-50 border-blue-200',
  'collection':           'text-teal-700 bg-teal-50 border-teal-200',
  'command-and-control':  'text-indigo-700 bg-indigo-50 border-indigo-200',
  'exfiltration':         'text-fuchsia-700 bg-fuchsia-50 border-fuchsia-200',
  'impact':               'text-red-700 bg-red-50 border-red-200',
}

// Normalize a tactic value ("Initial Access", "TA0001", "initial_access") to a slug key.
function tacticKey(tactic) {
  return String(tactic || '').toLowerCase().trim().replace(/[\s_]+/g, '-')
}
function tacticStyle(tactic) {
  return TACTIC_STYLES[tacticKey(tactic)] || 'text-gray-600 bg-gray-50 border-gray-200'
}
function tacticLabel(tactic) {
  const k = tacticKey(tactic)
  const known = ATTACK_TACTICS.find(t => t.id === k)
  return known ? known.label : String(tactic || '—')
}

function fmtTime(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return String(ts)
  return d.toLocaleString()
}

// Build the pivot query for a step (prefer fo_id, fall back to host + time).
function stepQuery(step) {
  if (step?.fo_id) return `fo_id:"${step.fo_id}"`
  const parts = []
  if (step?.host) parts.push(`host.hostname:"${step.host}"`)
  if (step?.ts) parts.push(`@timestamp:"${step.ts}"`)
  return parts.join(' AND ')
}

export default function KillChainPanel({
  caseId,
  onClose,
  onPivot,
  anchorFoId = null,
  anchorHost = null,
  anchorTimestamp = null,
}) {
  const hasAnchor = Boolean(anchorFoId || (anchorHost && anchorTimestamp))

  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)

  // Manual-entry form state (used when no anchor prop is supplied).
  const [formFoId, setFormFoId]   = useState('')
  const [formHost, setFormHost]   = useState('')
  const [formTs, setFormTs]       = useState('')
  const [windowMinutes, setWindow] = useState(60)

  const assemble = useCallback(async (opts) => {
    setLoading(true); setError(null); setData(null)
    try {
      const r = await api.killchain.get(caseId, opts)
      setData(r || null)
    } catch (e) {
      setError(e.message || 'Failed to assemble kill chain.')
    } finally {
      setLoading(false)
    }
  }, [caseId])

  // Auto-assemble on mount / when anchor props change, if an anchor is provided.
  useEffect(() => {
    if (!hasAnchor) { setData(null); setError(null); return }
    assemble({
      foId: anchorFoId,
      host: anchorHost,
      timestamp: anchorTimestamp,
      windowMinutes,
    })
    // windowMinutes intentionally excluded: anchor-driven open uses the default
    // and re-assembly on window change is triggered explicitly via the form.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, anchorFoId, anchorHost, anchorTimestamp, hasAnchor])

  function onSubmitForm(e) {
    e.preventDefault()
    const foId = formFoId.trim() || null
    const host = formHost.trim() || null
    const timestamp = formTs.trim() || null
    if (!foId && !(host && timestamp)) {
      setError('Provide a fo_id, or both a host and a timestamp.')
      return
    }
    assemble({ foId, host, timestamp, windowMinutes })
  }

  const anchor   = data?.anchor || null
  const steps    = data?.steps || []
  const covered  = new Set((data?.tactics_covered || []).map(tacticKey))

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[860px] max-w-full bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Crosshair size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Kill chain</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <p className="text-[11px] text-gray-500">
            Reconstructed attack progression around the anchor event — walked backward to
            first access and forward to impact.
          </p>

          {/* Manual anchor form (only when no anchor prop supplied) */}
          {!hasAnchor && (
            <form onSubmit={onSubmitForm} className="card p-3 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="col-span-2">
                  <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">fo_id</label>
                  <input
                    type="text"
                    value={formFoId}
                    onChange={e => setFormFoId(e.target.value)}
                    placeholder="anchor event id"
                    className="input h-8 text-xs w-full"
                  />
                </div>
                <div className="col-span-2 text-[10px] text-gray-400 text-center -my-1">— or —</div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Host</label>
                  <input
                    type="text"
                    value={formHost}
                    onChange={e => setFormHost(e.target.value)}
                    placeholder="hostname"
                    className="input h-8 text-xs w-full"
                  />
                </div>
                <div>
                  <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Timestamp</label>
                  <input
                    type="text"
                    value={formTs}
                    onChange={e => setFormTs(e.target.value)}
                    placeholder="2026-06-13T12:00:00Z"
                    className="input h-8 text-xs w-full"
                  />
                </div>
              </div>
              <div className="flex items-end gap-3">
                <div>
                  <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Window (min)</label>
                  <input
                    type="number" min={1} max={1440}
                    value={windowMinutes}
                    onChange={e => setWindow(+e.target.value || 60)}
                    className="input h-8 text-xs w-24"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="btn-primary text-xs flex items-center gap-1.5 h-8"
                >
                  {loading ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
                  Assemble
                </button>
              </div>
            </form>
          )}

          {error && (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200 flex items-center gap-2">
              <AlertTriangle size={14} /> {error}
            </div>
          )}

          {/* Anchor summary */}
          {anchor && (
            <div className="card p-3">
              <div className="text-[9px] uppercase tracking-wide text-gray-500 font-medium mb-1">Anchor event</div>
              <div className="text-xs text-gray-900">{anchor.summary || '—'}</div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-gray-500 font-mono">
                <span>{fmtTime(anchor.ts)}</span>
                {anchor.host && <span>host: {anchor.host}</span>}
                {anchor.user && <span>user: {anchor.user}</span>}
                {anchor.window_minutes != null && <span>±{anchor.window_minutes}m</span>}
              </div>
            </div>
          )}

          {/* Tactics covered — horizontal chip row */}
          {data && (
            <div className="card p-3">
              <div className="text-[9px] uppercase tracking-wide text-gray-500 font-medium mb-2">ATT&amp;CK tactics covered</div>
              <div className="flex flex-wrap gap-1.5">
                {ATTACK_TACTICS.map(t => {
                  const on = covered.has(t.id)
                  return (
                    <Badge
                      key={t.id}
                      color={on ? tacticStyle(t.id) : 'text-gray-300 bg-gray-50 border-gray-100'}
                      className={on ? 'font-semibold' : ''}
                    >
                      {t.label}
                    </Badge>
                  )
                })}
              </div>
            </div>
          )}

          {/* Loading */}
          {loading && (
            <div className="card p-6 flex items-center justify-center text-sm text-gray-500 gap-2">
              <Loader2 size={14} className="animate-spin" /> Assembling kill chain…
            </div>
          )}

          {/* Empty state */}
          {!loading && data && steps.length === 0 && (
            <div className="card p-6 text-center text-xs text-gray-500">
              No related activity found in the window.
            </div>
          )}

          {/* Vertical timeline */}
          {!loading && steps.length > 0 && (
            <div className="relative pl-6">
              {/* vertical rail */}
              <div className="absolute left-[7px] top-2 bottom-2 w-px bg-gray-200" aria-hidden />
              <div className="space-y-3">
                {steps.map((step, i) => (
                  <div key={step.fo_id || `${step.ts}-${i}`} className="relative">
                    {/* node on the rail */}
                    <div
                      className="absolute -left-[21px] top-3 w-3 h-3 rounded-full border-2 border-white ring-1 ring-gray-300 bg-brand-accent"
                      aria-hidden
                    />
                    <div className="card p-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Badge color={tacticStyle(step.tactic)} className="font-semibold">
                            {tacticLabel(step.tactic)}
                          </Badge>
                          {step.phase && (
                            <span className="text-[10px] text-gray-500">{step.phase}</span>
                          )}
                          {step.technique && (
                            <span className="text-[10px] font-mono text-gray-600 bg-gray-100 rounded px-1.5 py-0.5">
                              {step.technique}
                            </span>
                          )}
                        </div>
                        <button
                          onClick={() => onPivot?.(stepQuery(step))}
                          className="text-[10px] text-brand-accent hover:text-brand-accenthover inline-flex items-center gap-1 flex-shrink-0"
                          title="Pivot to this event in the timeline"
                        >
                          <ExternalLink size={10} /> Pivot
                        </button>
                      </div>

                      <div className="mt-1.5 text-xs text-gray-900">{step.summary || '—'}</div>

                      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-0.5 text-[10px] text-gray-500 font-mono">
                        <span>{fmtTime(step.ts)}</span>
                        {step.host && <span>host: {step.host}</span>}
                        {step.user && <span>user: {step.user}</span>}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Prompt to assemble when no anchor and nothing submitted yet */}
          {!hasAnchor && !data && !loading && !error && (
            <div className="card p-6 text-center text-xs text-gray-500">
              Enter an anchor above and click <strong>Assemble</strong> to reconstruct the kill chain.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
