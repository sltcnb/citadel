import { useEffect, useState } from 'react'
import {
  Bot, Loader2, RefreshCw, AlertTriangle, CheckCircle2,
  Eye, Search, ExternalLink, Clock, Brain, ListChecks,
} from 'lucide-react'
import { api } from '../../api/client'
import PanelShell from './PanelShell'

/**
 * Pilot "co-pilot" drawer.
 *
 * Section 1 — Continuous-watch nudges (#6):
 *   GET  /cases/{id}/pilot/watch
 *   POST /cases/{id}/pilot/watch/reviewed
 *
 * Section 2 — Cross-case memory lookup (#5):
 *   GET  /pilot/memory?kind=&value=
 *
 * Section 3 — Seen-before convenience:
 *   POST /cases/{id}/pilot/memory/seen
 *
 * Mounted alongside the other per-case right-side panels (Anomaly / IOCs / …).
 */
export default function CoPilotPanel({ caseId, onClose, onPivot }) {
  // ── Section 1: watch status ────────────────────────────────────────────────
  const [watch, setWatch]               = useState(null)
  const [watchLoading, setWatchLoading] = useState(true)
  const [watchError, setWatchError]     = useState(null)
  const [marking, setMarking]           = useState(false)

  // ── Section 2: cross-case memory ────────────────────────────────────────────
  const [kind, setKind]                 = useState('ioc')
  const [recallValue, setRecallValue]   = useState('')
  const [recall, setRecall]             = useState(null)
  const [recallLoading, setRecallLoad]  = useState(false)
  const [recallError, setRecallError]   = useState(null)

  // ── Section 3: seen-before ──────────────────────────────────────────────────
  const [seenText, setSeenText]         = useState('')
  const [seen, setSeen]                 = useState(null)
  const [seenLoading, setSeenLoading]   = useState(false)
  const [seenError, setSeenError]       = useState(null)

  async function loadWatch() {
    setWatchLoading(true); setWatchError(null)
    try {
      const r = await api.pilot.watchStatus(caseId)
      setWatch(r)
    } catch (e) {
      setWatchError(e.message || 'Failed to load watch status.')
    } finally {
      setWatchLoading(false)
    }
  }
  useEffect(() => { loadWatch() }, [caseId])

  async function markReviewed() {
    setMarking(true); setWatchError(null)
    try {
      await api.pilot.markReviewed(caseId)
      await loadWatch()
    } catch (e) {
      setWatchError(e.message || 'Failed to mark reviewed.')
    } finally {
      setMarking(false)
    }
  }

  async function runRecall() {
    const v = recallValue.trim()
    if (!v) return
    setRecallLoad(true); setRecallError(null)
    try {
      const r = await api.pilot.recallMemory(kind, v)
      setRecall(r)
    } catch (e) {
      setRecallError(e.message || 'Recall failed.')
      setRecall(null)
    } finally {
      setRecallLoad(false)
    }
  }

  async function runSeen() {
    const lines = seenText
      .split('\n')
      .map(s => s.trim())
      .filter(Boolean)
    if (lines.length === 0) return
    setSeenLoading(true); setSeenError(null)
    try {
      const r = await api.pilot.seenBefore(caseId, lines)
      setSeen(r)
    } catch (e) {
      setSeenError(e.message || 'Check failed.')
      setSeen(null)
    } finally {
      setSeenLoading(false)
    }
  }

  const kinds = [
    { id: 'ioc',     label: 'IOC' },
    { id: 'ttp',     label: 'TTP' },
    { id: 'verdict', label: 'Verdict' },
  ]

  const actions = (
    <button onClick={loadWatch} disabled={watchLoading} className="btn-secondary text-xs flex items-center gap-1.5">
      <RefreshCw size={12} className={watchLoading ? 'animate-spin' : ''} />
      Refresh
    </button>
  )

  return (
    <PanelShell
      icon={Bot}
      title="Pilot co-pilot"
      onClose={onClose}
      loading={false}
      error=""
      actions={actions}
      help={{
        use: "Surfaces what's new since you last reviewed the case, and looks up IOCs across all past cases.",
        when: 'Returning to a long-running case, or checking whether an indicator has burned you before.',
        data: ['Prior Pilot runs / sealed IOCs for the cross-case memory', 'Ongoing ingest for the since-you-last-looked delta'],
        tip: "Hit Mark reviewed once you've triaged the new events to reset the counter.",
      }}
      width="md:w-[900px]"
    >
      <div className="space-y-5">
          {/* ── SECTION 1: Since you last looked ─────────────────────────────── */}
          <section className="space-y-2">
            <div className="flex items-center gap-2">
              <Eye size={13} className="text-gray-500" />
              <h3 className="text-[11px] font-semibold text-gray-700 uppercase tracking-wide">Since you last looked</h3>
            </div>
            <p className="text-[11px] text-gray-500">
              Continuous watch — new events ingested since you last reviewed this case, plus what to look at next.
            </p>

            {watchError && (
              <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200 flex items-center gap-2">
                <AlertTriangle size={14} /> {watchError}
              </div>
            )}

            <div className="card p-4">
              {watchLoading ? (
                <div className="py-4 flex items-center justify-center text-sm text-gray-500 gap-2">
                  <Loader2 size={14} className="animate-spin" /> Loading…
                </div>
              ) : !watch ? (
                <div className="py-3 text-center text-xs text-gray-500">No watch status.</div>
              ) : (
                <>
                  <div className="flex items-start gap-4">
                    {watch.new_events > 0 ? (
                      <>
                        <div className="text-center">
                          <div className="text-3xl font-semibold text-brand-accent tabular-nums leading-none">
                            {watch.new_events.toLocaleString()}
                          </div>
                          <div className="text-[10px] uppercase tracking-wide text-gray-500 mt-1">new events</div>
                        </div>
                        <div className="flex-1 text-xs text-gray-600 pt-1">
                          {watch.since ? (
                            <span className="flex items-center gap-1.5">
                              <Clock size={11} className="text-gray-400" />
                              since {new Date(watch.since).toLocaleString()}
                            </span>
                          ) : (
                            <span>since the case was first reviewed</span>
                          )}
                          <div className="mt-1 text-[11px] text-gray-500 tabular-nums">
                            {watch.reviewed?.toLocaleString() ?? 0} reviewed · {watch.current?.toLocaleString() ?? 0} total
                          </div>
                        </div>
                      </>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-emerald-700">
                        <CheckCircle2 size={16} />
                        case reviewed — nothing new
                      </div>
                    )}
                  </div>

                  {Array.isArray(watch.suggestions) && watch.suggestions.length > 0 && (
                    <ul className="mt-3 pt-3 border-t border-gray-100 space-y-1.5">
                      {watch.suggestions.map((s, i) => (
                        <li key={i} className="flex items-start gap-2 text-xs text-gray-700">
                          <span className="mt-1 h-1 w-1 rounded-full bg-brand-accent flex-shrink-0" />
                          <span>{s}</span>
                        </li>
                      ))}
                    </ul>
                  )}

                  <div className="mt-3 pt-3 border-t border-gray-100 flex justify-end">
                    <button
                      onClick={markReviewed}
                      disabled={marking}
                      className="btn-primary text-xs flex items-center gap-1.5 h-8"
                    >
                      {marking ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle2 size={12} />}
                      Mark reviewed
                    </button>
                  </div>
                </>
              )}
            </div>
          </section>

          <hr className="border-gray-100" />

          {/* ── SECTION 2: Cross-case memory ─────────────────────────────────── */}
          <section className="space-y-2">
            <div className="flex items-center gap-2">
              <Brain size={13} className="text-gray-500" />
              <h3 className="text-[11px] font-semibold text-gray-700 uppercase tracking-wide">Cross-case memory</h3>
            </div>
            <p className="text-[11px] text-gray-500">
              Recall an IOC, TTP or verdict across every case you can see — has Pilot met this before?
            </p>

            <div className="card p-3">
              <div className="flex items-end gap-2 flex-wrap">
                <div>
                  <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Kind</label>
                  <div className="inline-flex rounded-lg border border-gray-200 overflow-hidden h-8">
                    {kinds.map(k => (
                      <button
                        key={k.id}
                        onClick={() => setKind(k.id)}
                        className={`px-2.5 text-xs ${kind === k.id ? 'bg-brand-accent text-white' : 'bg-white text-gray-600 hover:bg-gray-50'}`}
                      >
                        {k.label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="flex-1 min-w-[180px]">
                  <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Value</label>
                  <input
                    value={recallValue}
                    onChange={e => setRecallValue(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') runRecall() }}
                    placeholder={kind === 'ttp' ? 'T1059.001' : kind === 'verdict' ? 'malicious' : '8.8.8.8 / hash / domain'}
                    className="input h-8 text-xs w-full font-mono"
                  />
                </div>
                <button
                  onClick={runRecall}
                  disabled={recallLoading || !recallValue.trim()}
                  className="btn-primary text-xs flex items-center gap-1.5 h-8"
                >
                  {recallLoading ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
                  Recall
                </button>
              </div>
            </div>

            {recallError && (
              <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200 flex items-center gap-2">
                <AlertTriangle size={14} /> {recallError}
              </div>
            )}

            {recall && (
              recall.records?.length > 0 ? (
                <div className="space-y-2">
                  {recall.records.map((rec, i) => (
                    <div key={i} className="card p-3">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="font-mono text-xs text-gray-900 break-all">{rec.value}</div>
                          <div className="text-[11px] text-gray-500 mt-0.5">
                            seen in {rec.count ?? rec.cases?.length ?? 0} {((rec.count ?? rec.cases?.length ?? 0) === 1) ? 'case' : 'cases'}
                            {rec.last_seen && (
                              <> · last seen {new Date(rec.last_seen).toLocaleDateString()}</>
                            )}
                          </div>
                        </div>
                        {kind === 'ioc' && rec.cases?.length > 0 && onPivot && (
                          <button
                            onClick={() => onPivot(`message:"${rec.value}"`)}
                            className="text-[10px] text-brand-accent hover:text-brand-accenthover inline-flex items-center gap-1 flex-shrink-0"
                            title="Pivot to timeline"
                          >
                            <ExternalLink size={10} /> Pivot
                          </button>
                        )}
                      </div>
                      {rec.cases?.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {rec.cases.map((c, j) => (
                            <span key={j} className="px-1.5 py-0.5 rounded bg-gray-100 text-[10px] text-gray-600 font-mono">
                              {typeof c === 'string' ? c : (c?.name || c?.id || c?.case_id || JSON.stringify(c))}
                            </span>
                          ))}
                        </div>
                      )}
                      {(rec.first_case || rec.last_case) && (
                        <div className="mt-1.5 text-[10px] text-gray-400">
                          {rec.first_case && <>first: {String(rec.first_case)}</>}
                          {rec.first_case && rec.last_case && <> · </>}
                          {rec.last_case && <>last: {String(rec.last_case)}</>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="card p-4 text-center text-xs text-gray-500">
                  No cross-case memory for that {kind}. First time Pilot has seen it.
                </div>
              )
            )}
          </section>

          <hr className="border-gray-100" />

          {/* ── SECTION 3: Seen before in other cases ────────────────────────── */}
          <section className="space-y-2">
            <div className="flex items-center gap-2">
              <ListChecks size={13} className="text-gray-500" />
              <h3 className="text-[11px] font-semibold text-gray-700 uppercase tracking-wide">Seen before in other cases</h3>
            </div>
            <p className="text-[11px] text-gray-500">
              Paste IOC values (one per line). Pilot flags any that burned us in other cases — the amber rows are the warning.
            </p>

            <div className="card p-3 space-y-2">
              <textarea
                value={seenText}
                onChange={e => setSeenText(e.target.value)}
                rows={4}
                placeholder={'8.8.8.8\nevil.example.com\nd41d8cd98f00b204e9800998ecf8427e'}
                className="input text-xs w-full font-mono resize-y"
              />
              <div className="flex justify-end">
                <button
                  onClick={runSeen}
                  disabled={seenLoading || !seenText.trim()}
                  className="btn-primary text-xs flex items-center gap-1.5 h-8"
                >
                  {seenLoading ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
                  Check
                </button>
              </div>
            </div>

            {seenError && (
              <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200 flex items-center gap-2">
                <AlertTriangle size={14} /> {seenError}
              </div>
            )}

            {seen && (
              seen.hits?.length > 0 ? (
                <div className="space-y-2">
                  <div className="text-[11px] text-amber-700 font-medium flex items-center gap-1.5">
                    <AlertTriangle size={12} />
                    {seen.count ?? seen.hits.length} value{(seen.count ?? seen.hits.length) === 1 ? '' : 's'} seen in other cases
                  </div>
                  {seen.hits.map((h, i) => (
                    <div key={i} className="card p-3 bg-amber-50 border-amber-200">
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <div className="font-mono text-xs text-amber-900 break-all">{h.value}</div>
                          <div className="text-[11px] text-amber-700 mt-0.5">
                            in {h.count ?? h.cases?.length ?? 0} other {((h.count ?? h.cases?.length ?? 0) === 1) ? 'case' : 'cases'}
                            {h.last_seen && <> · last seen {new Date(h.last_seen).toLocaleDateString()}</>}
                          </div>
                        </div>
                        {onPivot && (
                          <button
                            onClick={() => onPivot(`message:"${h.value}"`)}
                            className="text-[10px] text-amber-800 hover:text-amber-900 inline-flex items-center gap-1 flex-shrink-0"
                            title="Pivot to timeline"
                          >
                            <ExternalLink size={10} /> Pivot
                          </button>
                        )}
                      </div>
                      {h.cases?.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {h.cases.map((c, j) => (
                            <span key={j} className="px-1.5 py-0.5 rounded bg-amber-100 text-[10px] text-amber-800 font-mono">
                              {typeof c === 'string' ? c : (c?.name || c?.id || c?.case_id || JSON.stringify(c))}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="card p-4 text-center text-xs text-emerald-700 flex items-center justify-center gap-2">
                  <CheckCircle2 size={14} />
                  None of those have been seen in other cases.
                </div>
              )
            )}
          </section>
      </div>
    </PanelShell>
  )
}
