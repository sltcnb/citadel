import { useState, useEffect, useRef, useCallback } from 'react'
import {
  ScrollText, RefreshCw, Pause, Play, Search as SearchIcon, Trash2,
  ShieldCheck, ShieldAlert, Inbox, RotateCcw, Loader2,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import ConfirmDialog from '../components/ConfirmDialog'
import Toast from '../components/Toast'
import { useToast } from '../hooks/useToast'
import ErrorBox from '../components/shared/ErrorBox'
import { useConfirm } from '../components/useConfirm'
import { currentUser } from '../utils/caseConstants'
import { api } from '../api/client'

// Functional service name → the suite tool(s) it runs (shown as a tooltip/subtitle).
const SERVICE_TOOLS = {
  tools:     'Tool ↔ Citadel orchestration (announce · capabilities · finalize)',
  api:       'Citadel platform (API)',
  processor: 'Workers — Sluice · Babel · Rosetta · Anvil',
  sluice:    'Intake & routing',
  babel:     'Parsers',
  rosetta:   'Canonicalizer',
  anvil:     'Analysis runner',
}

const LEVELS = ['all', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
// Colors tuned for the dark log viewer background.
const LEVEL_COLOR = {
  ERROR:    'text-red-400',
  CRITICAL: 'text-red-400',
  WARNING:  'text-amber-300',
  INFO:     'text-sky-300',
  DEBUG:    'text-gray-500',
}
const POLL_MS = 2500

// "2026-06-08T14:03:22.123456Z" → "14:03:22.123" (keep just the clock).
function shortTime(ts) {
  if (!ts) return ''
  const m = /T(\d{2}:\d{2}:\d{2})\.?(\d{0,3})/.exec(ts)
  return m ? `${m[1]}${m[2] ? '.' + m[2] : ''}` : ts
}

// ISO timestamp → short human age ("5m", "3h", "2d") for dead-letter entries.
function ageOf(ts) {
  const t = new Date(ts).getTime()
  if (!ts || Number.isNaN(t)) return ''
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) return `${Math.floor(s / 3600)}h`
  return `${Math.floor(s / 86400)}d`
}

// ── Admin: dead-letter queue ──────────────────────────────────────────────────
// Poison worker tasks parked after exhausting retries (see
// api/routers/admin_dead_letter.py). Each entry can be replayed individually,
// or the whole queue at once (behind a confirm — replays re-dispatch work).
function DeadLetterSection({ showToast }) {
  const [data, setData]         = useState(null)   // { count, total, entries }
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [replaying, setReplaying] = useState(null) // index being replayed
  const [confirmAll, setConfirmAll] = useState(false)
  const [replayingAll, setReplayingAll] = useState(false)

  const load = useCallback(() => {
    api.deadLetter.list()
      .then(r => { setData(r); setError(null) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])
  useEffect(() => { load() }, [load])

  async function replay(index) {
    setReplaying(index)
    try {
      const r = await api.deadLetter.replay(index)
      showToast(r.status === 'requeued'
        ? `Requeued ${r.task || 'task'}${r.queue ? ` → ${r.queue}` : ''}`
        : 'Skipped — job already finished')
      load()
    } catch (e) {
      showToast(e.message || 'Replay failed', 'error')
    } finally {
      setReplaying(null)
    }
  }

  async function replayAll() {
    setReplayingAll(true)
    try {
      const r = await api.deadLetter.replayAll()
      showToast(`Replayed ${r.replayed} · skipped ${r.skipped_already_processed} already-done`)
      load()
    } catch (e) {
      showToast(e.message || 'Replay-all failed', 'error')
    } finally {
      setReplayingAll(false)
      setConfirmAll(false)
    }
  }

  const entries = data?.entries || []

  return (
    <section className="card overflow-hidden flex-shrink-0">
      <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2 flex-wrap">
        <Inbox size={15} className="text-brand-accent" />
        <h2 className="font-semibold text-brand-text text-sm">Dead-letter queue</h2>
        <span className={`badge-pill ${entries.length ? 'bg-red-100 text-red-700' : 'bg-gray-100 text-gray-500'}`}>
          {data ? data.total : '…'}
        </span>
        <span className="text-[11px] text-gray-500">failed worker tasks parked after exhausting retries</span>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => { setLoading(true); load() }} disabled={loading} className="btn-secondary text-xs inline-flex items-center gap-1.5">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <button
            onClick={() => setConfirmAll(true)}
            disabled={!entries.length || replayingAll}
            className="btn-outline text-xs inline-flex items-center gap-1.5 disabled:opacity-50"
          >
            <RotateCcw size={12} /> Replay all
          </button>
        </div>
      </div>

      {error && (
        <ErrorBox msg={error} className="m-3 text-sm" />
      )}

      {loading && !data ? (
        <div className="p-5 text-sm text-gray-500 flex items-center gap-2">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : entries.length === 0 ? (
        <div className="p-5 text-xs text-gray-500">Queue is empty — no failed tasks waiting.</div>
      ) : (
        <div className="divide-y divide-gray-100 max-h-72 overflow-y-auto">
          {entries.map(e => (
            <div key={e.index} className="px-4 py-2.5 flex items-start gap-3 text-xs">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono font-semibold text-gray-800">{e.task || 'unknown task'}</span>
                  {e.failed_at && (
                    <span className="text-gray-500" title={e.failed_at}>{ageOf(e.failed_at)} ago</span>
                  )}
                  {e.args?.[0] && (
                    <span className="font-mono text-[10px] text-gray-400">job:{String(e.args[0]).slice(0, 8)}</span>
                  )}
                </div>
                {e.error && (
                  <p className="text-red-600/90 font-mono text-[11px] mt-0.5 break-words">{e.error}</p>
                )}
              </div>
              <button
                onClick={() => replay(e.index)}
                disabled={replaying !== null}
                className="btn-outline text-xs inline-flex items-center gap-1 flex-shrink-0 disabled:opacity-50"
                title="Re-enqueue this task and remove it from the queue"
              >
                {replaying === e.index
                  ? <Loader2 size={11} className="animate-spin" />
                  : <RotateCcw size={11} />}
                Replay
              </button>
            </div>
          ))}
        </div>
      )}

      {confirmAll && (
        <ConfirmDialog
          title="Replay all dead-lettered tasks?"
          icon={<RotateCcw size={14} className="text-brand-accent" />}
          message={`This re-enqueues all ${entries.length} parked task(s) at high priority. Tasks whose job already finished are skipped automatically.`}
          confirmLabel="Replay all"
          busy={replayingAll}
          onConfirm={replayAll}
          onCancel={() => setConfirmAll(false)}
        />
      )}
    </section>
  )
}

// ── Admin: audit trail ────────────────────────────────────────────────────────
// Tamper-evident, hash-chained record of every API call (write path is the
// middleware; these endpoints are read/verify only). "Verify chain" recomputes
// the hash chain over the recent window as a tamper-evidence proof.
function AuditLogSection({ showToast }) {
  const [items, setItems]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [verify, setVerify]     = useState(null)   // { ok, broken_at, checked }
  const [verifying, setVerifying] = useState(false)

  const load = useCallback(() => {
    api.audit.log({ limit: 100 })
      .then(r => { setItems(r.items || []); setError(null) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])
  useEffect(() => { load() }, [load])

  async function verifyChain() {
    setVerifying(true)
    try {
      setVerify(await api.audit.verify())
    } catch (e) {
      showToast(e.message || 'Verification failed', 'error')
    } finally {
      setVerifying(false)
    }
  }

  return (
    <section className="card overflow-hidden flex-shrink-0">
      <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2 flex-wrap">
        <ShieldCheck size={15} className="text-brand-accent" />
        <h2 className="font-semibold text-brand-text text-sm">Audit log</h2>
        <span className="text-[11px] text-gray-500">hash-chained record of API activity, newest first</span>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => { setLoading(true); load() }} disabled={loading} className="btn-secondary text-xs inline-flex items-center gap-1.5">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <button onClick={verifyChain} disabled={verifying} className="btn-outline text-xs inline-flex items-center gap-1.5 disabled:opacity-50">
            {verifying ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
            Verify chain
          </button>
        </div>
      </div>

      {verify && (
        <div className={`mx-3 mt-3 flex items-center gap-2 text-xs rounded-lg border px-3 py-2 ${
          verify.ok
            ? 'text-emerald-700 bg-emerald-50 border-emerald-200'
            : 'text-red-700 bg-red-50 border-red-200'
        }`}>
          {verify.ok ? <ShieldCheck size={14} /> : <ShieldAlert size={14} />}
          {verify.ok
            ? `Chain intact — ${verify.checked} record(s) verified, no tampering detected.`
            : `CHAIN BROKEN at seq ${verify.broken_at ?? '?'} after ${verify.checked} record(s) — the audit trail was altered.`}
        </div>
      )}

      {error && (
        <ErrorBox msg={error} className="m-3 text-sm" />
      )}

      {loading && items.length === 0 ? (
        <div className="p-5 text-sm text-gray-500 flex items-center gap-2">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : items.length === 0 ? (
        <div className="p-5 text-xs text-gray-500">No audit records yet.</div>
      ) : (
        <div className="max-h-80 overflow-auto">
          <table className="w-full text-[11px]">
            <thead className="bg-gray-50 text-gray-600 sticky top-0">
              <tr>
                <th className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-left">Time</th>
                <th className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-left">Actor</th>
                <th className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-left">Method</th>
                <th className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-left">Path</th>
                <th className="px-3 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-left">Status</th>
              </tr>
            </thead>
            <tbody>
              {items.map(r => (
                <tr key={r.seq} className="border-t border-gray-100 hover:bg-gray-50">
                  <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap" title={r.ts}>{shortTime(r.ts)}</td>
                  <td className="px-3 py-1.5 text-gray-700">{r.actor || '—'}</td>
                  <td className="px-3 py-1.5 font-mono text-gray-600">{r.method}</td>
                  <td className="px-3 py-1.5 font-mono text-gray-600 max-w-[24rem] truncate" title={r.path}>{r.path}</td>
                  <td className="px-3 py-1.5">
                    <span className={`font-semibold ${r.status < 400 ? 'text-emerald-600' : 'text-red-600'}`}>
                      {r.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}


function LogRow({ l }) {
  const [open, setOpen] = useState(false)
  const msg = l.msg || l.line || ''
  const hasExc = !!l.exc
  const lvl = (l.level || '').toUpperCase()
  return (
    <div className="px-3 py-1 hover:bg-gray-800/50">
      <div
        className={`flex items-start gap-3 ${hasExc ? 'cursor-pointer' : ''}`}
        onClick={hasExc ? () => setOpen(o => !o) : undefined}
      >
        <span className="text-gray-500 whitespace-nowrap select-none tabular-nums">
          {shortTime(l.ts)}
        </span>
        <span className={`w-16 shrink-0 font-semibold select-none ${LEVEL_COLOR[lvl] || 'text-gray-400'}`}>
          {lvl}
        </span>
        <span className="text-gray-500 whitespace-nowrap select-none hidden md:inline max-w-[14rem] truncate" title={l.logger}>
          {l.logger || ''}
        </span>
        <span className="text-gray-100 whitespace-pre-wrap break-words flex-1">
          {msg}
          {hasExc && (
            <span className="ml-2 text-[10px] text-amber-400/80 select-none">
              {open ? '▾ traceback' : '▸ traceback'}
            </span>
          )}
        </span>
      </div>
      {hasExc && open && (
        <pre className="mt-1 ml-3 pl-3 border-l-2 border-red-500/40 text-red-300/90 whitespace-pre-wrap break-words text-[11px] leading-snug overflow-x-auto">
          {l.exc}
        </pre>
      )}
    </div>
  )
}

export default function Logs() {
  const [services, setServices]   = useState([])     // [{service, lines}]
  const [service, setService]     = useState('')
  const [level, setLevel]         = useState('all')
  const [limit, setLimit]         = useState(200)
  const [q, setQ]                 = useState('')
  const [lines, setLines]         = useState([])
  const [live, setLive]           = useState(true)
  const [error, setError]         = useState(null)
  const [loading, setLoading]     = useState(false)
  const [toast, showToast]        = useToast()
  const timer = useRef(null)
  // Audit trail + dead-letter queue are admin-only endpoints — hide the
  // sections entirely for non-admins (nav already gates this page).
  const isAdmin = currentUser()?.role === 'admin'

  // discover services that currently have logs
  useEffect(() => {
    api.logs.services()
      .then(r => {
        const list = r.services || []
        setServices(list)
        if (!service && list.length) setService(list[0].service)
      })
      .catch(e => setError(e.message))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const [clearing, setClearing] = useState(false)
  const [confirmEl, askConfirm] = useConfirm()
  async function clearLogs(scope) {
    // scope: the current service, or 'all'
    const label = scope === 'all' ? 'ALL services' : scope
    if (!await askConfirm(`Reset captured logs for ${label}? This clears the viewer's buffer (stdout/cluster logs are untouched).`, { title: 'Reset captured logs?' })) return
    setClearing(true)
    api.logs.clear(scope)
      .then(() => { setLines([]); return api.logs.services() })
      .then(r => setServices(r.services || []))
      .catch(e => setError(e.message))
      .finally(() => setClearing(false))
  }

  const fetchTail = useCallback(() => {
    if (!service) return
    const params = { limit }
    if (level !== 'all') params.level = level
    setLoading(true)
    api.logs.tail(service, params)
      .then(r => { setLines(r.lines || []); setError(null) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [service, level, limit])

  // initial + on-change fetch
  useEffect(() => { fetchTail() }, [fetchTail])

  // live polling
  useEffect(() => {
    clearInterval(timer.current)
    if (live && service) timer.current = setInterval(fetchTail, POLL_MS)
    return () => clearInterval(timer.current)
  }, [live, service, fetchTail])

  const shown = q
    ? lines.filter(l => {
        const hay = `${l.msg || l.line || ''} ${l.logger || ''} ${l.exc || ''}`.toLowerCase()
        return hay.includes(q.toLowerCase())
      })
    : lines

  return (
    <PageShell className="h-full flex flex-col !space-y-4 overflow-y-auto">
      <PageHeader
        title="Tool Logs"
        subtitle="Recent structured logs shipped by each tool (newest first)"
        icon={ScrollText}
        actions={
          <div className="flex items-center gap-2">
            <button
              onClick={() => setLive(v => !v)}
              className="btn-secondary inline-flex items-center gap-1.5"
              title={live ? 'Pause auto-refresh' : 'Resume auto-refresh'}
            >
              {live ? <Pause size={15} /> : <Play size={15} />}
              {live ? 'Live' : 'Paused'}
            </button>
            <button onClick={fetchTail} className="btn-secondary inline-flex items-center gap-1.5">
              <RefreshCw size={15} className={loading ? 'animate-spin' : ''} /> Refresh
            </button>
            <button
              onClick={() => clearLogs(service)}
              disabled={!service || clearing}
              className="btn-secondary inline-flex items-center gap-1.5 text-red-600 disabled:opacity-50"
              title="Reset captured logs for the selected service"
            >
              <Trash2 size={15} /> Clear
            </button>
          </div>
        }
      />

      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <select
          value={service}
          onChange={e => setService(e.target.value)}
          className="input max-w-xs"
          title={SERVICE_TOOLS[service] || ''}
        >
          {services.length === 0 && <option value="">No services reporting yet</option>}
          {services.map(s => (
            <option key={s.service} value={s.service} title={SERVICE_TOOLS[s.service] || ''}>
              {s.service} — {SERVICE_TOOLS[s.service] || 'service'} ({s.lines})
            </option>
          ))}
        </select>

        <select value={level} onChange={e => setLevel(e.target.value)} className="input w-36">
          {LEVELS.map(l => <option key={l} value={l}>{l === 'all' ? 'All levels' : l}</option>)}
        </select>

        <select value={limit} onChange={e => setLimit(Number(e.target.value))} className="input w-28">
          {[200, 500, 1000, 2000].map(n => <option key={n} value={n}>{n} lines</option>)}
        </select>

        <div className="relative flex-1 min-w-[200px]">
          <SearchIcon size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={q}
            onChange={e => setQ(e.target.value)}
            placeholder="Filter lines…"
            className="input pl-9 w-full"
          />
        </div>
      </div>

      {service && (
        <p className="text-xs text-gray-500 mb-2">
          {service} · {SERVICE_TOOLS[service] || 'service'} · showing {shown.length} of {lines.length}
        </p>
      )}

      {error && (
        <ErrorBox msg={error} className="text-sm mb-3" />
      )}

      {/* Log viewer — fills the remaining height; scrolls internally only */}
      <div className="bg-gray-900 text-gray-100 rounded-xl border border-gray-800 overflow-auto flex-1 min-h-[20rem] flex-shrink-0 font-mono text-xs leading-relaxed">
        {shown.length === 0 ? (
          <div className="p-6 text-gray-500">
            {service ? 'No log lines (a tool appears here once it emits).' : 'Select a service.'}
          </div>
        ) : (
          <div className="divide-y divide-gray-800/70">
            {shown.map((l, i) => <LogRow key={i} l={l} />)}
          </div>
        )}
      </div>

      {/* Admin-only operational sections */}
      {isAdmin && <DeadLetterSection showToast={showToast} />}
      {isAdmin && <AuditLogSection showToast={showToast} />}

      <Toast toast={toast} />
      {confirmEl}
    </PageShell>
  )
}
