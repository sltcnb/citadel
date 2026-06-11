import { useState, useEffect, useRef, useCallback } from 'react'
import { ScrollText, RefreshCw, Pause, Play, Search as SearchIcon, AlertCircle, Trash2 } from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
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
  const timer = useRef(null)

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
  function clearLogs(scope) {
    // scope: the current service, or 'all'
    const label = scope === 'all' ? 'ALL services' : scope
    if (!window.confirm(`Reset captured logs for ${label}? This clears the viewer's buffer (stdout/cluster logs are untouched).`)) return
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
    <PageShell>
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
        <div className="flex items-center gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-3">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {/* Log viewer */}
      <div className="bg-gray-900 text-gray-100 rounded-xl border border-gray-800 overflow-auto h-[calc(100vh-18rem)] min-h-[24rem] font-mono text-xs leading-relaxed">
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
    </PageShell>
  )
}
