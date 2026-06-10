import { useState, useEffect, useRef, useCallback } from 'react'
import { ScrollText, RefreshCw, Pause, Play, Search as SearchIcon, AlertCircle } from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'

// Functional service name → the suite tool(s) it runs (shown as a tooltip/subtitle).
const SERVICE_TOOLS = {
  api:       'Citadel platform (API)',
  processor: 'Workers — Sluice · Babel · Rosetta · Anvil',
  sluice:    'Intake & routing',
  babel:     'Parsers',
  rosetta:   'Canonicalizer',
  anvil:     'Analysis runner',
}

const LEVELS = ['all', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
const LEVEL_COLOR = {
  ERROR:   'text-red-600',
  WARNING: 'text-amber-600',
  INFO:    'text-gray-600',
  DEBUG:   'text-gray-400',
}
const POLL_MS = 2500

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
    ? lines.filter(l => (l.line || '').toLowerCase().includes(q.toLowerCase()))
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
      <div className="bg-gray-900 text-gray-100 rounded-xl border border-gray-800 overflow-auto max-h-[68vh] font-mono text-xs leading-relaxed">
        {shown.length === 0 ? (
          <div className="p-6 text-gray-500">
            {service ? 'No log lines (a tool appears here once it emits).' : 'Select a service.'}
          </div>
        ) : (
          <table className="w-full border-collapse">
            <tbody>
              {shown.map((l, i) => (
                <tr key={i} className="hover:bg-gray-800/60 align-top">
                  <td className={`px-3 py-1 whitespace-nowrap select-none ${LEVEL_COLOR[l.level] || 'text-gray-500'}`}>
                    {l.level || ''}
                  </td>
                  <td className="px-3 py-1 text-gray-400 whitespace-nowrap select-none hidden sm:table-cell">
                    {l.logger || ''}
                  </td>
                  <td className="px-3 py-1 break-all text-gray-100">{l.line || ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </PageShell>
  )
}
