import { useState, useEffect, useCallback } from 'react'
import {
  Activity, AlertTriangle, RefreshCw, Loader2, ChevronRight, X, Info,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import ErrorBox, { NoticeBox } from '../components/shared/ErrorBox'
import { api } from '../api/client'

/**
 * Telemetry — rendered entirely from what the deployed components advertise.
 *
 * There is deliberately no per-tool code in this file. The API returns a list
 * of panels, each carrying its own label, columns and rows; this renders them
 * by `type`. Remove a tool and its panels disappear; plug one in and its panels
 * show up — the same contract that already drives the capability forms.
 *
 * Adding a panel is a manifest edit, never a change here. Adding a new panel
 * *type* is the only thing that needs a component, which is the point.
 */

const WINDOWS = [
  { hours: 24, label: '24h' },
  { hours: 168, label: '7d' },
  { hours: 720, label: '30d' },
]

const num = (n) => (n ?? 0).toLocaleString()

/** Format a metric using the unit its manifest declared. */
function fmt(value, unit) {
  if (value === null || value === undefined) return '—'
  if (unit === 'ms') return value >= 1000 ? `${(value / 1000).toFixed(1)}s` : `${Math.round(value)}ms`
  if (unit === 'usd') return value ? `$${Number(value).toFixed(4)}` : '—'
  if (unit === 'percent') return `${Math.round(value)}%`
  if (typeof value === 'number') return num(Math.round(value * 100) / 100)
  return String(value)
}

/** A `tone: bad` column goes red once it is non-zero; otherwise stay neutral. */
function toneClass(value, tone) {
  if (!tone || !value) return 'text-gray-500'
  return tone === 'bad' ? 'text-red-600 font-semibold' : 'text-emerald-600 font-semibold'
}

function ageOf(ts) {
  const t = new Date(ts).getTime()
  if (!ts || Number.isNaN(t)) return ''
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

function PanelShell({ panel, children, empty }) {
  return (
    <section className="card overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2 flex-wrap">
        <h2 className="font-semibold text-brand-text text-sm">{panel.label}</h2>
        {panel.tool && (
          <span className="badge-pill bg-gray-100 text-gray-500 text-[10px]">{panel.tool}</span>
        )}
        {panel.hint && <span className="text-[11px] text-gray-500">{panel.hint}</span>}
      </div>
      {empty
        ? <div className="px-4 py-6 text-sm text-gray-400">{empty}</div>
        : <div className="overflow-x-auto">{children}</div>}
    </section>
  )
}

function StatPanel({ panel }) {
  const row = panel.rows?.[0] || {}
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {panel.columns.map(col => (
        <div key={col.key} className="card p-4">
          <div className="text-[11px] uppercase tracking-wide text-gray-500">{col.label}</div>
          <div className={`mt-2 text-2xl font-bold tabular-nums ${
            row[col.key] && col.tone === 'bad' ? 'text-red-600' : 'text-brand-text'}`}>
            {fmt(row[col.key], col.unit)}
          </div>
        </div>
      ))}
    </div>
  )
}

function TimeseriesPanel({ panel }) {
  const rows = panel.rows || []
  const peak = Math.max(1, ...rows.map(r => r.count || 0))
  return (
    <PanelShell panel={panel} empty={rows.length ? null : 'No activity in this window.'}>
      <div className="px-4 py-4 flex items-end gap-1 h-28">
        {rows.map((r, i) => {
          const failures = r.m1 || 0
          const height = Math.max(2, ((r.count || 0) / peak) * 100)
          const badShare = r.count ? (failures / r.count) * 100 : 0
          return (
            <div key={i} className="flex-1 flex flex-col justify-end group relative"
                 title={`${r.key}\n${r.count} events, ${failures} failures`}>
              <div className="w-full rounded-t bg-brand-accent/70" style={{ height: `${height}%` }}>
                {badShare > 0 && (
                  <div className="w-full bg-red-500 rounded-t" style={{ height: `${badShare}%` }} />
                )}
              </div>
            </div>
          )
        })}
      </div>
    </PanelShell>
  )
}

function TablePanel({ panel, onDrill }) {
  const rows = panel.rows || []
  const clickable = !!panel.group_by
  return (
    <PanelShell panel={panel} empty={rows.length ? null : 'Nothing recorded in this window.'}>
      <table className="w-full text-sm">
        <thead className="bg-gray-50 text-[11px] uppercase tracking-wide text-gray-500">
          <tr>
            <th className="text-left font-medium px-4 py-2">{panel.group_by || 'Value'}</th>
            {panel.columns.map(c => (
              <th key={c.key} className="text-right font-medium px-4 py-2 w-24">{c.label}</th>
            ))}
            {clickable && <th className="w-8" />}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-100">
          {rows.map((r, i) => (
            <tr key={i}
                className={`hover:bg-gray-50 ${clickable ? 'cursor-pointer' : ''}`}
                onClick={clickable ? () => onDrill(panel, r) : undefined}>
              <td className="px-4 py-2.5">
                <div className="font-mono text-xs text-brand-text break-words">{r.key ?? '—'}</div>
                {r.sample && (
                  <div className="text-[11px] text-gray-500 mt-0.5">
                    {r.sample.service} · {ageOf(r.sample['@timestamp'])}
                    {r.sample['http.route'] ? ` · ${r.sample['http.route']}` : ''}
                  </div>
                )}
              </td>
              {panel.columns.map(c => (
                <td key={c.key} className={`px-4 py-2.5 text-right tabular-nums ${toneClass(r[c.key], c.tone)}`}>
                  {fmt(r[c.key], c.unit)}
                </td>
              ))}
              {clickable && <td className="px-2"><ChevronRight size={14} className="text-gray-300" /></td>}
            </tr>
          ))}
        </tbody>
      </table>
    </PanelShell>
  )
}

/** Raw events behind whatever the user clicked — filtered by the panel's own
 *  group_by field, so no per-panel knowledge is needed here either. */
function EventDrawer({ query, onClose }) {
  const [events, setEvents] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!query) return
    setEvents(null); setError(null)
    api.telemetry.events({ ...query.params, limit: 50 })
      .then(r => setEvents(r.events || []))
      .catch(e => setError(e.message))
  }, [query])

  if (!query) return null
  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/30" onClick={onClose}>
      <div className="w-full max-w-3xl h-full bg-white shadow-2xl flex flex-col"
           onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2">
          <h3 className="font-semibold text-sm text-brand-text truncate">{query.title}</h3>
          <button onClick={onClose} className="ml-auto text-gray-400 hover:text-gray-700">
            <X size={16} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {error && <ErrorBox msg={error} />}
          {!events && !error && (
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Loader2 size={14} className="animate-spin" /> Loading events…
            </div>
          )}
          {events?.length === 0 && <div className="text-sm text-gray-400">No events matched.</div>}
          {events?.map((e, i) => (
            <div key={i} className="rounded-lg border border-gray-200 p-3 text-xs">
              <div className="flex items-center gap-2 flex-wrap text-[11px] text-gray-500">
                <span className="font-mono">{e['@timestamp']}</span>
                <span className="badge-pill bg-gray-100 text-gray-600">{e.service}</span>
                <span className="badge-pill bg-gray-100 text-gray-600">{e.kind}</span>
                {e.outcome === 'failure' && (
                  <span className="badge-pill bg-red-100 text-red-700">failure</span>
                )}
                {e.correlation_id && (
                  <span className="font-mono text-gray-400">id={e.correlation_id}</span>
                )}
                {e.case_id && <span className="font-mono text-gray-400">case={e.case_id}</span>}
              </div>
              <div className="mt-1.5 text-brand-text break-words">
                {e.message || e['error.message'] || e.event}
              </div>
              {(e['http.method'] || e['http.route']) && (
                <div className="mt-1 font-mono text-[11px] text-gray-500">
                  {e['http.method']} {e['http.path'] || e['http.route']}
                  {e['http.status_code'] ? ` → ${e['http.status_code']}` : ''}
                  {e.duration_ms != null ? ` (${fmt(e.duration_ms, 'ms')})` : ''}
                </div>
              )}
              {e['error.stack'] && (
                <details className="mt-2">
                  <summary className="cursor-pointer text-[11px] text-gray-500">Stack trace</summary>
                  <pre className="mt-1 p-2 bg-gray-900 text-gray-200 rounded overflow-x-auto text-[10px] leading-relaxed">
                    {e['error.stack']}
                  </pre>
                </details>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

export default function Telemetry() {
  const [hours, setHours] = useState(24)
  const [data, setData] = useState(null)
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [drill, setDrill] = useState(null)

  const load = useCallback(() => {
    setLoading(true)
    Promise.all([api.telemetry.summary(hours), api.telemetry.health().catch(() => null)])
      .then(([summary, h]) => { setData(summary); setHealth(h); setError(null) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [hours])

  useEffect(() => { load() }, [load])

  function drillInto(panel, row) {
    setDrill({
      title: `${panel.label} — ${row.key}`,
      params: {
        hours,
        ...(panel.kind ? { kind: panel.kind } : {}),
        ...(panel.group_by ? { field: panel.group_by, value: row.key } : {}),
      },
    })
  }

  const panels = data?.panels || []
  const stats = panels.filter(p => p.type === 'stat')
  const rest = panels.filter(p => p.type !== 'stat')
  const sink = health?.sink
  const degraded = sink?.enabled && (sink.dropped > 0 || sink.failed > 0)

  return (
    <PageShell>
      <PageHeader
        title="Telemetry"
        subtitle="What the platform actually did — every panel here is declared by the component that emits it"
        icon={Activity}
        actions={
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg border border-gray-200 overflow-hidden">
              {WINDOWS.map(w => (
                <button key={w.hours} onClick={() => setHours(w.hours)}
                  className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                    hours === w.hours ? 'bg-brand-accent text-white'
                                      : 'bg-white text-gray-600 hover:bg-gray-50'}`}>
                  {w.label}
                </button>
              ))}
            </div>
            <button onClick={load} disabled={loading}
                    className="btn-secondary text-xs inline-flex items-center gap-1.5">
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
            </button>
          </div>
        }
      />

      {error && <ErrorBox msg={error} onRetry={load} />}

      {health && !sink?.enabled && (
        <NoticeBox msg="Telemetry is not recording — the sink is disabled or Elasticsearch is unreachable. This page shows only what was captured earlier." />
      )}
      {degraded && (
        <NoticeBox msg={`Telemetry is losing events: ${num(sink.dropped)} dropped (queue full), ${num(sink.failed)} rejected${sink.last_error ? ` — ${sink.last_error}` : ''}. Counts below undercount reality.`} />
      )}
      {data?.warnings?.map((w, i) => (
        <NoticeBox key={i} msg={`Advertisement problem: ${w}`} />
      ))}

      {stats.map(p => <StatPanel key={p.key} panel={p} />)}

      {!loading && !panels.length && (
        <div className="card p-6 flex items-start gap-2 text-sm">
          <Info size={16} className="text-brand-accent flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-medium text-brand-text">No component advertises a telemetry panel</div>
            <div className="text-gray-500 text-xs mt-0.5">
              Panels come from a <code>telemetry:</code> block in each tool&apos;s
              <code> capabilities.yaml</code>. See <code>docs/OBSERVABILITY.md</code>.
            </div>
          </div>
        </div>
      )}

      {rest.map(panel =>
        panel.type === 'timeseries'
          ? <TimeseriesPanel key={panel.key} panel={panel} />
          : <TablePanel key={panel.key} panel={panel} onDrill={drillInto} />,
      )}

      <EventDrawer query={drill} onClose={() => setDrill(null)} />
    </PageShell>
  )
}
