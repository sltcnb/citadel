import { useState, useEffect, useCallback } from 'react'
import {
  Activity, AlertTriangle, RefreshCw, Bug, Timer, Cpu, Brain, MonitorSmartphone,
  Loader2, ChevronRight, X,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import ErrorBox from '../components/shared/ErrorBox'
import { api } from '../api/client'

/**
 * Telemetry — the "what should we fix next?" page.
 *
 * Deliberately not another log viewer (that is /logs, a live tail of the last
 * ~2 000 lines). Everything here is an aggregate over weeks of history, and
 * every number is a link into the events behind it: a count you cannot drill
 * into is a number you cannot act on.
 */

const WINDOWS = [
  { hours: 24,   label: '24h' },
  { hours: 168,  label: '7d'  },
  { hours: 720,  label: '30d' },
]

function ageOf(ts) {
  const t = new Date(ts).getTime()
  if (!ts || Number.isNaN(t)) return ''
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000))
  if (s < 60) return `${s}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

const num = (n) => (n ?? 0).toLocaleString()
const ms = (n) => (n == null ? '—' : n >= 1000 ? `${(n / 1000).toFixed(1)}s` : `${Math.round(n)}ms`)

/** Failure ratio → colour. Anything failing at all is worth seeing in red. */
function failureTone(failed, total) {
  if (!failed) return 'text-gray-400'
  return failed / Math.max(1, total) > 0.1 ? 'text-red-600' : 'text-amber-600'
}

function Stat({ icon: Icon, label, value, sub, tone = 'text-brand-text' }) {
  return (
    <div className="card p-4">
      <div className="flex items-center gap-2 text-[11px] uppercase tracking-wide text-gray-500">
        <Icon size={13} className="text-brand-accent" /> {label}
      </div>
      <div className={`mt-2 text-2xl font-bold tabular-nums ${tone}`}>{value}</div>
      {sub && <div className="mt-1 text-[11px] text-gray-500">{sub}</div>}
    </div>
  )
}

function Section({ icon: Icon, title, hint, children, empty }) {
  return (
    <section className="card overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2 flex-wrap">
        <Icon size={15} className="text-brand-accent" />
        <h2 className="font-semibold text-brand-text text-sm">{title}</h2>
        {hint && <span className="text-[11px] text-gray-500">{hint}</span>}
      </div>
      {empty
        ? <div className="px-4 py-6 text-sm text-gray-400">{empty}</div>
        : <div className="overflow-x-auto">{children}</div>}
    </section>
  )
}

/** Raw events behind whatever the user just clicked. */
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
      <div
        className="w-full max-w-3xl h-full bg-white shadow-2xl flex flex-col"
        onClick={e => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-gray-100 flex items-center gap-2">
          <h3 className="font-semibold text-sm text-brand-text truncate">{query.title}</h3>
          <button onClick={onClose} className="ml-auto text-gray-400 hover:text-gray-700">
            <X size={16} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {error && <ErrorBox message={error} />}
          {!events && !error && (
            <div className="flex items-center gap-2 text-sm text-gray-500">
              <Loader2 size={14} className="animate-spin" /> Loading events…
            </div>
          )}
          {events?.length === 0 && (
            <div className="text-sm text-gray-400">No events matched.</div>
          )}
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
              </div>
              <div className="mt-1.5 text-brand-text break-words">
                {e.message || e['error.message'] || e.event}
              </div>
              {(e['http.method'] || e['http.route']) && (
                <div className="mt-1 font-mono text-[11px] text-gray-500">
                  {e['http.method']} {e['http.path'] || e['http.route']}
                  {e['http.status_code'] ? ` → ${e['http.status_code']}` : ''}
                  {e.duration_ms != null ? ` (${ms(e.duration_ms)})` : ''}
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
    Promise.all([
      api.telemetry.summary(hours),
      api.telemetry.health().catch(() => null),
    ])
      .then(([summary, h]) => { setData(summary); setHealth(h); setError(null) })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [hours])

  useEffect(() => { load() }, [load])

  const kinds = Object.fromEntries((data?.by_kind || []).map(k => [k.kind, k]))
  const errorCount = (kinds.error?.count || 0) + (kinds.ui?.count || 0)
  const failedRequests = (kinds.request?.outcomes?.failure) || 0
  const sink = health?.sink
  const sinkDegraded = sink && sink.enabled && (sink.dropped > 0 || sink.failed > 0)

  return (
    <PageShell>
      <PageHeader
        title="Telemetry"
        subtitle="What the platform actually did — errors, slow paths, parser reliability and LLM spend, aggregated over time"
        icon={Activity}
        actions={
          <div className="flex items-center gap-2">
            <div className="flex rounded-lg border border-gray-200 overflow-hidden">
              {WINDOWS.map(w => (
                <button
                  key={w.hours}
                  onClick={() => setHours(w.hours)}
                  className={`px-3 py-1.5 text-xs font-medium transition-colors ${
                    hours === w.hours
                      ? 'bg-brand-accent text-white'
                      : 'bg-white text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  {w.label}
                </button>
              ))}
            </div>
            <button onClick={load} disabled={loading} className="btn-secondary text-xs inline-flex items-center gap-1.5">
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
            </button>
          </div>
        }
      />

      {error && <ErrorBox message={error} />}

      {health && !sink?.enabled && (
        <div className="card p-4 flex items-start gap-2 text-sm">
          <AlertTriangle size={16} className="text-amber-500 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-medium text-brand-text">Telemetry is not recording</div>
            <div className="text-gray-500 text-xs mt-0.5">
              The sink is disabled or Elasticsearch is unreachable, so this page shows only
              what was captured earlier. Check <code>CITADEL_TELEMETRY_ENABLED</code> and
              <code> ELASTICSEARCH_URL</code>.
            </div>
          </div>
        </div>
      )}

      {sinkDegraded && (
        <div className="card p-4 flex items-start gap-2 text-sm">
          <AlertTriangle size={16} className="text-amber-500 flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-medium text-brand-text">Telemetry is losing events</div>
            <div className="text-gray-500 text-xs mt-0.5">
              {num(sink.dropped)} dropped (queue full), {num(sink.failed)} rejected by Elasticsearch
              {sink.last_error ? ` — ${sink.last_error}` : ''}. Counts below undercount reality.
            </div>
          </div>
        </div>
      )}

      {/* ── Headline numbers ─────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Stat icon={Activity} label="Events" value={num(data?.events)}
              sub={`across ${data?.by_service?.length || 0} service(s)`} />
        <Stat icon={Bug} label="Errors" value={num(errorCount)}
              tone={errorCount ? 'text-red-600' : 'text-brand-text'}
              sub="exceptions + browser crashes" />
        <Stat icon={AlertTriangle} label="Failed requests" value={num(failedRequests)}
              tone={failedRequests ? 'text-red-600' : 'text-brand-text'}
              sub="5xx responses" />
        <Stat icon={Brain} label="LLM spend" value={`$${(data?.llm?.cost_usd || 0).toFixed(2)}`}
              sub={`${num(data?.llm?.calls)} calls · ${num(data?.llm?.tokens)} tokens`} />
      </div>

      {/* ── Recurring errors ─────────────────────────────────────────────── */}
      <Section
        icon={Bug}
        title="Recurring errors"
        hint="grouped by signature — ids and numbers normalised, so one bug is one row"
        empty={data && !data.top_errors?.length ? 'No errors recorded in this window.' : null}
      >
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-[11px] uppercase tracking-wide text-gray-500">
            <tr>
              <th className="text-left font-medium px-4 py-2">Error</th>
              <th className="text-right font-medium px-4 py-2 w-20">Count</th>
              <th className="text-left font-medium px-4 py-2 w-32">Last seen</th>
              <th className="w-8" />
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {(data?.top_errors || []).map((e, i) => (
              <tr
                key={i}
                className="hover:bg-gray-50 cursor-pointer"
                onClick={() => setDrill({
                  title: e.signature,
                  params: { hours, signature: e.signature },
                })}
              >
                <td className="px-4 py-2.5">
                  <div className="font-mono text-xs text-brand-text break-words">{e.signature}</div>
                  <div className="text-[11px] text-gray-500 mt-0.5">
                    {e.services?.join(', ')}
                    {e.sample?.['http.route'] ? ` · ${e.sample['http.route']}` : ''}
                    {e.sample?.['ui.route'] ? ` · ${e.sample['ui.route']}` : ''}
                  </div>
                </td>
                <td className="px-4 py-2.5 text-right tabular-nums font-semibold text-red-600">{num(e.count)}</td>
                <td className="px-4 py-2.5 text-[11px] text-gray-500">{ageOf(e.last_seen)}</td>
                <td className="px-2"><ChevronRight size={14} className="text-gray-300" /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* ── Failing routes ─────────────────────────────────────────────── */}
        <Section
          icon={AlertTriangle}
          title="Failing endpoints"
          hint="4xx and 5xx by route"
          empty={data && !data.requests?.failing_routes?.length ? 'No failing requests.' : null}
        >
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              {(data?.requests?.failing_routes || []).map((r, i) => (
                <tr
                  key={i}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => setDrill({
                    title: r.route,
                    params: { hours, kind: 'request', outcome: 'failure' },
                  })}
                >
                  <td className="px-4 py-2 font-mono text-xs text-brand-text break-all">{r.route}</td>
                  <td className="px-4 py-2 text-[11px] text-gray-500 whitespace-nowrap">
                    {Object.entries(r.codes || {}).map(([c, n]) => `${c}×${n}`).join(' · ')}
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums font-semibold text-red-600">{num(r.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        {/* ── Slow routes ────────────────────────────────────────────────── */}
        <Section
          icon={Timer}
          title="Slowest endpoints"
          hint="by p95 — the tail users actually feel, not the average"
          empty={data && !data.requests?.slowest_routes?.length ? 'No request timings yet.' : null}
        >
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-[11px] uppercase tracking-wide text-gray-500">
              <tr>
                <th className="text-left font-medium px-4 py-2">Route</th>
                <th className="text-right font-medium px-4 py-2 w-16">p95</th>
                <th className="text-right font-medium px-4 py-2 w-16">avg</th>
                <th className="text-right font-medium px-4 py-2 w-14">n</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {(data?.requests?.slowest_routes || []).map((r, i) => (
                <tr key={i}>
                  <td className="px-4 py-2 font-mono text-xs text-brand-text break-all">{r.route}</td>
                  <td className="px-4 py-2 text-right tabular-nums font-semibold">{ms(r.p95_ms)}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-gray-500">{ms(r.avg_ms)}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-gray-400">{num(r.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      </div>

      {/* ── Parser reliability ───────────────────────────────────────────── */}
      <Section
        icon={Cpu}
        title="Parser & task reliability"
        hint="per artifact type — a failure ratio here is a parser worth fixing"
        empty={data && !data.tasks?.by_artifact_type?.length ? 'No parse activity in this window.' : null}
      >
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-[11px] uppercase tracking-wide text-gray-500">
            <tr>
              <th className="text-left font-medium px-4 py-2">Artifact type</th>
              <th className="text-right font-medium px-4 py-2 w-20">Runs</th>
              <th className="text-right font-medium px-4 py-2 w-20">Failed</th>
              <th className="text-right font-medium px-4 py-2 w-20">Avg</th>
              <th className="text-right font-medium px-4 py-2 w-24">Events</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {(data?.tasks?.by_artifact_type || []).map((t, i) => {
              const failed = t.outcomes?.failure || 0
              return (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-mono text-xs text-brand-text">{t.artifact_type}</td>
                  <td className="px-4 py-2 text-right tabular-nums">{num(t.count)}</td>
                  <td className={`px-4 py-2 text-right tabular-nums font-semibold ${failureTone(failed, t.count)}`}>
                    {failed ? `${num(failed)} (${Math.round((failed / t.count) * 100)}%)` : '—'}
                  </td>
                  <td className="px-4 py-2 text-right tabular-nums text-gray-500">{ms(t.avg_ms)}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-gray-500">{num(t.events)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </Section>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* ── LLM ────────────────────────────────────────────────────────── */}
        <Section
          icon={Brain}
          title="LLM by purpose"
          hint="which kind of call costs and fails"
          empty={data && !data.llm?.by_purpose?.length ? 'No LLM calls in this window.' : null}
        >
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-[11px] uppercase tracking-wide text-gray-500">
              <tr>
                <th className="text-left font-medium px-4 py-2">Purpose</th>
                <th className="text-right font-medium px-4 py-2 w-16">Calls</th>
                <th className="text-right font-medium px-4 py-2 w-20">Tokens</th>
                <th className="text-right font-medium px-4 py-2 w-16">Avg</th>
                <th className="text-right font-medium px-4 py-2 w-16">Failed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {(data?.llm?.by_purpose || []).map((p, i) => (
                <tr key={i} className="hover:bg-gray-50">
                  <td className="px-4 py-2 font-mono text-xs text-brand-text">{p.purpose}</td>
                  <td className="px-4 py-2 text-right tabular-nums">{num(p.calls)}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-gray-500">{num(p.tokens)}</td>
                  <td className="px-4 py-2 text-right tabular-nums text-gray-500">{ms(p.avg_ms)}</td>
                  <td className={`px-4 py-2 text-right tabular-nums ${failureTone(p.failures, p.calls)}`}>
                    {p.failures || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>

        {/* ── Browser ────────────────────────────────────────────────────── */}
        <Section
          icon={MonitorSmartphone}
          title="Browser errors"
          hint="render crashes and failed calls, as the user experienced them"
          empty={data && !data.ui?.routes?.length ? 'Nothing reported from the frontend.' : null}
        >
          <table className="w-full text-sm">
            <tbody className="divide-y divide-gray-100">
              {(data?.ui?.routes || []).map((r, i) => (
                <tr
                  key={i}
                  className="hover:bg-gray-50 cursor-pointer"
                  onClick={() => setDrill({ title: r.route, params: { hours, kind: 'ui' } })}
                >
                  <td className="px-4 py-2 font-mono text-xs text-brand-text break-all">{r.route}</td>
                  <td className="px-4 py-2 text-right tabular-nums font-semibold text-red-600">{num(r.count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Section>
      </div>

      <EventDrawer query={drill} onClose={() => setDrill(null)} />
    </PageShell>
  )
}
