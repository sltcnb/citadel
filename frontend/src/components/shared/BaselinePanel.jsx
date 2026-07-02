import { useEffect, useState } from 'react'
import { Layers, Loader2, ExternalLink, Info } from 'lucide-react'
import { api } from '../../api/client'
import PanelShell from './PanelShell'

/**
 * Right-side drawer: baseline diff / least-frequency-of-occurrence "stacking".
 *
 *   GET /cases/{id}/baseline/fields  → { fields:[{field,label}], hosts:[hostname] }
 *   GET /cases/{id}/baseline/stack   → { field, target_host, max_hosts,
 *                                        values_examined, rare:[{value,
 *                                        target_count, host_count, total_count}] }
 *
 * Surfaces artifact values present on a target host that are RARE across the
 * case (occur on ≤ N hosts) — the rare ones are the suspicious ones. Mounted
 * inside CaseTimeline next to the other per-case panels.
 */
export default function BaselinePanel({ caseId, onClose, onPivot }) {
  const [fields, setFields]     = useState([])
  const [hosts, setHosts]       = useState([])
  const [field, setField]       = useState('')
  const [host, setHost]         = useState('')
  const [maxHosts, setMaxHosts] = useState(2)

  const [meta, setMeta]         = useState(null)   // last stack response (minus rare)
  const [rare, setRare]         = useState(null)   // null = not run yet, [] = ran/empty

  const [loadingFields, setLoadingFields] = useState(true)
  const [stacking, setStacking] = useState(false)
  const [error, setError]       = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoadingFields(true); setError(null)
    api.baseline.fields(caseId)
      .then((r) => {
        if (cancelled) return
        const fs = r.fields || []
        const hs = r.hosts || []
        setFields(fs)
        setHosts(hs)
        if (fs.length) setField(fs[0].field)
        if (hs.length) setHost(hs[0])
      })
      .catch((e) => { if (!cancelled) setError(e.message || 'Failed to load baseline fields.') })
      .finally(() => { if (!cancelled) setLoadingFields(false) })
    return () => { cancelled = true }
  }, [caseId])

  async function runStack() {
    if (!field || !host) return
    setStacking(true); setError(null)
    try {
      const r = await api.baseline.stack(caseId, field, host, maxHosts)
      const { rare: rareRows = [], ...rest } = r
      setMeta(rest)
      setRare(rareRows)
    } catch (e) {
      setError(e.message || 'Stack failed.')
      setRare(null)
    } finally {
      setStacking(false)
    }
  }

  function pivot(value) {
    const f = field.replace('.keyword', '')
    const esc = s => String(s).replace(/"/g, '\\"')
    // Scope to the host being stacked — the whole point is "this rare value ON
    // this suspect host", so the timeline should land there, not case-wide.
    const parts = [`${f}:"${esc(value)}"`]
    if (host) parts.push(`host.hostname:"${esc(host)}"`)
    onPivot?.(parts.join(' AND '))
  }

  return (
    <PanelShell
      icon={Layers}
      title="Baseline / rare artifacts"
      onClose={onClose}
      loading={loadingFields}
      error={error}
      help={{
        use: 'Least-frequency-of-occurrence stacking — pick a field and see the values present on one host that are RARE across the whole case.',
        when: 'On a busy host where the malicious artifact is the uncommon one — an odd service, a lone scheduled task, a one-off process.',
        data: ['Multiple hosts ingested (stacking needs a population to compare against)', 'The chosen field populated on events (e.g. process.name, service.name)'],
        tip: "Rare isn't automatically bad — but rare AND on your suspect host is where to look first.",
      }}
      width="md:w-[900px]"
    >
      <p className="text-[11px] text-gray-500">
        Values present on the selected host that occur on ≤N hosts case-wide — the rare
        ones are worth a look.
      </p>

      {/* Stack controls */}
      <div className="card p-3">
        <div className="flex items-end gap-3 flex-wrap">
          <div>
            <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Field</label>
            <select
              value={field}
              onChange={e => setField(e.target.value)}
              disabled={loadingFields}
              className="input h-8 text-xs w-56"
            >
              {fields.map(f => (
                <option key={f.field} value={f.field}>{f.label || f.field}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Host</label>
            <select
              value={host}
              onChange={e => setHost(e.target.value)}
              disabled={loadingFields}
              className="input h-8 text-xs w-56"
            >
              {hosts.map(h => (
                <option key={h} value={h}>{h}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Max hosts</label>
            <input
              type="number" min={1} max={50}
              value={maxHosts}
              onChange={e => setMaxHosts(Math.min(50, Math.max(1, +e.target.value || 2)))}
              className="input h-8 text-xs w-20"
            />
          </div>
          <button
            onClick={runStack}
            disabled={stacking || loadingFields || !field || !host}
            className="btn-primary text-xs flex items-center gap-1.5 h-8"
          >
            {stacking ? <Loader2 size={12} className="animate-spin" /> : <Layers size={12} />}
            Stack
          </button>
          <div className="ml-auto text-[10px] text-gray-500 flex items-center gap-1">
            <Info size={10} />
            Rare = on ≤{maxHosts} host{maxHosts === 1 ? '' : 's'}.
          </div>
        </div>
      </div>

      {/* Summary */}
      {meta && rare && (
        <div className="grid grid-cols-3 gap-2">
          <SummaryCard label="Rare values" value={(rare.length).toLocaleString()} />
          <SummaryCard label="Values examined" value={(meta.values_examined ?? 0).toLocaleString()} />
          <SummaryCard label="Target host" value={meta.target_host || host || '—'} />
        </div>
      )}

      {/* Results */}
      <div className="card overflow-hidden">
        <div className="px-3 py-2 border-b border-gray-100 flex items-center justify-between">
          <h3 className="text-[11px] font-semibold text-gray-700 uppercase tracking-wide">Rare values</h3>
          {rare && <span className="text-[10px] text-gray-500">{rare.length.toLocaleString()} rows</span>}
        </div>

        {stacking ? (
          <div className="p-6 flex items-center justify-center text-sm text-gray-500 gap-2">
            <Loader2 size={14} className="animate-spin" /> Stacking…
          </div>
        ) : rare === null ? (
          <div className="p-6 text-center text-xs text-gray-500">
            Pick a field and host, then click <strong>Stack</strong>.
          </div>
        ) : rare.length === 0 ? (
          <div className="p-6 text-center text-xs text-gray-500">
            No rare values — nothing on this host is unusual for the field.
          </div>
        ) : (
          <table className="w-full text-[11px]">
            <thead className="bg-gray-50 text-gray-600">
              <tr>
                <Th>Value</Th>
                <Th right>Spread</Th>
                <Th right>On this host</Th>
                <Th right>Total</Th>
                <Th />
              </tr>
            </thead>
            <tbody>
              {rare.map((row, i) => (
                <tr key={`${row.value}-${i}`} className="border-t border-gray-100 hover:bg-brand-accentlight/40 cursor-pointer"
                  onClick={() => pivot(row.value)}
                  title="Pivot to the timeline for this value on this host">
                  <Td className="font-mono max-w-[420px] truncate" title={String(row.value)}>
                    {String(row.value)}
                  </Td>
                  <Td right>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold tabular-nums text-amber-700 bg-amber-50">
                      on {row.host_count} host{row.host_count === 1 ? '' : 's'}
                    </span>
                  </Td>
                  <Td right className="tabular-nums text-gray-700">
                    ×{(row.target_count ?? 0).toLocaleString()}
                  </Td>
                  <Td right className="tabular-nums text-gray-500">
                    {(row.total_count ?? 0).toLocaleString()}
                  </Td>
                  <Td right>
                    <button
                      onClick={e => { e.stopPropagation(); pivot(row.value) }}
                      className="text-[10px] text-brand-accent hover:text-brand-accenthover inline-flex items-center gap-1"
                      title="Pivot to timeline"
                    >
                      <ExternalLink size={10} />
                    </button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </PanelShell>
  )
}

function Th({ children, right }) {
  return <th className={`px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wide ${right ? 'text-right' : 'text-left'}`}>{children}</th>
}
function Td({ children, right, className = '', title }) {
  return <td title={title} className={`px-2 py-1.5 ${right ? 'text-right' : ''} ${className}`}>{children}</td>
}
function SummaryCard({ label, value }) {
  return (
    <div className="card p-3">
      <div className="text-[9px] uppercase tracking-wide text-gray-500 font-medium">{label}</div>
      <div className="text-lg font-semibold text-gray-900 mt-0.5 tabular-nums truncate">{value}</div>
    </div>
  )
}
