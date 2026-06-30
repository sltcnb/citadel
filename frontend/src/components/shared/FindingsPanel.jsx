import { useEffect, useMemo, useState } from 'react'
import { ClipboardList, Download, Trash2, Repeat, RefreshCw } from 'lucide-react'
import { api } from '../../api/client'
import PanelShell from './PanelShell'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'informational']
const SEV_CLASS = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high: 'bg-orange-100 text-orange-700 border-orange-200',
  medium: 'bg-amber-100 text-amber-700 border-amber-200',
  low: 'bg-sky-100 text-sky-700 border-sky-200',
  informational: 'bg-gray-100 text-gray-600 border-gray-200',
}

/**
 * FindingsPanel — the single place an analyst sees EVERY analysis output the
 * case has produced, regardless of which feature made it (IOC extraction,
 * anomaly scan, MITRE, kill-chain, modules, the co-pilot, or saved by hand).
 *
 * From here, uniformly: filter by kind/severity, export CSV, re-ingest a
 * selection (or a whole kind) back into the pipeline, or delete.
 */
export default function FindingsPanel({ caseId, onClose, onPivot }) {
  const [data, setData] = useState({ findings: [], total: 0 })
  const [summary, setSummary] = useState({ by_kind: {}, by_severity: {}, total: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [kind, setKind] = useState('')
  const [severity, setSeverity] = useState('')
  const [selected, setSelected] = useState(() => new Set())
  const [busy, setBusy] = useState('')

  function load() {
    setLoading(true)
    Promise.all([
      api.findings.list(caseId, { ...(kind ? { kind } : {}), ...(severity ? { severity } : {}) }),
      api.findings.summary(caseId),
    ])
      .then(([list, sum]) => { setData(list); setSummary(sum) })
      .catch(e => setError(e?.message || 'Failed to load findings'))
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() /* eslint-disable-next-line */ }, [caseId, kind, severity])

  const kinds = useMemo(() => Object.keys(summary.by_kind || {}).sort(), [summary])

  function toggle(id) {
    setSelected(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  async function promote(scope) {
    setBusy('promote')
    try {
      const body = scope === 'selection'
        ? { findingIds: [...selected] }
        : { kind: kind || null }
      const res = await api.findings.promote(caseId, body)
      setBusy(`re-ingesting ${res.count} as job ${res.job_id?.slice(0, 8)}…`)
      setSelected(new Set())
      setTimeout(() => setBusy(''), 4000)
    } catch (e) {
      setBusy(e?.message || 'Re-ingest failed')
      setTimeout(() => setBusy(''), 4000)
    }
  }

  async function remove(scope) {
    if (!confirm(scope === 'selection'
      ? `Delete ${selected.size} selected finding(s)?`
      : `Delete ALL ${kind || ''} findings?`)) return
    setBusy('delete')
    try {
      await api.findings.remove(caseId, scope === 'selection'
        ? { findingIds: [...selected] }
        : { kind: kind || null })
      setSelected(new Set())
      load()
    } catch (e) {
      setError(e?.message || 'Delete failed')
    } finally { setBusy('') }
  }

  const items = data.findings || []
  const countNode = (
    <span>
      <span className="font-semibold text-brand-text">{summary.total || 0}</span> findings
      {kinds.length > 0 && <span className="ml-1">· {kinds.length} kinds</span>}
    </span>
  )

  const actions = (
    <>
      <button onClick={load} className="btn-ghost text-[11px] px-2 py-1 rounded-lg flex items-center gap-1" title="Refresh">
        <RefreshCw size={13} />
      </button>
      <a
        href={api.findings.csvUrl(caseId, kind || null)}
        className="btn-ghost text-[11px] px-2 py-1 rounded-lg flex items-center gap-1"
        title="Export findings as CSV (respects the kind filter)"
      >
        <Download size={13} /> CSV
      </a>
    </>
  )

  return (
    <PanelShell
      icon={ClipboardList}
      title="Findings"
      count={countNode}
      onClose={onClose}
      loading={loading}
      error={error}
      empty={!loading && !error && items.length === 0}
      emptyText="No findings saved yet. Run an analysis panel or a module, then use “Save to findings”."
      actions={actions}
      help={{
        use: 'The one place every analysis output lands — IOCs, anomalies, MITRE, kill chains, module hits, co-pilot notes, or anything you save by hand.',
        when: 'Whenever you want to see, export, report on, or re-ingest what the investigation has established — all the same way.',
        data: ['Findings saved from any panel via “Save to findings”', 'Module runs write their hits here automatically'],
        tip: 'Select rows and “Re-ingest selection” to push them back into the timeline as a fresh job.',
      }}
      width="md:w-[900px]"
    >
      {/* Filters + bulk actions */}
      <div className="flex flex-wrap items-center gap-2">
        <select value={kind} onChange={e => setKind(e.target.value)} className="input text-xs py-1">
          <option value="">All kinds</option>
          {kinds.map(k => <option key={k} value={k}>{k} ({summary.by_kind[k]})</option>)}
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)} className="input text-xs py-1">
          <option value="">All severities</option>
          {SEV_ORDER.filter(s => summary.by_severity?.[s]).map(s => (
            <option key={s} value={s}>{s} ({summary.by_severity[s]})</option>
          ))}
        </select>
        <div className="flex-1" />
        <button
          onClick={() => promote('selection')}
          disabled={!selected.size || !!busy}
          className="btn-ghost text-[11px] px-2 py-1 rounded-lg flex items-center gap-1 disabled:opacity-40"
          title="Re-ingest the selected findings back into the case as a new ingest job"
        >
          <Repeat size={13} /> Re-ingest selection ({selected.size})
        </button>
        <button
          onClick={() => remove('selection')}
          disabled={!selected.size || !!busy}
          className="btn-ghost text-[11px] px-2 py-1 rounded-lg flex items-center gap-1 text-red-600 disabled:opacity-40"
        >
          <Trash2 size={13} /> Delete
        </button>
      </div>
      {busy && <div className="text-[11px] text-gray-500">{busy}</div>}

      {/* List */}
      <div className="space-y-1.5">
        {items.map(f => {
          const id = f.finding_id || f._id
          const sev = f.severity || 'informational'
          return (
            <div
              key={id}
              className="card p-2.5 flex items-start gap-2 text-xs hover:border-brand-accent/40"
            >
              <input
                type="checkbox"
                checked={selected.has(id)}
                onChange={() => toggle(id)}
                className="mt-0.5"
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-1.5 py-0.5 rounded border text-[10px] font-semibold ${SEV_CLASS[sev] || SEV_CLASS.informational}`}>
                    {sev}
                  </span>
                  <span className="px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 text-[10px]">{f.kind}</span>
                  {f.source_feature && (
                    <span className="text-[10px] text-gray-400">via {f.source_feature}</span>
                  )}
                  {f.timestamp && <span className="text-[10px] text-gray-400 ml-auto">{f.timestamp}</span>}
                </div>
                <div className="mt-1 text-brand-text break-words">{f.message}</div>
                {f.description && <div className="mt-0.5 text-gray-500 break-words">{f.description}</div>}
                {Array.isArray(f.evidence) && f.evidence.length > 0 && onPivot && (
                  <button
                    onClick={() => onPivot(`fo_id:(${f.evidence.join(' OR ')})`)}
                    className="mt-1 text-[10px] text-brand-accent hover:underline"
                  >
                    show {f.evidence.length} source event(s)
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </PanelShell>
  )
}
