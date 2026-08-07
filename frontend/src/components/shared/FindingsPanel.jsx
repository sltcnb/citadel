import { useCallback, useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import {
  Check, Clock, Flag, Loader2, RotateCcw, Trash2, Download, Upload, RefreshCw, X,
} from 'lucide-react'
import { api } from '../../api/client'
import { listTriage, setTriage } from '../../api/findingsTriage'
import PanelShell from './PanelShell'
import ConfirmDialog from '../ConfirmDialog'
import Toast from '../Toast'
import { useToast } from '../../hooks/useToast'
import { levelBadgeClass } from '../../utils/severity'
import { FINDING_KIND_LABELS } from '../../utils/caseConstants'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational']

const TRIAGE_TABS = [
  { id: '',               label: 'All' },
  { id: 'open',           label: 'Open' },
  { id: 'reviewed',       label: 'Reviewed' },
  { id: 'false_positive', label: 'False positive' },
]

/** Lucene pivot to the finding's evidence events in the timeline. */
export function evidencePivotQuery(f) {
  const quoted = (f.evidence || [])
    .filter(Boolean)
    .map(id => `fo_id:"${String(id).replace(/"/g, '\\"')}"`)
  if (!quoted.length) return ''
  return quoted.length === 1 ? quoted[0] : `(${quoted.join(' OR ')})`
}

/**
 * Findings — the triage hub for the one durable store every analysis surface
 * writes into (IOC extraction, anomaly scan, MITRE, kill-chain, modules,
 * co-pilot…). On top of the original management actions (delete, promote,
 * CSV) this panel is the review queue:
 *
 *   • header counts per triage status (open / reviewed / false_positive),
 *     with a severity breakdown of the active bucket — findings saved before
 *     triage existed count as open;
 *   • filter chips for severity, kind and source module;
 *   • bulk select + Mark reviewed / Mark false positive, per-finding triage
 *     buttons, and a pivot-to-timeline link built from the finding's evidence
 *     fo_ids;
 *   • list capped at 500 (server-side), severity-desc then newest-first.
 *
 *   GET  /cases/{id}/findings/triage?status=&severity=&kind=&source=
 *   POST /cases/{id}/findings/triage        { finding_ids, status }
 *   DELETE /cases/{id}/findings             delete by id list
 *   POST /cases/{id}/findings/promote       re-ingest a subset as a new job
 *   GET  /cases/{id}/export/csv?q=artifact_type:finding…   CSV download
 */
export default function FindingsPanel({ caseId, onClose }) {
  const navigate = useNavigate()
  const [findings, setFindings] = useState([])
  const [total, setTotal]       = useState(0)
  const [cap, setCap]           = useState(500)
  const [counts, setCounts]     = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [statusFilter, setStatusFilter]     = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [kindFilter, setKindFilter]         = useState('')
  const [sourceFilter, setSourceFilter]     = useState('')
  const [selected, setSelected] = useState(() => new Set())
  const [pendingDelete, setPendingDelete] = useState(null)  // finding awaiting confirm
  const [deleting, setDeleting]   = useState(false)
  const [promoting, setPromoting] = useState(null)          // id being promoted
  const [triageBusy, setTriageBusy] = useState(false)
  const [toast, showToast]        = useToast()

  const load = useCallback(() => {
    return listTriage(caseId, {
      status: statusFilter, severity: severityFilter, kind: kindFilter, source: sourceFilter,
    })
      .then(r => {
        setFindings(r.findings || [])
        setTotal(r.total ?? (r.findings || []).length)
        setCap(r.size || 500)
        setCounts(r.counts || null)
        setSelected(new Set())
        setError('')
      })
      .catch(e => setError(e.message || 'Failed to load findings'))
      .finally(() => setLoading(false))
  }, [caseId, statusFilter, severityFilter, kindFilter, sourceFilter])
  useEffect(() => { load() }, [load])

  // Click handler factory — show the spinner immediately, then the effect
  // reloads with the new filter.
  const filterClick = (setter, v) => () => { setLoading(true); setter(v) }

  const byStatus = counts?.by_status || {}
  const statusTotal = TRIAGE_TABS.filter(t => t.id).reduce((n, t) => n + (byStatus[t.id] || 0), 0)
  // Severity breakdown shown under the tabs: the active bucket, or the open
  // queue when "All" is selected (that's the work left to do).
  const breakdownBucket = statusFilter || 'open'
  const breakdown = counts?.by_status_severity?.[breakdownBucket] || {}

  const filtersActive = !!(statusFilter || severityFilter || kindFilter || sourceFilter)

  const allIds = useMemo(() => findings.map(f => f.finding_id || f._id), [findings])
  const allSelected = allIds.length > 0 && allIds.every(id => selected.has(id))

  function toggleOne(id) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }
  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(allIds))
  }

  async function markStatus(ids, status) {
    if (!ids.length) return
    setTriageBusy(true)
    try {
      const r = await setTriage(caseId, ids, status)
      const label = TRIAGE_TABS.find(t => t.id === status)?.label || status
      showToast(`${r.updated} finding${r.updated === 1 ? '' : 's'} marked ${label.toLowerCase()}`)
      setSelected(new Set())
      await load()
    } catch (e) {
      showToast(e.message || 'Triage update failed', 'error')
    } finally {
      setTriageBusy(false)
    }
  }

  async function doDelete() {
    if (!pendingDelete) return
    const id = pendingDelete.finding_id || pendingDelete._id
    setDeleting(true)
    try {
      await api.findings.remove(caseId, { findingIds: [id] })
      showToast('Finding deleted')
      setPendingDelete(null)
      load()
    } catch (e) {
      showToast(e.message || 'Delete failed', 'error')
    } finally {
      setDeleting(false)
    }
  }

  async function promote(f) {
    const id = f.finding_id || f._id
    setPromoting(id)
    try {
      const r = await api.findings.promote(caseId, { findingIds: [id] })
      showToast(`Re-ingest dispatched — ${r.count} finding(s) as ${r.filename}`)
    } catch (e) {
      showToast(e.message || 'Promote failed', 'error')
    } finally {
      setPromoting(null)
    }
  }

  function pivotToTimeline(f) {
    const q = evidencePivotQuery(f)
    if (!q) return
    onClose?.()
    navigate(`/cases/${caseId}`, { state: { pivotQuery: q } })
  }

  const countNode = (
    <span>
      <span className="font-semibold text-brand-text">{total.toLocaleString()}</span> finding{total === 1 ? '' : 's'}
    </span>
  )

  return (
    <PanelShell
      icon={Flag}
      title="Findings"
      count={countNode}
      onClose={onClose}
      loading={loading && findings.length === 0}
      error={error}
      empty={!loading && !error && findings.length === 0 && !filtersActive}
      emptyText="No findings saved yet. Findings are produced by the analysis panels (IOCs, anomalies, MITRE, modules…)."
      width="md:w-[920px]"
      help={{
        use: 'Triage every saved finding: filter by status / severity / kind / source, mark reviewed or false positive (single or bulk), pivot a finding back to its evidence in the timeline, prune stale ones, re-ingest a selection, or export as CSV.',
        when: 'Throughout the investigation — keep the open queue at zero so the report only carries real findings.',
        data: ['Findings saved by the IOC / anomaly / MITRE / kill-chain / module panels'],
        tip: 'The clock icon pivots the timeline to the finding\'s evidence events (fo_id query). Promote writes the finding back through ingest as a fresh job.',
      }}
      actions={
        <div className="flex items-center gap-2">
          <a
            href={api.findings.csvUrl(caseId, kindFilter || null)}
            className="btn-secondary text-xs flex items-center gap-1.5"
            title="Download findings as CSV"
            download
          >
            <Download size={12} /> CSV
          </a>
          <button onClick={() => { setLoading(true); load() }} disabled={loading} className="btn-secondary text-xs flex items-center gap-1.5">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      }
    >
      <div className="space-y-3">
        {/* ── Review-queue header: status tabs + severity breakdown ── */}
        <div className="card p-3 space-y-2">
          <div className="flex items-center gap-1.5 flex-wrap">
            {TRIAGE_TABS.map(t => {
              const n = t.id ? (byStatus[t.id] || 0) : statusTotal
              const active = statusFilter === t.id
              return (
                <button
                  key={t.id || 'all'}
                  onClick={filterClick(setStatusFilter, t.id)}
                  className={`badge text-[11px] cursor-pointer ${
                    active
                      ? 'bg-brand-accent text-white'
                      : t.id === 'false_positive'
                        ? 'bg-gray-100 text-gray-500 hover:bg-gray-200'
                        : t.id === 'reviewed'
                          ? 'bg-green-100 text-green-700 hover:bg-green-200'
                          : 'bg-amber-100 text-amber-700 hover:bg-amber-200'
                  }`}
                  title={t.id ? `Show ${t.label.toLowerCase()} findings` : 'Show all findings'}
                >
                  {t.label} · {n}
                </button>
              )
            })}
          </div>
          <div className="flex items-center gap-1.5 flex-wrap text-[10px] text-gray-400">
            <span className="uppercase tracking-wide">{breakdownBucket === 'false_positive' ? 'false positive' : breakdownBucket} by severity:</span>
            {SEVERITIES.filter(s => breakdown[s]).map(s => (
              <span key={s} className={`badge ${levelBadgeClass(s)}`}>{s} · {breakdown[s]}</span>
            ))}
            {!Object.keys(breakdown).length && <span>none</span>}
          </div>
        </div>

        {/* ── Filter chips: severity, kind, source module ── */}
        <div className="space-y-1.5">
          <div className="flex items-center gap-1 flex-wrap">
            <span className="text-[10px] text-gray-400 uppercase tracking-wide w-14">Severity</span>
            <button
              onClick={filterClick(setSeverityFilter, '')}
              className={`badge text-[10px] cursor-pointer ${!severityFilter ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-500 hover:bg-gray-200'}`}
            >
              All
            </button>
            {SEVERITIES.map(s => (
              <button
                key={s}
                onClick={filterClick(setSeverityFilter, severityFilter === s ? '' : s)}
                className={`badge text-[10px] cursor-pointer ${severityFilter === s ? 'ring-1 ring-brand-accent ' : ''}${levelBadgeClass(s)}`}
              >
                {s}
              </button>
            ))}
          </div>
          {!!Object.keys(counts?.by_kind || {}).length && (
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[10px] text-gray-400 uppercase tracking-wide w-14">Kind</span>
              <button
                onClick={filterClick(setKindFilter, '')}
                className={`badge text-[10px] cursor-pointer ${!kindFilter ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-500 hover:bg-gray-200'}`}
              >
                All
              </button>
              {Object.entries(counts.by_kind).map(([k, n]) => (
                <button
                  key={k}
                  onClick={filterClick(setKindFilter, kindFilter === k ? '' : k)}
                  className={`badge text-[10px] cursor-pointer ${kindFilter === k ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
                >
                  {FINDING_KIND_LABELS[k] || k} · {n}
                </button>
              ))}
            </div>
          )}
          {!!Object.keys(counts?.by_source || {}).length && (
            <div className="flex items-center gap-1 flex-wrap">
              <span className="text-[10px] text-gray-400 uppercase tracking-wide w-14">Source</span>
              <button
                onClick={filterClick(setSourceFilter, '')}
                className={`badge text-[10px] cursor-pointer ${!sourceFilter ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-500 hover:bg-gray-200'}`}
              >
                All
              </button>
              {Object.entries(counts.by_source).map(([s, n]) => (
                <button
                  key={s}
                  onClick={filterClick(setSourceFilter, sourceFilter === s ? '' : s)}
                  className={`badge text-[10px] cursor-pointer ${sourceFilter === s ? 'bg-brand-accent text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'}`}
                >
                  {s} · {n}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Bulk actions ── */}
        <div className="flex items-center gap-2 flex-wrap">
          <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={toggleAll}
              aria-label="Select all findings"
            />
            Select all
          </label>
          {selected.size > 0 && (
            <>
              <span className="text-xs text-brand-text font-medium">{selected.size} selected</span>
              <button
                onClick={() => markStatus([...selected], 'reviewed')}
                disabled={triageBusy}
                className="btn-secondary text-xs flex items-center gap-1"
              >
                {triageBusy ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
                Mark reviewed
              </button>
              <button
                onClick={() => markStatus([...selected], 'false_positive')}
                disabled={triageBusy}
                className="btn-secondary text-xs flex items-center gap-1"
              >
                <X size={12} /> Mark false positive
              </button>
              <button onClick={() => setSelected(new Set())} className="btn-ghost text-xs text-gray-400">
                Clear
              </button>
            </>
          )}
        </div>

        {/* ── The queue ── */}
        {findings.length === 0 && filtersActive && (
          <div className="card p-6 text-center text-xs text-gray-500">No findings match these filters.</div>
        )}
        <div className="space-y-2">
          {findings.map((f, i) => {
            const id = f.finding_id || f._id || i
            const triageStatus = f.triage_status || 'open'
            const pivotQ = evidencePivotQuery(f)
            return (
              <div key={id} className={`card p-3 ${selected.has(id) ? 'ring-1 ring-brand-accent' : ''}`}>
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    className="mt-1 flex-shrink-0"
                    checked={selected.has(id)}
                    onChange={() => toggleOne(id)}
                    aria-label={`Select finding ${f.title || id}`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`badge ${levelBadgeClass(f.severity)}`}>{f.severity || 'info'}</span>
                      <span className="font-medium text-brand-text text-sm">{f.title || '—'}</span>
                      {f.kind && (
                        <span className="badge bg-gray-100 text-gray-600 text-[10px]">
                          {FINDING_KIND_LABELS[f.kind] || f.kind}
                        </span>
                      )}
                      {triageStatus !== 'open' && (
                        <span className={`badge text-[10px] ${triageStatus === 'reviewed' ? 'bg-green-100 text-green-700' : 'bg-gray-200 text-gray-500'}`}>
                          {triageStatus === 'reviewed' ? 'reviewed' : 'false positive'}
                        </span>
                      )}
                    </div>
                    {f.description && (
                      <p className="text-xs text-gray-500 mt-1 break-words">{f.description}</p>
                    )}
                    <div className="flex items-center gap-3 mt-1 text-[10px] text-gray-400 flex-wrap">
                      {f.source_feature && <span>via {f.source_feature}</span>}
                      {f.host?.hostname && <span>host {f.host.hostname}</span>}
                      {f.timestamp && <span>{new Date(f.timestamp).toLocaleString()}</span>}
                      {!!(f.evidence || []).length && <span>{f.evidence.length} evidence</span>}
                    </div>
                  </div>
                  <div className="flex items-center gap-1 flex-shrink-0 flex-wrap justify-end">
                    {triageStatus === 'open' ? (
                      <>
                        <button
                          onClick={() => markStatus([id], 'reviewed')}
                          disabled={triageBusy}
                          className="btn-ghost px-2 py-1.5 text-xs text-green-600 hover:text-green-700 flex items-center gap-1"
                          title="Mark reviewed"
                        >
                          <Check size={13} /> Reviewed
                        </button>
                        <button
                          onClick={() => markStatus([id], 'false_positive')}
                          disabled={triageBusy}
                          className="btn-ghost px-2 py-1.5 text-xs text-gray-500 hover:text-gray-700 flex items-center gap-1"
                          title="Mark false positive"
                        >
                          <X size={13} /> FP
                        </button>
                      </>
                    ) : (
                      <button
                        onClick={() => markStatus([id], 'open')}
                        disabled={triageBusy}
                        className="btn-ghost px-2 py-1.5 text-xs text-amber-600 hover:text-amber-700 flex items-center gap-1"
                        title="Send back to the open queue"
                      >
                        <RotateCcw size={13} /> Reopen
                      </button>
                    )}
                    {pivotQ && (
                      <button
                        onClick={() => pivotToTimeline(f)}
                        className="btn-ghost px-2 py-1.5 text-xs text-gray-400 hover:text-brand-accent"
                        title="Pivot the timeline to this finding's evidence events"
                      >
                        <Clock size={13} />
                      </button>
                    )}
                    <button
                      onClick={() => promote(f)}
                      disabled={promoting !== null}
                      className="btn-ghost px-2 py-1.5 text-xs text-brand-accent hover:text-brand-accenthover flex items-center gap-1"
                      title="Re-ingest this finding back into the pipeline"
                    >
                      {promoting === id ? <Loader2 size={13} className="animate-spin" /> : <Upload size={13} />}
                      Promote
                    </button>
                    <button
                      onClick={() => setPendingDelete(f)}
                      className="btn-ghost px-2 py-1.5 text-xs text-gray-400 hover:text-red-600"
                      title="Delete finding"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {total > findings.length && (
          <div className="text-center text-[11px] text-gray-400">
            Showing {findings.length.toLocaleString()} of {total.toLocaleString()} findings (capped at {cap}) — narrow with the filters above.
          </div>
        )}
      </div>

      {pendingDelete && (
        <ConfirmDialog
          title="Delete this finding?"
          icon={<Trash2 size={14} className="text-red-500" />}
          message={`"${pendingDelete.title || 'Untitled'}" will be removed from the findings store. This cannot be undone.`}
          confirmLabel="Delete"
          confirmClass="btn-danger"
          busy={deleting}
          onConfirm={doDelete}
          onCancel={() => setPendingDelete(null)}
        />
      )}
      <Toast toast={toast} />
    </PanelShell>
  )
}
