import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Flag, Loader2, Trash2, Download, Upload, RefreshCw,
} from 'lucide-react'
import { api } from '../../api/client'
import PanelShell from './PanelShell'
import ConfirmDialog from '../ConfirmDialog'
import Toast from '../Toast'
import { useToast } from '../../hooks/useToast'
import { levelBadgeClass } from '../../utils/severity'
import { FINDING_KIND_LABELS } from '../../utils/caseConstants'

/**
 * Findings — the one durable store every analysis surface writes into (IOC
 * extraction, anomaly scan, MITRE, kill-chain, modules, co-pilot…). Until now
 * the store was write-only from the UI; this panel is its management view:
 * list, delete, promote (re-ingest back into the pipeline), CSV export.
 *
 *   GET    /cases/{id}/findings          list (filter by kind / severity)
 *   DELETE /cases/{id}/findings          delete by id list
 *   POST   /cases/{id}/findings/promote  re-ingest a subset as a new job
 *   GET    /cases/{id}/export/csv?q=artifact_type:finding…   CSV download
 */
export default function FindingsPanel({ caseId, onClose }) {
  const [findings, setFindings] = useState([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [kindFilter, setKindFilter] = useState('')
  const [pendingDelete, setPendingDelete] = useState(null)  // finding awaiting confirm
  const [deleting, setDeleting]   = useState(false)
  const [promoting, setPromoting] = useState(null)          // id being promoted
  const [toast, showToast]        = useToast()

  const load = useCallback(() => {
    api.findings.list(caseId, kindFilter ? { kind: kindFilter } : {})
      .then(r => { setFindings(r.findings || []); setTotal(r.total ?? (r.findings || []).length); setError('') })
      .catch(e => setError(e.message || 'Failed to load findings'))
      .finally(() => setLoading(false))
  }, [caseId, kindFilter])
  useEffect(() => { load() }, [load])

  // Kinds actually present, for the filter dropdown (labels when known).
  const kinds = useMemo(
    () => [...new Set(findings.map(f => f.kind).filter(Boolean))].sort(),
    [findings],
  )

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
      empty={!loading && !error && findings.length === 0}
      emptyText="No findings saved yet. Findings are produced by the analysis panels (IOCs, anomalies, MITRE, modules…)."
      width="md:w-[860px]"
      help={{
        use: 'Review every saved finding across all analysis features, delete stale ones, re-ingest a selection back into the pipeline, or export the lot as CSV.',
        when: 'Before writing the report — prune false positives so the deliverable only carries real findings.',
        data: ['Findings saved by the IOC / anomaly / MITRE / kill-chain / module panels'],
        tip: 'Promote writes the finding back through ingest as a fresh job — use it to re-process a finding with new parsers.',
      }}
      actions={
        <div className="flex items-center gap-2">
          <select
            value={kindFilter}
            onChange={e => { setLoading(true); setKindFilter(e.target.value) }}
            className="input text-xs h-8 w-36"
            title="Filter by kind"
          >
            <option value="">All kinds</option>
            {kinds.map(k => (
              <option key={k} value={k}>{FINDING_KIND_LABELS[k] || k}</option>
            ))}
          </select>
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
      <div className="space-y-2">
        {findings.map((f, i) => {
          const id = f.finding_id || f._id || i
          return (
            <div key={id} className="card p-3">
              <div className="flex items-start gap-3">
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`badge ${levelBadgeClass(f.severity)}`}>{f.severity || 'info'}</span>
                    <span className="font-medium text-brand-text text-sm">{f.title || '—'}</span>
                    {f.kind && (
                      <span className="badge bg-gray-100 text-gray-600 text-[10px]">
                        {FINDING_KIND_LABELS[f.kind] || f.kind}
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
                  </div>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
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
