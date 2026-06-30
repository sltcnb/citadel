import { useEffect, useState, useMemo } from 'react'
import {
  Activity, Loader2, RefreshCw, ExternalLink, Info,
} from 'lucide-react'
import { api, getToken } from '../../api/client'
import PanelShell from './PanelShell'

// Map a list of anomaly events into the standard Findings store (idempotent).
function persistAnomalyFindings(caseId, list) {
  const items = (list || []).map(a => {
    const z = Math.abs(a?.anomaly?.z_score ?? 0)
    return {
      title: a.message || `Anomaly: event ${a?.anomaly?.event_id} on ${a?.host?.hostname || '—'}`,
      severity: z >= 6 ? 'high' : z >= 4 ? 'medium' : 'low',
      description: `z=${a?.anomaly?.z_score} (μ=${a?.anomaly?.baseline_mean}, σ=${a?.anomaly?.baseline_stddev})`,
      timestamp: a.timestamp,
      host: a.host || {},
      evidence: a.fo_id ? [a.fo_id] : [],
      payload: a.anomaly || {},
      dedup_key: `${a?.host?.hostname}:${a?.anomaly?.event_id}:${a?.anomaly?.day}`,
    }
  })
  if (items.length) {
    api.findings.save(caseId, 'anomaly', items,
      { sourceFeature: 'anomaly_scan', replaceKind: true }).catch(() => {})
  }
}

/**
 * Right-side drawer version of the old Anomaly page.
 *
 *   POST /cases/{id}/anomaly/scan?days=14&threshold=3
 *   GET  /cases/{id}/anomaly
 *
 * Mounted inside CaseTimeline so it lives next to Templates / Report / IOCs /
 * Notes — consistent with the rest of the per-case panels.
 */
export default function AnomalyPanel({ caseId, onClose, onPivot }) {
  const [list, setList]         = useState([])
  const [loading, setLoading]   = useState(true)
  const [scanning, setScanning] = useState(false)
  const [error, setError]       = useState(null)
  const [okMessage, setOk]      = useState(null)
  const [days, setDays]         = useState(14)
  const [threshold, setThr]     = useState(3)

  async function refresh() {
    setLoading(true); setError(null)
    try {
      const r = await api.search.anomalies(caseId)
      setList(r.events || [])
      persistAnomalyFindings(caseId, r.events || [])
    } catch (e) {
      setError(e.message || 'Failed to load anomalies.')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { refresh() }, [caseId])

  async function runScan() {
    setScanning(true); setError(null); setOk(null)
    try {
      const url = `/api/v1/cases/${caseId}/anomaly/scan?days=${days}&threshold=${threshold}`
      const token = getToken()
      const res = await fetch(url, {
        method: 'POST',
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error(`Scan failed: HTTP ${res.status}`)
      const j = await res.json()
      // Backend returns `anomalies` = indexed count and optional `failed`/`error`
      // when ES bulk insert rejected docs. Surface that so a successful scan
      // with all docs rejected doesn't pretend it worked.
      const parts = [`${j.scanned ?? 0} series scanned`, `${j.anomalies ?? 0} indexed`]
      if (j.failed) parts.push(`${j.failed} failed`)
      setOk(`Scan complete — ${parts.join(', ')}.` + (j.error ? ` First error: ${j.error}` : ''))
      await refresh()
    } catch (e) {
      setError(e.message || 'Scan failed.')
    } finally {
      setScanning(false)
    }
  }

  const stats = useMemo(() => {
    const byHost = {}, byEventId = {}
    let maxZ = 0
    for (const a of list) {
      const h = a?.host?.hostname || '—'
      const e = a?.anomaly?.event_id ?? '—'
      byHost[h]    = (byHost[h]    || 0) + 1
      byEventId[e] = (byEventId[e] || 0) + 1
      const z = Math.abs(a?.anomaly?.z_score ?? 0)
      if (z > maxZ) maxZ = z
    }
    return {
      hosts: Object.entries(byHost).sort((a,b) => b[1]-a[1]).slice(0, 6),
      eids:  Object.entries(byEventId).sort((a,b) => b[1]-a[1]).slice(0, 6),
      maxZ:  maxZ.toFixed(2),
    }
  }, [list])

  const actions = (
    <button onClick={refresh} disabled={loading} className="btn-secondary text-xs flex items-center gap-1.5">
      <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
      Refresh
    </button>
  )

  return (
    <PanelShell
      icon={Activity}
      title="Anomaly detection"
      onClose={onClose}
      loading={loading}
      error={error}
      actions={actions}
      help={{
        use: "Flags host × event-id × day buckets whose volume is a statistical outlier (z-score) versus the case's own baseline.",
        when: "To catch volume spikes — mass logons, beaconing, sudden process churn — that you'd miss scrolling a flat timeline.",
        data: ['At least ~3 days of timestamped events per host', 'host.hostname plus an event id (e.g. EVTX event_id)'],
        tip: 'Run the scan first; lower the threshold to surface subtler spikes.',
      }}
      width="md:w-[900px]"
    >
      <p className="text-[11px] text-gray-500">
        Rolling z-score over (host, event_id, day). Scans the last N days, flags days that
        deviate ≥ threshold σ from baseline.
      </p>

      {/* Scan controls */}
      <div className="card p-3">
            <div className="flex items-end gap-3 flex-wrap">
              <div>
                <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Window (days)</label>
                <input
                  type="number" min={3} max={90}
                  value={days} onChange={e => setDays(+e.target.value || 14)}
                  className="input h-8 text-xs w-20"
                />
              </div>
              <div>
                <label className="block text-[10px] uppercase tracking-wide text-gray-500 mb-1">Threshold (σ)</label>
                <input
                  type="number" step="0.5" min={1.5} max={10}
                  value={threshold} onChange={e => setThr(+e.target.value || 3)}
                  className="input h-8 text-xs w-20"
                />
              </div>
              <button
                onClick={runScan}
                disabled={scanning}
                className="btn-primary text-xs flex items-center gap-1.5 h-8"
              >
                {scanning ? <Loader2 size={12} className="animate-spin" /> : <Activity size={12} />}
                Run scan
              </button>
              <div className="ml-auto text-[10px] text-gray-500 flex items-center gap-1">
                <Info size={10} />
                Re-runs replace previous results.
              </div>
            </div>
      </div>

      {okMessage && (
        <div className="card p-3 text-xs text-emerald-700 bg-emerald-50 border-emerald-200">{okMessage}</div>
      )}

      {/* Summary */}
      {list.length > 0 && (
        <div className="grid grid-cols-3 gap-2">
          <SummaryCard label="Anomalies" value={list.length.toLocaleString()} />
          <SummaryCard label="Max |z|"   value={stats.maxZ} />
          <SummaryCard label="Hosts affected" value={stats.hosts.length} />
        </div>
      )}

      {/* List */}
      <div className="card overflow-hidden">
        <div className="px-3 py-2 border-b border-gray-100 flex items-center justify-between">
          <h3 className="text-[11px] font-semibold text-gray-700 uppercase tracking-wide">Anomalous days</h3>
          <span className="text-[10px] text-gray-500">{list.length.toLocaleString()} entries</span>
        </div>

        {list.length === 0 ? (
          <div className="p-6 text-center text-xs text-gray-500">
            No anomalies indexed yet. Click <strong>Run scan</strong> above to generate them.
          </div>
        ) : (
          <table className="w-full text-[11px]">
                <thead className="bg-gray-50 text-gray-600">
                  <tr>
                    <Th>Day</Th>
                    <Th>Host</Th>
                    <Th>Event ID</Th>
                    <Th right>Count</Th>
                    <Th right>μ</Th>
                    <Th right>σ</Th>
                    <Th right>z</Th>
                    <Th />
                  </tr>
                </thead>
                <tbody>
                  {list.map((a) => {
                    const ano = a.anomaly || {}
                    const z = ano.z_score || 0
                    const colour =
                      Math.abs(z) >= 5 ? 'text-red-700 bg-red-50' :
                      Math.abs(z) >= 4 ? 'text-orange-700 bg-orange-50' :
                                         'text-amber-700 bg-amber-50'
                    return (
                      <tr key={a._id} className="border-t border-gray-100 hover:bg-gray-50">
                        <Td className="font-mono">{(ano.day || '').slice(0, 10)}</Td>
                        <Td>{ano.host || '—'}</Td>
                        <Td className="font-mono">{ano.event_id ?? '—'}</Td>
                        <Td right className="tabular-nums">{ano.count?.toLocaleString()}</Td>
                        <Td right className="tabular-nums text-gray-500">{ano.baseline_mean}</Td>
                        <Td right className="tabular-nums text-gray-500">{ano.baseline_stddev}</Td>
                        <Td right>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold tabular-nums ${colour}`}>
                            {z > 0 ? '+' : ''}{z}
                          </span>
                        </Td>
                        <Td right>
                          <button
                            onClick={() => {
                              const q = `host.hostname:"${ano.host}" AND evtx.event_id:${ano.event_id}`
                              onPivot?.(q)
                            }}
                            className="text-[10px] text-brand-accent hover:text-brand-accenthover inline-flex items-center gap-1"
                            title="Pivot to timeline"
                          >
                            <ExternalLink size={10} />
                          </button>
                        </Td>
                      </tr>
                    )
                  })}
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
function Td({ children, right, className = '' }) {
  return <td className={`px-2 py-1.5 ${right ? 'text-right' : ''} ${className}`}>{children}</td>
}
function SummaryCard({ label, value }) {
  return (
    <div className="card p-3">
      <div className="text-[9px] uppercase tracking-wide text-gray-500 font-medium">{label}</div>
      <div className="text-lg font-semibold text-gray-900 mt-0.5 tabular-nums">{value}</div>
    </div>
  )
}
