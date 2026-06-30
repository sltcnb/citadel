import { useEffect, useState, useMemo } from 'react'
import { Target, ArrowRight, Loader2, X } from 'lucide-react'
import { api } from '../../api/client'
import PanelHelp from './PanelHelp'

// Tactic ordering follows the ATT&CK Enterprise kill-chain
const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
]

export default function MitrePanel({ caseId, onClose, onPivot }) {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')

  useEffect(() => {
    setLoading(true)
    api.search.mitreCoverage(caseId)
      .then(d => {
        setData(d)
        // Auto-persist into the single Findings store (idempotent — replaceKind
        // overwrites this case's prior mitre findings, so re-opening never piles
        // up duplicates). No button: the panel is a live explorer, Findings is
        // the durable output.
        const items = (d?.techniques || []).map(t => ({
          title: `${t.id || t.technique || '?'}${t.name ? ' — ' + t.name : ''}`,
          severity: t.count >= 10 ? 'high' : t.count >= 3 ? 'medium' : 'low',
          description: `${t.count} event(s) · tactic: ${t.tactic || 'Unknown'}`,
          techniques: [t.id || t.technique].filter(Boolean),
          payload: { count: t.count, tactic: t.tactic },
          dedup_key: t.id || t.technique || t.name,
        }))
        if (items.length) {
          api.findings.save(caseId, 'mitre', items,
            { sourceFeature: 'mitre_coverage', replaceKind: true }).catch(() => {})
        }
      })
      .catch(e => setError(e?.message || 'Failed to load coverage'))
      .finally(() => setLoading(false))
  }, [caseId])

  const groups = useMemo(() => {
    if (!data) return []
    const byTactic = {}
    for (const t of data.techniques || []) {
      // Plugins emit comma-separated tactic strings ("Persistence, Privilege
      // Escalation") for techniques that map to several. Split so each
      // technique shows up in every tactic column it belongs to.
      const tactics = (t.tactic || 'Unknown')
        .split(',').map(s => s.trim()).filter(Boolean)
      for (const key of (tactics.length ? tactics : ['Unknown'])) {
        byTactic[key] = byTactic[key] || []
        byTactic[key].push(t)
      }
    }
    for (const k of Object.keys(byTactic)) {
      byTactic[k].sort((a, b) => b.count - a.count)
    }
    const ordered = []
    for (const tactic of TACTIC_ORDER) {
      if (byTactic[tactic]) ordered.push({ tactic, techniques: byTactic[tactic] })
    }
    for (const k of Object.keys(byTactic)) {
      if (!TACTIC_ORDER.includes(k)) ordered.push({ tactic: k, techniques: byTactic[k] })
    }
    return ordered
  }, [data])

  const max = useMemo(() => Math.max(1, ...(data?.techniques || []).map(t => t.count)), [data])

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="panel-drawer md:w-[920px]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Target size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">MITRE ATT&amp;CK coverage</span>
            {data && (
              <span className="text-[11px] text-gray-500 ml-2">
                <span className="font-semibold text-brand-text">{(data.techniques || []).length}</span> techniques ·
                <span className="font-semibold text-brand-text mx-1">{data.total_events_with_mitre.toLocaleString()}</span> events
              </span>
            )}
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <PanelHelp title="MITRE ATT&CK coverage"
            use="Shows which ATT&CK tactics and techniques this case's events cover."
            when="To see detection blind spots and to frame findings in ATT&CK terms for the report."
            data={['Events tagged with mitre.id / mitre.tactic — Sigil detections and rule hits produce these']}
            tip="A gap here means no visibility into that tactic, not necessarily that the case is clean." />
          <p className="text-[11px] text-gray-500">
            Techniques with evidence in this case, grouped by tactic along the kill-chain.
            Click any cell to jump to the timeline filtered by that technique.
          </p>

          {loading && (
            <div className="card p-6 flex items-center justify-center gap-2 text-sm text-gray-500">
              <Loader2 size={14} className="animate-spin" /> Computing coverage…
            </div>
          )}
          {error && <div className="card border-red-200 bg-red-50 p-3 text-xs text-red-700">{error}</div>}

          {!loading && !error && groups.length === 0 && (
            <div className="card p-6 text-center text-xs text-gray-500">
              No MITRE-tagged events in this case yet. Run detection modules
              (Hayabusa, Sigma, …) to populate.
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
            {groups.map(g => (
              <div key={g.tactic} className="card p-3">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-semibold text-brand-text">{g.tactic}</h3>
                  <span className="text-[9px] text-gray-500 uppercase tracking-wider">
                    {g.techniques.length} techniques
                  </span>
                </div>
                <div className="space-y-0.5">
                  {g.techniques.map(t => {
                    const pct = Math.max(8, Math.round((t.count / max) * 100))
                    return (
                      <button
                        key={t.technique_id}
                        onClick={() => onPivot?.(`mitre.technique_id:${t.technique_id}`)}
                        className="w-full flex items-center gap-2 text-left text-[11px] hover:bg-brand-accentlight/40 rounded px-1 py-1 transition-colors group"
                        title={`Jump to timeline filtered by ${t.technique_id}`}
                      >
                        <span className="font-mono text-gray-700 w-16 flex-shrink-0">{t.technique_id}</span>
                        <span className="text-gray-700 truncate flex-1">{t.technique_name}</span>
                        <div className="w-20 h-2 bg-gray-100 rounded overflow-hidden flex-shrink-0">
                          <div className="h-full bg-brand-accent" style={{ width: `${pct}%` }} />
                        </div>
                        <span className="font-mono tabular-nums text-gray-700 w-12 text-right">{t.count.toLocaleString()}</span>
                        <ArrowRight size={11} className="text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0" />
                      </button>
                    )
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
