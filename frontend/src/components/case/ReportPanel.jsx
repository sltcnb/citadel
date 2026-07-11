import { useState, useEffect, useRef } from 'react'
import {
  X, Loader2, Trash2, FileDown, FileText, Flag, Target, Crosshair, Sparkles,
  Cpu, ChevronDown, ChevronRight, ClipboardCheck, Printer, FileBarChart,
  Download, ExternalLink, XCircle,
} from 'lucide-react'
import { api, getToken } from '../../api/client'
import { ResizableDrawer } from '../shared/resizableDrawer'
import PanelHelp from '../shared/PanelHelp'
import { useLicense } from '../../contexts/LicenseContext'
import { MODULE_NAMES, FINDING_KIND_LABELS } from '../../utils/caseConstants'

// ─────────────────────────────────────────────────────────────────────────────
// ReportPanel — single entry-point for everything report-shaped on a case.
//   - AI Investigation Report (when ai_assist feature is enabled): generates a
//     narrative report from flagged events + AI analysis. Persists in Redis
//     under case:{id}:ai:report; survives panel close.
//   - Formal Markdown / HTML artifact: server-rendered from notes + flagged +
//     pinned + IOCs + module runs. Always available regardless of tier.
//
// Replaces the old "Final Report" tab in CaseNotes so the report flow has
// exactly one home.
// ─────────────────────────────────────────────────────────────────────────────
export default function ReportPanel({ caseId, onClose }) {
  const license = useLicense()
  const aiEnabled = !!license?.features?.ai_assist

  // ── Flat report download/preview (md + html) ────────────────────────────────
  const [busy, setBusy]   = useState(null)
  const [error, setError] = useState(null)

  // ── AI investigation summary ────────────────────────────────────────────────
  const [aiReport, setAiReport] = useState(null)
  const [aiLoading, setAiLoading] = useState(true)
  const [aiGenerating, setAiGen]  = useState(false)
  const [aiError, setAiError]     = useState(null)
  // Report generation can run for several minutes. Track elapsed time and keep
  // an AbortController so the analyst can cancel a request that's taking too long.
  const [elapsed, setElapsed]     = useState(0)
  const abortRef = useRef(null)
  const [reportHistory, setReportHistory] = useState([])
  const [showHistory, setShowHistory] = useState(false)

  function refreshHistory() {
    api.cases.aiReportHistory(caseId)
      .then(d => setReportHistory(d.reports || []))
      .catch(() => {})
  }

  // ── Module-run selection — feeds the AI report's prompt. Empty = include
  //    every completed run. Lives here (not in CaseNotes) because choosing
  //    what evidence the AI sees is a Report-time decision.
  const [moduleRuns, setModuleRuns] = useState([])
  const [selectedRunIds, setSelectedRunIds] = useState(new Set())
  const [showRunPicker, setShowRunPicker] = useState(false)

  // ── Report composition — live counts of every source the report pulls from,
  //    so the analyst SEES what the deliverable will contain before generating.
  const [contents, setContents] = useState(null)
  const [contentsLoading, setContentsLoading] = useState(true)

  // Report language is a generation-time choice (not an investigation-time one):
  // the agent always reasons in English, and we localise the prose only when the
  // report is produced — so the same case can be re-rendered in any language.
  const REPORT_LANGS = [
    ['en', 'English'], ['fr', 'Français'], ['es', 'Español'], ['de', 'Deutsch'],
    ['it', 'Italiano'], ['pt', 'Português'], ['nl', 'Nederlands'], ['ja', '日本語'], ['zh', '中文'],
  ]
  const [reportLang, setReportLang] = useState(() => {
    const saved = localStorage.getItem('fo_report_lang')
    if (saved && REPORT_LANGS.some(([c]) => c === saved)) return saved
    const auto = (navigator.language || 'en').slice(0, 2).toLowerCase()
    return REPORT_LANGS.some(([c]) => c === auto) ? auto : 'en'
  })
  useEffect(() => { localStorage.setItem('fo_report_lang', reportLang) }, [reportLang])

  useEffect(() => {
    api.cases.aiResults(caseId)
      .then(d => { if (d.report) setAiReport(d.report) })
      .catch(() => {})
      .finally(() => setAiLoading(false))

    refreshHistory()

    api.modules.listRuns(caseId)
      .then(r => {
        const completed = (r.runs || []).filter(x => x.status === 'COMPLETED')
        setModuleRuns(completed)
        // Pre-select every run that actually produced detections, so the report
        // includes all module output by default (analyst can untick to trim).
        setSelectedRunIds(new Set(completed.filter(x => (x.total_hits || 0) > 0).map(x => x.run_id)))
      })
      .catch(() => {})
  }, [caseId])

  // Fetch the live composition (best-effort per source; a failed source shows "—").
  useEffect(() => {
    let stillMounted = true
    const asNumber = (value) => (typeof value === 'number' && !isNaN(value) ? value : null)
    Promise.all([
      api.search.search(caseId, { q: 'is_flagged:true', size: 0 }).then(res => asNumber(res.total)).catch(() => null),
      api.search.pinned(caseId).then(res => asNumber(res.total) ?? (Array.isArray(res) ? res : res.events || res.pinned || []).length).catch(() => null),
      api.search.iocs(caseId).then(res => {
        if (Array.isArray(res)) return res.length
        if (Array.isArray(res.iocs)) return res.iocs.length
        if (typeof res.total === 'number') return res.total
        return Object.values(res || {}).reduce((sum, value) => sum + (Array.isArray(value) ? value.length : 0), 0)
      }).catch(() => null),
      api.findings.summary(caseId).then(res => ({
        total: asNumber(res.total) ?? asNumber(res.count) ??
          (res.by_kind ? Object.values(res.by_kind).reduce((sum, count) => sum + (count || 0), 0) : null),
        byKind: res.by_kind || {},
      })).catch(() => ({ total: null, byKind: {} })),
      api.notes.get(caseId).then(res => (res.body || '').trim().length > 0).catch(() => null),
      api.cases.aiResults(caseId).then(res => (res.investigations || res.runs || []).length).catch(() => null),
    ]).then(([flagged, pinned, iocs, findingsSummary, notesFilled, investigations]) => {
      if (!stillMounted) return
      setContents({
        flagged, pinned, iocs, notesFilled, investigations,
        findings: findingsSummary.total,
        findingsByKind: findingsSummary.byKind,
      })
      setContentsLoading(false)
    })
    return () => { stillMounted = false }
  }, [caseId])

  function toggleRun(id) {
    setSelectedRunIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  // Tick an elapsed-time counter while a report is generating, so the analyst
  // sees progress instead of a bare, silent spinner over a multi-minute request.
  useEffect(() => {
    if (!aiGenerating) return
    setElapsed(0)
    const started = Date.now()
    const t = setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000)
    return () => clearInterval(t)
  }, [aiGenerating])

  // Abort any in-flight request when the panel unmounts.
  useEffect(() => () => abortRef.current?.abort(), [])

  function cancelAi() {
    abortRef.current?.abort()
  }

  async function generateAi() {
    setAiGen(true); setAiError(null)
    const controller = new AbortController()
    abortRef.current = controller
    try {
      const runIds = selectedRunIds.size > 0 ? [...selectedRunIds] : undefined
      const res = await api.cases.aiReport(caseId, runIds, reportLang, controller.signal)
      setAiReport(res)
      refreshHistory()
    } catch (e) {
      if (e?.name === 'AbortError') setAiError('Report generation cancelled.')
      else setAiError(e.message || 'Report generation failed.')
    } finally {
      abortRef.current = null
      setAiGen(false)
    }
  }

  const fmtElapsed = (s) => {
    const m = Math.floor(s / 60)
    const sec = s % 60
    return m > 0 ? `${m}m ${sec}s` : `${sec}s`
  }

  // Human-readable "based on" line from a report's manifest.
  function manifestSummary(m) {
    if (!m) return ''
    const bits = []
    if (m.flagged_count != null) bits.push(`${m.flagged_count} flagged`)
    if (m.module_detections) bits.push(`${m.module_detections} module detection${m.module_detections > 1 ? 's' : ''}`)
    if (m.ioc_lines) bits.push(`${m.ioc_lines} IOC line${m.ioc_lines > 1 ? 's' : ''}`)
    if (m.investigations) bits.push('investigations')
    if (m.notes) bits.push('notes')
    if (m.run_ids?.length) bits.push(`${m.run_ids.length} pinned run${m.run_ids.length > 1 ? 's' : ''}`)
    return bits.join(' · ')
  }

  function printAiReport() {
    if (!aiReport?.content) return
    const win = window.open('', '_blank')
    if (!win) return
    const esc = s => String(s).replace(/[<>&]/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' }[c]))
    win.document.write(`<!DOCTYPE html><html><head><meta charset="utf-8">
<title>AI Investigation Report — Case ${esc(caseId)}</title>
<style>body{font-family:system-ui,sans-serif;font-size:13px;padding:40px;line-height:1.7;color:#111;max-width:900px;margin:0 auto;}
h1,h2,h3{font-weight:600;margin-top:1.5em;}h1{font-size:1.4em;}h2{font-size:1.1em;border-bottom:1px solid #eee;padding-bottom:4px;}
h3{font-size:1em;}pre,code{background:#f5f5f5;padding:2px 6px;border-radius:3px;font-family:monospace;}
ul,ol{padding-left:1.5em;}li{margin:2px 0;}
@media print{body{padding:0;}}</style>
</head><body><pre style="white-space:pre-wrap;font-family:system-ui">${aiReport.content.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre></body></html>`)
    win.document.close()
    win.focus()
    setTimeout(() => { win.print() }, 250)
  }

  // Export the AI LLM narrative report itself (not the Scribe bundle) as the
  // final deliverable in any format. base='ai/report' vs 'report'.
  async function downloadDoc(base, ext, lang) {
    const key = `${base}:${ext}`
    setBusy(key); setError(null)
    try {
      const token = getToken()
      const langQ = lang ? `?language=${lang}` : ''
      const res = await fetch(`/api/v1/cases/${caseId}/${base}.${ext}${langQ}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) {
        let detail = `HTTP ${res.status}`
        try { const j = await res.json(); if (j.detail) detail = j.detail } catch { /* not json */ }
        throw new Error(detail)
      }
      const blob = await res.blob()
      const objectUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objectUrl
      a.download = `case-${caseId}-${base.includes('ai') ? 'ai-' : ''}report.${ext}`
      document.body.appendChild(a); a.click(); a.remove()
      setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000)
    } catch (e) {
      setAiError(e.message || 'Export failed.')
    } finally {
      setBusy(null)
    }
  }

  // ext: 'md' | 'html' | 'pdf' | 'docx' — all share the same server-rendered
  // report data, just a different renderer.
  async function download(ext) {
    setBusy(ext); setError(null)
    try {
      const token = getToken()
      const url = `/api/v1/cases/${caseId}/report.${ext}?language=${reportLang}`
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      if (!res.ok) {
        let detail = `HTTP ${res.status}`
        try { const j = await res.json(); if (j.detail) detail = j.detail } catch { /* not json */ }
        throw new Error(detail)
      }
      const blob = await res.blob()
      const objectUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objectUrl
      a.download = `case-${caseId}-report.${ext}`
      document.body.appendChild(a); a.click(); a.remove()
      setTimeout(() => URL.revokeObjectURL(objectUrl), 10_000)
    } catch (e) {
      setError(e.message || 'Report generation failed.')
    } finally {
      setBusy(null)
    }
  }

  async function openHtml() {
    setBusy('html-view'); setError(null)
    try {
      const token = getToken()
      const res = await fetch(`/api/v1/cases/${caseId}/report.html`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const objectUrl = URL.createObjectURL(blob)
      window.open(objectUrl, '_blank', 'noopener')
      setTimeout(() => URL.revokeObjectURL(objectUrl), 60_000)
    } catch (e) {
      setError(e.message || 'Report preview failed.')
    } finally {
      setBusy(null)
    }
  }

  return (
    <ResizableDrawer slug="report" defaultWidth={640} onClose={onClose}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <FileDown size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Report</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <PanelHelp
            title="Report"
            use="Turns everything you've gathered in the case — flagged events, pinned items, module detections, IOCs, AI investigations and notes — into a deliverable."
            when="When wrapping up. Two outputs: an AI narrative report (needs a licence) and a no-AI case bundle. Both read the same live case state."
            tip="The contents card shows exactly what will be included. Enrich the report by flagging/pinning more in the timeline."
          />

          {error && (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200">{error}</div>
          )}

          {/* ── What this report contains — live composition ──────────────── */}
          {(() => {
            const moduleHits = moduleRuns.reduce((s, r) => s + (r.total_hits || 0), 0)
            const includedRuns = selectedRunIds.size > 0 ? selectedRunIds.size : moduleRuns.length
            const Count = ({ v, zero = 'none' }) => (
              v == null
                ? <span className="text-[10px] text-gray-400 font-mono">—</span>
                : v > 0
                  ? <span className="text-[11px] font-semibold text-brand-text tabular-nums">{v.toLocaleString()}</span>
                  : <span className="text-[10px] text-gray-400">{zero}</span>
            )
            const rows = [
              { key: 'flagged', Icon: Flag, label: 'Flagged events', desc: 'Events you marked relevant in the timeline', node: <Count v={contents?.flagged} /> },
              { key: 'pinned', Icon: Target, label: 'Pinned events', desc: 'Events pinned as key evidence', node: <Count v={contents?.pinned} /> },
              { key: 'iocs', Icon: Crosshair, label: 'IOCs', desc: 'Observed indicators + watchlist matches', node: <Count v={contents?.iocs} /> },
              { key: 'investigations', Icon: Sparkles, label: 'AI investigations', desc: 'Autonomous Pilot runs on this case', node: <Count v={contents?.investigations} /> },
              { key: 'notes', Icon: FileText, label: 'Case notes', desc: 'Your written investigation notes', node: (
                contents?.notesFilled == null ? <span className="text-[10px] text-gray-400 font-mono">—</span>
                : contents.notesFilled ? <span className="text-[10px] text-green-600 font-medium">included</span>
                : <span className="text-[10px] text-gray-400">empty</span>
              ) },
            ]
            return (
              <div className="card p-4">
                <div className="flex items-center gap-2 mb-1">
                  <ClipboardCheck size={14} className="text-brand-accent" />
                  <span className="text-sm font-semibold text-gray-900">What this report contains</span>
                </div>
                <p className="text-[11px] text-gray-500 mb-3">
                  Assembled live from the case's current state — flagged &amp; pinned events, IOCs, notes,
                  AI investigations, module detections AND every analysis surface's findings (anomalies,
                  MITRE, baseline, kill-chain, entity graph, Co-Pilot). Everything below is included
                  automatically; flag or pin more in the timeline to enrich it.
                </p>
                {contentsLoading ? (
                  <div className="flex items-center gap-2 text-xs text-gray-500 py-3">
                    <Loader2 size={12} className="animate-spin" /> Reading case state…
                  </div>
                ) : (
                  <div className="border border-gray-100 rounded-lg divide-y divide-gray-100">
                    {rows.map(({ key, Icon, label, desc, node }) => (
                      <div key={key} className="flex items-center gap-3 px-3 py-2">
                        <Icon size={14} className="text-gray-400 flex-shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-medium text-gray-800">{label}</div>
                          <div className="text-[10px] text-gray-500 truncate">{desc}</div>
                        </div>
                        {node}
                      </div>
                    ))}

                    {/* Module detections — expandable to pick which runs feed the report */}
                    <div className="px-3 py-2">
                      <div className="flex items-center gap-3">
                        <Cpu size={14} className="text-gray-400 flex-shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-medium text-gray-800">Module detections</div>
                          <div className="text-[10px] text-gray-500 truncate">
                            {moduleRuns.length === 0
                              ? 'No completed module runs yet — launch modules to add detections'
                              : selectedRunIds.size > 0
                                ? `${includedRuns} of ${moduleRuns.length} run${moduleRuns.length > 1 ? 's' : ''} pinned`
                                : `all ${moduleRuns.length} completed run${moduleRuns.length > 1 ? 's' : ''} with hits`}
                          </div>
                        </div>
                        {moduleHits > 0
                          ? <span className="text-[11px] font-semibold text-brand-text tabular-nums">{moduleHits.toLocaleString()}</span>
                          : <span className="text-[10px] text-gray-400">none</span>}
                        {moduleRuns.length > 0 && (
                          <button
                            onClick={() => setShowRunPicker(v => !v)}
                            className="text-[10px] text-brand-accent hover:underline flex items-center gap-0.5 flex-shrink-0"
                            title="Choose which module runs the report includes"
                          >
                            Choose <ChevronDown size={10} className={`transition-transform ${showRunPicker ? 'rotate-180' : ''}`} />
                          </button>
                        )}
                      </div>

                      {showRunPicker && moduleRuns.length > 0 && (
                        <div className="mt-2">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[10px] text-gray-500">
                              {selectedRunIds.size === 0
                                ? 'None ticked → every completed run with hits is included.'
                                : `${selectedRunIds.size} pinned (overrides auto-include).`}
                            </span>
                            {selectedRunIds.size > 0 && (
                              <button onClick={() => setSelectedRunIds(new Set())} className="text-[10px] text-gray-500 hover:text-gray-700">Clear</button>
                            )}
                          </div>
                          <div className="max-h-40 overflow-y-auto border border-gray-100 rounded">
                            {moduleRuns.map(run => {
                              const selected = selectedRunIds.has(run.run_id)
                              const ts = run.completed_at || run.started_at
                              return (
                                <label key={run.run_id}
                                  className={`flex items-center gap-2 px-2 py-1.5 cursor-pointer border-b border-gray-100 last:border-b-0 ${selected ? 'bg-brand-accent/5' : 'hover:bg-gray-50'}`}>
                                  <input type="checkbox" checked={selected} onChange={() => toggleRun(run.run_id)}
                                    className="rounded border-gray-300 accent-brand-accent flex-shrink-0" />
                                  <div className="min-w-0 flex-1">
                                    <div className="text-[11px] font-medium text-brand-text truncate">{MODULE_NAMES[run.module_id] || run.module_id}</div>
                                    {ts && <div className="text-[10px] text-gray-500">{new Date(ts).toLocaleString()}</div>}
                                  </div>
                                  {run.total_hits > 0
                                    ? <span className="text-[10px] font-semibold text-orange-600 flex-shrink-0">{run.total_hits.toLocaleString()} hits</span>
                                    : <span className="text-[10px] text-green-600 flex-shrink-0">clean</span>}
                                </label>
                              )
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Findings by feature — every surface (anomaly, MITRE, IOC,
                    kill-chain, entity, process-tree, module, Co-Pilot…) persists
                    to the findings store and ALL of it feeds the report. */}
                {!contentsLoading && contents?.findingsByKind && Object.keys(contents.findingsByKind).length > 0 && (
                  <div className="mt-2">
                    <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1">
                      Findings by feature — all included
                    </p>
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(contents.findingsByKind)
                        .filter(([, n]) => n > 0)
                        .sort((a, b) => b[1] - a[1])
                        .map(([kind, n]) => (
                          <span key={kind} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border border-gray-200 bg-gray-50 text-[10px] text-gray-600">
                            {FINDING_KIND_LABELS[kind] || kind}
                            <span className="font-semibold text-brand-text tabular-nums">{n.toLocaleString()}</span>
                          </span>
                        ))}
                    </div>
                  </div>
                )}
              </div>
            )
          })()}

          {/* Section 2 — turn the contents above into a deliverable */}
          <div className="flex items-center gap-2 pt-1">
            <FileDown size={12} className="text-gray-400" />
            <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Generate a deliverable</span>
            <span className="flex-1 border-t border-gray-100" />
          </div>
          <p className="text-[11px] text-gray-500 -mt-1">
            Two options, both built from the contents above: an <strong>AI narrative report</strong>{aiEnabled ? '' : ' (licence required)'} and a
            no-AI <strong>case bundle</strong>. Pick a language, then generate or download.
          </p>

          {/* ── AI Investigation Report ───────────────────────────────── */}
          <div className="card p-4">
            <div className="flex items-center justify-between gap-3 mb-3">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-purple-50">
                  <Sparkles size={14} className="text-purple-600" />
                </div>
                <div>
                  <div className="text-sm font-semibold text-gray-900">AI investigation report (final)</div>
                  <div className="text-[10px] text-gray-500">
                    {aiEnabled
                      ? 'Complete deliverable from flagged events + module detections + IOCs. Export below.'
                      : 'Available on Pro / Enterprise / MSSP tiers'}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1 flex-shrink-0">
                {aiReport && (
                  <>
                    <button onClick={printAiReport} className="btn-ghost text-xs flex items-center gap-1.5" title="Print / save as PDF">
                      <Printer size={11} />
                    </button>
                    <button
                      onClick={async () => {
                        if (!confirm('Delete the AI Investigation Report? The agent runs + your analysis stay intact.')) return
                        try {
                          await api.cases.aiDeleteReport(caseId)
                          setAiReport(null)
                        } catch (e) {
                          setAiError(e.message || 'Failed to delete report')
                        }
                      }}
                      className="btn-ghost text-xs flex items-center gap-1.5 text-red-500 hover:text-red-700"
                      title="Delete the generated report"
                    >
                      <Trash2 size={11} />
                    </button>
                  </>
                )}
                {aiEnabled && (
                  <select
                    value={reportLang}
                    onChange={e => setReportLang(e.target.value)}
                    disabled={aiGenerating}
                    title="Report language — applied when the report is generated"
                    className="text-[11px] border border-gray-200 rounded-md px-1.5 py-1 bg-white text-gray-600 focus:outline-none focus:ring-1 focus:ring-brand-accent"
                  >
                    {REPORT_LANGS.map(([code, label]) => (
                      <option key={code} value={code}>{label}</option>
                    ))}
                  </select>
                )}
                {aiEnabled && (
                  aiGenerating ? (
                    <button
                      onClick={cancelAi}
                      className="btn-ghost text-xs flex items-center gap-1.5 text-red-600 hover:text-red-700"
                      title="Cancel report generation"
                    >
                      <XCircle size={11} /> Cancel
                    </button>
                  ) : (
                    <button
                      onClick={generateAi}
                      className="btn-primary text-xs flex items-center gap-1.5"
                    >
                      <FileBarChart size={11} /> {aiReport ? 'Regenerate' : 'Generate'}
                    </button>
                  )
                )}
              </div>
            </div>

            {aiError && (
              <div className="text-[11px] text-red-700 bg-red-50 border border-red-200 rounded px-2 py-1 mb-2">
                {aiError}
              </div>
            )}

            {aiGenerating ? (
              <div className="flex flex-col items-center justify-center py-6 gap-2 text-center" role="status" aria-live="polite">
                <Loader2 size={20} className="animate-spin text-purple-600" />
                <div className="text-xs font-medium text-gray-700">Generating report…</div>
                <div className="text-[11px] text-gray-500 tabular-nums">
                  Elapsed {fmtElapsed(elapsed)} · this can take a few minutes
                </div>
                <button
                  onClick={cancelAi}
                  className="mt-1 btn-ghost text-[11px] flex items-center gap-1 text-red-600 hover:text-red-700"
                >
                  <XCircle size={12} /> Cancel
                </button>
              </div>
            ) : aiLoading ? (
              <div className="flex items-center justify-center py-6 text-xs text-gray-500 gap-2">
                <Loader2 size={12} className="animate-spin" /> Loading…
              </div>
            ) : aiReport ? (
              <>
                <div className="text-[10px] text-gray-500 mb-1">
                  Generated {new Date(aiReport.generated_at).toLocaleString()}
                  {aiReport.model_used && <> · {aiReport.model_used}</>}
                  {aiReport.language && <> · {aiReport.language.toUpperCase()}</>}
                  {aiReport.source && <> · {aiReport.source}</>}
                </div>
                {manifestSummary(aiReport.manifest) && (
                  <div className="text-[10px] text-gray-600 mb-2 bg-gray-50 border border-gray-200 rounded px-2 py-1">
                    <span className="font-semibold text-gray-500">Based on:</span> {manifestSummary(aiReport.manifest)}
                  </div>
                )}
                <pre className="text-[11px] text-gray-700 leading-relaxed bg-gray-50 border border-gray-200 rounded-lg p-3 whitespace-pre-wrap font-mono overflow-auto max-h-[50vh]">
                  {aiReport.content}
                </pre>
                {/* Export the LLM report as the final deliverable */}
                <div className="mt-2">
                  <div className="text-[10px] text-gray-400 mb-1">Export this report as</div>
                  <div className="grid grid-cols-4 gap-1.5">
                    {[
                      ['pdf', 'PDF', 'Court-ready, native'],
                      ['docx', 'Word', 'Editable .docx'],
                      ['html', 'HTML', 'Graphical'],
                      ['md', 'Markdown', 'Diff-friendly'],
                    ].map(([ext, label, hint]) => (
                      <button
                        key={ext}
                        onClick={() => downloadDoc('ai/report', ext)}
                        disabled={busy === `ai/report:${ext}`}
                        title={hint}
                        className="border border-gray-200 rounded-lg p-2 flex flex-col items-center gap-1 hover:border-purple-400 hover:bg-purple-50 transition-colors disabled:opacity-50"
                      >
                        {busy === `ai/report:${ext}`
                          ? <Loader2 size={13} className="animate-spin text-purple-600" />
                          : <Download size={13} className="text-purple-600" />}
                        <span className="text-[10px] font-semibold text-gray-900">{label}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            ) : aiEnabled ? (
              <div className="text-[11px] text-gray-500 italic text-center py-3">
                No AI summary yet. Flag relevant events first, then click <strong>Generate</strong>.
              </div>
            ) : (
              <div className="text-[11px] text-gray-500 italic text-center py-3">
                AI summaries require an AI-enabled licence tier. The downloadable
                Markdown / HTML artifact below still works on every tier.
              </div>
            )}

            {/* Report history — prior generations, newest first */}
            {reportHistory.length > 1 && (
              <div className="mt-3 border-t border-gray-100 pt-2">
                <button
                  onClick={() => setShowHistory(v => !v)}
                  className="text-[10px] text-gray-500 hover:text-gray-700 flex items-center gap-1"
                >
                  {showHistory ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                  Previous reports ({reportHistory.length})
                </button>
                {showHistory && (
                  <div className="mt-1.5 space-y-1">
                    {reportHistory.map((h, i) => (
                      <div
                        key={i}
                        className={`flex items-center gap-2 text-[10px] rounded px-2 py-1 ${
                          aiReport && h.generated_at === aiReport.generated_at
                            ? 'bg-brand-accent/5 border border-brand-accent/30'
                            : 'bg-gray-50 border border-gray-100'
                        }`}
                      >
                        <button
                          onClick={() => setAiReport(h)}
                          className="flex-1 text-left min-w-0 hover:text-brand-accent"
                          title="Open this report"
                        >
                          <span className="text-gray-700">{new Date(h.generated_at).toLocaleString()}</span>
                          {h.language && <span className="text-gray-400"> · {h.language.toUpperCase()}</span>}
                          {h.source && <span className="text-gray-400"> · {h.source}</span>}
                          {manifestSummary(h.manifest) && (
                            <span className="block text-gray-400 truncate">{manifestSummary(h.manifest)}</span>
                          )}
                        </button>
                        <button
                          onClick={async () => {
                            try { await api.cases.aiDeleteReportHistory(caseId, i); refreshHistory() }
                            catch (e) { setAiError(e.message || 'Failed to delete') }
                          }}
                          className="text-gray-400 hover:text-red-600 flex-shrink-0"
                          title="Delete this history entry"
                        >
                          <Trash2 size={10} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ── Formal artifact downloads ─────────────────────────────── */}
          <div className="card p-4">
            <div className="flex items-center gap-2 mb-3">
              <div className="p-1.5 rounded-lg bg-indigo-50">
                <FileText size={14} className="text-indigo-600" />
              </div>
              <div>
                <div className="text-sm font-semibold text-gray-900">Case bundle (no AI)</div>
                <div className="text-[10px] text-gray-500">
                  Manifest + flagged + pinned + module detections + saved searches +
                  correlations + IOCs + notes. Server-rendered, works without AI. Language: {reportLang.toUpperCase()}.
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between mb-2">
              <button
                onClick={openHtml}
                disabled={busy === 'html-view'}
                className="btn-secondary text-xs flex items-center gap-1 justify-center"
                title="Open the HTML report in a new tab"
              >
                {busy === 'html-view' ? <Loader2 size={11} className="animate-spin" /> : <ExternalLink size={11} />}
                Preview
              </button>
              <span className="text-[10px] text-gray-400">Download as</span>
            </div>

            <div className="grid grid-cols-4 gap-2">
              {[
                ['pdf', 'PDF', 'Court-ready, native'],
                ['docx', 'Word', 'Editable .docx'],
                ['html', 'HTML', 'Graphical'],
                ['md', 'Markdown', 'Diff-friendly'],
              ].map(([ext, label, hint]) => (
                <button
                  key={ext}
                  onClick={() => download(ext)}
                  disabled={busy === ext}
                  title={hint}
                  className="border border-gray-200 rounded-lg p-2 flex flex-col items-center gap-1 hover:border-brand-accent hover:bg-brand-accent/5 transition-colors disabled:opacity-50"
                >
                  {busy === ext
                    ? <Loader2 size={14} className="animate-spin text-brand-accent" />
                    : <Download size={14} className="text-brand-accent" />}
                  <span className="text-[11px] font-semibold text-gray-900">{label}</span>
                  <span className="text-[9px] text-gray-400 text-center leading-tight">{hint}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
    </ResizableDrawer>
  )
}
