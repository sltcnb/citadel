import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useParams, useNavigate, useLocation, useSearchParams } from 'react-router-dom'
import {
  Upload, Search, Bell, X, ChevronRight, AlertTriangle,
  CheckCircle, Clock, Database, Loader2, Shield,
  Cpu, RefreshCw, Plus, Download, Play, Terminal,
  AlertCircle, ChevronDown, FileCode, ExternalLink,
  Flag, Filter, Sparkles, FileText, Trash2, Crosshair,
  Monitor, HardDrive, Globe, Brain,
  Binary, Bug, Network, FileImage, TextSearch, Tag,
  GitBranch, Target, Activity, LayoutTemplate, FileDown,
  Printer, FileBarChart, Layers, Bot, Pencil, Copy,
} from 'lucide-react'

const MOD_CATEGORY_ICONS = {
  'Threat Hunting':     <Shield     size={13} className="text-red-500     flex-shrink-0" />,
  'Malware Detection':  <Bug        size={13} className="text-red-400     flex-shrink-0" />,
  'Binary Analysis':    <Binary     size={13} className="text-orange-500  flex-shrink-0" />,
  'Windows':            <Monitor    size={13} className="text-sky-500     flex-shrink-0" />,
  'Memory Forensics':   <Brain      size={13} className="text-purple-500  flex-shrink-0" />,
  'Disk Forensics':     <HardDrive  size={13} className="text-amber-500   flex-shrink-0" />,
  'Browser Forensics':  <Globe      size={13} className="text-blue-500    flex-shrink-0" />,
  'Network':            <Network    size={13} className="text-teal-500    flex-shrink-0" />,
  'Threat Intelligence':<Tag        size={13} className="text-pink-500    flex-shrink-0" />,
  'Metadata Extraction':<FileImage  size={13} className="text-indigo-500  flex-shrink-0" />,
  'Search':             <TextSearch size={13} className="text-gray-500    flex-shrink-0" />,
}
const MOD_CATEGORY_ORDER = [
  'Threat Hunting', 'Malware Detection', 'Binary Analysis', 'Windows',
  'Memory Forensics', 'Disk Forensics', 'Browser Forensics', 'Network',
  'Threat Intelligence', 'Metadata Extraction', 'Search',
]
import { api, getToken } from '../api/client'
import Timeline from './Timeline'
import AlertRules from './AlertRules'
import CaseNotes from './CaseNotes'
import IngestPanel from '../components/IngestPanel'
import IocPanel from '../components/IocPanel'
import CaseAiPanel from '../components/CaseAiPanel'
import AnomalyPanel from '../components/shared/AnomalyPanel'
import ProcessTreePanel from '../components/shared/ProcessTreePanel'
import MitrePanel from '../components/shared/MitrePanel'
import BaselinePanel from '../components/shared/BaselinePanel'
import EntityGraphPanel from '../components/shared/EntityGraphPanel'
import KillChainPanel from '../components/shared/KillChainPanel'
import EvidencePanel from '../components/shared/EvidencePanel'
import CoPilotPanel from '../components/shared/CoPilotPanel'
import ToolbarMenu from '../components/shared/ToolbarMenu'
import { useLicense } from '../contexts/LicenseContext'
import { useCollab } from '../hooks/useCollab'
import { severityStyle } from '../utils/severity'
import { statusStyle } from '../utils/status'

// ── Artifact badge colours ────────────────────────────────────────────────────
const ARTIFACT_BADGE = {
  evtx:      'badge-evtx',
  prefetch:  'badge-prefetch',
  mft:       'badge-mft',
  registry:  'badge-registry',
  lnk:       'badge-lnk',
  plaso:     'badge-plaso',
  hayabusa:  'badge-hayabusa',
  antivirus: 'badge-antivirus',
  login_event: 'badge-login',
}

// ── Severity colours ──────────────────────────────────────────────────────────
const LEVEL_BADGE = {
  critical:      'badge-critical',
  high:          'badge-high',
  medium:        'badge-medium',
  low:           'badge-low',
  informational: 'badge-informational',
  info:          'badge-informational',
}

const MODULE_NAMES = {
  wintriage:   'Windows Triage',
  hayabusa:    'Hayabusa',
  hindsight:   'Hindsight',
  strings:     'Strings',
  regripper:   'RegRipper',
  chainsaw:    'Chainsaw',
  evtxecmd:    'EvtxECmd',
  volatility3: 'Volatility 3',
  yara:        'YARA Scanner',
  exiftool:    'ExifTool',
  bulk_extractor: 'Bulk Extractor',
  capa:        'CAPA',
}

// ─────────────────────────────────────────────────────────────────────────────
// AlertResultsPanel
// ─────────────────────────────────────────────────────────────────────────────
function AlertResultsPanel({ results, caseId, onClose }) {
  const { matches = [], rules_checked = 0 } = results
  const navigate = useNavigate()

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[580px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div>
            <div className="flex items-center gap-2">
              <Shield size={16} className="text-brand-accent" />
              <span className="font-semibold text-brand-text">Alert Results</span>
            </div>
            <p className="text-xs text-gray-500 mt-0.5">
              {rules_checked} rule{rules_checked !== 1 ? 's' : ''} checked ·{' '}
              <span className={matches.length > 0 ? 'text-red-600 font-medium' : 'text-green-600'}>
                {matches.length} match{matches.length !== 1 ? 'es' : ''}
              </span>
            </p>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {matches.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <CheckCircle size={40} className="text-green-400 mb-3" />
              <p className="font-medium text-brand-text">No alerts triggered</p>
              <p className="text-sm text-gray-500 mt-1">All rules checked — no matches found</p>
            </div>
          ) : matches.map((m, i) => (
            <AlertMatchCard key={m.rule?.rule_id ?? m.rule?.name ?? i} match={m} caseId={caseId} navigate={navigate} />
          ))}
        </div>
      </div>
    </div>
  )
}

function AlertMatchCard({ match, caseId, navigate }) {
  const [open, setOpen] = useState(false)
  const rule = match.rule || {}

  function goToSearch(q) {
    navigate(`/cases/${caseId}`, { state: { pivotQuery: q } })
  }

  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        <AlertTriangle size={16} className="text-red-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-medium text-brand-text text-sm">{rule.name}</span>
            <span className="badge-pill bg-red-100 text-red-700">
              {match.match_count.toLocaleString()} hits
            </span>
            {rule.artifact_type && (
              <span className={`badge ${ARTIFACT_BADGE[rule.artifact_type] || 'badge-generic'}`}>
                {rule.artifact_type}
              </span>
            )}
          </div>
          {rule.description && (
            <p className="text-xs text-gray-500 mt-0.5 truncate">{rule.description}</p>
          )}
          <code className="text-xs text-gray-600 mt-1 block font-mono">{rule.query}</code>
        </div>
        <ChevronRight size={14} className={`text-gray-500 flex-shrink-0 mt-0.5 transition-transform ${open ? 'rotate-90' : ''}`} />
      </button>

      {open && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-2">
          {/* View all hits link */}
          <button
            onClick={() => goToSearch(rule.query)}
            className="w-full flex items-center justify-between bg-brand-accent/10 hover:bg-brand-accent/20 border border-brand-accent/30 rounded-lg px-3 py-2 transition-colors"
          >
            <span className="text-xs font-medium text-brand-accent">
              View all {match.match_count.toLocaleString()} matching events in Search
            </span>
            <ExternalLink size={12} className="text-brand-accent flex-shrink-0" />
          </button>

          {/* Sample events */}
          {match.sample_events?.length > 0 && (
            <>
              <p className="section-title mt-1">Sample events</p>
              {match.sample_events.map((ev, j) => (
                <button
                  key={j}
                  onClick={() => ev.fo_id ? goToSearch(`fo_id:${ev.fo_id}`) : goToSearch(rule.query)}
                  className="w-full text-left bg-white hover:bg-blue-50 rounded-lg border border-gray-200 hover:border-blue-300 p-2.5 transition-colors group"
                  title="Click to view this event in Search"
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <div className="flex items-center gap-1.5 text-xs text-gray-500 font-mono">
                      <Clock size={10} />
                      {ev.timestamp || '—'}
                    </div>
                    <ExternalLink size={10} className="text-gray-500 group-hover:text-blue-400 flex-shrink-0 transition-colors" />
                  </div>
                  <p className="text-xs text-brand-text">{ev.message || '—'}</p>
                  {ev.host?.hostname && (
                    <p className="text-xs text-gray-500 mt-0.5">Host: {ev.host.hostname}</p>
                  )}
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ReIngestButton — re-submits a module output artifact as a new ingest job
// ─────────────────────────────────────────────────────────────────────────────
function ReIngestButton({ caseId, runId, filename }) {
  const [state, setState] = useState('idle')  // 'idle' | 'loading' | 'done' | 'error'
  const [jobId, setJobId] = useState(null)

  async function handleReIngest(e) {
    e.stopPropagation()
    if (state !== 'idle') return
    setState('loading')
    try {
      const res = await api.modules.reingestArtifact(caseId, runId, filename)
      setJobId(res.job_id)
      setState('done')
    } catch {
      setState('error')
      setTimeout(() => setState('idle'), 3000)
    }
  }

  if (state === 'done') {
    return (
      <span className="flex items-center gap-1 text-[10px] text-green-600 bg-green-50 rounded px-1.5 py-1">
        <CheckCircle size={9} />
        Ingesting
      </span>
    )
  }

  return (
    <button
      onClick={handleReIngest}
      disabled={state === 'loading'}
      className={`flex items-center gap-1 text-[10px] rounded px-1.5 py-1 transition-all ${
        state === 'error'
          ? 'text-red-500 bg-red-50'
          : 'text-gray-500 hover:text-violet-600 hover:bg-violet-50'
      }`}
      title={`Re-ingest ${filename} into timeline`}
    >
      {state === 'loading'
        ? <><Loader2 size={9} className="animate-spin" /> Re-ingesting…</>
        : state === 'error'
          ? <><AlertCircle size={9} /> Failed</>
          : <><Plus size={9} /> Re-ingest</>
      }
    </button>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// LevelGroup — one severity accordion inside ModuleRunCard
// ─────────────────────────────────────────────────────────────────────────────
// Flat header — no full-row colour bg. Severity comes through the small badge
// on the left + a 2px accent rail. Keeps the card feeling modern + neutral.
const LEVEL_ACCENT = {
  critical:      '#DC2626',
  high:          '#EA580C',
  medium:        '#D97706',
  low:           '#2563EB',
  informational: '#9CA3AF',
}

function LevelGroup({ level, hits, totalInLevel, defaultOpen, caseId, runId, navigate, buildQuery }) {
  const [open, setOpen]       = useState(defaultOpen)
  const [expandedHit, setExpandedHit] = useState(null)
  const accent = LEVEL_ACCENT[level] || LEVEL_ACCENT.informational

  return (
    <div className="border-t border-gray-100">
      <button
        className="w-full flex items-center gap-2.5 px-4 py-2 text-left transition-colors hover:bg-gray-50"
        onClick={() => setOpen(v => !v)}
        style={{ boxShadow: `inset 2px 0 0 0 ${accent}` }}
      >
        <span className={`badge ${LEVEL_BADGE[level] || 'badge-generic'} flex-shrink-0`}>
          {level}
        </span>
        <span className="text-xs font-medium text-gray-700 flex-1">
          {totalInLevel.toLocaleString()} detection{totalInLevel !== 1 ? 's' : ''}
          {hits.length < totalInLevel && (
            <span className="text-gray-500 font-normal"> · top {hits.length} by severity</span>
          )}
        </span>
        <ChevronDown size={12} className={`text-gray-500 flex-shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="divide-y divide-gray-100">
          {hits.map((hit, i) => {
            const isExpanded = expandedHit === i
            return (
              <div key={i} className="bg-white hover:bg-gray-100/60 transition-colors group">
                <div className="flex items-start gap-2 px-4 py-2.5">
                  {/* Hit detail */}
                  <div
                    className="flex-1 min-w-0 cursor-pointer"
                    onClick={() => setExpandedHit(isExpanded ? null : i)}
                  >
                    <div className="flex items-center gap-1.5 flex-wrap mb-0.5">
                      <span className="font-semibold text-xs text-brand-text leading-tight">
                        {hit.rule_title}
                      </span>
                      {hit.event_id && (
                        <span className="badge bg-purple-50 text-purple-700 border border-purple-100 font-mono text-[10px] flex-shrink-0">
                          EID {hit.event_id}
                        </span>
                      )}
                    </div>
                    <div className="flex flex-wrap gap-x-3 gap-y-0 text-[10px] font-mono mt-0.5">
                      {hit.computer  && <span className="text-gray-600 font-semibold">{hit.computer}</span>}
                      {hit.channel   && (
                        <span className="text-blue-500 truncate max-w-[200px]" title={hit.channel}>
                          {hit.channel}
                        </span>
                      )}
                      {hit.timestamp && <span className="text-gray-500">{hit.timestamp}</span>}
                    </div>
                    {hit.details_raw && (
                      <p
                        className={`text-[10px] text-gray-500 font-mono mt-1 ${
                          isExpanded ? 'whitespace-pre-wrap break-all' : 'truncate'
                        }`}
                        title={!isExpanded ? hit.details_raw : undefined}
                      >
                        {hit.details_raw}
                      </p>
                    )}
                  </div>
                  {/* Action buttons — appear on row hover */}
                  <div className="flex-shrink-0 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all">
                    {/* Download + Re-ingest buttons for module output artifacts (e.g. de4dot) */}
                    {(() => {
                      try {
                        const det = JSON.parse(hit.details_raw || '{}')
                        if (det.download_key && det.download_name && runId) {
                          const dlUrl = `/api/v1/cases/${caseId}/modules/${runId}/artifacts/${encodeURIComponent(det.download_name)}`
                          return (
                            <>
                              <a
                                href={dlUrl}
                                download={det.download_name}
                                className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-emerald-600 hover:bg-emerald-50 rounded px-1.5 py-1 transition-all"
                                title={`Download: ${det.download_name}`}
                                onClick={e => e.stopPropagation()}
                              >
                                <Download size={9} />
                                Download
                              </a>
                              <ReIngestButton
                                caseId={caseId}
                                runId={runId}
                                filename={det.download_name}
                              />
                            </>
                          )
                        }
                      } catch { /* ignore JSON parse errors */ }
                      return null
                    })()}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleLaunchModal
// ─────────────────────────────────────────────────────────────────────────────
function ModuleLaunchModal({ caseId, onClose, onRunCreated }) {
  const [modules, setModules]               = useState([])
  const [sources, setSources]               = useState([])
  const [selectedModule, setSelectedModule] = useState(null)
  const [selectedJobs, setSelectedJobs]     = useState(new Set())
  const [sourceSearch, setSourceSearch]     = useState('')
  const [loading, setLoading]               = useState(true)
  const [running, setRunning]               = useState(false)
  const [runningAll, setRunningAll]         = useState(false)
  const [runAllProgress, setRunAllProgress] = useState(null)  // null | {done, total}
  const [error, setError]                   = useState(null)
  const [moduleSearch, setModuleSearch]     = useState('')
  const moduleSearchRef                     = useRef(null)

  // YARA-specific state
  const [yaraRules, setYaraRules]                   = useState('')
  const [yaraValidating, setYaraValidating]         = useState(false)
  const [yaraValid, setYaraValid]                   = useState(null)  // null | {valid, error}
  const [yaraLibraryRules, setYaraLibraryRules]     = useState([])
  const [selectedYaraIds, setSelectedYaraIds]       = useState(new Set())
  const yaraDebounce                                = useRef(null)

  // Recommendation state — module_id → number of compatible case files
  const [recommendedCounts, setRecommendedCounts] = useState({})

  // Grep-specific state
  const [grepPatterns, setGrepPatterns]   = useState('')
  const [grepPresets, setGrepPresets]     = useState(() => {
    try { return JSON.parse(localStorage.getItem('fo_grep_presets') || '[]') }
    catch { return [] }
  })
  const [grepPresetName, setGrepPresetName] = useState('')
  const [showPresetInput, setShowPresetInput] = useState(false)

  function saveGrepPreset() {
    const name = grepPresetName.trim()
    if (!name || !grepPatterns.trim()) return
    const preset = { id: Date.now().toString(), name, patterns: grepPatterns.trim() }
    const updated = [...grepPresets, preset]
    setGrepPresets(updated)
    localStorage.setItem('fo_grep_presets', JSON.stringify(updated))
    setGrepPresetName('')
    setShowPresetInput(false)
  }

  function deleteGrepPreset(id) {
    const updated = grepPresets.filter(p => p.id !== id)
    setGrepPresets(updated)
    localStorage.setItem('fo_grep_presets', JSON.stringify(updated))
  }

  function loadGrepPreset(preset) {
    setGrepPatterns(preset.patterns)
  }

  useEffect(() => {
    const settled = Promise.allSettled([api.modules.list(), api.modules.listSources(caseId)])
    const timer   = new Promise(resolve => setTimeout(() => resolve('__timeout__'), 8000))

    Promise.race([settled, timer]).then(result => {
      if (result === '__timeout__') {
        setError('Request timed out — the API may be starting up. Close and try again.')
        setLoading(false)
        return
      }
      const [modResult, srcResult] = result
      if (modResult.status === 'fulfilled') {
        setModules((modResult.value.modules || []).filter(m => m.available))
      } else {
        setError('Could not load modules: ' + (modResult.reason?.message || 'server error'))
      }
      if (srcResult.status === 'fulfilled') {
        setSources(srcResult.value.sources || [])
      }
      setLoading(false)
    })

    // Best-effort: ranked module suggestions for this case's file mix
    api.modules.recommended(caseId)
      .then(r => {
        const counts = {}
        for (const m of r.recommended || []) counts[m.id] = m.matched_files
        setRecommendedCounts(counts)
      })
      .catch(() => {})
  }, [caseId])

  // Load YARA library rules when YARA module is selected
  useEffect(() => {
    if (selectedModule?.id !== 'yara') return
    api.yaraRules.list()
      .then(r => setYaraLibraryRules(r.rules || []))
      .catch(() => {})
  }, [selectedModule])

  // Validate YARA rules with debounce
  useEffect(() => {
    if (selectedModule?.id !== 'yara') return
    if (!yaraRules.trim()) { setYaraValid(null); return }
    if (yaraDebounce.current) clearTimeout(yaraDebounce.current)
    setYaraValidating(true)
    yaraDebounce.current = setTimeout(() => {
      api.modules.validateYara(yaraRules)
        .then(r => setYaraValid(r))
        .catch(() => setYaraValid({ valid: false, error: 'Validation request failed' }))
        .finally(() => setYaraValidating(false))
    }, 600)
  }, [yaraRules, selectedModule])

  const compatibleSources = selectedModule
    ? sources.filter(s => {
        const fnameLower = (s.original_filename || '').toLowerCase()
        const extList  = selectedModule.input_extensions || []
        const nameList = selectedModule.input_filenames  || []
        if (extList.length === 0 && nameList.length === 0) return true
        if (extList.some(e => e === '*' || e === '.*')) return true
        const extMatch  = extList.some(ext => fnameLower.endsWith(ext.toLowerCase()))
        const basename  = fnameLower.split('/').pop().split('\\').pop()
        const nameMatch = nameList.some(fn => basename === fn.toLowerCase())
        return extMatch || nameMatch
      })
    : sources

  const visibleSources = sourceSearch.trim()
    ? compatibleSources.filter(s =>
        (s.original_filename || '').toLowerCase().includes(sourceSearch.toLowerCase())
      )
    : compatibleSources

  // Group modules by category for the left panel
  const groupedModules = useMemo(() => {
    const q = moduleSearch.toLowerCase().trim()
    const filtered = q
      ? modules.filter(m =>
          (m.name || '').toLowerCase().includes(q) ||
          (m.description || '').toLowerCase().includes(q) ||
          (m.category || '').toLowerCase().includes(q) ||
          (m.tags || []).some(t => t.toLowerCase().includes(q))
        )
      : modules
    const groups = {}
    filtered.forEach(m => {
      const cat = m.category || 'Other'
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(m)
    })
    const sorted = Object.entries(groups).sort(([a], [b]) => {
      const ai = MOD_CATEGORY_ORDER.indexOf(a)
      const bi = MOD_CATEGORY_ORDER.indexOf(b)
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return a.localeCompare(b)
    })
    // Synthetic "Recommended" group on top — modules whose declared inputs
    // match files actually present in this case, ranked by match count.
    if (!q) {
      const recs = filtered
        .filter(m => recommendedCounts[m.id] > 0)
        .sort((a, b) => recommendedCounts[b.id] - recommendedCounts[a.id])
        .slice(0, 6)
      if (recs.length > 0) sorted.unshift(['Recommended', recs])
    }
    return sorted
  }, [modules, moduleSearch, recommendedCounts])

  function toggleJob(jobId) {
    setSelectedJobs(prev => {
      const next = new Set(prev)
      next.has(jobId) ? next.delete(jobId) : next.add(jobId)
      return next
    })
  }

  function selectAll() {
    setSelectedJobs(new Set(compatibleSources.map(s => s.job_id)))
  }

  function selectModule(mod) {
    setSelectedModule(mod)
    setSelectedJobs(new Set())
    setYaraRules('')
    setYaraValid(null)
    setGrepPatterns('')
    setShowPresetInput(false)
    setGrepPresetName('')
  }

  async function handleRun() {
    if (!selectedModule || selectedJobs.size === 0) return
    if (selectedModule.id === 'yara' && yaraValid && !yaraValid.valid) return
    setRunning(true)
    setError(null)
    try {
      const params = {}
      if (selectedModule.id === 'yara') {
        if (yaraRules.trim()) params.custom_rules = yaraRules.trim()
        if (selectedYaraIds.size > 0) params.selected_rule_ids = [...selectedYaraIds]
      }
      if (selectedModule.id === 'grep_search' && grepPatterns.trim()) {
        params.patterns = grepPatterns.split('\n').map(p => p.trim()).filter(Boolean)
      }
      const run = await api.modules.createRun(caseId, {
        module_id:    selectedModule.id,
        source_files: sources
          .filter(s => selectedJobs.has(s.job_id))
          .map(s => ({ job_id: s.job_id, filename: s.original_filename, minio_key: s.minio_object_key })),
        params,
      })
      onRunCreated(run)
    } catch (err) {
      setError(err.message)
      setRunning(false)
    }
  }

  async function handleRunAll() {
    if (runningAll || sources.length === 0) return
    const eligible = modules.filter(m => {
      // Skip modules that require external service credentials (API keys, sandbox URLs)
      if (m.config_keys?.length > 0) return false
      const extList  = m.input_extensions || []
      const nameList = m.input_filenames  || []
      const acceptsAll = extList.length === 0 && nameList.length === 0
      if (acceptsAll) return sources.length > 0
      const hasCompatible = sources.some(s => {
        const fnameLower = (s.original_filename || '').toLowerCase()
        if (extList.some(e => e === '*' || e === '.*')) return true
        const extMatch  = extList.some(ext => fnameLower.endsWith(ext.toLowerCase()))
        const basename  = fnameLower.split('/').pop().split('\\').pop()
        const nameMatch = nameList.some(fn => basename === fn.toLowerCase())
        return extMatch || nameMatch
      })
      return hasCompatible
    })
    if (eligible.length === 0) return
    if (!window.confirm(
      `Launch all ${eligible.length} applicable module${eligible.length > 1 ? 's' : ''} against their compatible files?\n\n` +
      eligible.map(m => `• ${m.name}`).join('\n')
    )) return

    setRunningAll(true)
    setRunAllProgress({ done: 0, total: eligible.length })
    setError(null)

    let done = 0
    for (const mod of eligible) {
      const extList  = mod.input_extensions || []
      const nameList = mod.input_filenames  || []
      const acceptsAll = extList.length === 0 && nameList.length === 0
      const jobIds = sources
        .filter(s => {
          if (acceptsAll) return true
          if (extList.some(e => e === '*' || e === '.*')) return true
          const fnameLower = (s.original_filename || '').toLowerCase()
          const extMatch  = extList.some(ext => fnameLower.endsWith(ext.toLowerCase()))
          const basename  = fnameLower.split('/').pop().split('\\').pop()
          const nameMatch = nameList.some(fn => basename === fn.toLowerCase())
          return extMatch || nameMatch
        })
        .map(s => s.job_id)
      if (jobIds.length === 0) { done++; setRunAllProgress({ done, total: eligible.length }); continue }
      try {
        const resolvedFiles = sources
          .filter(s => jobIds.includes(s.job_id))
          .map(s => ({ job_id: s.job_id, filename: s.original_filename, minio_key: s.minio_object_key }))
        const run = await api.modules.createRun(caseId, { module_id: mod.id, source_files: resolvedFiles, params: {} })
        onRunCreated(run)
      } catch {
        // best-effort — don't abort remaining modules on one failure
      }
      done++
      setRunAllProgress({ done, total: eligible.length })
    }
    setRunningAll(false)
    setRunAllProgress(null)
    onClose()
  }

  const yaraInvalid = selectedModule?.id === 'yara' && yaraValid && !yaraValid.valid
  const canRun = selectedModule && selectedJobs.size > 0 && !running && !yaraInvalid && !runningAll

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[860px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-6px 0 40px rgba(0,0,0,0.18)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* ── Header ────────────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-200 bg-gray-50 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-brand-accent/15 flex items-center justify-center flex-shrink-0">
              <Play size={13} className="text-brand-accent" />
            </div>
            <div>
              <p className="font-semibold text-brand-text text-sm leading-tight">Run Analysis Module</p>
              <p className="text-[11px] text-gray-500 leading-tight mt-px">Select module → pick files → launch</p>
            </div>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={15} />
          </button>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center text-gray-500">
            <Loader2 size={20} className="animate-spin mr-2" /> Loading…
          </div>
        ) : (
          <div className="flex-1 flex overflow-hidden min-h-0">

            {/* ── Left: module list ─────────────────────────────────────────── */}
            <div className="w-[300px] flex-shrink-0 border-r border-gray-200 flex flex-col bg-gray-50">

              {/* Search */}
              <div className="px-3 pt-3 pb-2 flex-shrink-0">
                <div className="relative">
                  <Search size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
                  <input
                    ref={moduleSearchRef}
                    value={moduleSearch}
                    onChange={e => setModuleSearch(e.target.value)}
                    placeholder="Search modules…"
                    className="input w-full text-xs py-1.5 pl-7 pr-6"
                  />
                  {moduleSearch && (
                    <button onClick={() => setModuleSearch('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600">
                      <X size={10} />
                    </button>
                  )}
                </div>
              </div>

              {/* Module list */}
              <div className="flex-1 overflow-y-auto px-2 pb-3">
                {groupedModules.length === 0 ? (
                  <p className="text-xs text-gray-500 italic text-center py-8">No modules match</p>
                ) : groupedModules.map(([category, mods]) => (
                  <div key={category} className="mb-2">
                    {/* Category header — sticky, uses same bg as sidebar */}
                    <div className="flex items-center gap-2 px-1 pt-3 pb-1.5 sticky top-0 bg-gray-50 z-10">
                      <span className="text-[10px] font-bold uppercase tracking-widest text-gray-500 flex-1">
                        {category}
                      </span>
                      <span className="text-[10px] text-gray-500">{mods.length}</span>
                    </div>

                    <div className="space-y-0.5">
                      {mods.map(mod => {
                        const isSelected = selectedModule?.id === mod.id
                        const isAvailable = mod.available !== false
                        return (
                          <button
                            key={mod.id}
                            onClick={() => selectModule(mod)}
                            className={`w-full text-left px-3 py-2.5 rounded-lg border transition-all ${
                              isSelected
                                ? 'border-brand-accent bg-brand-accentlight'
                                : isAvailable
                                  ? 'border-transparent hover:bg-gray-100 hover:border-gray-200'
                                  : 'border-transparent opacity-40 cursor-not-allowed'
                            }`}
                            disabled={!isAvailable}
                          >
                            <div className="flex items-center gap-1.5">
                              <p className={`font-medium text-xs leading-tight flex-1 ${isSelected ? 'text-brand-accent' : 'text-brand-text'}`}>
                                {mod.name}
                              </p>
                              {recommendedCounts[mod.id] > 0 && (
                                <span className="px-1.5 py-px rounded text-[9px] font-medium bg-emerald-50 text-emerald-600 border border-emerald-200 flex-shrink-0">
                                  {recommendedCounts[mod.id]} file{recommendedCounts[mod.id] > 1 ? 's' : ''}
                                </span>
                              )}
                            </div>
                            {isSelected && mod.description && (
                              <p className="text-[10px] mt-0.5 text-brand-accent/70 leading-snug line-clamp-2">
                                {mod.description}
                              </p>
                            )}
                            {(mod.tags || []).length > 0 && isSelected && (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {mod.tags.slice(0, 4).map(tag => (
                                  <span key={tag} className="px-1.5 py-px rounded text-[9px] font-medium bg-brand-accent/10 text-brand-accent">
                                    {tag}
                                  </span>
                                ))}
                              </div>
                            )}
                          </button>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Right: file picker + module options ───────────────────────── */}
            <div className="flex-1 flex flex-col overflow-hidden min-h-0">

              {!selectedModule ? (
                <div className="flex-1 flex flex-col items-center justify-center text-center px-8 gap-3">
                  <div className="w-12 h-12 rounded-2xl bg-gray-100 flex items-center justify-center">
                    <Cpu size={20} className="text-gray-500" />
                  </div>
                  <p className="font-medium text-sm text-brand-text">Pick a module</p>
                  <p className="text-xs text-gray-500 max-w-xs leading-relaxed">
                    Choose a module from the left, then select which ingested files to run it against.
                  </p>
                </div>
              ) : (
                <>
                  {/* Selected module info bar */}
                  <div className="px-4 pt-3.5 pb-2.5 border-b border-gray-200 flex-shrink-0 bg-gray-50">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="font-semibold text-sm text-brand-text">{selectedModule.name}</p>
                        {selectedModule.description && (
                          <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{selectedModule.description}</p>
                        )}
                      </div>
                      {(selectedModule.tags || []).length > 0 && (
                        <div className="flex flex-wrap gap-1 flex-shrink-0">
                          {selectedModule.tags.slice(0, 3).map(tag => (
                            <span key={tag} className="px-1.5 py-px rounded text-[9px] font-medium bg-gray-100 text-gray-600 border border-gray-200">
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* File selection */}
                  <div className="flex items-center justify-between px-4 pt-3 pb-1.5 flex-shrink-0">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                      Input Files
                      {compatibleSources.length > 0 && (
                        <span className="ml-1.5 font-normal normal-case">
                          {selectedJobs.size}/{compatibleSources.length}
                        </span>
                      )}
                    </p>
                    {compatibleSources.length > 0 && (
                      <div className="flex items-center gap-2">
                        {selectedJobs.size < compatibleSources.length && (
                          <button onClick={selectAll} className="text-[11px] text-brand-accent hover:underline">
                            All
                          </button>
                        )}
                        {selectedJobs.size > 0 && (
                          <button onClick={() => setSelectedJobs(new Set())} className="text-[11px] text-gray-500 hover:text-gray-700 hover:underline">
                            Clear
                          </button>
                        )}
                      </div>
                    )}
                  </div>

                  {compatibleSources.length === 0 ? (
                    <div className="mx-4 mb-3 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-700">
                      <p className="font-medium mb-0.5">No compatible files ingested yet</p>
                      <p className="text-[11px]">
                        {selectedModule.name} requires:{' '}
                        <span className="font-mono">
                          {[...(selectedModule.input_extensions || []), ...(selectedModule.input_filenames || [])].join(', ') || 'any file'}
                        </span>
                      </p>
                    </div>
                  ) : (
                    <>
                      {compatibleSources.length > 6 && (
                        <div className="px-4 pb-1.5 flex-shrink-0">
                          <input
                            type="text"
                            value={sourceSearch}
                            onChange={e => setSourceSearch(e.target.value)}
                            placeholder="Filter files…"
                            className="input w-full text-xs py-1.5"
                          />
                        </div>
                      )}
                      <div className={`px-4 pb-2 space-y-1 ${selectedModule?.id === 'yara' ? 'max-h-44' : 'flex-1'} overflow-y-auto flex-shrink-0`}>
                        {visibleSources.map(src => (
                          <label
                            key={src.job_id}
                            className={`flex items-center gap-2.5 px-4 py-3 rounded-lg cursor-pointer border transition-colors ${
                              selectedJobs.has(src.job_id)
                                ? 'border-brand-accent bg-brand-accentlight'
                                : 'border-gray-100 hover:border-gray-200 hover:bg-gray-50'
                            }`}
                          >
                            <input
                              type="checkbox"
                              checked={selectedJobs.has(src.job_id)}
                              onChange={() => toggleJob(src.job_id)}
                              className="rounded border-gray-300 flex-shrink-0 accent-brand-accent"
                            />
                            <div className="flex-1 min-w-0">
                              <p className="text-xs text-brand-text truncate font-medium">
                                {src.original_filename}
                              </p>
                              <p className="text-[10px] text-gray-500 mt-px">
                                {(src.events_indexed || 0).toLocaleString()} events
                                {src.plugin_used ? ` · ${src.plugin_used}` : ''}
                              </p>
                            </div>
                          </label>
                        ))}
                        {visibleSources.length === 0 && sourceSearch && (
                          <p className="text-xs text-gray-500 italic py-4 text-center">
                            No files match "{sourceSearch}"
                          </p>
                        )}
                      </div>
                    </>
                  )}

                  {/* ── Grep patterns ─────────────────────────────────────── */}
                  {selectedModule.id === 'grep_search' && (
                    <div className="flex-1 flex flex-col min-h-0 overflow-hidden border-t border-gray-200">
                      {grepPresets.length > 0 && (
                        <div className="px-4 pt-2.5 pb-2 flex-shrink-0 border-b border-gray-100">
                          <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-1.5">Saved Presets</p>
                          <div className="flex flex-wrap gap-1.5 max-h-20 overflow-y-auto">
                            {grepPresets.map(preset => (
                              <div key={preset.id} className="flex items-center gap-1 bg-gray-100 hover:bg-brand-accentlight border border-gray-200 hover:border-brand-accent/30 rounded-lg px-2 py-1 group transition-colors">
                                <button
                                  onClick={() => loadGrepPreset(preset)}
                                  className="text-[11px] text-gray-700 group-hover:text-brand-text font-medium"
                                  title={`Load: ${preset.patterns.split('\n').slice(0,3).join(', ')}`}
                                >
                                  {preset.name}
                                </button>
                                <button onClick={() => deleteGrepPreset(preset.id)} className="text-gray-500 hover:text-red-500 transition-colors ml-0.5" title="Delete preset">
                                  <X size={9} />
                                </button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="flex-1 flex flex-col px-4 pt-2.5 pb-3 min-h-0">
                        <div className="flex items-center gap-2 mb-1.5 flex-shrink-0">
                          <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold flex-1">
                            Patterns <span className="normal-case font-normal">(one regex per line)</span>
                          </p>
                          {!showPresetInput ? (
                            <button onClick={() => setShowPresetInput(true)} disabled={!grepPatterns.trim()}
                              className="text-[10px] text-gray-500 hover:text-brand-accent disabled:opacity-40 transition-colors">
                              + Save preset
                            </button>
                          ) : (
                            <div className="flex items-center gap-1">
                              <input autoFocus value={grepPresetName} onChange={e => setGrepPresetName(e.target.value)}
                                onKeyDown={e => { if (e.key === 'Enter') saveGrepPreset(); if (e.key === 'Escape') setShowPresetInput(false) }}
                                placeholder="Preset name…"
                                className="text-[10px] border border-gray-200 rounded px-1.5 py-0.5 w-24 focus:outline-none focus:border-brand-accent" />
                              <button onClick={saveGrepPreset} className="text-[10px] text-green-600 hover:text-green-700 font-medium">Save</button>
                              <button onClick={() => setShowPresetInput(false)} className="text-[10px] text-gray-500 hover:text-gray-600">✕</button>
                            </div>
                          )}
                        </div>
                        <textarea
                          value={grepPatterns}
                          onChange={e => setGrepPatterns(e.target.value)}
                          placeholder={"Leave empty to run built-in IOC patterns:\n  URLs, IPs, MD5/SHA hashes,\n  powershell, cmd.exe, certutil…\n\nOr enter your own (one per line):\n  192\\.168\\.\\d+\\.\\d+\n  base64\\.b64decode\n  C:\\\\Windows\\\\Temp"}
                          spellCheck={false}
                          className="flex-1 w-full min-h-0 px-3 py-2.5 text-[11px] font-mono border border-gray-200 bg-gray-950 text-green-300 rounded-xl resize-none focus:outline-none focus:ring-2 focus:ring-brand-accent/30 focus:border-brand-accent leading-relaxed"
                        />
                      </div>
                    </div>
                  )}

                  {/* ── YARA library rules ────────────────────────────────── */}
                  {selectedModule.id === 'yara' && yaraLibraryRules.length > 0 && (
                    <div className="px-4 pb-2 flex-shrink-0 border-t border-gray-200 pt-2.5">
                      <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold mb-1.5">
                        Library Rules <span className="normal-case font-normal">(leave all unchecked = run all)</span>
                      </p>
                      <div className="max-h-28 overflow-y-auto space-y-0.5 border border-gray-200 rounded-lg p-2 bg-white">
                        {yaraLibraryRules.map(rule => (
                          <label key={rule.id} className="flex items-center gap-2 cursor-pointer group">
                            <input type="checkbox" checked={selectedYaraIds.has(rule.id)}
                              onChange={e => setSelectedYaraIds(prev => { const s = new Set(prev); e.target.checked ? s.add(rule.id) : s.delete(rule.id); return s })}
                              className="accent-brand-accent" />
                            <span className="text-[11px] text-gray-700 truncate group-hover:text-gray-900">{rule.name}</span>
                            {rule.tags?.length > 0 && <span className="text-[10px] text-gray-500 flex-shrink-0">{rule.tags[0]}</span>}
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* ── YARA custom rules ─────────────────────────────────── */}
                  {selectedModule.id === 'yara' && (
                    <div className="flex-1 flex flex-col px-4 pb-3 min-h-0 border-t border-gray-200 pt-2.5">
                      <div className="flex items-center gap-2 mb-1.5 flex-shrink-0">
                        <FileCode size={11} className="text-gray-500" />
                        <p className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold flex-1">
                          Custom YARA Rules <span className="normal-case font-normal">(appended to built-in)</span>
                        </p>
                        {yaraValidating && <Loader2 size={10} className="animate-spin text-gray-500" />}
                        {!yaraValidating && yaraValid && (
                          yaraValid.valid
                            ? <span className="text-[10px] text-green-600 flex items-center gap-1"><CheckCircle size={10} /> Valid</span>
                            : <span className="text-[10px] text-red-500 flex items-center gap-1"><AlertCircle size={10} /> Syntax error</span>
                        )}
                      </div>
                      <textarea
                        value={yaraRules}
                        onChange={e => setYaraRules(e.target.value)}
                        placeholder={`rule MyRule {\n    meta:\n        description = "My custom rule"\n        severity = "high"\n    strings:\n        $s1 = "suspicious_string" ascii nocase\n    condition:\n        any of them\n}`}
                        spellCheck={false}
                        className={`flex-1 w-full min-h-0 px-3 py-2.5 text-[11px] font-mono border rounded-xl resize-none focus:outline-none focus:ring-2 leading-relaxed ${
                          yaraValid && !yaraValid.valid
                            ? 'border-red-300 bg-red-50 focus:ring-red-200'
                            : 'border-gray-200 bg-gray-950 text-green-300 focus:ring-brand-accent/30 focus:border-brand-accent'
                        }`}
                      />
                      {yaraValid && !yaraValid.valid && (
                        <p className="mt-1 text-[10px] text-red-500 font-mono flex-shrink-0">{yaraValid.error}</p>
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>
        )}

        {/* ── Footer ────────────────────────────────────────────────────────── */}
        <div className="border-t border-gray-200 px-4 py-3 flex items-center gap-2 bg-gray-50 flex-shrink-0">
          <button
            onClick={handleRunAll}
            disabled={runningAll || running || sources.length === 0}
            className={`btn-outline flex items-center gap-1.5 text-xs px-3 py-1.5 ${
              runningAll || running || sources.length === 0 ? 'opacity-40 cursor-not-allowed' : ''
            }`}
            title="Launch every applicable module against its compatible files"
          >
            {runningAll
              ? <><Loader2 size={11} className="animate-spin" /> {runAllProgress ? `${runAllProgress.done}/${runAllProgress.total}` : 'Launching…'}</>
              : <><Sparkles size={11} /> All modules</>
            }
          </button>

          {error && (
            <p className="flex-1 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-1.5 truncate" title={error}>
              {error}
            </p>
          )}

          <div className="ml-auto flex items-center gap-2">
            {selectedModule && selectedJobs.size === 0 && !runningAll && (
              <p className="text-xs text-gray-500">Select at least one file</p>
            )}
            <button
              onClick={handleRun}
              disabled={!canRun}
              className={`btn flex items-center gap-1.5 text-xs px-4 py-1.5 font-semibold ${
                canRun ? 'btn-primary' : 'opacity-40 cursor-not-allowed bg-gray-100 text-gray-500 border-gray-200'
              }`}
            >
              {running
                ? <><Loader2 size={12} className="animate-spin" /> Launching…</>
                : <><Play size={12} /> Run {selectedModule?.name || 'Module'}</>
              }
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleRunCard
// ─────────────────────────────────────────────────────────────────────────────
const LEVEL_ORDER_KEYS = ['critical', 'high', 'medium', 'low', 'informational']

// Full color palette — covers every module_id that can appear.
// `strip` = the 3px top strip color; `bg` = dark-mode card tint at 15% opacity.
const MODULE_ACCENT = {
  hayabusa:           { strip: '#fb923c', bg: 'rgba(251,146,60,0.15)'   },
  wintriage:          { strip: '#38bdf8', bg: 'rgba(56,189,248,0.15)'   },
  chainsaw:           { strip: '#f87171', bg: 'rgba(248,113,113,0.15)'  },
  evtxecmd:           { strip: '#818cf8', bg: 'rgba(129,140,248,0.15)'  },
  regripper:          { strip: '#fbbf24', bg: 'rgba(251,191,36,0.15)'   },
  volatility3:        { strip: '#c084fc', bg: 'rgba(192,132,252,0.15)'  },
  yara:               { strip: '#4ade80', bg: 'rgba(74,222,128,0.15)'   },
  exiftool:           { strip: '#f472b6', bg: 'rgba(244,114,182,0.15)'  },
  bulk_extractor:     { strip: '#2dd4bf', bg: 'rgba(45,212,191,0.15)'   },
  capa:               { strip: '#fb7185', bg: 'rgba(251,113,133,0.15)'  },
  hindsight:          { strip: '#60a5fa', bg: 'rgba(96,165,250,0.15)'   },
  strings:            { strip: '#94a3b8', bg: 'rgba(148,163,184,0.15)'  },
  browser_report:     { strip: '#34d399', bg: 'rgba(52,211,153,0.15)'   },
  cti_match:          { strip: '#e879f9', bg: 'rgba(232,121,249,0.15)'  },
  cuckoo:             { strip: '#f97316', bg: 'rgba(249,115,22,0.15)'   },
  de4dot:             { strip: '#a78bfa', bg: 'rgba(167,139,250,0.15)'  },
  floss:              { strip: '#67e8f9', bg: 'rgba(103,232,249,0.15)'  },
  grep_search:        { strip: '#fde047', bg: 'rgba(253,224,71,0.15)'   },
  malwoverview:       { strip: '#f43f5e', bg: 'rgba(244,63,94,0.15)'    },
  ole_analysis:       { strip: '#fb923c', bg: 'rgba(251,146,60,0.15)'   },
  oletools:           { strip: '#fdba74', bg: 'rgba(253,186,116,0.15)'  },
  pe_analysis:        { strip: '#e11d48', bg: 'rgba(225,29,72,0.15)'    },
  strings_analysis:   { strip: '#86efac', bg: 'rgba(134,239,172,0.15)'  },
  access_log_analysis:{ strip: '#22d3ee', bg: 'rgba(34,211,238,0.15)'   },
}

// ── LLM analysis display ──────────────────────────────────────────────────────
function LLMAnalysisPanel({ analysis }) {
  if (!analysis) return null
  const sev = (analysis.severity || 'unknown').toLowerCase()
  return (
    <div className="border-t border-purple-100 bg-purple-50/40 px-4 py-3 space-y-3">
      <div className="flex items-center gap-2">
        <Sparkles size={13} className="text-purple-500 flex-shrink-0" />
        <span className="text-xs font-semibold text-purple-700">AI Analysis</span>
        {analysis.model_used && (
          <span className="text-[10px] text-purple-400 font-mono">{analysis.model_used}</span>
        )}
        <span className={`ml-auto text-[10px] font-medium border rounded-full px-2 py-0.5 ${severityStyle(sev)}`}>
          {sev}
        </span>
      </div>

      {analysis.summary && (
        <p className="text-xs text-gray-700 leading-relaxed">{analysis.summary}</p>
      )}

      {analysis.timeline?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">Timeline</p>
          <ul className="space-y-0.5">
            {analysis.timeline.map((item, i) => (
              <li key={i} className="text-xs text-gray-600 flex gap-1.5">
                <span className="text-purple-400 flex-shrink-0">▸</span>{item}
              </li>
            ))}
          </ul>
        </div>
      )}

      {analysis.indicators?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">Indicators</p>
          <div className="flex flex-wrap gap-1">
            {analysis.indicators.map((ioc, i) => (
              <span key={i} className="text-[10px] font-mono bg-white border border-gray-200 rounded px-1.5 py-0.5 text-gray-700">
                {ioc}
              </span>
            ))}
          </div>
        </div>
      )}

      {analysis.mitre_techniques?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-1">
            {analysis.mitre_techniques.map((t, i) => (
              <span key={i} className="text-[10px] bg-red-50 border border-red-200 text-red-700 rounded px-1.5 py-0.5">
                {t}
              </span>
            ))}
          </div>
        </div>
      )}

      {analysis.recommendations?.length > 0 && (
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide mb-1">Recommendations</p>
          <ul className="space-y-0.5">
            {analysis.recommendations.map((rec, i) => (
              <li key={i} className="text-xs text-gray-600 flex gap-1.5">
                <span className="text-green-500 flex-shrink-0">→</span>{rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function ModuleRunCard({
  run, caseId, navigate, onClose,
  // Hit-level filters (all optional — undefined = no filtering)
  activeLevels, activeComputers, activeChannels, activeTags, ruleSearch,
  onResetFilter,
}) {
  const zeroDetected = run.status === 'COMPLETED' && run.total_hits === 0
  const [showOutput, setShowOutput] = useState(zeroDetected)
  const [analyzing, setAnalyzing]   = useState(false)
  const [analysis,  setAnalysis]    = useState(run.llm_analysis || null)
  const [analyzeErr, setAnalyzeErr] = useState('')
  const [retrying,   setRetrying]   = useState(false)
  const [retryErr,   setRetryErr]   = useState('')
  const [cancelling, setCancelling] = useState(false)

  async function retryRun() {
    setRetrying(true)
    setRetryErr('')
    try {
      await api.modules.retryRun(run.run_id)
    } catch (err) {
      setRetryErr(err.message)
    } finally {
      setRetrying(false)
    }
  }

  async function cancelRun() {
    if (!confirm('Cancel this module run? A module already executing will finish its current step, then stop.')) return
    setCancelling(true)
    setRetryErr('')
    try {
      await api.modules.cancelRun(run.run_id)
    } catch (err) {
      setRetryErr(err.message)
      setCancelling(false)
    }
  }

  async function runAnalysis() {
    setAnalyzing(true)
    setAnalyzeErr('')
    try {
      const res = await api.modules.analyze(run.run_id)
      setAnalysis(res.analysis)
    } catch (err) {
      setAnalyzeErr(err.message)
    } finally {
      setAnalyzing(false)
    }
  }

  const moduleName  = MODULE_NAMES[run.module_id] || run.module_id
  const preview     = run.results_preview || []
  const byLevel     = run.hits_by_level   || {}

  const statusCls = statusStyle(run.status).cls

  const ts = run.completed_at || run.started_at
  const tsDisplay = ts
    ? new Date(ts).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })
    : null

  // Strip residual ANSI codes
  const _stripAnsi = s => s.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/\x1b[@-_][^\x1b]*/g, '')
  const rawOutput  = (run.tool_stdout || '') + (run.tool_log ? '\n--- log ---\n' + run.tool_log : '')
  const toolOutput = _stripAnsi(rawOutput)
  const hasOutput  = toolOutput.trim().length > 0

  // ── Per-hit filtering ──────────────────────────────────────────────────────
  // Applies all active filters at once so every dimension is ANDed together.
  const filteredPreview = useMemo(() => {
    const hasFilters = (activeLevels?.size > 0) || ruleSearch?.trim() ||
                       (activeComputers?.size > 0) || (activeChannels?.size > 0) ||
                       (activeTags?.size > 0)
    if (!hasFilters) return preview
    return preview.filter(hit => {
      const lvl = (hit.level || 'informational').toLowerCase()
      if (activeLevels?.size  && !activeLevels.has(lvl))              return false
      if (ruleSearch?.trim()  && !hit.rule_title?.toLowerCase().includes(ruleSearch.trim().toLowerCase())) return false
      if (activeComputers?.size && !activeComputers.has(hit.computer)) return false
      if (activeChannels?.size  && !activeChannels.has(hit.channel))   return false
      if (activeTags?.size) {
        const ht = hit.tags || []
        if (!ht.some(t => activeTags.has(t))) return false
      }
      return true
    })
  }, [preview, activeLevels, ruleSearch, activeComputers, activeChannels, activeTags])

  // Group filtered hits by level for accordion display
  const hitsByLevel = {}
  for (const hit of filteredPreview) {
    const lvl = (hit.level || 'informational').toLowerCase()
    if (!hitsByLevel[lvl]) hitsByLevel[lvl] = []
    hitsByLevel[lvl].push(hit)
  }
  const filteredLevels = LEVEL_ORDER_KEYS.filter(lvl => hitsByLevel[lvl]?.length > 0)

  // Used to show "no detections at selected filters" empty state
  const anyHitsInPreview = preview.length > 0
  const hasFilteredHits  = filteredLevels.length > 0

  // Auto-open completed cards that have detections matching the active filter
  const [open, setOpen] = useState(hasFilteredHits && run.status === 'COMPLETED')

  // Build smart Lucene pivot query for a hit.
  // EVTX modules (hayabusa, wintriage) → event_id + hostname
  // Event-query modules (browser_report, access_log) → artifact_type
  // File-scan modules (yara, grep, de4dot, pe_analysis…) → rule_title message search
  // computer = hostname ONLY when event_id is also present (EVTX hits)
  const MODULE_ARTIFACT_TYPES = {
    browser_report:      'browser',
    access_log_analysis: 'access_log',
    hindsight:           'browser',
    ole_analysis:        'oletools',
    volatility3:         'volatility',
    cti_match:           'cti_match',  // now indexed as cti_match events
    strings:             null,    // too noisy, not indexed
    strings_analysis:    null,    // too noisy, not indexed
  }
  function getModuleArtifactType(moduleId) {
    if (moduleId in MODULE_ARTIFACT_TYPES) return MODULE_ARTIFACT_TYPES[moduleId]
    return moduleId.replace(/-/g, '_').replace(/ /g, '_')
  }
  function buildQuery(hit) {
    if (hit.event_id) {
      const parts = [`evtx.event_id:${hit.event_id}`]
      if (hit.computer) parts.push(`host.hostname:"${hit.computer}"`)
      return parts.join(' AND ')
    }
    const artType = MODULE_ARTIFACT_TYPES[run.module_id]
    if (artType) return `artifact_type:${artType}`
    const title = (hit.rule_title || '').replace(/"/g, '')
    return title ? `message:"${title}"` : '*'
  }

  const _mc = MODULE_ACCENT[run.module_id]

  return (
    <div className="card overflow-hidden">
      {/* ── Card header ───────────────────────────────────────── */}
      <button
        className="w-full flex items-start gap-3 p-3 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        {/* Compact module dot — flat, no full-width strip */}
        {_mc && (
          <span
            className="mt-1.5 w-2 h-2 rounded-full flex-shrink-0"
            style={{ backgroundColor: _mc.strip }}
            title={moduleName}
          />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm text-brand-text">{moduleName}</span>
            <span className={`badge ${statusCls} inline-flex items-center gap-1`}>
              {run.status === 'RUNNING' && <Loader2 size={9} className="animate-spin" />}
              {run.status}
            </span>

            {/* Level pills in header — only for completed runs */}
            {run.status === 'COMPLETED' && LEVEL_ORDER_KEYS.map(lvl => {
              const count = byLevel[lvl] || 0
              if (!count) return null
              return (
                <span key={lvl} className={`badge ${LEVEL_BADGE[lvl] || 'badge-generic'}`}>
                  {count.toLocaleString()} {lvl === 'informational' ? 'info' : lvl.slice(0, 4)}
                </span>
              )
            })}
            {zeroDetected && (
              <span className="badge bg-green-50 text-green-600 border border-green-200">
                ✓ clean
              </span>
            )}
          </div>
          {tsDisplay && (
            <p className="text-[10px] text-gray-500 mt-0.5 font-mono">{tsDisplay}</p>
          )}
          {run.status === 'FAILED' && run.error && (
            <p className="text-xs text-red-600 mt-0.5 line-clamp-2" title={run.error}>
              {run.error}
            </p>
          )}
        </div>
        <ChevronDown
          size={14}
          className={`text-gray-500 flex-shrink-0 mt-0.5 transition-transform ${open ? 'rotate-180' : ''}`}
        />
      </button>

      {(run.status === 'FAILED' || run.status === 'PENDING' || run.status === 'RUNNING') && (
        <div className="px-3 pb-2 flex items-center gap-2">
          {(run.status === 'FAILED' || run.status === 'PENDING') && (
            <button
              onClick={retryRun}
              disabled={retrying}
              className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent hover:text-brand-accenthover flex items-center gap-1"
              title={run.status === 'PENDING' ? 'Re-dispatch stuck run' : 'Retry this module run'}
            >
              <RefreshCw size={11} className={retrying ? 'animate-spin' : ''} />
              {retrying ? '' : (run.status === 'PENDING' ? 'Re-queue' : 'Retry')}
            </button>
          )}
          {(run.status === 'PENDING' || run.status === 'RUNNING') && (
            <button
              onClick={cancelRun}
              disabled={cancelling}
              className="btn-ghost text-xs px-1.5 py-0.5 text-red-500 hover:text-red-600 flex items-center gap-1"
              title="Cancel this module run"
            >
              <X size={11} />
              {cancelling ? 'Cancelling…' : 'Cancel'}
            </button>
          )}
          {retryErr && <span className="text-[10px] text-red-500">{retryErr}</span>}
        </div>
      )}

      {/* ── Expanded body ─────────────────────────────────────── */}
      {open && (
        <div>
          {/* No detections state */}
          {preview.length === 0 && run.status === 'COMPLETED' && (
            <div className="border-t border-gray-100 p-5 text-center bg-green-50/40">
              <CheckCircle size={20} className="text-green-400 mx-auto mb-2" />
              <p className="text-sm font-medium text-gray-700">No detections</p>
              <p className="text-xs text-gray-500 mt-0.5">
                {moduleName} found nothing suspicious in the selected files
              </p>
            </div>
          )}

          {/* Severity accordion groups */}
          {filteredLevels.length === 0 && anyHitsInPreview && (
            <div className="border-t border-gray-100 px-4 py-5 text-center">
              <p className="text-xs text-gray-500">No detections match the active filters.</p>
              <button
                onClick={onResetFilter}
                className="mt-1 text-[11px] text-brand-accent hover:underline"
              >
                Clear filters
              </button>
            </div>
          )}
          {filteredLevels.map(lvl => (
            <LevelGroup
              key={lvl}
              level={lvl}
              hits={hitsByLevel[lvl]}
              totalInLevel={byLevel[lvl] || 0}
              defaultOpen={lvl === 'critical' || lvl === 'high'}
              caseId={caseId}
              runId={run.run_id}
              navigate={navigate}
              buildQuery={buildQuery}
            />
          ))}

          {/* Truncation / filter notice */}
          {preview.length > 0 && (
            <div className="border-t border-gray-100 px-4 py-1.5 text-center">
              <p className="text-[10px] text-gray-500">
                {filteredPreview.length !== preview.length
                  ? <>{filteredPreview.length.toLocaleString()} matched / top {preview.length} by severity{run.total_hits > preview.length && <> of {run.total_hits.toLocaleString()} total</>}</>
                  : <>Top {preview.length} by severity{run.total_hits > preview.length && <> of{' '}<span className="font-semibold text-gray-700">{run.total_hits.toLocaleString()}</span> total</>}</>
                }
              </p>
            </div>
          )}

          {/* Tool output (stdout / log) */}
          {(hasOutput || run.status === 'FAILED') && (
            <div className="border-t border-gray-100 px-4 py-2">
              <button
                onClick={() => setShowOutput(v => !v)}
                className="inline-flex items-center gap-1.5 px-2 py-1 text-[11px] font-medium text-gray-500 hover:text-brand-text rounded-md hover:bg-gray-100 transition-colors"
              >
                <Terminal size={11} />
                Tool output
                <ChevronDown size={10} className={`transition-transform ${showOutput ? 'rotate-180' : ''}`} />
              </button>
              {showOutput && (
                <pre className="mt-2 bg-gray-950 text-green-300 rounded-md p-3 text-[10px] font-mono overflow-x-auto max-h-72 leading-relaxed whitespace-pre-wrap break-all">
                  {toolOutput || run.error || '(no output)'}
                </pre>
              )}
            </div>
          )}

          {/* View in Timeline + AI Analysis */}
          {run.status === 'COMPLETED' && (() => {
            const artType = getModuleArtifactType(run.module_id)
            return (
              <div className="border-t border-gray-100 px-4 py-2 bg-gray-100/30 flex items-center gap-2 flex-wrap">
                {artType && (
                  <button
                    onClick={() => {
                      onClose?.()
                      navigate(`/cases/${caseId}`, { state: { pivotQuery: `artifact_type:${artType}` } })
                    }}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-medium text-brand-accent
                               bg-brand-accentlight border border-brand-accent/20 rounded-md hover:bg-brand-accent/10
                               transition-colors"
                  >
                    <Search size={10} /> Search in Timeline
                  </button>
                )}
                {!analysis ? (
                  <button
                    onClick={runAnalysis}
                    disabled={analyzing}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-[10px] font-medium text-purple-600
                               bg-purple-50 border border-purple-200 rounded-md hover:bg-purple-100
                               disabled:opacity-50 transition-colors"
                  >
                    {analyzing
                      ? <><Loader2 size={10} className="animate-spin" /> Analyzing…</>
                      : <><Sparkles size={10} /> Analyze with AI</>
                    }
                  </button>
                ) : null}
                {analyzeErr && (
                  <p className="text-[10px] text-red-500">{analyzeErr}</p>
                )}
              </div>
            )
          })()}
          {run.status === 'COMPLETED' && analysis && (
            <LLMAnalysisPanel analysis={analysis} />
          )}
        </div>
      )}
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleRunsPanel
// ─────────────────────────────────────────────────────────────────────────────
function ModuleRunsPanel({ caseId, onClose }) {
  const navigate              = useNavigate()
  const [runs, setRuns]       = useState([])
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState(null)

  const [showFilters, setShowFilters]   = useState(false)

  // ── Level filter (hit-level) ───────────────────────────────────────────────
  const [activeLevels, setActiveLevels] = useState(new Set())

  // ── Run-level filters ──────────────────────────────────────────────────────
  const [moduleFilter, setModuleFilter] = useState('')   // '' = all
  const [dateFrom,     setDateFrom]     = useState('')
  const [dateTo,       setDateTo]       = useState('')
  const [flaggedOnly,  setFlaggedOnly]  = useState(false)

  // ── Hit-level filters ──────────────────────────────────────────────────────
  const [ruleSearch,      setRuleSearch]      = useState('')
  const [activeComputers, setActiveComputers] = useState(new Set())
  const [activeChannels,  setActiveChannels]  = useState(new Set())
  const [activeTags,      setActiveTags]      = useState(new Set())

  const fetchRuns = useCallback(() => {
    api.modules.listRuns(caseId)
      .then(r => { setRuns(r.runs || []); setLoadError(null); setLoading(false) })
      .catch(e => { setLoadError(e.message); setLoading(false) })
  }, [caseId])

  useEffect(() => { fetchRuns() }, [fetchRuns])

  // Auto-poll every 3 s while any run is active
  useEffect(() => {
    const hasActive = runs.some(r => r.status === 'PENDING' || r.status === 'RUNNING')
    if (!hasActive) return
    const id = setInterval(fetchRuns, 3000)
    return () => clearInterval(id)
  }, [runs, fetchRuns])

  // Unique module IDs present in the runs list
  const uniqueModuleIds = useMemo(
    () => [...new Set(runs.map(r => r.module_id).filter(Boolean))],
    [runs],
  )

  // Apply run-level filters
  const filteredRuns = useMemo(() => runs.filter(run => {
    if (moduleFilter && run.module_id !== moduleFilter) return false

    const runDate = run.completed_at || run.started_at
    if (runDate) {
      const d = new Date(runDate)
      if (dateFrom && d < new Date(dateFrom))               return false
      if (dateTo   && d > new Date(dateTo + 'T23:59:59'))   return false
    }

    if (flaggedOnly) {
      const bl = run.hits_by_level || {}
      if (!((bl.critical || 0) > 0 || (bl.high || 0) > 0)) return false
    }

    return true
  }), [runs, moduleFilter, dateFrom, dateTo, flaggedOnly])

  const hasActiveRunFilters = moduleFilter || dateFrom || dateTo || flaggedOnly
  const hasActiveHitFilters = activeLevels.size > 0 || ruleSearch.trim() ||
                              activeComputers.size > 0 || activeChannels.size > 0 || activeTags.size > 0
  const hasActiveFilters    = hasActiveRunFilters || hasActiveHitFilters

  // Derive available filter options from the visible run previews
  const { allComputers, allChannels, allTags } = useMemo(() => {
    const computers = new Set()
    const channels  = new Set()
    const tags      = new Set()
    for (const run of filteredRuns) {
      for (const hit of (run.results_preview || [])) {
        if (hit.computer) computers.add(hit.computer)
        if (hit.channel)  channels.add(hit.channel)
        for (const t of (hit.tags || [])) tags.add(t)
      }
    }
    return {
      allComputers: [...computers].sort(),
      allChannels:  [...channels].sort(),
      allTags:      [...tags].sort(),
    }
  }, [filteredRuns])

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[580px] bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            <Cpu size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Module Runs</span>
            {runs.length > 0 && (
              <span className="badge bg-gray-100 text-gray-600">
                {filteredRuns.length !== runs.length
                  ? `${filteredRuns.length} / ${runs.length}`
                  : runs.length}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button onClick={fetchRuns} className="btn-ghost p-1.5 rounded-lg" title="Refresh">
              <RefreshCw size={14} />
            </button>
            <button
              onClick={() => setShowFilters(v => !v)}
              title="Toggle filters"
              className={`btn-ghost p-1.5 rounded-lg flex items-center gap-1 text-xs transition-colors ${showFilters ? 'bg-brand-accent/10 text-brand-accent' : ''}`}
            >
              <Filter size={13} />
              {hasActiveFilters && <span className="w-1.5 h-1.5 rounded-full bg-brand-accent flex-shrink-0" />}
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
              <X size={16} />
            </button>
          </div>
        </div>

        {/* ── Filter panel (collapsible) ─────────────────────────────────── */}
        {showFilters && <div className="border-b border-gray-100 bg-gray-50/60 divide-y divide-gray-100">

          {/* Level filter row */}
          <div className="px-4 py-2 flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0">
              Level
            </span>
            <button
              onClick={() => setActiveLevels(new Set())}
              className={`badge cursor-pointer select-none transition-colors ${
                activeLevels.size === 0
                  ? 'bg-gray-600 text-white border-gray-500'
                  : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
              }`}
            >
              All
            </button>
            {LEVEL_ORDER_KEYS.map(lvl => {
              const active = activeLevels.has(lvl)
              return (
                <button
                  key={lvl}
                  onClick={() =>
                    setActiveLevels(prev => {
                      const next = new Set(prev)
                      if (next.has(lvl)) {
                        next.delete(lvl)
                        if (next.size === 0) return new Set()
                      } else {
                        next.add(lvl)
                      }
                      return next
                    })
                  }
                  className={`badge cursor-pointer select-none transition-colors ${
                    active
                      ? (LEVEL_BADGE[lvl] || 'badge-generic')
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                >
                  {lvl === 'informational' ? 'info' : lvl}
                </button>
              )
            })}
          </div>

          {/* Artifact / module type row */}
          <div className="px-4 py-2 flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0">
              Type
            </span>
            <button
              onClick={() => setModuleFilter('')}
              className={`badge cursor-pointer select-none transition-colors ${
                moduleFilter === ''
                  ? 'bg-gray-600 text-white border-gray-500'
                  : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
              }`}
            >
              All types
            </button>
            {uniqueModuleIds.map(id => (
              <button
                key={id}
                onClick={() => setModuleFilter(prev => prev === id ? '' : id)}
                className={`badge cursor-pointer select-none transition-colors ${
                  moduleFilter === id
                    ? 'bg-brand-accent text-white border-brand-accent'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                {MODULE_NAMES[id] || id}
              </button>
            ))}
          </div>

          {/* Date range + Flagged row */}
          <div className="px-4 py-2 flex items-center gap-2 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0">
              Date
            </span>
            <input
              type="date"
              value={dateFrom}
              onChange={e => setDateFrom(e.target.value)}
              className="text-[11px] border border-gray-200 rounded-md px-2 py-1 text-gray-600 bg-white focus:outline-none focus:ring-1 focus:ring-brand-accent"
              title="From date"
            />
            <span className="text-[10px] text-gray-500">→</span>
            <input
              type="date"
              value={dateTo}
              onChange={e => setDateTo(e.target.value)}
              className="text-[11px] border border-gray-200 rounded-md px-2 py-1 text-gray-600 bg-white focus:outline-none focus:ring-1 focus:ring-brand-accent"
              title="To date"
            />
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => setFlaggedOnly(v => !v)}
                className={`flex items-center gap-1 badge cursor-pointer select-none transition-colors ${
                  flaggedOnly
                    ? 'bg-orange-100 text-orange-700 border-orange-200'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
                title="Show only runs with critical or high detections"
              >
                <Flag size={9} />
                Flagged only
              </button>
            </div>
          </div>

          {/* Rule title search */}
          <div className="px-4 py-2 flex items-center gap-2">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0">
              Rule
            </span>
            <input
              type="text"
              value={ruleSearch}
              onChange={e => setRuleSearch(e.target.value)}
              placeholder="Filter by rule title…"
              className="flex-1 text-[11px] border border-gray-200 rounded-md px-2.5 py-1 text-gray-600 bg-white focus:outline-none focus:ring-1 focus:ring-brand-accent placeholder-gray-300"
            />
            {ruleSearch && (
              <button onClick={() => setRuleSearch('')} className="text-gray-500 hover:text-gray-600">
                <X size={12} />
              </button>
            )}
          </div>

          {/* Computer filter — only shown when >1 computer appears in results */}
          {allComputers.length > 1 && (
            <div className="px-4 py-2 flex items-start gap-1.5 flex-wrap">
              <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0 mt-0.5">
                Host
              </span>
              <button
                onClick={() => setActiveComputers(new Set())}
                className={`badge cursor-pointer select-none transition-colors ${
                  activeComputers.size === 0
                    ? 'bg-gray-600 text-white border-gray-500'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                All
              </button>
              {allComputers.map(c => (
                <button
                  key={c}
                  onClick={() => setActiveComputers(prev => {
                    const next = new Set(prev)
                    if (next.has(c)) { next.delete(c); return next.size === 0 ? new Set() : next }
                    next.add(c); return next
                  })}
                  className={`badge cursor-pointer select-none transition-colors truncate max-w-[140px] ${
                    activeComputers.has(c)
                      ? 'bg-indigo-100 text-indigo-700 border-indigo-200'
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                  title={c}
                >
                  {c}
                </button>
              ))}
            </div>
          )}

          {/* Channel filter — only shown when >1 channel */}
          {allChannels.length > 1 && (
            <div className="px-4 py-2 flex items-start gap-1.5 flex-wrap">
              <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0 mt-0.5">
                Chan
              </span>
              <button
                onClick={() => setActiveChannels(new Set())}
                className={`badge cursor-pointer select-none transition-colors ${
                  activeChannels.size === 0
                    ? 'bg-gray-600 text-white border-gray-500'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                All
              </button>
              {allChannels.map(ch => (
                <button
                  key={ch}
                  onClick={() => setActiveChannels(prev => {
                    const next = new Set(prev)
                    if (next.has(ch)) { next.delete(ch); return next.size === 0 ? new Set() : next }
                    next.add(ch); return next
                  })}
                  className={`badge cursor-pointer select-none transition-colors truncate max-w-[180px] ${
                    activeChannels.has(ch)
                      ? 'bg-teal-100 text-teal-700 border-teal-200'
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                  title={ch}
                >
                  {ch.replace(/^Microsoft-Windows-/, '')}
                </button>
              ))}
            </div>
          )}

          {/* MITRE ATT&CK tags filter — only shown when tags exist */}
          {allTags.length > 0 && (
            <div className="px-4 py-2 flex items-start gap-1.5 flex-wrap">
              <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-10 flex-shrink-0 mt-0.5">
                Tags
              </span>
              <button
                onClick={() => setActiveTags(new Set())}
                className={`badge cursor-pointer select-none transition-colors ${
                  activeTags.size === 0
                    ? 'bg-gray-600 text-white border-gray-500'
                    : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                }`}
              >
                All
              </button>
              {allTags.map(tag => (
                <button
                  key={tag}
                  onClick={() => setActiveTags(prev => {
                    const next = new Set(prev)
                    if (next.has(tag)) { next.delete(tag); return next.size === 0 ? new Set() : next }
                    next.add(tag); return next
                  })}
                  className={`badge cursor-pointer select-none transition-colors truncate max-w-[180px] font-mono ${
                    activeTags.has(tag)
                      ? 'bg-purple-100 text-purple-700 border-purple-200'
                      : 'bg-white text-gray-500 border-gray-200 hover:bg-gray-100'
                  }`}
                  title={tag}
                >
                  {tag.replace(/^attack\./, '')}
                </button>
              ))}
            </div>
          )}

          {/* Clear all filters */}
          {hasActiveFilters && (
            <div className="px-4 py-1.5 flex justify-end">
              <button
                onClick={() => {
                  setModuleFilter(''); setDateFrom(''); setDateTo(''); setFlaggedOnly(false)
                  setActiveLevels(new Set()); setRuleSearch(''); setActiveComputers(new Set())
                  setActiveChannels(new Set()); setActiveTags(new Set())
                }}
                className="text-[10px] text-brand-accent hover:underline"
              >
                Clear all filters
              </button>
            </div>
          )}
        </div>}

        {/* Body */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3">

          {loading ? (
            <div className="flex items-center justify-center py-16 text-gray-500">
              <Loader2 size={20} className="animate-spin mr-2" />
              Loading runs…
            </div>
          ) : runs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-center">
              <Cpu size={40} className="text-gray-500 mb-3" />
              {loadError
                ? <p className="text-xs text-red-400">{loadError}</p>
                : <>
                    <p className="font-medium text-gray-500">No module runs yet</p>
                    <p className="text-sm text-gray-500 mt-1">
                      Launch a module to analyse ingested files
                    </p>
                  </>
              }
            </div>
          ) : filteredRuns.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <Filter size={28} className="text-gray-500 mb-3" />
              <p className="font-medium text-gray-500">No runs match the filters</p>
              <button
                onClick={() => {
                  setModuleFilter(''); setDateFrom(''); setDateTo(''); setFlaggedOnly(false)
                  setActiveLevels(new Set()); setRuleSearch(''); setActiveComputers(new Set())
                  setActiveChannels(new Set()); setActiveTags(new Set())
                }}
                className="mt-2 text-xs text-brand-accent hover:underline"
              >
                Clear all filters
              </button>
            </div>
          ) : (
            filteredRuns.map(run => (
              <ModuleRunCard
                key={run.run_id}
                run={run}
                caseId={caseId}
                navigate={navigate}
                onClose={onClose}
                activeLevels={activeLevels}
                activeComputers={activeComputers}
                activeChannels={activeChannels}
                activeTags={activeTags}
                ruleSearch={ruleSearch}
                onResetFilter={() => {
                  setActiveLevels(new Set()); setRuleSearch(''); setActiveComputers(new Set())
                  setActiveChannels(new Set()); setActiveTags(new Set())
                }}
              />
            ))
          )}
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseTimeline — main page
// ─────────────────────────────────────────────────────────────────────────────
function _currentUser() {
  try { return JSON.parse(localStorage.getItem('fo_user')) } catch { return null }
}

export default function CaseTimeline() {
  const _me = _currentUser()
  const { presence } = useCollab(useParams().caseId, _me)
  const { caseId } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const [searchParams] = useSearchParams()
  const initialQuery = location.state?.pivotQuery || searchParams.get('q') || ''

  const [caseData, setCaseData]             = useState(null)
  const [loading, setLoading]               = useState(true)
  const [editingCompany, setEditingCompany] = useState(false)
  const [companyValue, setCompanyValue]     = useState('')
  const [availableCompanies, setAvailableCompanies] = useState([])
  const [showIngest, setShowIngest]         = useState(false)
  const [runningAlerts, setRunningAlerts]   = useState(false)
  const [showModules, setShowModules]       = useState(false)
  const [showModuleRuns, setShowModuleRuns] = useState(false)
  const [showAlertRules, setShowAlertRules] = useState(false)
  const [showNotes, setShowNotes]           = useState(false)
  const [showIocs, setShowIocs]             = useState(false)
  const [showTemplates, setShowTemplates]   = useState(false)
  const [showReport, setShowReport]         = useState(false)
  const [showAnomaly, setShowAnomaly]       = useState(false)
  const [showProcessTree, setShowProcessTree] = useState(false)
  const [showMitre, setShowMitre]           = useState(false)
  const [showBaseline, setShowBaseline]     = useState(false)
  const [showGraph, setShowGraph]           = useState(false)
  const [showKillChain, setShowKillChain]   = useState(false)
  const [showEvidence, setShowEvidence]     = useState(false)
  const [showCoPilot, setShowCoPilot]       = useState(false)
  const [showAI, setShowAI]                 = useState(false)
  const [iocPivotQuery, setIocPivotQuery]   = useState(null)
  // When react-router pushes a new location.state.pivotQuery (time-window pivot,
  // tag click, IOC search, …), clear the panel-driven iocPivotQuery so the new
  // initialQuery actually reaches Timeline.
  useEffect(() => {
    if (location.state?.pivotQuery) setIocPivotQuery(null)
  }, [location.key])
  const [confirmDelete, setConfirmDelete]   = useState(false)
  const [deleting, setDeleting]             = useState(false)
  const [jobSummary, setJobSummary]         = useState({ active: 0, failed: 0, eventsPerSec: null, totalEvents: 0 })
  const prevJobSnap                         = useRef(null)

  // Poll job counts + compute live events/s rate when the IngestPanel is closed.
  // Suspended while the panel is open — IngestPanel runs its own 3 s batch poller.
  // Adaptive rate: 3s when jobs are active, 30s when all are terminal.
  useEffect(() => {
    if (showIngest) return
    prevJobSnap.current = null
    const ACTIVE = new Set(['RUNNING', 'PENDING', 'UPLOADING'])
    let tid = null
    let cancelled = false

    async function fetchSummary() {
      if (cancelled) return
      try {
        const r    = await api.ingest.listJobs(caseId)
        const jobs = r.jobs || []
        const now  = Date.now()
        const hasActive = jobs.some(j => ACTIVE.has(j.status))

        const totalEvents = jobs
          .filter(j => j.status === 'RUNNING')
          .reduce((s, j) => s + (parseInt(j.events_indexed) || 0), 0)

        let eventsPerSec = null
        if (prevJobSnap.current !== null) {
          const elapsed = (now - prevJobSnap.current.ts) / 1000
          if (elapsed > 0)
            eventsPerSec = Math.max(0, Math.round((totalEvents - prevJobSnap.current.total) / elapsed))
        }
        prevJobSnap.current = { total: totalEvents, ts: now }

        setJobSummary({
          active:      jobs.filter(j => ACTIVE.has(j.status)).length,
          failed:      jobs.filter(j => j.status === 'FAILED').length,
          totalEvents,
          eventsPerSec,
        })

        if (!cancelled) tid = setTimeout(fetchSummary, hasActive ? 3000 : 30000)
      } catch {
        if (!cancelled) tid = setTimeout(fetchSummary, 10000)
      }
    }
    fetchSummary()
    return () => { cancelled = true; clearTimeout(tid) }
  }, [caseId, showIngest])

  const loadCase = useCallback(() => {
    api.cases.get(caseId)
      .then(data => { setCaseData(data); setCompanyValue(data?.company || '') })
      .catch(() => navigate('/'))
      .finally(() => setLoading(false))
  }, [caseId, navigate])

  useEffect(() => { loadCase() }, [loadCase])
  useEffect(() => {
    api.companies.list().then(d => setAvailableCompanies(d.companies || [])).catch(() => {})
  }, [])
  async function runAlerts() {
    setRunningAlerts(true)
    try {
      await api.alertRules.runLibrary(caseId)
    } catch (err) {
      console.error('Alert run failed:', err)
    } finally {
      setRunningAlerts(false)
    }
  }

  function handleRunCreated() {
    setShowModules(false)
    setShowModuleRuns(true)
  }

  async function saveCompany() {
    setEditingCompany(false)
    try {
      const updated = await api.cases.update(caseId, { company: companyValue })
      setCaseData(prev => ({ ...prev, company: updated?.company ?? companyValue }))
    } catch { /* silent */ }
  }

  async function deleteCase() {
    setDeleting(true)
    try {
      await api.cases.delete(caseId)
      navigate('/')
    } catch {
      setDeleting(false)
      setConfirmDelete(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-gray-500">
        <Loader2 size={20} className="animate-spin mr-2" />
        Loading case…
      </div>
    )
  }

  const artifactTypes = caseData?.artifact_types || []

  return (
    <div className="flex flex-col h-full">

      {/* ── Case header ──────────────────────────────────────────────────── */}
      <div className="bg-white border-b border-gray-200 px-4 sm:px-6 py-3 flex flex-wrap items-center gap-x-4 gap-y-2 flex-shrink-0">

        {/* Case name + meta */}
        <div className="flex-1 min-w-0 basis-full lg:basis-auto">
          <div className="flex items-center gap-2 flex-wrap">
            <h1 className="text-base font-semibold text-brand-text truncate">
              {caseData?.name || 'Case'}
            </h1>

            {caseData?.event_count != null && (
              <span className="flex items-center gap-1 badge bg-gray-100 text-gray-600 flex-shrink-0">
                <Database size={10} />
                {(caseData.event_count || 0).toLocaleString()} events
              </span>
            )}

            {/* Live collab presence — who else is in this case right now */}
            {Object.keys(presence || {}).length > 0 && (
              <div className="flex items-center gap-1 flex-shrink-0" title={`Active: ${Object.keys(presence).join(', ')}`}>
                {Object.keys(presence).slice(0, 4).map(u => (
                  <span
                    key={u}
                    className="w-5 h-5 rounded-full bg-brand-accent text-white text-[9px] font-semibold flex items-center justify-center ring-2 ring-white -ml-1 first:ml-0"
                    title={u}
                  >
                    {u.slice(0, 2).toUpperCase()}
                  </span>
                ))}
                {Object.keys(presence).length > 4 && (
                  <span className="text-[10px] text-gray-500 ml-1">+{Object.keys(presence).length - 4}</span>
                )}
              </div>
            )}
          </div>

          {caseData?.description && (
            <p className="text-xs text-gray-500 mt-0.5 truncate">{caseData.description}</p>
          )}
          {/* Case-header artifact_type chip strip removed — duplicated the
              timeline sidebar filter chips and just added visual noise
              (anomaly, file, binary_files, hosts_entry, …). The same list
              is still passed down to <Timeline artifactTypes=… /> so the
              filter sidebar keeps working. */}
          <div className="mt-0.5">
            {editingCompany ? (
              <select
                autoFocus
                value={companyValue}
                onChange={e => {
                  const val = e.target.value
                  setCompanyValue(val)
                  setEditingCompany(false)
                  api.cases.update(caseId, { company: val })
                    .then(updated => setCaseData(prev => ({ ...prev, company: updated?.company ?? val })))
                    .catch(() => {})
                }}
                onKeyDown={e => { if (e.key === 'Escape') { setEditingCompany(false); setCompanyValue(caseData?.company || '') } }}
                className="text-xs border border-brand-accent/50 rounded px-1.5 py-0.5 text-gray-700 focus:outline-none focus:ring-1 focus:ring-brand-accent bg-white"
              >
                <option value="">— no company —</option>
                {availableCompanies.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            ) : (
              <button
                onClick={() => setEditingCompany(true)}
                className="text-xs text-gray-500 hover:text-gray-600 transition-colors"
                title="Click to edit company"
              >
                {companyValue || <span className="italic">Add company…</span>}
              </button>
            )}
          </div>
        </div>


        {/* Action buttons */}
        <div className="flex flex-wrap items-center gap-2 w-full lg:w-auto lg:ml-auto justify-start lg:justify-end">
          <button
            onClick={() => setShowIngest(true)}
            className="btn-primary"
          >
            <Upload size={14} />
            Ingest
            {jobSummary.active > 0 && (
              <span className="ml-1 flex items-center gap-1 bg-white/20 rounded px-1.5 py-px text-[10px] font-mono leading-none">
                <span className="w-1.5 h-1.5 rounded-full bg-white animate-pulse flex-shrink-0" />
                {jobSummary.active}
                {jobSummary.eventsPerSec !== null && (
                  <span className="opacity-75">
                    {' · '}{jobSummary.eventsPerSec > 0
                      ? `${jobSummary.eventsPerSec.toLocaleString()} ev/s`
                      : 'indexing…'}
                  </span>
                )}
              </span>
            )}
            {jobSummary.failed > 0 && (
              <span className="ml-1 bg-red-500 rounded px-1.5 py-px text-[10px] font-mono">
                ⚠ {jobSummary.failed}
              </span>
            )}
          </button>

          {/* AI (Pilot) — autonomous investigation */}
          <button
            onClick={() => setShowAI(v => !v)}
            className={`btn-outline ${showAI ? 'bg-purple-50 border-purple-300 text-purple-700' : ''}`}
            title="Pilot — autonomous AI investigation of this case"
          >
            <Sparkles size={14} />
            AI
          </button>

          {/* Detect — find what's suspicious */}
          <ToolbarMenu
            label="Detect"
            icon={<Bell size={14} />}
            anyActive={showAlertRules || showAnomaly || showBaseline || showMitre}
            items={[
              { key: 'rules', label: 'Detection Rules', icon: <Bell size={13} />, active: showAlertRules,
                title: 'Run the Sigma/EQL rule library against this case',
                onClick: () => setShowAlertRules(v => !v) },
              { key: 'anomaly', label: 'Anomalies', icon: <Activity size={13} />, active: showAnomaly,
                title: 'Statistical z-score outliers (host × event_id × day)',
                onClick: () => setShowAnomaly(true) },
              { key: 'baseline', label: 'Baseline / rare artifacts', icon: <Layers size={13} />, active: showBaseline,
                title: 'Stack a field; surface values rare across the case but present on a host',
                onClick: () => setShowBaseline(true) },
              { key: 'mitre', label: 'MITRE coverage', icon: <Target size={13} />, active: showMitre,
                title: 'ATT&CK technique coverage for this case',
                onClick: () => setShowMitre(true) },
            ]}
          />

          {/* Investigate — dig into and pivot around findings */}
          <ToolbarMenu
            label="Investigate"
            icon={<Crosshair size={14} />}
            anyActive={showIocs || showProcessTree || showGraph || showKillChain || showCoPilot}
            items={[
              { key: 'iocs', label: 'IOCs', icon: <Crosshair size={13} />, active: showIocs,
                title: 'Observed indicators + threat-intel matching',
                onClick: () => setShowIocs(v => !v) },
              { key: 'ptree', label: 'Process Tree', icon: <GitBranch size={13} />, active: showProcessTree,
                title: 'Parent→child process chains (EVTX / Sysmon / auditd)',
                onClick: () => setShowProcessTree(true) },
              { key: 'graph', label: 'Entity graph', icon: <Network size={13} />, active: showGraph,
                title: 'Host ↔ user ↔ IP relationships (lateral movement)',
                onClick: () => setShowGraph(true) },
              { key: 'killchain', label: 'Kill chain', icon: <Crosshair size={13} />, active: showKillChain,
                title: 'Assemble the attack story around an anchor event',
                onClick: () => setShowKillChain(true) },
              { key: 'copilot', label: 'Co-Pilot — watch & memory', icon: <Bot size={13} />, active: showCoPilot,
                title: "What's new since you last looked + cross-case IOC memory",
                onClick: () => setShowCoPilot(true) },
            ]}
          />

          {/* Case — document, template, report, prove integrity */}
          <ToolbarMenu
            label="Case"
            icon={<FileText size={14} />}
            anyActive={showNotes || showTemplates || showReport || showEvidence}
            items={[
              { key: 'notes', label: 'Notes', icon: <FileText size={13} />, active: showNotes,
                title: 'Free-form case notes',
                onClick: () => setShowNotes(v => !v) },
              { key: 'templates', label: 'Templates', icon: <LayoutTemplate size={13} />,
                title: 'Apply a pre-canned investigation template (ransomware / insider / phishing)',
                onClick: () => setShowTemplates(true) },
              { key: 'report', label: 'Report', icon: <FileDown size={13} />,
                title: 'Generate a Markdown / HTML case report',
                onClick: () => setShowReport(true) },
              { key: 'evidence', label: 'Evidence chain', icon: <Shield size={13} />, active: showEvidence,
                title: 'Signed chain-of-custody — verify integrity, export court-ready manifest',
                onClick: () => setShowEvidence(true) },
            ]}
          />

          <button
            onClick={() => { setShowModules(true); setShowModuleRuns(false) }}
            className="btn-outline"
            title="Run analysis modules (Hayabusa, YARA, CAPA, Volatility…)"
          >
            <Cpu size={14} />
            Modules
          </button>

          {/* View runs shortcut — only when runs panel is closed */}
          {!showModuleRuns && (
            <button
              onClick={() => { setShowModuleRuns(true); setShowModules(false) }}
              className="btn-ghost p-1.5 rounded-lg text-gray-500 hover:text-brand-accent"
              title="View module runs"
            >
              <Clock size={14} />
            </button>
          )}

          {/* Delete case — two-click confirmation */}
          {confirmDelete ? (
            <div className="flex items-center gap-1.5 bg-red-50 border border-red-200 rounded-lg px-2 py-1">
              <span className="text-xs text-red-700 font-medium whitespace-nowrap">Delete case?</span>
              <button
                onClick={deleteCase}
                disabled={deleting}
                className="text-[11px] font-semibold text-white bg-red-500 hover:bg-red-600 rounded px-2 py-0.5 transition-colors disabled:opacity-50"
              >
                {deleting ? 'Deleting…' : 'Confirm'}
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="text-[11px] text-gray-500 hover:text-gray-700"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setConfirmDelete(true)}
              className="btn-ghost p-1.5 rounded-lg text-gray-500 hover:text-red-500"
              title="Delete this case"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>

      {/* ── Timeline ─────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-hidden">
        <Timeline
          key={(iocPivotQuery || initialQuery) || '_'}
          caseId={caseId}
          artifactTypes={artifactTypes}
          initialQuery={iocPivotQuery || initialQuery}
        />
      </div>

      {/* ── Modals / Panels ───────────────────────────────────────────────── */}
      {showIngest && (
        <IngestPanel
          caseId={caseId}
          onClose={() => setShowIngest(false)}
          onComplete={() => loadCase()}
        />
      )}

      {showAI && (
        <CaseAiPanel
          caseId={caseId}
          onClose={() => setShowAI(false)}
          onSearchQuery={q => {
            setIocPivotQuery(q)
            setShowAI(false)
          }}
          onOpenReport={() => {
            setShowAI(false)
            setShowReport(true)
          }}
        />
      )}

      {showNotes && (
        <div className="panel-backdrop" onClick={() => setShowNotes(false)}>
          <div
            className="absolute right-0 top-0 h-full w-[560px] bg-white border-l border-gray-200 flex flex-col"
            style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
              <div className="flex items-center gap-2">
                <FileText size={16} className="text-brand-accent" />
                <span className="font-semibold text-brand-text">Investigation Report</span>
              </div>
              <button onClick={() => setShowNotes(false)} className="btn-ghost p-1.5 rounded-lg">
                <X size={16} />
              </button>
            </div>
            <div className="flex-1 min-h-0 overflow-hidden">
              <CaseNotes caseId={caseId} />
            </div>
          </div>
        </div>
      )}

      {showIocs && (
        <div className="panel-backdrop" onClick={() => setShowIocs(false)}>
          <div
            className="absolute right-0 top-0 h-full w-[480px] bg-white border-l border-gray-200 flex flex-col"
            style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
              <div className="flex items-center gap-2">
                <Crosshair size={16} className="text-red-500" />
                <span className="font-semibold text-brand-text">Observed IOCs</span>
              </div>
              <button onClick={() => setShowIocs(false)} className="btn-ghost p-1.5 rounded-lg">
                <X size={16} />
              </button>
            </div>
            <div className="flex-1 overflow-hidden">
              <IocPanel
                caseId={caseId}
                onSearch={q => {
                  setIocPivotQuery(q)
                  setShowIocs(false)
                }}
              />
            </div>
          </div>
        </div>
      )}

      {showAlertRules && (
        <div className="panel-backdrop" onClick={() => setShowAlertRules(false)}>
          <div
            className="absolute right-0 top-0 h-full w-[760px] bg-white border-l border-gray-200 flex flex-col overflow-y-auto"
            style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 flex-shrink-0">
              <div className="flex items-center gap-2">
                <Bell size={15} className="text-yellow-500" />
                <span className="font-semibold text-brand-text text-sm">Detection Rules</span>
              </div>
              <button onClick={() => setShowAlertRules(false)} className="btn-ghost p-1.5 rounded-lg">
                <X size={16} />
              </button>
            </div>
            <AlertRules
              caseId={caseId}
              onSearchQuery={q => {
                setShowAlertRules(false)
                navigate(`/cases/${caseId}`, { state: { pivotQuery: q } })
              }}
            />
          </div>
        </div>
      )}

      {showModules && (
        <ModuleLaunchModal
          caseId={caseId}
          onClose={() => setShowModules(false)}
          onRunCreated={handleRunCreated}
        />
      )}

      {showModuleRuns && (
        <ModuleRunsPanel
          caseId={caseId}
          onClose={() => setShowModuleRuns(false)}
        />
      )}

      {showTemplates && (
        <TemplatesPanel
          caseId={caseId}
          onClose={() => setShowTemplates(false)}
        />
      )}

      {showReport && (
        <ReportPanel
          caseId={caseId}
          onClose={() => setShowReport(false)}
        />
      )}

      {showAnomaly && (
        <AnomalyPanel
          caseId={caseId}
          onClose={() => setShowAnomaly(false)}
          onPivot={q => { setIocPivotQuery(q); setShowAnomaly(false) }}
        />
      )}

      {showProcessTree && (
        <ProcessTreePanel
          caseId={caseId}
          onClose={() => setShowProcessTree(false)}
          onPivot={q => { setIocPivotQuery(q); setShowProcessTree(false) }}
        />
      )}

      {showMitre && (
        <MitrePanel
          caseId={caseId}
          onClose={() => setShowMitre(false)}
          onPivot={q => { setIocPivotQuery(q); setShowMitre(false) }}
        />
      )}

      {showBaseline && (
        <BaselinePanel
          caseId={caseId}
          onClose={() => setShowBaseline(false)}
          onPivot={q => { setIocPivotQuery(q); setShowBaseline(false) }}
        />
      )}

      {showGraph && (
        <EntityGraphPanel
          caseId={caseId}
          onClose={() => setShowGraph(false)}
          onPivot={q => { setIocPivotQuery(q); setShowGraph(false) }}
        />
      )}

      {showKillChain && (
        <KillChainPanel
          caseId={caseId}
          onClose={() => setShowKillChain(false)}
          onPivot={q => { setIocPivotQuery(q); setShowKillChain(false) }}
        />
      )}

      {showCoPilot && (
        <CoPilotPanel
          caseId={caseId}
          onClose={() => setShowCoPilot(false)}
          onPivot={q => { setIocPivotQuery(q); setShowCoPilot(false) }}
        />
      )}

      {showEvidence && (
        <EvidencePanel
          caseId={caseId}
          onClose={() => setShowEvidence(false)}
        />
      )}

    </div>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// TemplatesPanel — apply a pre-canned investigation kit (ransomware / insider /
// phishing). Lists `/case-templates`, applies via `/cases/{id}/apply-template`.
// Side-effects on apply: seeds watchlist IOCs, adds case tags, seeds notes
// skeleton (only if notes empty).
// ─────────────────────────────────────────────────────────────────────────────
// Inline editor for create / edit / clone of a custom case template.
const WL_KINDS = ['cmdline', 'regex', 'domain', 'ip', 'hash', 'filename', 'user', 'host']
function TemplateEditor({ editor, saving, error, onChange, onSave, onCancel, setWlRow, addWlRow, removeWlRow }) {
  if (editor.loading) {
    return (
      <div className="card p-4 flex items-center justify-center gap-2 text-xs text-gray-500">
        <Loader2 size={12} className="animate-spin" /> Loading template…
      </div>
    )
  }
  const upd = (patch) => onChange(prev => ({ ...prev, ...patch }))
  return (
    <div className="card p-4 space-y-3 border-indigo-200 bg-indigo-50/30">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-gray-900">
          {editor.editingId ? 'Edit template' : 'New template'}
        </span>
        <button onClick={onCancel} className="btn-ghost p-1 rounded"><X size={13} /></button>
      </div>

      {error && <div className="text-[11px] text-red-700 bg-red-50 border border-red-200 rounded p-2">{error}</div>}

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Name</label>
        <input value={editor.name} onChange={e => upd({ name: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5" placeholder="e.g. BEC investigation" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Description</label>
        <input value={editor.description} onChange={e => upd({ description: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Tags (comma-separated)</label>
        <input value={editor.tags} onChange={e => upd({ tags: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5" placeholder="phishing, bec" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Watchlist IOCs</label>
        <div className="space-y-1.5">
          {editor.watchlist.map((w, i) => (
            <div key={i} className="flex items-center gap-1.5">
              <select value={w.kind} onChange={e => setWlRow(i, { kind: e.target.value })}
                className="text-[11px] border border-gray-300 rounded px-1.5 py-1 bg-white">
                {WL_KINDS.map(k => <option key={k} value={k}>{k}</option>)}
              </select>
              <input value={w.value} onChange={e => setWlRow(i, { value: e.target.value })}
                className="flex-1 min-w-0 text-[11px] border border-gray-300 rounded px-2 py-1" placeholder="value" />
              <input value={w.label} onChange={e => setWlRow(i, { label: e.target.value })}
                className="flex-1 min-w-0 text-[11px] border border-gray-300 rounded px-2 py-1" placeholder="label (optional)" />
              <button onClick={() => removeWlRow(i)} className="btn-ghost p-1 rounded text-gray-400 hover:text-red-600"><Trash2 size={11} /></button>
            </div>
          ))}
        </div>
        <button onClick={addWlRow} className="text-[10px] text-brand-accent hover:underline flex items-center gap-1 mt-1.5">
          <Plus size={10} /> Add IOC
        </button>
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Rule categories (comma-separated)</label>
        <input value={editor.rule_categories} onChange={e => upd({ rule_categories: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5 font-mono"
          placeholder="sigma_hq/01_initial_access, sigma_hq/02_execution" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Notes (markdown)</label>
        <textarea value={editor.notes} onChange={e => upd({ notes: e.target.value })} rows={6}
          className="w-full text-[11px] border border-gray-300 rounded px-2 py-1.5 font-mono" />
      </div>

      <div className="flex items-center justify-end gap-2 pt-1">
        <button onClick={onCancel} className="btn-ghost text-xs">Cancel</button>
        <button onClick={onSave} disabled={saving} className="btn-primary text-xs flex items-center gap-1.5">
          {saving ? <><Loader2 size={11} className="animate-spin" /> Saving…</> : 'Save template'}
        </button>
      </div>
    </div>
  )
}

function TemplatesPanel({ caseId, onClose }) {
  const navigate = useNavigate()
  const isAdmin = _currentUser()?.role === 'admin'
  const [list, setList]         = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)

  // Per-template expanded state: { [tplId]: { loading, checks, tags, notes } }
  const [expanded, setExpanded] = useState({})
  // Per-template seed status
  const [seeding, setSeeding]   = useState(null)
  const [seedResult, setSeedResult] = useState(null)

  // Editor state. `editor` is null when closed; otherwise the working draft.
  // `editor.editingId` = id being updated (null = create / clone).
  const [editor, setEditor]   = useState(null)
  const [saving, setSaving]   = useState(false)
  const [editorErr, setEditorErr] = useState(null)

  function refresh() {
    return api.caseTemplates.list()
      .then(r => setList(r.templates || []))
      .catch(e => setError(e.message || 'Failed to load templates.'))
  }

  useEffect(() => {
    refresh().finally(() => setLoading(false))
  }, [])

  const EMPTY_DRAFT = {
    editingId: null, name: '', description: '', tags: '',
    watchlist: [{ kind: 'cmdline', value: '', label: '' }],
    rule_categories: '', notes: '',
  }

  function openNew() {
    setEditorErr(null)
    setEditor({ ...EMPTY_DRAFT, watchlist: [{ kind: 'cmdline', value: '', label: '' }] })
  }

  async function openEdit(tplId, { clone = false } = {}) {
    setEditorErr(null)
    setEditor({ loading: true })
    try {
      const f = await api.caseTemplates.getFull(tplId)
      const wl = (f.watchlist || []).map(w => ({ kind: w.kind, value: w.value, label: w.label || '' }))
      setEditor({
        editingId: clone ? null : tplId,
        name: clone ? `${f.name} (copy)` : f.name,
        description: f.description || '',
        tags: (f.tags || []).join(', '),
        watchlist: wl.length ? wl : [{ kind: 'cmdline', value: '', label: '' }],
        rule_categories: (f.rule_categories || []).join(', '),
        notes: f.notes || '',
      })
    } catch (e) {
      setEditor(null)
      setError(e.message || 'Failed to load template for editing.')
    }
  }

  async function saveEditor() {
    if (!editor || editor.loading) return
    if (!editor.name.trim()) { setEditorErr('Name is required.'); return }
    const payload = {
      name: editor.name.trim(),
      description: editor.description.trim(),
      tags: editor.tags,
      watchlist: editor.watchlist.filter(w => w.kind && w.value.trim()),
      rule_categories: editor.rule_categories,
      notes: editor.notes,
    }
    setSaving(true); setEditorErr(null)
    try {
      if (editor.editingId) await api.caseTemplates.update(editor.editingId, payload)
      else await api.caseTemplates.create(payload)
      setEditor(null)
      await refresh()
    } catch (e) {
      setEditorErr(e.message || 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  async function deleteTemplate(tplId) {
    if (!confirm('Delete this custom template? This cannot be undone.')) return
    setError(null)
    try {
      await api.caseTemplates.remove(tplId)
      setExpanded(prev => { const n = { ...prev }; delete n[tplId]; return n })
      await refresh()
    } catch (e) {
      setError(e.message || 'Delete failed.')
    }
  }

  function setWlRow(i, patch) {
    setEditor(prev => ({ ...prev, watchlist: prev.watchlist.map((w, j) => j === i ? { ...w, ...patch } : w) }))
  }
  function addWlRow() {
    setEditor(prev => ({ ...prev, watchlist: [...prev.watchlist, { kind: 'cmdline', value: '', label: '' }] }))
  }
  function removeWlRow(i) {
    setEditor(prev => ({ ...prev, watchlist: prev.watchlist.filter((_, j) => j !== i) }))
  }

  async function toggleExpand(tplId) {
    if (expanded[tplId]) {
      setExpanded(prev => { const next = { ...prev }; delete next[tplId]; return next })
      return
    }
    // Load detail (with pre-run hit counts per check)
    setExpanded(prev => ({ ...prev, [tplId]: { loading: true } }))
    try {
      const d = await api.caseTemplates.detail(caseId, tplId)
      setExpanded(prev => ({ ...prev, [tplId]: { loading: false, ...d } }))
    } catch (e) {
      setExpanded(prev => ({ ...prev, [tplId]: { loading: false, error: e.message || 'Failed to load template' } }))
    }
  }

  async function seedAll(tplId) {
    if (!confirm(
      'Seed this case with the template?\n\n' +
      '• Adds IOCs to the GLOBAL watchlist\n' +
      '• Appends scenario tags to this case\n' +
      '• Writes the notes skeleton (only if your notes are empty)\n\n' +
      'Continue?'
    )) return
    setSeeding(tplId); setSeedResult(null); setError(null)
    try {
      const r = await api.caseTemplates.apply(caseId, tplId)
      setSeedResult(r)
    } catch (e) {
      setError(e.message || 'Seeding failed.')
    } finally {
      setSeeding(null)
    }
  }

  function pivot(q) {
    navigate(`/cases/${caseId}`, { state: { pivotQuery: q } })
    onClose()
  }

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[640px] max-w-full bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <LayoutTemplate size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Investigation playbooks</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <p className="text-[11px] text-gray-500 leading-relaxed flex-1">
              Each playbook is a curated checklist of scenario-specific queries
              (run against this case right now — hit counts are live) plus an
              optional seed-the-watchlist + notes-skeleton bundle for analysts who
              want the magic-apply behaviour.
            </p>
            {isAdmin && !editor && (
              <button onClick={openNew} className="btn-primary text-xs flex items-center gap-1.5 flex-shrink-0 whitespace-nowrap">
                <Plus size={12} /> New template
              </button>
            )}
          </div>

          {editor && (
            <TemplateEditor
              editor={editor}
              saving={saving}
              error={editorErr}
              onChange={setEditor}
              onSave={saveEditor}
              onCancel={() => setEditor(null)}
              setWlRow={setWlRow}
              addWlRow={addWlRow}
              removeWlRow={removeWlRow}
            />
          )}

          {error && (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200">{error}</div>
          )}
          {seedResult && (
            <div className="card p-3 text-xs text-emerald-700 bg-emerald-50 border-emerald-200">
              Seeded <strong>{seedResult.template}</strong> · {seedResult.watchlist_seeded} watchlist
              entries · tags: {seedResult.tags_added.join(', ')}
              {!seedResult.notes_seeded && <em className="block mt-1 text-emerald-600/70">Notes left untouched — already populated.</em>}
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center gap-2 text-xs text-gray-500 py-6">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : list.length === 0 ? (
            <div className="text-xs text-gray-500 italic text-center py-6">No playbooks available.</div>
          ) : (
            list.map(t => {
              const exp = expanded[t.id]
              const open = !!exp
              return (
                <div key={t.id} className="card overflow-hidden">
                  {/* Header — click to expand */}
                  <button
                    onClick={() => toggleExpand(t.id)}
                    className="w-full text-left p-4 flex items-start justify-between gap-3 hover:bg-gray-50 transition-colors"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <ChevronRight size={12} className={`text-gray-400 transition-transform ${open ? 'rotate-90' : ''}`} />
                        <span className="text-sm font-semibold text-gray-900">{t.name}</span>
                        {t.builtin
                          ? <span className="badge text-[9px] bg-gray-100 text-gray-500">built-in</span>
                          : <span className="badge text-[9px] bg-indigo-100 text-indigo-700">custom</span>}
                      </div>
                      <p className="text-[11px] text-gray-600 mt-0.5 ml-4">{t.description}</p>
                      <div className="flex flex-wrap gap-1 mt-2 ml-4">
                        {(t.tags || []).map(tag => (
                          <span key={tag} className="badge text-[10px] bg-gray-100 text-gray-600">{tag}</span>
                        ))}
                        <span className="badge text-[10px] bg-gray-100 text-gray-500">
                          {t.watchlist_count} check{t.watchlist_count === 1 ? '' : 's'}
                        </span>
                      </div>
                    </div>
                  </button>

                  {isAdmin && !editor && (
                    <div className="flex items-center gap-3 px-4 pb-2 -mt-1 ml-4">
                      {t.builtin ? (
                        <button onClick={() => openEdit(t.id, { clone: true })} className="text-[10px] text-brand-accent hover:underline flex items-center gap-1">
                          <Copy size={10} /> Clone
                        </button>
                      ) : (
                        <>
                          <button onClick={() => openEdit(t.id)} className="text-[10px] text-brand-accent hover:underline flex items-center gap-1">
                            <Pencil size={10} /> Edit
                          </button>
                          <button onClick={() => deleteTemplate(t.id)} className="text-[10px] text-red-600 hover:underline flex items-center gap-1">
                            <Trash2 size={10} /> Delete
                          </button>
                        </>
                      )}
                    </div>
                  )}

                  {/* Expanded: per-check hit counts + actions */}
                  {open && (
                    <div className="border-t border-gray-100 p-3 space-y-2 bg-gray-50/50">
                      {exp.loading ? (
                        <div className="flex items-center justify-center gap-2 text-xs text-gray-500 py-4">
                          <Loader2 size={12} className="animate-spin" /> Running checks against this case…
                        </div>
                      ) : exp.error ? (
                        <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded p-2">{exp.error}</div>
                      ) : (
                        <>
                          <p className="text-[10px] text-gray-500 mb-1">
                            Hit counts are live for this case. Click <strong>Pivot</strong> to open the
                            timeline filtered by that check.
                          </p>
                          {(exp.checks || []).map((c, i) => {
                            const hits = c.result_count
                            const empty = hits === 0
                            return (
                              <div
                                key={i}
                                className={`border rounded bg-white ${empty ? 'border-gray-200' : 'border-amber-200'}`}
                              >
                                <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-gray-100">
                                  <span className="text-xs font-medium text-brand-text flex-1 truncate">{c.label}</span>
                                  {typeof hits === 'number' ? (
                                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded tabular-nums ${
                                      empty ? 'bg-gray-100 text-gray-500' : 'bg-amber-100 text-amber-800'
                                    }`}>
                                      {hits.toLocaleString()} {hits === 1 ? 'hit' : 'hits'}
                                    </span>
                                  ) : (
                                    <span className="text-[10px] text-gray-400">—</span>
                                  )}
                                  <button
                                    onClick={() => pivot(c.query)}
                                    disabled={empty}
                                    className={`text-[10px] font-medium flex items-center gap-1 ${
                                      empty
                                        ? 'text-gray-400 cursor-not-allowed'
                                        : 'text-brand-accent hover:underline'
                                    }`}
                                  >
                                    Pivot <ExternalLink size={9} />
                                  </button>
                                </div>
                                <code className="block text-[10px] font-mono text-gray-600 px-2.5 py-1 break-all">
                                  {c.query}
                                </code>
                              </div>
                            )
                          })}

                          {/* Seed-the-watchlist button — optional, kept for the
                              old "apply" flow but no longer the default action. */}
                          <div className="pt-2 mt-2 border-t border-gray-200">
                            <p className="text-[10px] text-gray-500 mb-1.5">
                              Optional: seed the global watchlist with these IOCs + append
                              scenario tags + drop a notes skeleton (notes only if empty).
                            </p>
                            <button
                              onClick={() => seedAll(t.id)}
                              disabled={seeding === t.id}
                              className="btn-secondary text-xs flex items-center gap-1.5 w-full justify-center"
                            >
                              {seeding === t.id
                                ? <><Loader2 size={11} className="animate-spin" /> Seeding…</>
                                : <><Play size={11} /> Seed watchlist + tags + notes</>
                              }
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}

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
function ReportPanel({ caseId, onClose }) {
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

  // ── Module-run selection — feeds the AI report's prompt. Empty = include
  //    every completed run. Lives here (not in CaseNotes) because choosing
  //    what evidence the AI sees is a Report-time decision.
  const [moduleRuns, setModuleRuns] = useState([])
  const [runsLoading, setRunsLoading] = useState(true)
  const [selectedRunIds, setSelectedRunIds] = useState(new Set())

  useEffect(() => {
    api.cases.aiResults(caseId)
      .then(d => { if (d.report) setAiReport(d.report) })
      .catch(() => {})
      .finally(() => setAiLoading(false))

    api.modules.listRuns(caseId)
      .then(r => setModuleRuns((r.runs || []).filter(x => x.status === 'COMPLETED')))
      .catch(() => {})
      .finally(() => setRunsLoading(false))
  }, [caseId])

  function toggleRun(id) {
    setSelectedRunIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  async function generateAi() {
    setAiGen(true); setAiError(null)
    try {
      const runIds = selectedRunIds.size > 0 ? [...selectedRunIds] : undefined
      const res = await api.cases.aiReport(caseId, runIds)
      setAiReport(res)
    } catch (e) {
      setAiError(e.message || 'Report generation failed.')
    } finally {
      setAiGen(false)
    }
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

  async function download(fmt) {
    setBusy(fmt); setError(null)
    try {
      const token = getToken()
      const url = fmt === 'html'
        ? `/api/v1/cases/${caseId}/report.html`
        : `/api/v1/cases/${caseId}/report.md`
      const res = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const blob = await res.blob()
      const objectUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = objectUrl
      a.download = `case-${caseId}-report.${fmt === 'html' ? 'html' : 'md'}`
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
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="absolute right-0 top-0 h-full w-[640px] max-w-full bg-white border-l border-gray-200 flex flex-col"
        style={{ boxShadow: '-4px 0 24px rgba(0,0,0,0.10)' }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <FileDown size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Report</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <p className="text-[11px] text-gray-500">
            One place for all case deliverables — AI narrative summary on top,
            downloadable artifacts below. Both pull from current case state.
          </p>

          {error && (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200">{error}</div>
          )}

          {/* ── AI Investigation Report ───────────────────────────────── */}
          <div className="card p-4">
            <div className="flex items-center justify-between gap-3 mb-3">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-purple-50">
                  <Sparkles size={14} className="text-purple-600" />
                </div>
                <div>
                  <div className="text-sm font-semibold text-gray-900">AI investigation summary</div>
                  <div className="text-[10px] text-gray-500">
                    {aiEnabled
                      ? 'Generated from flagged events + module findings'
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
                  <button
                    onClick={generateAi}
                    disabled={aiGenerating}
                    className="btn-primary text-xs flex items-center gap-1.5"
                  >
                    {aiGenerating
                      ? <><Loader2 size={11} className="animate-spin" /> Generating…</>
                      : <><FileBarChart size={11} /> {aiReport ? 'Regenerate' : 'Generate'}</>
                    }
                  </button>
                )}
              </div>
            </div>

            {aiError && (
              <div className="text-[11px] text-red-700 bg-red-50 border border-red-200 rounded px-2 py-1 mb-2">
                {aiError}
              </div>
            )}

            {aiLoading ? (
              <div className="flex items-center justify-center py-6 text-xs text-gray-500 gap-2">
                <Loader2 size={12} className="animate-spin" /> Loading…
              </div>
            ) : aiReport ? (
              <>
                <div className="text-[10px] text-gray-500 mb-2">
                  Generated {new Date(aiReport.generated_at).toLocaleString()}
                  {aiReport.model_used && <> · {aiReport.model_used}</>}
                  {typeof aiReport.flagged_count === 'number' && <> · {aiReport.flagged_count} flagged</>}
                </div>
                <pre className="text-[11px] text-gray-700 leading-relaxed bg-gray-50 border border-gray-200 rounded-lg p-3 whitespace-pre-wrap font-mono overflow-auto max-h-[50vh]">
                  {aiReport.content}
                </pre>
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
          </div>

          {/* ── Module runs to include (drives AI prompt) ────────────── */}
          <div className="card p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 rounded-lg bg-emerald-50">
                <Cpu size={14} className="text-emerald-600" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-semibold text-gray-900 flex items-center gap-1.5">
                  Module results to include
                  {selectedRunIds.size > 0 && (
                    <span className="text-[10px] bg-brand-accent text-white font-bold rounded-full px-1.5 py-px">
                      {selectedRunIds.size}
                    </span>
                  )}
                </div>
                <div className="text-[10px] text-gray-500">
                  {selectedRunIds.size === 0
                    ? 'None ticked → AI sees all completed runs.'
                    : `${selectedRunIds.size} run${selectedRunIds.size > 1 ? 's' : ''} pinned for the AI report.`}
                </div>
              </div>
              {selectedRunIds.size > 0 && (
                <button
                  onClick={() => setSelectedRunIds(new Set())}
                  className="btn-ghost text-[10px] text-gray-500 hover:text-gray-700"
                >
                  Clear
                </button>
              )}
            </div>

            {runsLoading ? (
              <div className="flex items-center justify-center py-3 text-xs text-gray-500 gap-2">
                <Loader2 size={11} className="animate-spin" /> Loading…
              </div>
            ) : moduleRuns.length === 0 ? (
              <div className="text-[11px] text-gray-500 italic py-2">
                No completed module runs yet. Trigger one from the Modules button.
              </div>
            ) : (
              <div className="max-h-48 overflow-y-auto border border-gray-100 rounded">
                {moduleRuns.map(run => {
                  const selected = selectedRunIds.has(run.run_id)
                  const ts = run.completed_at || run.started_at
                  return (
                    <label
                      key={run.run_id}
                      className={`flex items-center gap-2 px-2 py-1.5 cursor-pointer border-b border-gray-100 last:border-b-0 ${
                        selected ? 'bg-brand-accent/5' : 'hover:bg-gray-50'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={selected}
                        onChange={() => toggleRun(run.run_id)}
                        className="rounded border-gray-300 accent-brand-accent flex-shrink-0"
                      />
                      <div className="min-w-0 flex-1">
                        <div className="text-[11px] font-medium text-brand-text truncate">
                          {MODULE_NAMES[run.module_id] || run.module_id}
                        </div>
                        {ts && (
                          <div className="text-[10px] text-gray-500">
                            {new Date(ts).toLocaleString()}
                          </div>
                        )}
                      </div>
                      {run.total_hits > 0 ? (
                        <span className="text-[10px] font-semibold text-orange-600 flex-shrink-0">
                          {run.total_hits.toLocaleString()} hits
                        </span>
                      ) : (
                        <span className="text-[10px] text-green-600 flex-shrink-0">clean</span>
                      )}
                    </label>
                  )
                })}
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
                <div className="text-sm font-semibold text-gray-900">Formal report</div>
                <div className="text-[10px] text-gray-500">
                  Notes + flagged + pinned + IOCs + module runs. Server-rendered.
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2">
              {/* Markdown card */}
              <div className="border border-gray-200 rounded-lg p-3">
                <div className="text-xs font-semibold text-gray-900 mb-0.5">Markdown</div>
                <p className="text-[10px] text-gray-500 mb-2">
                  Diff-friendly. Paste into a ticket or commit to a case repo.
                </p>
                <button
                  onClick={() => download('md')}
                  disabled={busy === 'md'}
                  className="btn-primary text-xs flex items-center gap-1.5 w-full justify-center"
                >
                  {busy === 'md' ? <Loader2 size={11} className="animate-spin" /> : <Download size={11} />}
                  .md
                </button>
              </div>

              {/* HTML card */}
              <div className="border border-gray-200 rounded-lg p-3">
                <div className="text-xs font-semibold text-gray-900 mb-0.5">HTML</div>
                <p className="text-[10px] text-gray-500 mb-2">
                  Printable. Browser → Print → Save as PDF for legal-hold.
                </p>
                <div className="flex gap-1">
                  <button
                    onClick={openHtml}
                    disabled={busy === 'html-view'}
                    className="btn-secondary text-xs flex items-center gap-1 flex-1 justify-center"
                  >
                    {busy === 'html-view' ? <Loader2 size={11} className="animate-spin" /> : <ExternalLink size={11} />}
                    Preview
                  </button>
                  <button
                    onClick={() => download('html')}
                    disabled={busy === 'html'}
                    className="btn-primary text-xs flex items-center gap-1 flex-1 justify-center"
                  >
                    {busy === 'html' ? <Loader2 size={11} className="animate-spin" /> : <Download size={11} />}
                    .html
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
