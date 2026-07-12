import { Fragment, Suspense, lazy, useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useParams, useNavigate, useLocation, useSearchParams } from 'react-router-dom'
import {
  Upload,
  Search,
  Bell,
  X,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Clock,
  Database,
  Loader2,
  Shield,
  Cpu,
  RefreshCw,
  Plus,
  Download,
  Play,
  Terminal,
  AlertCircle,
  ChevronDown,
  FileCode,
  ExternalLink,
  Flag,
  Filter,
  Sparkles,
  FileText,
  Trash2,
  Crosshair,
  Monitor,
  HardDrive,
  Globe,
  Brain,
  Binary,
  Bug,
  Network,
  FileImage,
  TextSearch,
  Tag,
  Target,
  LayoutTemplate,
  FileDown,
  Printer,
  FileBarChart,
  Pencil,
  Copy,
  ClipboardCheck,
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
// Heavy, only-when-opened panels — split into their own chunks to lighten the
// first paint of the case view (backed by Suspense boundaries at their sites).
const IngestPanel = lazy(() => import('../components/IngestPanel'))
const CaseAiPanel = lazy(() => import('../components/CaseAiPanel'))
import ToolbarMenu from '../components/shared/ToolbarMenu'
import { buildToolbarGroups, CASE_CAPABILITIES, readLegacyPanelState } from './caseCapabilities'
import { CASE_PANELS } from './casePanels'
import PanelHelp from '../components/shared/PanelHelp'
import { ResizableDrawer } from '../components/shared/resizableDrawer'
import { useLicense } from '../contexts/LicenseContext'
import { useCollab } from '../hooks/useCollab'
import { usePersistedState } from '../hooks/usePersistedState'
import { severityStyle, levelBadgeClass, SEVERITY_ORDER } from '../utils/severity'
import { MODULE_NAMES, currentUser } from '../utils/caseConstants'
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

// Severity colours + ordering are canonical in utils/severity (levelBadgeClass,
// SEVERITY_ORDER) — no local duplicate.

// MODULE_NAMES / FINDING_KIND_LABELS moved to utils/caseConstants so the
// extracted case panels (ReportPanel, …) share the same single copy.

// ─────────────────────────────────────────────────────────────────────────────
// AlertResultsPanel
// ─────────────────────────────────────────────────────────────────────────────
function AlertResultsPanel({ results, caseId, onClose }) {
  const { matches = [], rules_checked = 0 } = results
  const navigate = useNavigate()

  return (
    <ResizableDrawer slug="alertResults" defaultWidth={580} onClose={onClose}>
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
          <PanelHelp
            title="Alert Results"
            use="Shows which detection rules fired against this case, how many events each matched, and sample hits."
            when="Right after running the rule library — to triage what lit up before diving into the timeline."
            tip="Expand a rule, then click a sample event or 'View all…' to pivot the timeline to those hits."
          />
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
    </ResizableDrawer>
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
// ModuleLaunchModal
// ─────────────────────────────────────────────────────────────────────────────
// Resilient fetch: aborts each attempt after `timeoutMs` and retries with
// linear backoff. Tolerates cold-starting / slow API instead of giving up
// after a single short window. `fn` receives an AbortSignal.
async function withRetry(fn, { attempts = 4, timeoutMs = 15000, onAttempt } = {}) {
  let lastErr
  for (let i = 0; i < attempts; i++) {
    if (onAttempt) onAttempt(i + 1, attempts)
    const ctrl = new AbortController()
    const to = setTimeout(() => ctrl.abort(), timeoutMs)
    try {
      return await fn(ctrl.signal)
    } catch (e) {
      lastErr = e
      if (i < attempts - 1) {
        await new Promise(r => setTimeout(r, Math.min(1500 * (i + 1), 5000)))
      }
    } finally {
      clearTimeout(to)
    }
  }
  throw lastErr
}

function ModuleLaunchModal({ caseId, onClose, onRunCreated, onViewRuns, embedded = false }) {
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
  const [catFilter, setCatFilter]           = useState(null)   // null = all categories
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
  const [retrying, setRetrying]             = useState(false)   // loading attempt > 1
  const [sourcesLoading, setSourcesLoading] = useState(true)
  const [sourcesError, setSourcesError]     = useState(null)
  const mountedRef                          = useRef(true)
  useEffect(() => () => { mountedRef.current = false }, [])

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

  // Modules (left panel) and sources (right panel) load INDEPENDENTLY so a slow
  // sources scan never blanks the module list, and each retries on its own with
  // backoff to ride out a cold-starting API.
  const loadModules = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await withRetry(
        signal => api.modules.list({ signal }),
        { onAttempt: n => { if (mountedRef.current) setRetrying(n > 1) } },
      )
      if (!mountedRef.current) return
      setModules((r.modules || []).filter(m => m.available))
    } catch (e) {
      if (mountedRef.current)
        setError('Could not load modules: ' + (e?.message || 'server unreachable') + ' — retry below.')
    } finally {
      if (mountedRef.current) { setLoading(false); setRetrying(false) }
    }
  }, [])

  const loadSources = useCallback(async () => {
    setSourcesLoading(true)
    setSourcesError(null)
    try {
      const r = await withRetry(signal => api.modules.listSources(caseId, { signal }))
      if (!mountedRef.current) return
      setSources(r.sources || [])
    } catch (e) {
      if (mountedRef.current)
        setSourcesError(e?.message || 'Could not load case files')
    } finally {
      if (mountedRef.current) setSourcesLoading(false)
    }
  }, [caseId])

  useEffect(() => { loadModules() }, [loadModules])
  useEffect(() => { loadSources() }, [loadSources])

  useEffect(() => {
    // Best-effort: ranked module suggestions for this case's file mix
    let cancelled = false
    withRetry(signal => api.modules.recommended(caseId, { signal }), { attempts: 2 })
      .then(r => {
        if (cancelled) return
        const counts = {}
        for (const m of r.recommended || []) counts[m.id] = m.matched_files
        setRecommendedCounts(counts)
      })
      .catch(() => {})
    return () => { cancelled = true }
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

  // Category chips — every category present, in canonical order.
  const allCategories = useMemo(() => {
    const set = new Set(modules.map(m => m.category || 'Other'))
    return [...set].sort((a, b) => {
      const ai = MOD_CATEGORY_ORDER.indexOf(a), bi = MOD_CATEGORY_ORDER.indexOf(b)
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return a.localeCompare(b)
    })
  }, [modules])

  // Group modules by category for the left panel. A text search or an active
  // category chip both narrow the list; the "Recommended" group only appears on
  // the unfiltered view.
  const groupedModules = useMemo(() => {
    const q = moduleSearch.toLowerCase().trim()
    let filtered = q
      ? modules.filter(m =>
          (m.name || '').toLowerCase().includes(q) ||
          (m.description || '').toLowerCase().includes(q) ||
          (m.category || '').toLowerCase().includes(q) ||
          (m.tags || []).some(t => t.toLowerCase().includes(q))
        )
      : modules
    if (catFilter) filtered = filtered.filter(m => (m.category || 'Other') === catFilter)
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
    if (!q && !catFilter) {
      const recs = filtered
        .filter(m => recommendedCounts[m.id] > 0)
        .sort((a, b) => recommendedCounts[b.id] - recommendedCounts[a.id])
        .slice(0, 6)
      if (recs.length > 0) sorted.unshift(['Recommended', recs])
    }
    return sorted
  }, [modules, moduleSearch, catFilter, recommendedCounts])

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

  const inner = (
    <>
        {/* ── Header ────────────────────────────────────────────────────────── */}
        {!embedded && (
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-200 bg-gray-50 flex-shrink-0">
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded-lg bg-brand-accent/15 flex items-center justify-center flex-shrink-0">
              <Play size={13} className="text-brand-accent" />
            </div>
            <div>
              <p className="font-semibold text-brand-text text-sm leading-tight">Run Analysis Module</p>
              <p className="text-[11px] text-gray-500 leading-tight mt-px">Select module → pick files → launch · watch progress in Runs &amp; results</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            {onViewRuns && (
              <button onClick={onViewRuns} className="btn-ghost text-[11px] px-2 py-1 rounded-lg flex items-center gap-1" title="See status / progress / failures of launched runs">
                <Clock size={13} /> Run status
              </button>
            )}
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
              <X size={15} />
            </button>
          </div>
        </div>
        )}

        {loading ? (
          <div className="flex-1 flex flex-col items-center justify-center text-gray-500 gap-1">
            <div className="flex items-center"><Loader2 size={20} className="animate-spin mr-2" /> Loading modules…</div>
            {retrying && <p className="text-[11px] text-gray-400">API waking up — retrying…</p>}
          </div>
        ) : error && modules.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center text-gray-500 gap-3 px-8 text-center">
            <AlertTriangle size={22} className="text-amber-500" />
            <p className="text-sm text-brand-text font-medium">Couldn’t load modules</p>
            <p className="text-xs text-gray-500 max-w-sm">{error}</p>
            <button onClick={() => { loadModules(); loadSources() }} className="btn-primary text-xs px-4 py-1.5 flex items-center gap-1.5">
              <RefreshCw size={12} /> Retry
            </button>
          </div>
        ) : (
          <div className="flex-1 flex overflow-hidden min-h-0">

            {/* ── Left: module chooser ──────────────────────────────────────── */}
            <div className="w-[320px] flex-shrink-0 border-r border-gray-200 flex flex-col bg-gray-50">

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
                    <button onClick={() => setModuleSearch('')} title="Clear search"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600">
                      <X size={10} />
                    </button>
                  )}
                </div>
              </div>

              {/* Category filter chips */}
              {allCategories.length > 1 && (
                <div className="px-3 pb-2 flex-shrink-0 flex flex-wrap gap-1">
                  <button
                    onClick={() => setCatFilter(null)}
                    title="Show all categories"
                    className={`px-2 py-0.5 rounded-full text-[10px] font-medium border transition-colors ${
                      !catFilter ? 'bg-brand-accent text-white border-brand-accent' : 'bg-white text-gray-500 border-gray-200 hover:border-brand-accent'
                    }`}
                  >All</button>
                  {allCategories.map(cat => (
                    <button
                      key={cat}
                      onClick={() => setCatFilter(c => c === cat ? null : cat)}
                      title={`Show only ${cat} modules`}
                      className={`px-2 py-0.5 rounded-full text-[10px] font-medium border transition-colors inline-flex items-center gap-1 ${
                        catFilter === cat ? 'bg-brand-accent text-white border-brand-accent' : 'bg-white text-gray-600 border-gray-200 hover:border-brand-accent'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              )}

              {/* Module list — every row is self-describing (icon + name + one-liner) */}
              <div className="flex-1 overflow-y-auto px-2 pb-3">
                {groupedModules.length === 0 ? (
                  <p className="text-xs text-gray-500 italic text-center py-8">No modules match</p>
                ) : groupedModules.map(([category, mods]) => (
                  <div key={category} className="mb-2">
                    <div className="flex items-center gap-2 px-1 pt-3 pb-1.5 sticky top-0 bg-gray-50 z-10">
                      {MOD_CATEGORY_ICONS[category] || <Cpu size={12} className="text-gray-400 flex-shrink-0" />}
                      <span className="text-[10px] font-bold uppercase tracking-widest text-gray-500 flex-1">
                        {category}
                      </span>
                      <span className="text-[10px] text-gray-500">{mods.length}</span>
                    </div>

                    <div className="space-y-0.5">
                      {mods.map(mod => {
                        const isSelected = selectedModule?.id === mod.id
                        const isAvailable = mod.available !== false
                        const recN = recommendedCounts[mod.id] || 0
                        return (
                          <button
                            key={mod.id}
                            onClick={() => selectModule(mod)}
                            title={isAvailable ? (mod.description || mod.name) : `${mod.name} — not available on this deployment`}
                            className={`w-full text-left px-2.5 py-2 rounded-lg border transition-all ${
                              isSelected
                                ? 'border-brand-accent bg-brand-accentlight'
                                : isAvailable
                                  ? 'border-transparent hover:bg-gray-100 hover:border-gray-200'
                                  : 'border-transparent opacity-40 cursor-not-allowed'
                            }`}
                            disabled={!isAvailable}
                          >
                            <div className="flex items-start gap-2">
                              <span className="mt-0.5 flex-shrink-0">
                                {MOD_CATEGORY_ICONS[mod.category] || <Cpu size={13} className="text-gray-400" />}
                              </span>
                              <div className="min-w-0 flex-1">
                                <div className="flex items-center gap-1.5">
                                  <p className={`font-medium text-xs leading-tight flex-1 truncate ${isSelected ? 'text-brand-accent' : 'text-brand-text'}`}>
                                    {mod.name}
                                  </p>
                                  {recN > 0 && (
                                    <span className="px-1.5 py-px rounded text-[9px] font-medium bg-emerald-50 text-emerald-600 border border-emerald-200 flex-shrink-0"
                                      title={`${recN} file${recN > 1 ? 's' : ''} in this case match this module's inputs`}>
                                      {recN} file{recN > 1 ? 's' : ''}
                                    </span>
                                  )}
                                </div>
                                {mod.description && (
                                  <p className={`text-[10px] mt-0.5 leading-snug ${isSelected ? 'text-brand-accent/70' : 'text-gray-500'} ${isSelected ? '' : 'line-clamp-1'}`}>
                                    {mod.description}
                                  </p>
                                )}
                                {isSelected && (mod.tags || []).length > 0 && (
                                  <div className="flex flex-wrap gap-1 mt-1">
                                    {mod.tags.slice(0, 4).map(tag => (
                                      <span key={tag} className="px-1.5 py-px rounded text-[9px] font-medium bg-brand-accent/10 text-brand-accent">
                                        {tag}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
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
                    Choose a module on the left, then select which ingested files to run it against.
                    Modules with a green badge already have matching files in this case.
                  </p>
                </div>
              ) : (
                <>
                  {/* Selected module info bar */}
                  <div className="px-4 pt-3.5 pb-3 border-b border-gray-200 flex-shrink-0 bg-gray-50">
                    <div className="flex items-start gap-2.5">
                      <span className="mt-0.5 flex-shrink-0">
                        {MOD_CATEGORY_ICONS[selectedModule.category] || <Cpu size={15} className="text-brand-accent" />}
                      </span>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="font-semibold text-sm text-brand-text">{selectedModule.name}</p>
                          {selectedModule.category && (
                            <span className="text-[9px] uppercase tracking-wider text-gray-400 font-semibold">{selectedModule.category}</span>
                          )}
                        </div>
                        {selectedModule.description && (
                          <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{selectedModule.description}</p>
                        )}
                        {/* What this module eats — makes the file step self-explanatory */}
                        {(() => {
                          const ins = [...(selectedModule.input_extensions || []), ...(selectedModule.input_filenames || [])]
                          const label = ins.length === 0 || ins.some(e => e === '*' || e === '.*') ? 'any file' : ins.join(', ')
                          return (
                            <p className="text-[10px] text-gray-500 mt-1">
                              <span className="font-semibold text-gray-500">Accepts:</span>{' '}
                              <span className="font-mono text-gray-600">{label}</span>
                            </p>
                          )
                        })()}
                        {(selectedModule.tags || []).length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {selectedModule.tags.slice(0, 5).map(tag => (
                              <span key={tag} className="px-1.5 py-px rounded text-[9px] font-medium bg-gray-100 text-gray-600 border border-gray-200">
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Step 1 — choose files */}
                  <div className="flex items-center justify-between px-4 pt-3 pb-1.5 flex-shrink-0">
                    <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 flex items-center gap-1.5">
                      <span className="w-4 h-4 rounded-full bg-brand-accent/15 text-brand-accent inline-flex items-center justify-center text-[9px] font-bold">1</span>
                      Choose files
                      {compatibleSources.length > 0 && (
                        <span className="font-normal normal-case text-gray-400">
                          — {selectedJobs.size} of {compatibleSources.length} selected
                        </span>
                      )}
                    </p>
                    {compatibleSources.length > 0 && (
                      <div className="flex items-center gap-2">
                        {selectedJobs.size < compatibleSources.length && (
                          <button onClick={selectAll} className="text-[11px] text-brand-accent hover:underline" title="Select all compatible files">
                            All
                          </button>
                        )}
                        {selectedJobs.size > 0 && (
                          <button onClick={() => setSelectedJobs(new Set())} className="text-[11px] text-gray-500 hover:text-gray-700 hover:underline" title="Deselect all">
                            Clear
                          </button>
                        )}
                      </div>
                    )}
                  </div>

                  {sourcesLoading ? (
                    <div className="mx-4 mb-3 p-3 text-xs text-gray-500 flex items-center gap-2">
                      <Loader2 size={14} className="animate-spin" /> Loading case files…
                    </div>
                  ) : sourcesError ? (
                    <div className="mx-4 mb-3 p-3 bg-red-50 border border-red-200 rounded-lg text-xs text-red-600 flex items-center justify-between gap-2">
                      <span className="truncate" title={sourcesError}>Couldn’t load case files: {sourcesError}</span>
                      <button onClick={loadSources} className="btn-outline text-[11px] px-2 py-1 flex items-center gap-1 flex-shrink-0">
                        <RefreshCw size={10} /> Retry
                      </button>
                    </div>
                  ) : compatibleSources.length === 0 ? (
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
              : <><Sparkles size={11} /> Run all applicable</>
            }
          </button>

          {error && (
            <div className="flex-1 flex items-center gap-2 min-w-0">
              <p className="flex-1 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-1.5 truncate" title={error}>
                {error}
              </p>
              <button
                onClick={() => { loadModules(); loadSources() }}
                className="btn-outline text-xs px-2.5 py-1.5 flex items-center gap-1 flex-shrink-0"
              >
                <RefreshCw size={11} /> Retry
              </button>
            </div>
          )}

          <div className="ml-auto flex items-center gap-2 min-w-0">
            {/* Plain-language run summary — what's about to happen */}
            {!error && (
              <p className="text-[11px] text-gray-500 truncate hidden sm:block" title={
                !selectedModule ? 'Pick a module first'
                : selectedJobs.size === 0 ? 'Select at least one file'
                : `Run ${selectedModule.name} on ${selectedJobs.size} file${selectedJobs.size > 1 ? 's' : ''}`
              }>
                {!selectedModule ? 'Pick a module'
                  : selectedJobs.size === 0 ? 'Select at least one file'
                  : <>Ready: <span className="font-semibold text-gray-700">{selectedModule.name}</span> × {selectedJobs.size} file{selectedJobs.size > 1 ? 's' : ''}</>}
              </p>
            )}
            <button
              onClick={handleRun}
              disabled={!canRun}
              className={`btn flex items-center gap-1.5 text-xs px-4 py-1.5 font-semibold flex-shrink-0 ${
                canRun ? 'btn-primary' : 'opacity-40 cursor-not-allowed bg-gray-100 text-gray-500 border-gray-200'
              }`}
              title={canRun ? `Launch ${selectedModule?.name} on ${selectedJobs.size} file${selectedJobs.size > 1 ? 's' : ''}` : 'Pick a module and at least one file'}
            >
              {running
                ? <><Loader2 size={12} className="animate-spin" /> Launching…</>
                : <><Play size={12} /> Run{selectedJobs.size > 0 ? ` on ${selectedJobs.size}` : ''}</>
              }
            </button>
          </div>
        </div>
    </>
  )
  if (embedded) return <div className="flex flex-col h-full min-h-0">{inner}</div>
  return (
    <ResizableDrawer slug="moduleLaunch" defaultWidth={860} onClose={onClose}>
      {inner}
    </ResizableDrawer>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModuleRunCard
// ─────────────────────────────────────────────────────────────────────────────
const LEVEL_ORDER_KEYS = SEVERITY_ORDER  // canonical order (utils/severity)

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
  run, caseId, navigate, onClose, onRunOptimistic, onRefreshRuns,
  // Hit-level filters (all optional — undefined = no filtering)
  activeLevels, activeComputers, activeChannels, activeTags, ruleSearch,
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
    // Optimistically flip to PENDING so the card reflects the re-queue immediately
    // and the parent's 3 s status poller re-arms (it watches for PENDING/RUNNING).
    onRunOptimistic?.(run.run_id, 'PENDING')
    try {
      await api.modules.retryRun(run.run_id)
      // Pull fresh state right away rather than waiting a full poll tick.
      onRefreshRuns?.()
    } catch (err) {
      setRetryErr(err.message)
      // Re-sync so the card doesn't stay stuck on the optimistic PENDING.
      onRefreshRuns?.()
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
                <span key={lvl} className={`badge ${levelBadgeClass(lvl)}`}>
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

          {/* Detections are indexed as findings (artifact_type:finding). The
              card summarises them inline; the button pivots the timeline to this
              run's detections. Pinning meaningful ones into the report happens
              in the Report panel's "Module results to include" section. */}
          {preview.length > 0 && (
            <div className="border-t border-gray-100 px-4 py-3 bg-amber-50/40">
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <p className="text-xs text-gray-600">
                  <span className="font-semibold text-gray-800">{run.total_hits.toLocaleString()}</span> detection{run.total_hits === 1 ? '' : 's'} —
                  {Object.entries(byLevel).filter(([, n]) => n).length > 0 && (
                    <span className="ml-1">
                      {Object.entries(byLevel).filter(([, n]) => n)
                        .map(([lvl, n]) => `${n} ${lvl}`).join(', ')}
                    </span>
                  )}
                </p>
                <button
                  onClick={() => { onClose?.(); navigate(`/cases/${caseId}`, { state: { pivotQuery: `artifact_type:finding AND (source_feature:"${run.module_id}" OR tags:"${run.module_id}" OR provenance.module_id:"${run.module_id}")` } }) }}
                  className="btn-ghost text-[11px] px-2 py-1 rounded-lg inline-flex items-center gap-1 text-amber-700"
                  title="Show this run's detections in the timeline"
                >
                  <Search size={12} /> View {run.total_hits.toLocaleString()} in timeline
                </button>
              </div>
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
function ModuleRunsPanel({ caseId, onClose, embedded = false }) {
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

  const inner = (
    <>
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200">
          <div className="flex items-center gap-2">
            {!embedded && <Cpu size={16} className="text-brand-accent" />}
            <span className="font-semibold text-brand-text">{embedded ? 'Runs & results' : 'Module run status'}</span>
            {runs.length > 0 && (
              <span className="badge bg-gray-100 text-gray-600">
                {filteredRuns.length !== runs.length
                  ? `${filteredRuns.length} / ${runs.length}`
                  : runs.length}
              </span>
            )}
          </div>
          <div className="flex items-center gap-1.5">
            <button onClick={fetchRuns} className="btn-ghost p-1.5 rounded-lg" title="Refresh run list">
              <RefreshCw size={14} />
            </button>
            <button
              onClick={() => setShowFilters(v => !v)}
              title="Toggle filters — narrow by level, module, date, host, channel or MITRE tag"
              className={`btn-ghost p-1.5 rounded-lg flex items-center gap-1 text-xs transition-colors ${showFilters ? 'bg-brand-accent/10 text-brand-accent' : ''}`}
            >
              <Filter size={13} />
              {hasActiveFilters && <span className="w-1.5 h-1.5 rounded-full bg-brand-accent flex-shrink-0" />}
            </button>
            {!embedded && (
              <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
                <X size={16} />
              </button>
            )}
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
                      ? levelBadgeClass(lvl)
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
          <PanelHelp
            title="Module run status"
            use="Live status of every module you launched — PENDING / RUNNING / COMPLETED / FAILED — with logs, retry, and cancel."
            when="After launching modules, to confirm they finished (or catch and retry a failure), then open a run to see its detections."
            data={['At least one launched module run for this case']}
            tip="Use the funnel to filter by level, module, date, host, channel or MITRE tag. Auto-refreshes every 3s while runs are active."
          />

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
                onRunOptimistic={(runId, status) =>
                  setRuns(prev => prev.map(r => r.run_id === runId ? { ...r, status } : r))}
                onRefreshRuns={fetchRuns}
                activeLevels={activeLevels}
                activeComputers={activeComputers}
                activeChannels={activeChannels}
                activeTags={activeTags}
                ruleSearch={ruleSearch}
              />
            ))
          )}
        </div>
    </>
  )
  if (embedded) return <div className="flex flex-col h-full min-h-0">{inner}</div>
  return (
    <ResizableDrawer slug="moduleRuns" defaultWidth={580} onClose={onClose}>
      {inner}
    </ResizableDrawer>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// ModulesPanel — one home for module analysis: pick & launch, plus live run
// status + logs + results. Two views behind a segmented switch so the whole
// module workflow lives in a single, resizable, self-explaining panel.
// ─────────────────────────────────────────────────────────────────────────────
function ModulesPanel({ caseId, onClose, initialView = 'launch', onRunCreated }) {
  const [view, setView] = usePersistedState(`fo_modulesview_${caseId}`, initialView)

  return (
    <ResizableDrawer slug="modules" defaultWidth={880} onClose={onClose}>
      {/* Unified header — icon + title + segmented view switch + close */}
      <div className="flex items-center justify-between gap-3 px-5 py-3 border-b border-gray-200 bg-gray-50 flex-shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <Cpu size={16} className="text-brand-accent flex-shrink-0" />
          <span className="font-semibold text-brand-text">Modules</span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <div className="flex gap-0.5 bg-gray-100 rounded-lg p-0.5">
            {[
              { id: 'launch', label: 'Launch', Icon: Play, title: 'Pick a module and files, then run it' },
              { id: 'runs',   label: 'Runs & results', Icon: Clock, title: 'Live status, logs and detections of launched runs' },
            ].map(({ id, label, Icon, title }) => (
              <button
                key={id}
                onClick={() => setView(id)}
                title={title}
                className={`text-xs px-3 py-1 rounded-md transition-colors inline-flex items-center gap-1.5 ${
                  view === id ? 'bg-white shadow-sm text-brand-text font-semibold' : 'text-gray-500 hover:text-gray-700'
                }`}
              >
                <Icon size={12} /> {label}
              </button>
            ))}
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>
      </div>

      <div className="px-4 pt-3 flex-shrink-0">
        <PanelHelp
          title="Modules"
          use="Runs forensic analysis tools (Hayabusa, YARA, CAPA, Volatility, RegRipper…) against ingested files. Launch here; watch progress, logs and detections under Runs & results."
          when="After ingesting evidence — to extract detections a raw timeline scan would miss."
          data={['Ingested case files matching a module’s declared inputs (the Launch view highlights compatible modules)']}
          tip="Launch auto-switches to Runs & results. Meaningful detections can be pinned into the case report."
        />
      </div>

      {/* Body — one embedded view at a time, both content-only (no own drawer) */}
      <div className="flex-1 min-h-0 flex flex-col">
        {view === 'launch' ? (
          <ModuleLaunchModal
            caseId={caseId}
            embedded
            onClose={onClose}
            onRunCreated={(run) => { onRunCreated?.(run); setView('runs') }}
            onViewRuns={() => setView('runs')}
          />
        ) : (
          <ModuleRunsPanel caseId={caseId} embedded onClose={onClose} />
        )}
      </div>
    </ResizableDrawer>
  )
}

// ─────────────────────────────────────────────────────────────────────────────
// CaseTimeline — main page
// ─────────────────────────────────────────────────────────────────────────────
export default function CaseTimeline() {
  const _me = currentUser()
  const { presence } = useCollab(useParams().caseId, _me)
  const { caseId } = useParams()
  // Toolbar is agile: capabilities the current licence doesn't advertise are
  // hidden rather than shown as dead buttons.
  const license = useLicense()
  const aiEnabled = !!license?.features?.ai_assist
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
  // Panel open/close state — persisted per-case so the analyst's Detect /
  // Investigate / Case / AI workspace survives reload, nav, and browser
  // restart. Capability panels live in ONE map (fo_panels_<caseId>) keyed by
  // capability id; legacy per-panel keys are migrated on first read.
  // Unified Modules panel: launch + live run status/logs/results in one drawer.
  // `modulesView` seeds which view it opens on ('launch' | 'runs').
  const [showModules, setShowModules]       = usePersistedState(`fo_panel_modules_${caseId}`, false)
  const [modulesView, setModulesView]       = useState('launch')
  const legacyPanels = useMemo(() => readLegacyPanelState(caseId), [caseId])
  const [panels, setPanels]                 = usePersistedState(`fo_panels_${caseId}`, legacyPanels)
  const openPanel   = useCallback(id => setPanels(p => ({ ...p, [id]: true })),  [setPanels])
  const closePanel  = useCallback(id => setPanels(p => ({ ...p, [id]: false })), [setPanels])
  const togglePanel = useCallback(id => setPanels(p => ({ ...p, [id]: !p[id] })), [setPanels])
  const [showAI, setShowAI]                 = usePersistedState(`fo_panel_ai_${caseId}`, false)
  // Auto-pilot: kick off an autonomous AI investigation the moment evidence
  // ingestion finishes (active jobs fall to 0). Persisted opt-out per case.
  // Default OFF — the analyst decides when to launch the AI (and with what
  // context). Opt in via the Auto-AI toggle if you want hands-off triage.
  const [autoPilot, setAutoPilot]           = usePersistedState(`fo_autopilot_${caseId}`, false)
  const autoPilotRef                        = useRef(autoPilot)
  useEffect(() => { autoPilotRef.current = autoPilot }, [autoPilot])
  const prevActiveRef                       = useRef(null)
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

  // Auto-launch an autonomous AI run when ingest completes. Best-effort:
  // skips if an agent is already running, reuses the analyst's saved scenario
  // (fo_ai_circ_<caseId>) if present, else a generic triage prompt. Opens the
  // AI panel so the live run is visible on return.
  const launchAutoPilot = useCallback(async () => {
    try {
      const active = await api.cases.aiAgentActive(caseId).catch(() => null)
      if (active?.runs?.some(r => r.status === 'running')) { setShowAI(true); return }
      let circ = ''
      try { circ = localStorage.getItem(`fo_ai_circ_${caseId}`) || '' } catch { /* ignore */ }
      const scenario = circ.trim() ||
        'Evidence ingestion just completed. Perform an autonomous triage of this case: ' +
        'identify suspicious activity, likely attacker actions, lateral movement, persistence, ' +
        'and notable IOCs. Conclude with a risk assessment.'
      await api.cases.aiAgentStart(caseId, scenario)
      setShowAI(true)
    } catch { /* best-effort — analyst can launch manually */ }
  }, [caseId, setShowAI])

  // Poll job counts + compute live events/s rate when the IngestPanel is closed.
  // Suspended while the panel is open — IngestPanel runs its own 3 s batch poller.
  // Adaptive rate: 3s when jobs are active, 30s when all are terminal.
  useEffect(() => {
    if (showIngest) return
    prevJobSnap.current = null
    prevActiveRef.current = null
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

        const activeCount = jobs.filter(j => ACTIVE.has(j.status)).length
        setJobSummary({
          active:      activeCount,
          failed:      jobs.filter(j => j.status === 'FAILED').length,
          totalEvents,
          eventsPerSec,
        })

        // Ingest-complete edge: active jobs just fell from >0 to 0. Auto-launch
        // the AI investigation so a walked-away analyst returns to a finished
        // (or in-flight) triage. Fires once per completion; guarded against an
        // already-running agent inside launchAutoPilot.
        const prevActive = prevActiveRef.current
        prevActiveRef.current = activeCount
        if (autoPilotRef.current && prevActive != null && prevActive > 0 && activeCount === 0) {
          launchAutoPilot()
        }

        if (!cancelled) tid = setTimeout(fetchSummary, hasActive ? 3000 : 30000)
      } catch {
        if (!cancelled) tid = setTimeout(fetchSummary, 10000)
      }
    }
    fetchSummary()
    return () => { cancelled = true; clearTimeout(tid) }
  }, [caseId, showIngest, launchAutoPilot])

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

  // ── Data-driven toolbar ─────────────────────────────────────────────────────
  // The Detect / Investigate / Case menus are generated from the capability
  // registry (caseCapabilities.jsx), so the toolbar advertises only what THIS
  // case + the active licence can do. Here we just wire each capability id to
  // its open/close handler + active state; the registry owns labels + gating.
  const hasEvents = (caseData?.event_count || 0) > 0
  const capabilityWiring = Object.fromEntries(
    CASE_CAPABILITIES.map(cap => [cap.id, {
      active: !!panels[cap.id],
      onClick: () => togglePanel(cap.id),
    }])
  )
  const toolbarGroups = buildToolbarGroups({
    features: license?.features || {},
    hasEvents,
    wiring: capabilityWiring,
  })

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
            title="Add evidence — upload files, import from S3, or run a server-side harvest"
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

          {/* AI (Pilot) — opens the investigation panel. The Auto-AI toggle
              lives in the Ingest panel (armed alongside evidence), not here. */}
          {aiEnabled && (
            <button
              onClick={() => setShowAI(v => !v)}
              className={`btn-outline ${showAI ? 'bg-purple-50 border-purple-300 text-purple-700' : ''}`}
              title="Pilot — autonomous AI investigation of this case"
            >
              <Sparkles size={14} />
              AI
            </button>
          )}

          {/* Detect / Investigate / Case — generated from the capability list
              above so the toolbar only advertises what this case can do. */}
          {toolbarGroups.map(g => (
            <ToolbarMenu
              key={g.key}
              label={g.label}
              icon={g.icon}
              anyActive={g.items.some(i => i.active)}
              items={g.items}
            />
          ))}

          <button
            onClick={() => { setModulesView('launch'); setShowModules(true) }}
            className={`btn-outline ${showModules ? 'bg-brand-accentlight border-brand-accent/40 text-brand-accent' : ''}`}
            title="Modules — launch analysis tools (Hayabusa, YARA, CAPA, Volatility…) and watch their runs, logs and detections in one panel."
          >
            <Cpu size={14} />
            Modules
          </button>

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
        <Suspense fallback={null}>
          <IngestPanel
            caseId={caseId}
            onClose={() => setShowIngest(false)}
            onComplete={() => loadCase()}
            autoPilot={autoPilot}
            setAutoPilot={aiEnabled ? setAutoPilot : undefined}
          />
        </Suspense>
      )}

      {showAI && (
        <Suspense fallback={null}>
          <CaseAiPanel
            caseId={caseId}
            onClose={() => setShowAI(false)}
            onSearchQuery={q => {
              setIocPivotQuery(q)
              setShowAI(false)
            }}
            onOpenReport={() => {
              setShowAI(false)
              openPanel('report')
            }}
          />
        </Suspense>
      )}

      {/* Capability panels — rendered generically from the registry pair
          (caseCapabilities + casePanels). Each open capability id gets its
          renderer with the same {caseId, close, pivot, navigate} contract. */}
      {CASE_CAPABILITIES.filter(cap => panels[cap.id] && CASE_PANELS[cap.id]).map(cap => (
        <Suspense key={cap.id} fallback={null}>
          {CASE_PANELS[cap.id]({
            caseId,
            navigate,
            close: () => closePanel(cap.id),
            pivot: q => { setIocPivotQuery(q); closePanel(cap.id) },
          })}
        </Suspense>
      ))}

      {showModules && (
        <ModulesPanel
          caseId={caseId}
          initialView={modulesView}
          onClose={() => setShowModules(false)}
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
        <button onClick={onCancel} className="btn-ghost p-1 rounded" aria-label="Cancel"><X size={13} /></button>
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
  const isAdmin = currentUser()?.role === 'admin'
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
    <ResizableDrawer slug="templates" defaultWidth={640} onClose={onClose}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <LayoutTemplate size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Investigation playbooks</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <PanelHelp
            title="Investigation playbooks"
            use="Scenario checklists (ransomware, insider, phishing…) of curated queries, run live against this case, plus optional watchlist/tags/notes seeding."
            when="At case kickoff — to apply a known methodology and see which scenario checks already have hits."
            tip="Expand a playbook to see live hit counts; click Pivot to open the timeline filtered to a check."
          />
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
    </ResizableDrawer>
  )
}
