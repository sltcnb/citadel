import { useEffect, useLayoutEffect, useState, useCallback, useRef, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Search, Filter, X, Flag, Loader2, Download, RefreshCw,
  BarChart2, Plus, Minus, Keyboard, SlidersHorizontal, Brain,
  Sparkles, Trash2, BookmarkCheck, Bookmark, ChevronDown, CalendarDays, Layers, Sigma, BookOpen, HelpCircle,
} from 'lucide-react'
import { api } from '../api/client'
import EventDetail from '../components/shared/EventDetail'
import StatsPopover from '../components/shared/StatsPopover'

const ARTIFACT_COLORS = {
  evtx:          'badge-evtx',
  prefetch:      'badge-prefetch',
  mft:           'badge-mft',
  registry:      'badge-registry',
  registry_hive: 'badge-registry',
  user_account:  'badge-registry',
  lnk:           'badge-lnk',
  plaso:         'badge-plaso',
  hayabusa:      'badge-hayabusa',
  antivirus:     'badge-antivirus',
  login_event:   'badge-login',
  generic:       'badge-generic',
}

const OS_COLORS = {
  windows: 'bg-sky-100 text-sky-700 border border-sky-200',
  linux:   'bg-amber-100 text-amber-700 border border-amber-200',
  macos:   'bg-purple-100 text-purple-700 border border-purple-200',
  mobile:  'bg-emerald-100 text-emerald-700 border border-emerald-200',
  cloud:   'bg-indigo-100 text-indigo-700 border border-indigo-200',
  cross:   'bg-gray-100 text-gray-600 border border-gray-200',
}

const LEVEL_COLORS = {
  crit:          'bg-red-100 text-red-700 border border-red-200',
  critical:      'bg-red-100 text-red-700 border border-red-200',
  high:          'bg-orange-100 text-orange-700 border border-orange-200',
  med:           'bg-yellow-100 text-yellow-700 border border-yellow-200',
  medium:        'bg-yellow-100 text-yellow-700 border border-yellow-200',
  low:           'bg-blue-100 text-blue-700 border border-blue-200',
  info:          'bg-gray-100 text-gray-500',
  informational: 'bg-gray-100 text-gray-500',
}

// ── Column definitions ───────────────────────────────────────────────────────
const ALL_COLUMNS = [
  { id: 'timestamp',   label: 'Timestamp',   defaultOn: true  },
  { id: 'os',          label: 'OS',          defaultOn: true  },
  { id: 'type',        label: 'Type',        defaultOn: true  },
  { id: 'level',       label: 'Level',       defaultOn: true  },
  { id: 'event_id',    label: 'Event ID',    defaultOn: true  },
  { id: 'host',        label: 'Host',        defaultOn: true  },
  { id: 'user',        label: 'User',        defaultOn: true  },
  { id: 'process',     label: 'Process',     defaultOn: false },
  { id: 'action',      label: 'Action',      defaultOn: false },
  { id: 'protocol',    label: 'Protocol',    defaultOn: false },
  { id: 'src_ip',      label: 'Src IP',      defaultOn: false },
  { id: 'src_port',    label: 'Src Port',    defaultOn: false },
  { id: 'dst_ip',      label: 'Dst IP',      defaultOn: false },
  { id: 'dst_port',    label: 'Dst Port',    defaultOn: false },
  { id: 'run_count',   label: 'Run Count',   defaultOn: false },
  { id: 'pid',         label: 'PID',         defaultOn: false },
  { id: 'http_method', label: 'Method',      defaultOn: false },
  { id: 'http_status', label: 'Status',      defaultOn: false },
  { id: 'http_path',   label: 'Path',        defaultOn: false },
  { id: 'user_agent',  label: 'User Agent',  defaultOn: false },
  { id: 'resp_size',   label: 'Resp Bytes',  defaultOn: false },
  { id: 'cmdline',     label: 'Command Line', defaultOn: false },
  { id: 'proc_path',   label: 'Proc Path',   defaultOn: false },
  { id: 'parent_proc', label: 'Parent Proc', defaultOn: false },
  { id: 'parent_pid',  label: 'Parent PID',  defaultOn: false },
  { id: 'host_ip',     label: 'Host IP',     defaultOn: false },
  { id: 'host_fqdn',   label: 'FQDN',        defaultOn: false },
  { id: 'user_domain', label: 'User Domain', defaultOn: false },
  { id: 'user_sid',    label: 'User SID',    defaultOn: false },
  { id: 'bytes',       label: 'Bytes',       defaultOn: false },
  { id: 'mitre',       label: 'MITRE',       defaultOn: false },
  { id: 'channel',     label: 'Channel',     defaultOn: false },
  { id: 'rule',        label: 'Rule',        defaultOn: false },
  { id: 'message',     label: 'Message',     defaultOn: true  },
  { id: 'tags',        label: 'Tags',        defaultOn: true  },
  { id: 'raw_data',    label: 'Raw',         defaultOn: false },
]

const DEFAULT_COLUMNS = ALL_COLUMNS.filter(c => c.defaultOn).map(c => c.id)
const LS_KEY       = 'timeline_visible_cols'
const LS_WIDTHS_KEY = 'timeline_col_widths'
const LS_AUTO_KEY  = 'timeline_cols_auto'

// Columns that are always shown regardless of auto-detect
const ALWAYS_ON_COLS = new Set(['timestamp', 'message'])

// All columns eligible for auto-detection (everything except always-on)
const ALL_DETECT_COLS = ALL_COLUMNS.map(c => c.id).filter(id => !ALWAYS_ON_COLS.has(id))

// Default pixel widths per column
const DEFAULT_COL_WIDTHS = {
  timestamp: 160, os: 76, type: 96,  level: 80,  event_id: 80, host: 112, user: 96,
  process: 112, action: 80, protocol: 72, src_ip: 128, src_port: 60,
  dst_ip: 128, dst_port: 60, run_count: 56, pid: 60, http_method: 72,
  http_status: 60, http_path: 192, user_agent: 192, resp_size: 64,
  cmdline: 280, proc_path: 200, bytes: 72,
  parent_proc: 144, parent_pid: 72,
  host_ip: 128, host_fqdn: 160, user_domain: 112, user_sid: 200,
  mitre: 144, channel: 112, rule: 144, message: 320, tags: 128, raw_data: 480,
}

function loadSavedWidths() {
  try {
    const raw = localStorage.getItem(LS_WIDTHS_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      if (parsed && typeof parsed === 'object') return parsed
    }
  } catch {}
  return {}
}

function loadSavedColumns() {
  try {
    const raw = localStorage.getItem(LS_KEY)
    if (raw) {
      const parsed = JSON.parse(raw)
      if (Array.isArray(parsed) && parsed.length > 0) return parsed
    }
  } catch {}
  return DEFAULT_COLUMNS
}

function loadAutoMode() {
  const saved = localStorage.getItem(LS_AUTO_KEY)
  if (saved === 'false') return false  // user explicitly chose manual
  if (saved === 'true')  return true   // user explicitly re-enabled auto
  return !localStorage.getItem(LS_KEY) // default: auto on first use, manual if saved pref exists
}

function loadCaseFilters(caseId) {
  try {
    const raw = localStorage.getItem(`timeline_filters_${caseId}`)
    if (raw) return JSON.parse(raw) || {}
  } catch {}
  return {}
}

function saveCaseFilters(caseId, filters) {
  try {
    localStorage.setItem(`timeline_filters_${caseId}`, JSON.stringify(filters))
  } catch {}
}

const PAGE_SIZE = 100

const SHORTCUTS = [
  { keys: ['/'],        desc: 'Focus search bar' },
  { keys: ['↑', '↓'],  desc: 'Navigate events' },
  { keys: ['Enter'],    desc: 'Open selected event' },
  { keys: ['Esc'],      desc: 'Close panel / blur search' },
  { keys: ['?'],        desc: 'Toggle this help' },
]

// Helper: pull artifact-specific sub-object from event
function getArtifact(ev) {
  return ev[ev.artifact_type] || {}
}

// Deduplication: fingerprint on content, not fo_id (which changes on re-ingest)
function eventFingerprint(ev) {
  return `${ev.timestamp}|${ev.message}|${ev.artifact_type}|${ev.host?.hostname ?? ''}|${ev.user?.name ?? ''}`
}

function deduplicateEvents(events) {
  const seen = new Set()
  return events.filter(ev => {
    const fp = eventFingerprint(ev)
    if (seen.has(fp)) return false
    seen.add(fp)
    return true
  })
}

// Map column IDs → ES sort field names
const SORT_ES_FIELDS = {
  timestamp:   'timestamp',
  type:        'artifact_type',
  level:       'evtx.level.keyword',
  event_id:    'evtx.event_id',
  host:        'host.hostname.keyword',
  user:        'user.name.keyword',
  process:     'process.name.keyword',
  pid:         'process.pid',
  action:      'network.action.keyword',
  protocol:    'network.protocol.keyword',
  src_ip:      'network.src_ip.keyword',
  dst_ip:      'network.dst_ip.keyword',
  src_port:    'network.src_port',
  dst_port:    'network.dst_port',
  run_count:   'prefetch.run_count',
  http_method: 'http.method.keyword',
  http_status: 'http.status_code',
  http_path:   'http.request_path.keyword',
  resp_size:   'http.response_size',
  channel:     'evtx.channel.keyword',
  rule:        'evtx.rule_title.keyword',
}


function getMitreValue(ev, art) {
  const mitreTags = (ev.tags || []).filter(t =>
    t.toLowerCase().startsWith('attack.') || /^t\d{4}/i.test(t)
  )
  if (mitreTags.length) return mitreTags.join(', ')
  return art?.mitre_attack || ev.mitre_attack || ''
}

// Render any raw payload as a compact single-line preview for the timeline.
// Plugins now ship structured raw dicts ({key_path, values, xml, content…}),
// so just-line-or-xml misses everything else. Falls back to JSON.
function _rawPreview(r) {
  if (!r || typeof r !== 'object') return ''
  if (r.line)    return String(r.line)
  if (r.xml)     return String(r.xml)
  if (r.content) return String(r.content)
  const keys = Object.keys(r)
  if (keys.length === 0) return ''
  try { return JSON.stringify(r) } catch { return '' }
}

function getColValue(colId, ev) {
  const art = getArtifact(ev)
  switch (colId) {
    case 'timestamp':   return ev.timestamp || ''
    case 'os':          return ev.os || ''
    case 'type':        return ev.artifact_type || ''
    case 'level':       return ev.evtx?.level || art.level || ev.level || ''
    case 'event_id':    { const eid = art.event_id ?? ev.evtx?.event_id; return eid != null ? String(eid) : '' }
    case 'host':        return ev.host?.hostname || ''
    case 'user':        return ev.user?.name || ''
    case 'message':     return ev.message || ''
    case 'tags':        return (ev.tags || []).length > 0 ? 'y' : ''
    case 'raw_data': return _rawPreview(ev.raw)
    case 'process':     return ev.process?.name || ev.process?.path || ''
    case 'pid':         return ev.process?.pid != null ? String(ev.process.pid) : ''
    case 'run_count':   return art.run_count != null ? String(art.run_count) : ''
    case 'action':      return ev.network?.action || art.action || ''
    case 'protocol':    return ev.network?.protocol || art.protocol || ''
    case 'src_ip':      return ev.network?.src_ip || art.src_ip || ''
    case 'src_port':    return ev.network?.src_port != null ? String(ev.network.src_port) : (art.src_port != null ? String(art.src_port) : '')
    case 'dst_ip':      return ev.network?.dst_ip || art.dst_ip || ''
    case 'dst_port':    return ev.network?.dst_port != null ? String(ev.network.dst_port) : (art.dst_port != null ? String(art.dst_port) : '')
    case 'http_method': return ev.http?.method || ''
    case 'http_status': return ev.http?.status_code ? String(ev.http.status_code) : ''
    case 'http_path':   return ev.http?.request_path || ''
    case 'user_agent':  return ev.http?.user_agent || ''
    case 'resp_size':   return ev.http?.response_size != null ? String(ev.http.response_size) : ''
    case 'cmdline':     return ev.process?.command_line || ''
    case 'proc_path':   return ev.process?.path || ''
    case 'parent_proc': return ev.process?.parent_name || ''
    case 'parent_pid':  return ev.process?.parent_pid != null ? String(ev.process.parent_pid) : ''
    case 'host_ip':     return ev.host?.ip || ''
    case 'host_fqdn':   return ev.host?.fqdn || ''
    case 'user_domain': return ev.user?.domain || ''
    case 'user_sid':    return ev.user?.sid || ''
    case 'bytes':       return ev.network?.bytes != null ? String(ev.network.bytes) : ''
    case 'mitre':       return getMitreValue(ev, art)
    case 'channel':     return art.channel || ev.channel || ''
    case 'rule':        return art.rule_title || ev.rule_title || ''
    default:            return ''
  }
}

// Column → Elasticsearch field path. Used by the column-header "non-empty" toggle
// to append `_exists_:<field>` to the search query.
const COLUMN_ES_FIELD = {
  timestamp:   'timestamp',
  os:          'os',
  type:        'artifact_type',
  level:       'evtx.level',
  event_id:    'evtx.event_id',
  host:        'host.hostname',
  user:        'user.name',
  process:     'process.name',
  pid:         'process.pid',
  cmdline:     'process.command_line',
  proc_path:   'process.path',
  parent_proc: 'process.parent_name',
  parent_pid:  'process.parent_pid',
  host_ip:     'host.ip',
  host_fqdn:   'host.fqdn',
  user_domain: 'user.domain',
  user_sid:    'user.sid',
  action:      'network.action',
  protocol:    'network.protocol',
  src_ip:      'network.src_ip',
  src_port:    'network.src_port',
  dst_ip:      'network.dst_ip',
  dst_port:    'network.dst_port',
  bytes:       'network.bytes',
  http_method: 'http.method',
  http_status: 'http.status_code',
  http_path:   'http.request_path',
  user_agent:  'http.user_agent',
  resp_size:   'http.response_size',
  channel:     'evtx.channel',
  rule:        'evtx.rule_title',
  run_count:   'prefetch.run_count',
  mitre:       'mitre.technique_id',
  message:     'message',
  tags:        'tags',
  raw_data:    'raw',
}

// Types that pollute the timeline if shown by default but stay available
// as filter chips so analysts can toggle them on when they want them.
// Earlier the chip blacklist hid these from the sidebar too — but on cases
// where every artifact_type is on the list the sidebar ended up empty and
// the user lost the filter UI entirely. Keep chips visible; just deselect
// the noisy ones at init time.
const DEFAULT_HIDDEN_TYPES = new Set([
  'file', 'binary_file', 'binary_files', 'anomaly',
])
const CHIP_BLACKLIST = new Set()

export default function Timeline({ caseId, artifactTypes, initialQuery = '' }) {
  // URL params take precedence over per-case localStorage. Shareable links:
  //   /cases/<id>?q=…&from=…&to=…&types=evtx,prefetch&flagged=1&level=high
  const [urlParams, setUrlParams] = useSearchParams()
  const _urlQuery   = urlParams.get('q')        || ''
  const _urlFrom    = urlParams.get('from')     || ''
  const _urlTo      = urlParams.get('to')       || ''
  const _urlTypes   = urlParams.get('types')    || ''
  const _urlFlagged = urlParams.get('flagged') === '1'
  const _urlLevel   = urlParams.get('level')    || ''

  // Restore per-case filters from localStorage on mount (URL overrides)
  const _sf = useMemo(() => loadCaseFilters(caseId), [])
  const _hasTypesFilter = Object.prototype.hasOwnProperty.call(_sf, 'selectedTypesStr')

  const [events, setEvents]               = useState([])
  const [total, setTotal]                 = useState(0)
  const [page, setPage]                   = useState(0)
  const [loading, setLoading]             = useState(false)
  const [selectedTypesStr, setSelectedTypesStr] = useState(_urlTypes || (_hasTypesFilter ? (_sf.selectedTypesStr || '') : ''))
  const [typeDropdownOpen, setTypeDropdownOpen] = useState(false)
  const [fromTs, setFromTs]               = useState(_urlFrom || _sf.fromTs || '')
  const [toTs, setToTs]                   = useState(_urlTo || _sf.toTs || '')
  // initialQuery wins when present (pivot from AI panel, IOC, alert, …) —
  // otherwise restore from per-case localStorage.
  const [query, setQuery]                 = useState(initialQuery || _sf.query || '')
  const [inputVal, setInputVal]           = useState(initialQuery || _sf.query || '')
  const [selectedEvent, setSelectedEvent] = useState(null)
  const [histogram, setHistogram]         = useState([])
  const [showHistogram, setShowHistogram] = useState(true)
  const histoDragRef                       = useRef(null)   // {start, end} bar indices while swiping
  const [histoDragSel, setHistoDragSel]   = useState(null)  // mirror for live highlight
  const [selectedRowIdx, setSelectedRowIdx] = useState(-1)
  const [showFieldExplorer, setShowFieldExplorer] = useState(false)
  const [showAggregate, setShowAggregate]       = useState(false)
  const [aggState, setAggState]                 = useState({ fields: [], agg: 'terms', size: 20, interval: '1d', subCard: [] })
  const [aggResult, setAggResult]               = useState(null)
  const [aggLoading, setAggLoading]             = useState(false)
  const [fieldMap, setFieldMap]             = useState(null)
  const [suggestOpen, setSuggestOpen]       = useState(false)
  const [suggestIdx,  setSuggestIdx]        = useState(0)
  const [showHelp, setShowHelp]           = useState(false)
  const [flaggedOnly, setFlaggedOnly]     = useState(_urlFlagged || _sf.flaggedOnly || false)
  const [selectedLevel, setSelectedLevel] = useState(_urlLevel || _sf.selectedLevel || '')
  const [visibleCols, setVisibleCols]     = useState(loadSavedColumns)
  const [autoMode, setAutoMode]           = useState(loadAutoMode)
  const [detectedCols, setDetectedCols]   = useState(new Set())
  const [showColPicker, setShowColPicker] = useState(false)
  const colPickerRef                      = useRef(null)
  const pageResetRef                      = useRef(true)  // true = next events update is a full reset

  const [checkedFoIds, setCheckedFoIds]     = useState(new Set())
  const [refreshing, setRefreshing]         = useState(false)
  const [explaining, setExplaining]         = useState(false)
  const [explainResult, setExplainResult]   = useState(null)
  const [naturalDate, setNaturalDate]       = useState('')
  const [showCustomRange, setShowCustomRange] = useState(false)
  const [naturalDateErr, setNaturalDateErr] = useState('')
  const [activePreset, setActivePreset]     = useState(null)

  const [facets, setFacets]                 = useState({})
  const [facetFilters, setFacetFilters]     = useState({})
  const [savedSearches, setSavedSearches]   = useState([])
  const [showSaveForm, setShowSaveForm]     = useState(false)
  const [saveSearchName, setSaveSearchName] = useState('')
  const [showAiAssist, setShowAiAssist]     = useState(false)

  const [sortField, setSortField]           = useState('timestamp')
  const [sortOrder, setSortOrder]           = useState('desc')
  const [colWidths, setColWidths]           = useState(loadSavedWidths)

  const loaderRef       = useRef(null)
  const searchRef       = useRef(null)
  const rowRefs         = useRef({})
  const resizeRef       = useRef(null)  // { colId, startX, startWidth, thEl }
  const typesInitRef    = useRef(_hasTypesFilter) // skip init if restored from localStorage
  const fromInputRef    = useRef(null)
  const toInputRef      = useRef(null)
  const fromCalRef      = useRef(null)
  const toCalRef        = useRef(null)

  function getColWidth(colId) {
    return colWidths[colId] ?? DEFAULT_COL_WIDTHS[colId]
  }

  function onResizeStart(e, colId, thEl) {
    e.preventDefault()
    e.stopPropagation()
    const startWidth = thEl.getBoundingClientRect().width
    // Target the <col> element so table-layout:fixed respects the change
    const colEl = thEl.closest('table')?.querySelectorAll('colgroup col')[thEl.cellIndex] ?? null
    resizeRef.current = { colId, startX: e.clientX, startWidth, colEl }

    function onMouseMove(ev) {
      if (!resizeRef.current) return
      const { startX, startWidth: sw, colEl: col } = resizeRef.current
      const w = Math.max(48, sw + ev.clientX - startX)
      if (col) col.style.width = `${w}px`
    }

    function onMouseUp(ev) {
      if (!resizeRef.current) return
      const { colId: cid, startX, startWidth: sw } = resizeRef.current
      const w = Math.max(48, sw + ev.clientX - startX)
      setColWidths(prev => {
        const next = { ...prev, [cid]: w }
        localStorage.setItem(LS_WIDTHS_KEY, JSON.stringify(next))
        return next
      })
      resizeRef.current = null
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup',   onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor     = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup',   onMouseUp)
  }

  function onResizeDblClick(e, colId, thEl) {
    e.preventDefault()
    e.stopPropagation()
    const table  = thEl.closest('table')
    if (!table) return
    const colIdx = thEl.cellIndex
    const cells  = table.querySelectorAll(`tr > *:nth-child(${colIdx + 1})`)
    const canvas = document.createElement('canvas')
    const ctx    = canvas.getContext('2d')
    ctx.font     = '12px Inter, ui-sans-serif, system-ui, sans-serif'
    let maxW = DEFAULT_COL_WIDTHS[colId] ?? 80
    cells.forEach(cell => {
      const text = cell.textContent?.trim() ?? ''
      const w    = ctx.measureText(text).width + 28
      if (w > maxW) maxW = w
    })
    maxW = Math.min(maxW, 400)
    const colEl = table.querySelectorAll('colgroup col')[colIdx]
    if (colEl) colEl.style.width = `${maxW}px`
    setColWidths(prev => {
      const next = { ...prev, [colId]: maxW }
      localStorage.setItem(LS_WIDTHS_KEY, JSON.stringify(next))
      return next
    })
  }

  // Load saved searches on mount
  useEffect(() => {
    api.savedSearches.list(caseId).then(r => setSavedSearches(r.searches || [])).catch(() => {})
  }, [caseId])

  // Initialize selectedTypesStr: all types except file/binary_file selected by default
  useLayoutEffect(() => {
    if (!typesInitRef.current && artifactTypes.length > 0) {
      typesInitRef.current = true
      if (artifactTypes.some(t => DEFAULT_HIDDEN_TYPES.has(t))) {
        setSelectedTypesStr(artifactTypes.filter(t => !DEFAULT_HIDDEN_TYPES.has(t)).sort().join(','))
      }
    }
  }, [artifactTypes])

  // When switching type filter: if in auto mode, mark the next events load as a reset
  useEffect(() => {
    if (autoMode) pageResetRef.current = true
  }, [selectedTypesStr, autoMode])

  // Auto-detect columns whenever events change
  useEffect(() => {
    if (events.length === 0) return

    // Compute which columns have data in the current event batch
    const detected = new Set(
      ALL_DETECT_COLS.filter(colId => events.some(ev => getColValue(colId, ev)))
    )
    setDetectedCols(detected)

    const isReset = pageResetRef.current
    pageResetRef.current = false

    if (!autoMode) return  // manual mode: only update data indicators, don't change visible cols

    if (isReset) {
      // Full reset: set exactly the columns with data (plus always-on)
      const next = ALL_COLUMNS.map(c => c.id).filter(id =>
        ALWAYS_ON_COLS.has(id) || detected.has(id)
      )
      setVisibleCols(next)
      localStorage.setItem(LS_KEY, JSON.stringify(next))
    } else {
      // Scroll load: only add newly detected columns, never remove
      setVisibleCols(prev => {
        const prevSet = new Set(prev)
        const added = [...detected].filter(id => !prevSet.has(id))
        if (added.length === 0) return prev
        const next = [...prev, ...added]
        localStorage.setItem(LS_KEY, JSON.stringify(next))
        return next
      })
    }
  }, [events, autoMode])

  // Refresh facets whenever query, facetFilters, or selectedTypesStr changes
  useEffect(() => {
    const params = {}
    let facetQ = query
    const typesArr = selectedTypesStr ? selectedTypesStr.split(',') : []
    if (typesArr.length > 0) {
      const typeQ = `artifact_type:(${typesArr.join(' OR ')})`
      facetQ = facetQ ? `(${facetQ}) AND ${typeQ}` : typeQ
    }
    if (facetQ) params.q = facetQ
    Object.assign(params, facetFilters)
    // Scope the activity histogram to the zoomed range so it rescales
    // (days → hours → minutes) instead of always bucketing by day.
    if (fromTs) params.from_ts = new Date(fromTs).toISOString()
    if (toTs)   params.to_ts   = new Date(toTs).toISOString()
    api.search.facets(caseId, params)
      .then(r => {
        const f = r.facets || {}
        setFacets(f)
        setHistogram(f.events_over_time?.buckets || [])
      })
      .catch(() => {})
  }, [caseId, query, selectedTypesStr, facetFilters, fromTs, toTs])

  // Load the mapping field list once per case — drives field explorer + autocomplete
  useEffect(() => {
    api.search.fields(caseId).then(setFieldMap).catch(() => setFieldMap(null))
  }, [caseId])

  // Flat list of all searchable fields for autocomplete
  const allFieldNames = useMemo(() => {
    if (!fieldMap?.groups) return []
    const out = []
    for (const g of fieldMap.groups) {
      for (const f of g.fields) if (f.searchable) out.push(f.name)
    }
    return out
  }, [fieldMap])

  // Compute the current "in-progress" field name token at the input caret.
  // Returns a list of matching field names to suggest, or [] if no completion.
  const fieldSuggestions = useMemo(() => {
    if (!allFieldNames.length || !inputVal) return []
    // Take the last whitespace-delimited token. If it ends with `:` user is
    // about to enter a value — don't suggest fields. If it contains `:`
    // already, also stop. Otherwise treat the token as a prefix.
    const tail = inputVal.split(/[\s()]/).pop() || ''
    if (!tail || tail.includes(':')) return []
    const tl = tail.toLowerCase()
    const matches = allFieldNames.filter(n => n.toLowerCase().includes(tl))
    return matches.slice(0, 12)
  }, [allFieldNames, inputVal])

  const load = useCallback(async (pg = 0, reset = false) => {
    setLoading(true)
    try {
      const esSortField = SORT_ES_FIELDS[sortField] || sortField
      const params = { page: pg, size: PAGE_SIZE, sort_field: esSortField, sort_order: sortOrder }
      if (fromTs) params.from = fromTs
      if (toTs)   params.to   = toTs
      Object.assign(params, facetFilters)
      let effectiveQ = query
      const typesArr = selectedTypesStr ? selectedTypesStr.split(',') : []
      if (typesArr.length > 0) {
        const typeQ = `artifact_type:(${typesArr.join(' OR ')})`
        effectiveQ = effectiveQ ? `(${effectiveQ}) AND ${typeQ}` : typeQ
      }
      if (selectedLevel) {
        // Levels live in different sub-objects depending on plugin:
        //   evtx.level (Windows), hayabusa.level (Sigma alerts), top-level
        //   `level` (some plugins). Cover all three with OR.
        const levelQ = selectedLevel === 'none'
          ? '(NOT _exists_:level) AND (NOT _exists_:evtx.level) AND (NOT _exists_:hayabusa.level)'
          : `(evtx.level:${selectedLevel} OR hayabusa.level:${selectedLevel} OR level:${selectedLevel})`
        effectiveQ = effectiveQ ? `(${effectiveQ}) AND ${levelQ}` : levelQ
      }
      if (flaggedOnly) {
        effectiveQ = effectiveQ ? `(${effectiveQ}) AND is_flagged:true` : 'is_flagged:true'
      }
      const hasSearch = effectiveQ || Object.keys(facetFilters).length > 0
      const r = hasSearch
        ? await api.search.search(caseId, { ...params, q: effectiveQ })
        : await api.search.timeline(caseId, params)
      setTotal(r.total || 0)
      const incoming = deduplicateEvents(r.events || [])
      if (reset) pageResetRef.current = true
      setEvents(prev => {
        if (reset) return incoming
        const seenFps = new Set(prev.map(eventFingerprint))
        return [...prev, ...incoming.filter(ev => !seenFps.has(eventFingerprint(ev)))]
      })
      setPage(pg)
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }, [caseId, selectedTypesStr, fromTs, toTs, query, flaggedOnly, selectedLevel, facetFilters, sortField, sortOrder])

  useEffect(() => { load(0, true) }, [load])

  // Persist filters to localStorage on change
  useEffect(() => {
    saveCaseFilters(caseId, { selectedTypesStr, fromTs, toTs, query, flaggedOnly, selectedLevel })
    // Mirror current filters to the URL so links are shareable. `replace: true`
    // keeps the browser history clean (no entry per keystroke).
    const next = new URLSearchParams(urlParams)
    const setOrDelete = (k, v) => v ? next.set(k, v) : next.delete(k)
    setOrDelete('q',       query)
    setOrDelete('from',    fromTs)
    setOrDelete('to',      toTs)
    setOrDelete('types',   selectedTypesStr)
    setOrDelete('flagged', flaggedOnly ? '1' : '')
    setOrDelete('level',   selectedLevel)
    setUrlParams(next, { replace: true })
  }, [caseId, selectedTypesStr, fromTs, toTs, query, flaggedOnly, selectedLevel])

  useEffect(() => {
    setSelectedRowIdx(-1)
    rowRefs.current = {}
  }, [query, selectedTypesStr, fromTs, toTs])

  useEffect(() => {
    if (selectedRowIdx >= 0 && rowRefs.current[selectedRowIdx]) {
      rowRefs.current[selectedRowIdx].scrollIntoView({ block: 'nearest', behavior: 'smooth' })
    }
  }, [selectedRowIdx])

  // Infinite scroll sentinel
  useEffect(() => {
    if (!loaderRef.current) return
    const obs = new IntersectionObserver(entries => {
      if (entries[0].isIntersecting && !loading && events.length < total)
        load(page + 1, false)
    }, { threshold: 0.1 })
    obs.observe(loaderRef.current)
    return () => obs.disconnect()
  }, [loaderRef.current, loading, events.length, total, page, load])

  // Close col picker on outside click
  useEffect(() => {
    if (!showColPicker) return
    function handleClick(e) {
      if (colPickerRef.current && !colPickerRef.current.contains(e.target))
        setShowColPicker(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [showColPicker])

  // Global keyboard navigation
  useEffect(() => {
    function handleKey(e) {
      const tag = document.activeElement?.tagName
      const inInput = ['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)

      if (e.key === '?' && !inInput) { e.preventDefault(); setShowHelp(v => !v); return }
      if (e.key === '/' && !inInput) { e.preventDefault(); searchRef.current?.focus(); return }
      if (e.key === 'Escape') {
        if (document.activeElement === searchRef.current) { searchRef.current.blur(); return }
        if (showHelp)      { setShowHelp(false);      return }
        if (selectedEvent) { setSelectedEvent(null);  return }
        return
      }
      if (inInput) return
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelectedRowIdx(i => Math.min(i + 1, events.length - 1)); return }
      if (e.key === 'ArrowUp')   { e.preventDefault(); setSelectedRowIdx(i => Math.max(i - 1, 0)); return }
      if (e.key === 'Enter' && selectedRowIdx >= 0) {
        e.preventDefault()
        const ev = events[selectedRowIdx]
        if (ev) setSelectedEvent(ev)
      }
    }
    window.addEventListener('keydown', handleKey)
    return () => window.removeEventListener('keydown', handleKey)
  }, [events, selectedRowIdx, selectedEvent, showHelp])

  function submitSearch(e) {
    e.preventDefault()
    setQuery(inputVal.trim())
  }

  function toggleSort(colId) {
    if (!SORT_ES_FIELDS[colId]) return
    if (sortField === colId) {
      setSortOrder(o => o === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(colId)
      setSortOrder('asc')
    }
  }

  function clearSearch() { setInputVal(''); setQuery('') }

  function escapeLucene(val) {
    // Escape special Lucene characters inside a quoted phrase
    return String(val).replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  }

  function addFilter(field, value, exclude = false) {
    const term = `${field}:"${escapeLucene(value)}"`
    const clause = exclude ? `NOT ${term}` : term
    const next = query ? `${query} AND ${clause}` : clause
    setInputVal(next)
    setQuery(next)
  }

  // Toggle `_exists_:<field>` in the query — adds it if missing, strips it if present.
  function toggleExists(field, missing = false) {
    if (!field) return
    const presentRe = new RegExp(`(?:^|\\s)(?:AND\\s+)?_exists_:${field}(?=\\s|$)`, 'g')
    const missingRe = new RegExp(`(?:^|\\s)(?:AND\\s+)?(?:NOT\\s+)_exists_:${field}(?=\\s|$)`, 'g')
    let next = query
    // Strip any prior exists/missing clause for this field, leave other tokens intact.
    next = next.replace(missingRe, '').replace(presentRe, '').replace(/\s+AND\s+AND\s+/g, ' AND ').replace(/^\s*AND\s+/, '').trim()
    const clause = missing ? `NOT _exists_:${field}` : `_exists_:${field}`
    next = next ? `${next} AND ${clause}` : clause
    setInputVal(next)
    setQuery(next)
  }

  // Histogram range selection — click = single day (toggle), click+drag =
  // span of days. dragRef carries the live drag; dragSel mirrors it in
  // state purely for the highlight preview.
  function applyHistogramRange(i0, i1) {
    if (!histogram.length) return
    const [a, b] = i0 <= i1 ? [i0, i1] : [i1, i0]
    // Bucket width comes from the (uniform) auto_date_histogram spacing, so a
    // click selects exactly one bucket whether that's a day, an hour or a minute.
    const widthMs = histogram.length > 1
      ? (histogram[1].key - histogram[0].key)
      : 86400000
    const fromIso = new Date(histogram[a].key).toISOString()
    const toIso   = new Date(histogram[b].key + widthMs).toISOString()
    // Toggle: re-selecting the exact active range clears the filter
    if (fromTs === fromIso && toTs === toIso) {
      setFromTs('')
      setToTs('')
    } else {
      setFromTs(fromIso)
      setToTs(toIso)
    }
  }

  function histoBarDown(i, e) {
    e.preventDefault()   // stop text selection while swiping
    histoDragRef.current = { start: i, end: i }
    setHistoDragSel({ start: i, end: i })
  }

  function histoBarEnter(i) {
    if (!histoDragRef.current) return
    histoDragRef.current.end = i
    setHistoDragSel({ ...histoDragRef.current })
  }

  useEffect(() => {
    function onUp() {
      if (!histoDragRef.current) return
      const { start, end } = histoDragRef.current
      histoDragRef.current = null
      setHistoDragSel(null)
      applyHistogramRange(start, end)
    }
    window.addEventListener('mouseup', onUp)
    return () => window.removeEventListener('mouseup', onUp)
  })

  async function refresh() {
    setRefreshing(true)
    try {
      const facetParams = {}
      let refreshQ = query
      const typesArr = selectedTypesStr ? selectedTypesStr.split(',') : []
      if (typesArr.length > 0) {
        const typeQ = `artifact_type:(${typesArr.join(' OR ')})`
        refreshQ = refreshQ ? `(${refreshQ}) AND ${typeQ}` : typeQ
      }
      if (refreshQ) facetParams.q = refreshQ
      Object.assign(facetParams, facetFilters)
      await Promise.all([
        api.search.facets(caseId, facetParams)
          .then(r => { const f = r.facets || {}; setFacets(f); setHistogram(f.events_over_time?.buckets || []) })
          .catch(() => {}),
        load(0, true),
      ])
    } finally {
      setRefreshing(false)
    }
  }

  function downloadCsv() {
    const params = {}
    let csvQ = query
    const typesArr = selectedTypesStr ? selectedTypesStr.split(',') : []
    if (typesArr.length > 0) {
      const typeQ = `artifact_type:(${typesArr.join(' OR ')})`
      csvQ = csvQ ? `(${csvQ}) AND ${typeQ}` : typeQ
    }
    if (csvQ) params.q = csvQ
    window.open(api.export.csv(caseId, params))
  }

  function toggleCol(id) {
    setAutoMode(false)
    localStorage.setItem(LS_AUTO_KEY, 'false')
    const next = visibleCols.includes(id)
      ? visibleCols.filter(c => c !== id)
      : [...visibleCols, id]
    setVisibleCols(next)
    localStorage.setItem(LS_KEY, JSON.stringify(next))
  }

  function resetCols() {
    setAutoMode(false)
    localStorage.setItem(LS_AUTO_KEY, 'false')
    setVisibleCols(DEFAULT_COLUMNS)
    localStorage.setItem(LS_KEY, JSON.stringify(DEFAULT_COLUMNS))
  }

  function resetToAuto() {
    setAutoMode(true)
    localStorage.setItem(LS_AUTO_KEY, 'true')
    // Re-detect from current events immediately
    const detected = new Set(
      ALL_DETECT_COLS.filter(colId => events.some(ev => getColValue(colId, ev)))
    )
    setDetectedCols(detected)
    const next = ALL_COLUMNS.map(c => c.id).filter(id =>
      ALWAYS_ON_COLS.has(id) || detected.has(id)
    )
    setVisibleCols(next)
    localStorage.setItem(LS_KEY, JSON.stringify(next))
  }

  // Parse natural language date phrases → ISO string (or null)
  function parseNaturalDate(text) {
    const t = text.trim().toLowerCase()
    const now = new Date()
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())

    if (t === 'today')     return today.toISOString()
    if (t === 'yesterday') { const d = new Date(today); d.setDate(d.getDate() - 1); return d.toISOString() }
    if (t === 'last week') { const d = new Date(today); d.setDate(d.getDate() - 7); return d.toISOString() }
    if (t === 'last month') { const d = new Date(today); d.setMonth(d.getMonth() - 1); return d.toISOString() }

    const daysMatch   = t.match(/^(\d+)\s*days?\s*ago$/)
    if (daysMatch)   { const d = new Date(today); d.setDate(d.getDate() - parseInt(daysMatch[1])); return d.toISOString() }
    const weeksMatch  = t.match(/^(\d+)\s*weeks?\s*ago$/)
    if (weeksMatch)  { const d = new Date(today); d.setDate(d.getDate() - parseInt(weeksMatch[1]) * 7); return d.toISOString() }
    const monthsMatch = t.match(/^(\d+)\s*months?\s*ago$/)
    if (monthsMatch) { const d = new Date(today); d.setMonth(d.getMonth() - parseInt(monthsMatch[1])); return d.toISOString() }
    const hoursMatch  = t.match(/^(\d+)\s*hours?\s*ago$/)
    if (hoursMatch)  { const d = new Date(now); d.setHours(d.getHours() - parseInt(hoursMatch[1])); return d.toISOString() }

    // Named weekdays: "monday", "last monday", "from monday"
    const DAYS = ['sunday','monday','tuesday','wednesday','thursday','friday','saturday']
    const dayName = t.replace(/^(from\s+|last\s+)/, '').trim()
    const dayIdx = DAYS.indexOf(dayName)
    if (dayIdx >= 0) {
      const d = new Date(today)
      const diff = (today.getDay() - dayIdx + 7) % 7
      d.setDate(d.getDate() - (diff === 0 ? 7 : diff))
      return d.toISOString()
    }

    return null
  }

  function applyNaturalDate(e) {
    e.preventDefault()
    if (!naturalDate.trim()) return
    setNaturalDateErr('')
    const iso = parseNaturalDate(naturalDate)
    if (iso) { setFromTs(iso); setNaturalDate(''); setNaturalDateErr(''); setActivePreset(null) }
    else setNaturalDateErr(`Try: "monday", "3 days ago", "last week", "2 months ago"`)
  }

  // Apply a quick date preset (null = clear)
  function applyPreset(preset) {
    setNaturalDateErr('')
    setActivePreset(preset)
    if (!preset) { setFromTs(''); setToTs(''); setShowCustomRange(false); return }
    const now = new Date()
    setToTs('')  // clear To so "now" is implied
    setShowCustomRange(false)
    switch (preset) {
      case '1h':  { const d = new Date(now); d.setHours(d.getHours() - 1);   setFromTs(d.toISOString()); break }
      case '6h':  { const d = new Date(now); d.setHours(d.getHours() - 6);   setFromTs(d.toISOString()); break }
      case '24h': { const d = new Date(now); d.setDate(d.getDate() - 1);      setFromTs(d.toISOString()); break }
      case '7d':  { const d = new Date(now); d.setDate(d.getDate() - 7);      setFromTs(d.toISOString()); break }
      case '30d': { const d = new Date(now); d.setDate(d.getDate() - 30);     setFromTs(d.toISOString()); break }
      default: break
    }
  }

  function downloadSelectedJSON() {
    const selectedEvs = events.filter(e => checkedFoIds.has(e.fo_id))
    if (!selectedEvs.length) return
    const blob = new Blob([JSON.stringify(selectedEvs, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `events-${caseId}-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Explain selected events with LLM
  async function explainSelected() {
    const selectedEvs = events.filter(e => checkedFoIds.has(e.fo_id))
    if (!selectedEvs.length) return
    setExplaining(true)
    setExplainResult(null)
    try {
      const r = await api.llm.explainEvents({ events: selectedEvs })
      setExplainResult(r)
    } catch (err) {
      setExplainResult({ error: err.message })
    } finally {
      setExplaining(false)
    }
  }

  function toggleCheck(foId) {
    setCheckedFoIds(prev => {
      const next = new Set(prev)
      if (next.has(foId)) next.delete(foId); else next.add(foId)
      return next
    })
  }

  const maxCount  = histogram.reduce((m, b) => Math.max(m, b.doc_count), 1)
  const hasFilters = selectedTypesStr || fromTs || toTs || flaggedOnly || selectedLevel || Object.keys(facetFilters).length > 0
  const vis        = col => visibleCols.includes(col)

  return (
    <div className="flex h-full">
      {/* ── Filter sidebar ─────────────────────────────── */}
      <div className="w-44 flex-shrink-0 bg-gray-50 border-r border-gray-200 flex flex-col">
        <div className="p-3 border-b border-gray-200">
          <p className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 uppercase tracking-widest">
            <Filter size={11} /> Filters
          </p>
        </div>

        <div className="p-3 space-y-3 flex-1 overflow-y-auto">
          {/* Artifact type — chips (≤6) or dropdown (>6) */}
          {(() => {
            const visibleTypes = artifactTypes.filter(at => !CHIP_BLACKLIST.has(at))
            if (visibleTypes.length === 0) return null
            const activeSet = selectedTypesStr ? new Set(selectedTypesStr.split(',')) : null
            const activeCount = selectedTypesStr === '__none__' ? 0 : (activeSet ? activeSet.size : visibleTypes.length)
            function toggleType(at) {
              setSelectedTypesStr(prev => {
                const cur = new Set(prev === '__none__' ? [] : (prev ? prev.split(',') : artifactTypes))
                if (cur.has(at)) cur.delete(at); else cur.add(at)
                if (cur.size === 0) return '__none__'
                if (cur.size === artifactTypes.length) return ''
                return [...cur].sort().join(',')
              })
            }
            if (visibleTypes.length <= 6) {
              return (
                <div>
                  <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Artifact</label>
                  <div className="flex flex-wrap gap-1">
                    {visibleTypes.map(at => {
                      const active = !activeSet || activeSet.has(at)
                      return (
                        <span key={at} className="inline-flex items-center gap-0.5">
                          <button
                            onClick={() => toggleType(at)}
                            title={active ? `Hide ${at}` : `Show ${at}`}
                            className={`badge cursor-pointer select-none transition-all ${
                              active
                                ? (ARTIFACT_COLORS[at] || ARTIFACT_COLORS.generic)
                                : `${ARTIFACT_COLORS[at] || ARTIFACT_COLORS.generic} opacity-40 hover:opacity-90`
                            }`}
                          >
                            {at}
                          </button>
                          {active && <StatsPopover caseId={caseId} type={at} />}
                        </span>
                      )
                    })}
                  </div>
                </div>
              )
            }
            return (
              <div>
                <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Artifact</label>
                <button
                  onClick={() => setTypeDropdownOpen(v => !v)}
                  className="w-full flex items-center justify-between px-2 py-1.5 text-xs border border-gray-200 rounded-lg bg-white hover:border-brand-accent hover:text-brand-accent transition-colors"
                >
                  <span className="text-gray-600">{activeCount} / {visibleTypes.length} types</span>
                  <ChevronDown size={11} className={`text-gray-400 transition-transform ${typeDropdownOpen ? 'rotate-180' : ''}`} />
                </button>
                {typeDropdownOpen && (
                  <div className="mt-1 border border-gray-200 rounded-lg bg-white overflow-hidden">
                    <div className="flex gap-1 px-2 py-1.5 border-b border-gray-100">
                      <button
                        onClick={() => setSelectedTypesStr('')}
                        className="text-[10px] text-brand-accent hover:underline"
                      >All</button>
                      <span className="text-[10px] text-gray-300">·</span>
                      <button
                        onClick={() => setSelectedTypesStr('__none__')}
                        className="text-[10px] text-gray-500 hover:underline"
                      >None</button>
                    </div>
                    <div className="max-h-48 overflow-y-auto">
                      {visibleTypes.map(at => {
                        const active = !activeSet || activeSet.has(at)
                        return (
                          <label key={at} className="flex items-center gap-2 px-2 py-1 hover:bg-gray-50 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={active}
                              onChange={() => toggleType(at)}
                              className="accent-brand-accent flex-shrink-0"
                            />
                            <span className={`badge text-[10px] ${ARTIFACT_COLORS[at] || ARTIFACT_COLORS.generic} ${active ? '' : 'opacity-40'}`}>
                              {at}
                            </span>
                            {active && (
                              <span className="ml-auto" onClick={e => e.stopPropagation()}>
                                <StatsPopover caseId={caseId} type={at} />
                              </span>
                            )}
                          </label>
                        )
                      })}
                    </div>
                  </div>
                )}
              </div>
            )
          })()}

          {/* Date range */}
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Time Range</label>

            {/* Quick presets */}
            <div className="grid grid-cols-3 gap-1 mb-1.5">
              {[
                { id: '1h',  label: '1h'  },
                { id: '6h',  label: '6h'  },
                { id: '24h', label: '24h' },
                { id: '7d',  label: '7d'  },
                { id: '30d', label: '30d' },
              ].map(p => (
                <button
                  key={p.id}
                  onClick={() => applyPreset(p.id)}
                  className={`text-[10px] py-0.5 rounded border transition-colors ${
                    activePreset === p.id
                      ? 'bg-brand-accent text-white border-brand-accent'
                      : 'bg-white text-gray-600 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                  }`}
                >
                  {p.label}
                </button>
              ))}
              <button
                onClick={() => { setShowCustomRange(v => !v); setActivePreset(null) }}
                className={`text-[10px] py-0.5 rounded border transition-colors col-span-3 mt-0.5 ${
                  showCustomRange
                    ? 'bg-brand-accent text-white border-brand-accent'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                }`}
              >
                Custom range
              </button>
            </div>

            {/* Custom date range inputs */}
            {showCustomRange && (
              <div className="space-y-2 mt-1 p-2 bg-gray-50 rounded border border-gray-200">
                {(() => {
                  function parseDate(val) {
                    if (!val?.trim()) return null
                    const normalized = val.trim().replace(' ', 'T')
                    // No timezone → treat as UTC (timeline displays UTC timestamps)
                    const asUtc = /Z|[+-]\d{2}:\d{2}$/.test(normalized) ? normalized : normalized + 'Z'
                    const d = new Date(asUtc)
                    return isNaN(d.getTime()) ? null : d.toISOString()
                  }
                  function fmtTs(iso) {
                    return iso ? iso.slice(0, 19).replace('T', ' ') : ''
                  }
                  function applyRange() {
                    const fv = fromInputRef.current?.value
                    const tv = toInputRef.current?.value
                    const fp = parseDate(fv)
                    const tp = parseDate(tv)
                    if (fp) { setFromTs(fp); setActivePreset(null) } else if (!fv?.trim()) setFromTs('')
                    if (tp) setToTs(tp); else if (!tv?.trim()) setToTs('')
                  }
                  function DateField({ label, inputRef, calRef, defaultVal }) {
                    return (
                      <div className="mb-2">
                        <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-0.5">{label}</p>
                        <div className="flex gap-1 items-center">
                          <input
                            ref={inputRef}
                            type="text"
                            defaultValue={defaultVal}
                            placeholder="2026-03-24 11:36:00"
                            className="input flex-1 text-[10px] py-0.5 px-1.5 font-mono"
                          />
                          <button
                            type="button"
                            title="Pick date"
                            onClick={() => calRef.current?.showPicker()}
                            className="btn-ghost p-1 text-gray-400 hover:text-brand-accent flex-shrink-0"
                          >
                            <CalendarDays size={12} />
                          </button>
                          <input
                            ref={calRef}
                            type="date"
                            className="absolute opacity-0 w-0 h-0 pointer-events-none"
                            onChange={e => {
                              if (e.target.value && inputRef.current) {
                                const existingTime = inputRef.current.value.split(' ')[1] || '00:00:00'
                                inputRef.current.value = `${e.target.value} ${existingTime}`
                              }
                            }}
                          />
                        </div>
                      </div>
                    )
                  }
                  return (
                    <form onSubmit={e => { e.preventDefault(); applyRange() }}>
                      <DateField label="From" inputRef={fromInputRef} calRef={fromCalRef} defaultVal={fmtTs(fromTs)} key={`from-${fromTs}`} />
                      <DateField label="To"   inputRef={toInputRef}   calRef={toCalRef}   defaultVal={fmtTs(toTs)}   key={`to-${toTs}`} />
                      <button type="submit" className="w-full btn-ghost text-[10px] py-0.5 border border-gray-200 rounded">
                        Apply
                      </button>
                    </form>
                  )
                })()}
                <div>
                  <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-0.5">Natural language (From)</p>
                  <form onSubmit={applyNaturalDate} className="flex gap-1">
                    <input
                      type="text"
                      value={naturalDate}
                      onChange={e => { setNaturalDate(e.target.value); setNaturalDateErr('') }}
                      placeholder="monday, 3 days ago…"
                      className="input flex-1 text-[10px] py-0.5 px-1.5"
                    />
                    <button type="submit" className="btn-ghost text-[10px] px-1.5 py-0.5">→</button>
                  </form>
                  {naturalDateErr && (
                    <p className="text-[10px] text-amber-600 mt-0.5">{naturalDateErr}</p>
                  )}
                </div>
              </div>
            )}

            {/* Active range display */}
            {(fromTs || toTs) && (
              <div className="mt-1.5 flex items-center gap-1 text-[10px] text-gray-500 bg-gray-50 rounded px-1.5 py-1">
                <span className="flex-1 truncate">
                  {fromTs ? new Date(fromTs).toLocaleDateString() : '…'}
                  {' → '}
                  {toTs ? new Date(toTs).toLocaleDateString() : 'now'}
                </span>
                <button onClick={() => applyPreset(null)} className="text-gray-500 hover:text-red-500 flex-shrink-0">
                  <X size={9} />
                </button>
              </div>
            )}
          </div>

          {/* Level filter */}
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Level</label>
            <div className="flex flex-wrap gap-1">
              {[
                { value: '',              label: 'All',   cls: 'border-gray-200 text-gray-500' },
                { value: 'critical',      label: 'Crit',  cls: 'bg-red-100 text-red-700 border-red-200' },
                { value: 'high',          label: 'High',  cls: 'bg-orange-100 text-orange-700 border-orange-200' },
                { value: 'medium',        label: 'Med',   cls: 'bg-yellow-100 text-yellow-700 border-yellow-200' },
                { value: 'low',           label: 'Low',   cls: 'bg-blue-100 text-blue-700 border-blue-200' },
                { value: 'informational', label: 'Info',  cls: 'bg-gray-100 text-gray-500 border-gray-200' },
                { value: 'none',          label: 'None',  cls: 'bg-slate-100 text-slate-400 border-slate-200' },
              ].map(({ value, label, cls }) => (
                <button
                  key={value || 'all'}
                  onClick={() => setSelectedLevel(value)}
                  className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
                    selectedLevel === value
                      ? (value === '' || value === 'none') ? 'bg-gray-600 text-white border-gray-500' : cls
                      : 'border-gray-200 text-gray-500 hover:border-brand-accent hover:text-brand-accent'
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Flagged only */}
          <div>
            <button
              onClick={() => setFlaggedOnly(v => !v)}
              className={`flex items-center gap-2 w-full text-xs px-2 py-1.5 rounded-lg border transition-colors ${
                flaggedOnly
                  ? 'bg-red-50 text-red-600 border-red-200'
                  : 'text-gray-600 hover:bg-gray-50 border-transparent'
              }`}
            >
              <Flag size={11} className={flaggedOnly ? 'text-red-500' : 'text-gray-500'} />
              Flagged only
            </button>
          </div>

          {hasFilters && (
            <button
              onClick={() => { setSelectedTypesStr(''); setFromTs(''); setToTs(''); setFlaggedOnly(false); setSelectedLevel(''); setFacetFilters({}) }}
              className="btn-ghost w-full text-xs justify-center"
            >
              <X size={11} /> Clear all
            </button>
          )}

          {/* ── Saved searches ───────────────────────── */}
          <div className="border-t border-gray-100 pt-3">
            <div className="flex items-center justify-between mb-1.5">
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider flex items-center gap-1">
                <Bookmark size={9} /> Saved
              </p>
              {(query || Object.keys(facetFilters).length > 0) && (
                <button onClick={() => setShowSaveForm(v => !v)}
                  className="text-[10px] text-brand-accent hover:text-brand-accenthover">+ Save</button>
              )}
            </div>
            {showSaveForm && (
              <div className="mb-1.5 flex gap-1">
                <input value={saveSearchName} onChange={e => setSaveSearchName(e.target.value)}
                  placeholder="Name…" className="input flex-1 text-[11px] py-0.5 px-1.5" />
                <button
                  onClick={async () => {
                    if (!saveSearchName.trim()) return
                    const s = await api.savedSearches.create(caseId, { name: saveSearchName.trim(), query, filters: facetFilters })
                    setSavedSearches(p => [...p, s])
                    setSaveSearchName(''); setShowSaveForm(false)
                  }}
                  className="btn-primary text-xs px-1.5 py-0.5">
                  <BookmarkCheck size={10} />
                </button>
              </div>
            )}
            {savedSearches.length === 0 && (
              <p className="text-[10px] text-gray-500 italic">None yet</p>
            )}
            {savedSearches.map(s => (
              <div key={s.id} className="flex items-center gap-0.5 mb-0.5 group">
                <button
                  onClick={() => { setInputVal(s.query || ''); setQuery(s.query || ''); setFacetFilters(s.filters || {}) }}
                  className="flex-1 text-left text-[11px] text-gray-600 hover:text-brand-text truncate px-1 py-0.5 rounded hover:bg-gray-50 transition-colors">
                  {s.name}
                </button>
                <button
                  onClick={async () => { await api.savedSearches.delete(caseId, s.id); setSavedSearches(p => p.filter(x => x.id !== s.id)) }}
                  className="opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-gray-100 text-gray-500 hover:text-red-500 transition-all">
                  <Trash2 size={9} />
                </button>
              </div>
            ))}
          </div>

          {/* ── Facet chips ──────────────────────────── */}
          {['by_hostname','by_username','by_event_id','by_channel','by_src_ip','by_dest_ip','by_status_code','by_http_method','by_domain'].map(facetKey => {
            const filterKey = { by_hostname:'hostname', by_username:'username', by_event_id:'event_id', by_channel:'channel', by_src_ip:'src_ip', by_dest_ip:'dest_ip', by_status_code:'status_code', by_http_method:'http_method', by_domain:'domain' }[facetKey]
            const label     = { by_hostname:'Host',    by_username:'User',     by_event_id:'Event ID', by_channel:'Channel', by_src_ip:'Source IP', by_dest_ip:'Dest IP', by_status_code:'HTTP Status', by_http_method:'Method', by_domain:'Domain' }[facetKey]
            const buckets   = facets[facetKey]?.buckets || []
            if (!buckets.length) return null
            return (
              <div key={facetKey} className="border-t border-gray-100 pt-3">
                <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1">{label}</p>
                <div className="flex flex-wrap gap-0.5">
                  {buckets.slice(0, 8).map(b => (
                    <button key={b.key}
                      onClick={() => setFacetFilters(prev =>
                        prev[filterKey] === String(b.key)
                          ? Object.fromEntries(Object.entries(prev).filter(([k]) => k !== filterKey))
                          : { ...prev, [filterKey]: String(b.key) }
                      )}
                      className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors mb-0.5 ${
                        facetFilters[filterKey] === String(b.key)
                          ? 'bg-brand-accent text-white border-brand-accent'
                          : 'border-gray-200 text-gray-600 hover:border-brand-accent'
                      }`}>
                      <span className="truncate max-w-[80px] block">{b.key}</span>
                      <span className="text-[10px] opacity-60">{b.doc_count}</span>
                    </button>
                  ))}
                </div>
              </div>
            )
          })}
        </div>

        {/* Event count footer */}
        <div className="p-3 border-t border-gray-200 space-y-0.5">
          <p className="text-xs font-semibold text-brand-text">{total.toLocaleString()}</p>
          <p className="text-[10px] text-gray-500">{query ? 'search results' : 'events total'}</p>
          {events.length < total && (
            <p className="text-[10px] text-gray-500">{events.length.toLocaleString()} loaded</p>
          )}
        </div>
      </div>

      {/* ── Main content ──────────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0">

        {/* Search bar */}
        <div className="px-4 py-3 border-b border-gray-200 bg-white">
          <form onSubmit={submitSearch} className="flex gap-2 items-center">
            <div className="relative flex-1">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
              <input
                ref={searchRef}
                value={inputVal}
                onChange={e => { setInputVal(e.target.value); setSuggestOpen(true); setSuggestIdx(0) }}
                onFocus={() => setSuggestOpen(true)}
                onBlur={() => setTimeout(() => setSuggestOpen(false), 150)}
                onKeyDown={e => {
                  if (!suggestOpen || fieldSuggestions.length === 0) return
                  if (e.key === 'ArrowDown') { e.preventDefault(); setSuggestIdx(i => (i + 1) % fieldSuggestions.length) }
                  else if (e.key === 'ArrowUp')   { e.preventDefault(); setSuggestIdx(i => (i - 1 + fieldSuggestions.length) % fieldSuggestions.length) }
                  else if (e.key === 'Tab' || (e.key === 'Enter' && fieldSuggestions[suggestIdx])) {
                    e.preventDefault()
                    const chosen = fieldSuggestions[suggestIdx]
                    const before = inputVal.replace(/[^\s()]*$/, '')
                    setInputVal(before + chosen + ':')
                    setSuggestOpen(false)
                  } else if (e.key === 'Escape') {
                    setSuggestOpen(false)
                  }
                }}
                placeholder='Lucene: evtx.event_id:4624  process.executable_name:powershell.exe  message:/cmd\.exe/  NOT user.name:SYSTEM'
                className="input-lg pl-9 pr-4 text-xs font-mono"
              />
              {suggestOpen && fieldSuggestions.length > 0 && (
                <div className="absolute top-full left-0 right-0 mt-1 bg-white border border-gray-200 rounded-md shadow-card-md z-20 max-h-72 overflow-y-auto fade-in">
                  <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-gray-500 border-b border-gray-100 bg-gray-50">
                    Fields · ↑↓ select · Tab/Enter insert · Esc dismiss
                  </div>
                  {fieldSuggestions.map((name, i) => (
                    <button
                      key={name}
                      type="button"
                      onMouseDown={e => e.preventDefault()}
                      onClick={() => {
                        const before = inputVal.replace(/[^\s()]*$/, '')
                        setInputVal(before + name + ':')
                        setSuggestOpen(false)
                        searchRef.current?.focus()
                      }}
                      className={`block w-full text-left px-3 py-1.5 text-xs font-mono ${
                        i === suggestIdx ? 'bg-brand-accentlight text-brand-text' : 'text-gray-700 hover:bg-gray-50'
                      }`}
                    >
                      {name}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => setShowFieldExplorer(v => !v)}
              title="Fields + syntax — browse all indexed fields, see Lucene examples"
              className={`btn-ghost text-xs px-2 ${showFieldExplorer ? 'text-brand-accent' : 'text-gray-500'}`}
            >
              <Layers size={13} />
            </button>

            <button
              type="button"
              onClick={() => setShowAggregate(v => !v)}
              title="Aggregate — count, sum, distribution by any field"
              className={`btn-ghost text-xs px-2 ${showAggregate ? 'text-brand-accent' : 'text-gray-500'}`}
            >
              <Sigma size={13} />
            </button>

            <button
              type="button"
              onClick={() => setShowAiAssist(v => !v)}
              title="AI Search Assist — describe what you want to find"
              className={`btn-ghost text-xs ${showAiAssist ? 'text-indigo-500' : 'text-gray-500'}`}
            >
              <Sparkles size={13} />
            </button>

            <button type="submit" className="btn-primary text-xs px-4">Search</button>

            {(query || inputVal) && (
              <button type="button" onClick={clearSearch} className="btn-ghost text-xs" title="Clear search">
                <X size={13} />
              </button>
            )}

            <button type="button" onClick={downloadCsv} className="btn-ghost text-xs" title="Export CSV">
              <Download size={13} />
            </button>

            <button
              type="button"
              onClick={refresh}
              disabled={refreshing}
              className={`btn-ghost text-xs ${refreshing ? 'text-brand-accent' : ''}`}
              title="Refresh — reload events and histogram to see newly ingested files"
            >
              <RefreshCw size={13} className={refreshing ? 'animate-spin' : ''} />
            </button>

            {histogram.length > 0 && (
              <button
                type="button"
                onClick={() => setShowHistogram(v => !v)}
                className={`btn-ghost text-xs ${showHistogram ? 'text-brand-accent' : ''}`}
                title="Toggle histogram"
              >
                <BarChart2 size={13} />
              </button>
            )}

            {/* Column picker trigger */}
            <div className="relative" ref={colPickerRef}>
              <button
                type="button"
                onClick={() => setShowColPicker(v => !v)}
                className={`btn-ghost text-xs relative ${showColPicker ? 'text-brand-accent' : ''}`}
                title={autoMode ? 'Columns (auto-detect active)' : 'Configure columns'}
              >
                <SlidersHorizontal size={13} />
                {autoMode && (
                  <span className="absolute -top-1 -right-1 w-2 h-2 bg-brand-accent rounded-full border border-white" />
                )}
              </button>

              {showColPicker && (
                <div className="absolute top-full right-0 mt-1 bg-white border border-gray-200 rounded-lg shadow-lg z-20 w-52">
                  {/* Auto / Presets section */}
                  <div className="p-3 border-b border-gray-100 flex flex-col gap-1">
                    <div className="flex items-center gap-1.5 mb-1">
                      <button
                        onClick={resetToAuto}
                        className={`flex items-center gap-1 text-[10px] font-medium px-2 py-0.5 rounded border transition-colors ${
                          autoMode
                            ? 'bg-brand-accentlight text-brand-accent border-brand-accent/30'
                            : 'text-gray-500 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${autoMode ? 'bg-brand-accent animate-pulse' : 'bg-gray-300'}`} />
                        Auto-detect
                      </button>
                      <button onClick={resetCols} className="text-[10px] text-gray-400 hover:text-gray-600 hover:underline ml-auto">Defaults</button>
                    </div>
                    <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mt-0.5 mb-0.5">Presets</p>
                    <button
                      onClick={() => {
                        setAutoMode(false); localStorage.setItem(LS_AUTO_KEY, 'false')
                        const net = ['action','protocol','src_ip','src_port','dst_ip','dst_port']
                        setVisibleCols(prev => { const next = [...new Set([...prev, ...net])]; localStorage.setItem(LS_KEY, JSON.stringify(next)); return next })
                      }}
                      className="text-[10px] text-teal-600 hover:underline text-left"
                    >+ Network</button>
                    <button
                      onClick={() => {
                        setAutoMode(false); localStorage.setItem(LS_AUTO_KEY, 'false')
                        const http = ['http_method','http_status','http_path','src_ip','user_agent','resp_size']
                        setVisibleCols(prev => { const next = [...new Set([...prev, ...http])]; localStorage.setItem(LS_KEY, JSON.stringify(next)); return next })
                      }}
                      className="text-[10px] text-blue-600 hover:underline text-left"
                    >+ HTTP</button>
                    <button
                      onClick={() => {
                        setAutoMode(false); localStorage.setItem(LS_AUTO_KEY, 'false')
                        const pf = ['process','run_count','pid']
                        setVisibleCols(prev => { const next = [...new Set([...prev, ...pf])]; localStorage.setItem(LS_KEY, JSON.stringify(next)); return next })
                      }}
                      className="text-[10px] text-amber-600 hover:underline text-left"
                    >+ Process</button>
                    <button
                      onClick={() => {
                        setAutoMode(false); localStorage.setItem(LS_AUTO_KEY, 'false')
                        const evtx = ['event_id','level','channel','rule']
                        setVisibleCols(prev => { const next = [...new Set([...prev, ...evtx])]; localStorage.setItem(LS_KEY, JSON.stringify(next)); return next })
                      }}
                      className="text-[10px] text-violet-600 hover:underline text-left"
                    >+ EVTX / Windows</button>
                  </div>
                  {/* Scrollable column checkboxes with data indicators */}
                  <div className="p-3 max-h-64 overflow-y-auto">
                    <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-2">Columns</p>
                    <div className="space-y-0.5">
                      {ALL_COLUMNS.map(col => {
                        const hasData = ALWAYS_ON_COLS.has(col.id) || detectedCols.has(col.id)
                        const isAlways = ALWAYS_ON_COLS.has(col.id)
                        return (
                          <label key={col.id} className="flex items-center gap-2 cursor-pointer py-1 px-1 rounded hover:bg-gray-50">
                            <input
                              type="checkbox"
                              checked={visibleCols.includes(col.id)}
                              onChange={() => toggleCol(col.id)}
                              disabled={isAlways}
                              className="rounded border-gray-300 accent-brand-accent disabled:opacity-40"
                            />
                            <span
                              className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${hasData ? 'bg-green-400' : 'bg-gray-200'}`}
                              title={hasData ? 'Has data in current events' : 'No data in current events'}
                            />
                            <span className={`text-xs ${hasData ? 'text-gray-700' : 'text-gray-400'}`}>{col.label}</span>
                            {isAlways && <span className="text-[9px] text-gray-400 ml-auto">always</span>}
                          </label>
                        )
                      })}
                    </div>
                  </div>
                </div>
              )}
            </div>

            <button
              type="button"
              onClick={() => setShowHelp(v => !v)}
              className={`btn-ghost text-xs ${showHelp ? 'text-brand-accent' : ''}`}
              title="Keyboard shortcuts (?)"
            >
              <Keyboard size={13} />
            </button>
          </form>

          {(query || Object.keys(facetFilters).length > 0) && (
            <div className="flex items-center gap-2 mt-2 flex-wrap">
              {query && (
                <>
                  <span className="text-[10px] text-gray-500">Query:</span>
                  <code className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 text-[10px] max-w-xs truncate font-mono">
                    {query}
                  </code>
                </>
              )}
              {Object.entries(facetFilters).map(([k, v]) => (
                <span key={k}
                  className="badge bg-indigo-50 text-indigo-700 border border-indigo-200 cursor-pointer hover:bg-indigo-100 text-[10px]"
                  onClick={() => setFacetFilters(prev => Object.fromEntries(Object.entries(prev).filter(([key]) => key !== k)))}>
                  {k}: {v} ×
                </span>
              ))}
              <span className="text-[10px] text-gray-500">
                — {total.toLocaleString()} result{total !== 1 ? 's' : ''}
              </span>
            </div>
          )}

          {/* AI Search Assist inline panel */}
          {showAiAssist && (
            <AiSearchAssistPanel
              caseId={caseId}
              onApply={(q, fts, tts) => {
                setInputVal(q); setQuery(q)
                if (fts) setFromTs(fts)
                if (tts) setToTs(tts)
                setShowAiAssist(false)
              }}
              onClose={() => setShowAiAssist(false)}
            />
          )}

          {showFieldExplorer && (
            <FieldExplorer
              fieldMap={fieldMap}
              onInsert={(name, withColon = true) => {
                setInputVal(v => (v.replace(/[^\s()]*$/, '') + name + (withColon ? ':' : '')))
                searchRef.current?.focus()
              }}
              onUseSnippet={(q) => { setInputVal(q); setShowFieldExplorer(false); searchRef.current?.focus() }}
              onAggregate={(name) => {
                setAggState(s => ({ ...s, fields: [name], agg: 'terms' }))
                setShowFieldExplorer(false)
                setShowAggregate(true)
              }}
              onClose={() => setShowFieldExplorer(false)}
            />
          )}

          {showAggregate && (
            <AggregatePanel
              caseId={caseId}
              query={query}
              fieldMap={fieldMap}
              state={aggState}
              setState={setAggState}
              result={aggResult}
              loading={aggLoading}
              onRun={async () => {
                if (!aggState.fields.length) return
                setAggLoading(true)
                try {
                  const params = {
                    field: aggState.fields.join(','),
                    agg: aggState.agg, q: query,
                    size: aggState.size, interval: aggState.interval,
                  }
                  if (aggState.subCard?.length) params.sub_card = aggState.subCard.join(',')
                  const r = await api.search.aggregate(caseId, params)
                  setAggResult(r)
                } catch (err) {
                  setAggResult({ error: err?.message || 'Aggregation failed' })
                } finally {
                  setAggLoading(false)
                }
              }}
              onClose={() => setShowAggregate(false)}
            />
          )}
        </div>

        {/* Histogram */}
        {showHistogram && histogram.length > 0 && (() => {
          // Uniform spacing from auto_date_histogram → drives label granularity.
          const bucketMs = histogram.length > 1 ? (histogram[1].key - histogram[0].key) : 86400000
          const fmtBucket = (key) => {
            const d = new Date(key)
            if (bucketMs < 60000)    return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' })
            if (bucketMs < 3600000)  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
            if (bucketMs < 86400000) return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' })
            return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
          }
          const grain = bucketMs < 60000 ? 'second' : bucketMs < 3600000 ? 'minute' : bucketMs < 86400000 ? 'hour' : 'day'
          const humanizeSpan = (ms) => {
            const s = Math.round(ms / 1000)
            if (s < 90) return `${s}s`
            const m = Math.round(s / 60); if (m < 90) return `${m}m`
            const h = Math.round(m / 60); if (h < 48) return `${h}h`
            return `${Math.round(h / 24)}d`
          }
          // Live read-out while dragging — span + event count, before release.
          const dragInfo = histoDragSel ? (() => {
            const a = Math.min(histoDragSel.start, histoDragSel.end)
            const b = Math.max(histoDragSel.start, histoDragSel.end)
            let n = 0
            for (let i = a; i <= b; i++) n += histogram[i].doc_count
            const from = histogram[a].key
            const to = histogram[b].key + bucketMs
            return { from, to, count: n, bars: b - a + 1, span: to - from }
          })() : null
          return (
          <div className="px-4 py-2 border-b border-gray-200 bg-gray-50">
            <div className="flex items-center gap-2 mb-1.5">
              <p className="text-[10px] text-gray-500 flex items-center gap-1">
                <BarChart2 size={9} /> Event activity (per {grain}) — click a bar, or click + swipe to zoom a range
              </p>
              {dragInfo ? (
                <span className="text-[10px] font-semibold text-brand-accent flex items-center gap-1 tabular-nums">
                  {fmtBucket(dragInfo.from)} – {fmtBucket(dragInfo.to - bucketMs)}
                  <span className="text-gray-400 font-normal">
                    · {humanizeSpan(dragInfo.span)} · {dragInfo.count.toLocaleString()} events
                  </span>
                </span>
              ) : fromTs && toTs && (
                <span className="text-[10px] font-semibold text-brand-accent flex items-center gap-1">
                  {fmtBucket(new Date(fromTs).getTime())}
                  {(() => {
                    const end = new Date(new Date(toTs).getTime() - bucketMs)
                    return end.getTime() > new Date(fromTs).getTime()
                      ? <> – {fmtBucket(end.getTime())}</>
                      : null
                  })()}
                  <button
                    onClick={() => { setFromTs(''); setToTs('') }}
                    className="text-gray-400 hover:text-red-500 transition-colors ml-0.5"
                    title="Clear time filter (zoom out)"
                  >×</button>
                </span>
              )}
            </div>
            {/* Bars fill the width (no scroll) so the axis stays aligned. Each
                column is a full-height click/drag target — not just the bar. */}
            <div className="flex items-stretch gap-px h-12 select-none">
              {histogram.map((b, i) => {
                const h = Math.max(2, Math.round((b.doc_count / maxCount) * 40))
                const day = fmtBucket(b.key)
                const inDrag = histoDragSel &&
                  i >= Math.min(histoDragSel.start, histoDragSel.end) &&
                  i <= Math.max(histoDragSel.start, histoDragSel.end)
                const active = !histoDragSel && fromTs && toTs &&
                  b.key >= new Date(fromTs).getTime() &&
                  b.key < new Date(toTs).getTime()
                return (
                  <div
                    key={i}
                    className={`flex-1 min-w-0 flex flex-col justify-end group cursor-pointer rounded-sm ${
                      inDrag ? 'bg-brand-accent/15' : 'hover:bg-gray-200/60'
                    }`}
                    onMouseDown={e => histoBarDown(i, e)}
                    onMouseEnter={() => histoBarEnter(i)}
                    title={`${day}: ${b.doc_count.toLocaleString()} events — click or drag to filter`}
                  >
                    <div
                      style={{ height: h }}
                      className={`w-full rounded-t transition-colors ${
                        inDrag
                          ? 'bg-brand-accent'
                          : active
                            ? 'bg-brand-accent ring-1 ring-brand-accent/50'
                            : 'bg-brand-accent/40 group-hover:bg-brand-accent/70'
                      }`}
                    />
                  </div>
                )
              })}
            </div>
            {/* Time axis — start · middle · end, aligned to the bar row width */}
            {histogram.length > 1 && (
              <div className="flex justify-between text-[9px] text-gray-400 mt-1 tabular-nums">
                <span>{fmtBucket(histogram[0].key)}</span>
                <span>{fmtBucket(histogram[Math.floor((histogram.length - 1) / 2)].key)}</span>
                <span>{fmtBucket(histogram[histogram.length - 1].key)}</span>
              </div>
            )}
          </div>
          )
        })()}

        {/* AI explain floating action bar */}
        {checkedFoIds.size > 0 && (
          <div className="px-4 py-2 border-b border-purple-200 bg-purple-50 flex items-center gap-3">
            <Brain size={13} className="text-purple-500 flex-shrink-0" />
            <span className="text-xs text-purple-700 font-medium">
              {checkedFoIds.size} event{checkedFoIds.size !== 1 ? 's' : ''} selected
            </span>
            <button
              onClick={downloadSelectedJSON}
              className="ml-auto btn-ghost text-xs text-gray-600 hover:text-gray-800 border border-gray-200 rounded-lg px-2.5 py-1 flex items-center gap-1.5"
              title="Download selected events as JSON"
            >
              <Download size={11} /> Download
            </button>
            <button
              onClick={explainSelected}
              disabled={explaining}
              className="btn-ghost text-xs text-purple-600 hover:text-purple-800 border border-purple-200 rounded-lg px-2.5 py-1 flex items-center gap-1.5"
            >
              {explaining
                ? <><Loader2 size={11} className="animate-spin" /> Analyzing…</>
                : <><Brain size={11} /> Explain with AI</>}
            </button>
            <button
              onClick={() => { setCheckedFoIds(new Set()); setExplainResult(null) }}
              className="text-gray-500 hover:text-gray-600"
              title="Deselect all"
            >
              <X size={13} />
            </button>
          </div>
        )}

        {/* Events table */}
        <div className="flex-1 overflow-y-auto overflow-x-auto">
          {events.length === 0 && !loading && (
            <div className="flex flex-col items-center justify-center h-48 text-center">
              <Search size={28} className="text-gray-500 mb-3" />
              <p className="text-gray-500 text-sm">
                {query ? 'No events match your search.' : 'No events yet.'}
              </p>
              <p className="text-gray-500 text-xs mt-1">
                {query ? 'Try a different query.' : 'Upload forensics files using the Ingest button.'}
              </p>
            </div>
          )}

          {/* width: max-content + minWidth: 100% — table grows to fit the
              colgroup sum when columns overflow (so row backgrounds extend
              the full scroll width), but still fills the viewport when
              columns are narrower than the panel. */}
          <table className="text-xs" style={{ tableLayout: 'fixed', width: 'max-content', minWidth: '100%' }}>
            <colgroup>
              <col style={{ width: 28 }} />{/* checkbox */}
              <col style={{ width: 18 }} />{/* note dot */}
              <col style={{ width: 28 }} />{/* flag */}
              {visibleCols.map(colId => (
                <col key={colId} style={{ width: getColWidth(colId) }} />
              ))}
            </colgroup>
            <thead className="border-b border-gray-200 z-10">
              <tr>
                {/* Checkbox for AI explain — always visible */}
                <th className="sticky top-0 z-10 px-2 py-2.5 bg-gray-50">
                  <input
                    type="checkbox"
                    className="rounded border-gray-300 accent-brand-accent"
                    checked={events.length > 0 && events.every(e => checkedFoIds.has(e.fo_id))}
                    onChange={e => {
                      if (e.target.checked) setCheckedFoIds(new Set(events.map(ev => ev.fo_id)))
                      else setCheckedFoIds(new Set())
                    }}
                    title="Select all visible events"
                  />
                </th>
                {/* Note indicator — always visible */}
                <th className="sticky top-0 z-10 px-1 py-2.5 bg-gray-50" />
                {/* Flag — always visible */}
                <th className="sticky top-0 z-10 px-2 py-2.5 bg-gray-50" />

                {vis('timestamp') && (
                  <SortableTh colId="timestamp" label="Timestamp" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('timestamp')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('os') && (
                  <SortableTh colId="os" label="OS" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('os')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('type') && (
                  <SortableTh colId="type" label="Type" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('type')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('level') && (
                  <SortableTh colId="level" label="Level" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('level')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('event_id') && (
                  <SortableTh colId="event_id" label="Event ID" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('event_id')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('host') && (
                  <SortableTh colId="host" label="Host" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('host')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('user') && (
                  <SortableTh colId="user" label="User" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('user')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('process') && (
                  <SortableTh colId="process" label="Process" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('process')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('action') && (
                  <SortableTh colId="action" label="Action" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('action')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('protocol') && (
                  <SortableTh colId="protocol" label="Proto" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('protocol')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('src_ip') && (
                  <SortableTh colId="src_ip" label="Src IP" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('src_ip')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('src_port') && (
                  <SortableTh colId="src_port" label="S.Port" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('src_port')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('dst_ip') && (
                  <SortableTh colId="dst_ip" label="Dst IP" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('dst_ip')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('dst_port') && (
                  <SortableTh colId="dst_port" label="D.Port" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('dst_port')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('run_count') && (
                  <SortableTh colId="run_count" label="Runs" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('run_count')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('pid') && (
                  <SortableTh colId="pid" label="PID" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('pid')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('http_method') && (
                  <SortableTh colId="http_method" label="Method" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('http_method')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('http_status') && (
                  <SortableTh colId="http_status" label="Status" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('http_status')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('http_path') && (
                  <SortableTh colId="http_path" label="Path" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('http_path')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('user_agent') && (
                  <SortableTh colId="user_agent" label="User Agent" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('user_agent')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('resp_size') && (
                  <SortableTh colId="resp_size" label="Bytes" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('resp_size')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('cmdline') && (
                  <SortableTh colId="cmdline" label="Command Line" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('cmdline')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('proc_path') && (
                  <SortableTh colId="proc_path" label="Proc Path" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('proc_path')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('parent_proc') && (
                  <SortableTh colId="parent_proc" label="Parent Proc" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('parent_proc')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('parent_pid') && (
                  <SortableTh colId="parent_pid" label="Parent PID" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('parent_pid')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('host_ip') && (
                  <SortableTh colId="host_ip" label="Host IP" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('host_ip')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('host_fqdn') && (
                  <SortableTh colId="host_fqdn" label="FQDN" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('host_fqdn')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('user_domain') && (
                  <SortableTh colId="user_domain" label="User Domain" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('user_domain')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('user_sid') && (
                  <SortableTh colId="user_sid" label="User SID" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('user_sid')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('bytes') && (
                  <SortableTh colId="bytes" label="Bytes" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('bytes')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('mitre') && (
                  <SortableTh colId="mitre" label="MITRE" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('mitre')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('channel') && (
                  <SortableTh colId="channel" label="Channel" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('channel')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('rule') && (
                  <SortableTh colId="rule" label="Rule" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('rule')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('message') && (
                  <SortableTh colId="message" label="Message" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('message')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('tags') && (
                  <SortableTh colId="tags" label="Tags" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('tags')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
                {vis('raw_data') && (
                  <SortableTh colId="raw_data" label="Raw" sortField={sortField} sortOrder={sortOrder} onSort={toggleSort} width={getColWidth('raw_data')} onResizeStart={onResizeStart} onResizeDblClick={onResizeDblClick} onToggleExists={toggleExists} />
                )}
              </tr>
            </thead>
            <tbody>
              {events.map((ev, i) => (
                <EventRow
                  key={ev.fo_id || i}
                  index={i}
                  event={ev}
                  caseId={caseId}
                  visibleCols={visibleCols}
                  onSelect={(ev, idx) => { setSelectedEvent(ev); setSelectedRowIdx(idx) }}
                  selected={selectedEvent?.fo_id === ev.fo_id}
                  keyboardSelected={selectedRowIdx === i}
                  onFilterIn={(field, value)  => addFilter(field, value, false)}
                  onFilterOut={(field, value) => addFilter(field, value, true)}
                  rowRef={el => { rowRefs.current[i] = el }}
                  onFlagged={(foId, flagged) =>
                    setEvents(prev => prev.map(e =>
                      e.fo_id === foId ? { ...e, is_flagged: flagged } : e
                    ))
                  }
                  checked={checkedFoIds.has(ev.fo_id)}
                  onCheck={() => toggleCheck(ev.fo_id)}
                />
              ))}
            </tbody>
          </table>

          <div ref={loaderRef} className="py-5 flex items-center justify-center text-gray-500 text-xs gap-2">
            {loading
              ? <><Loader2 size={13} className="animate-spin" /> Loading…</>
              : events.length < total
              ? <span className="text-gray-500">↓ Scroll for more</span>
              : events.length > 0
              ? <span className="text-gray-500">— End of results —</span>
              : null}
          </div>
        </div>
      </div>

      {/* Event detail panel */}
      {selectedEvent && (
        <EventDetail
          key={selectedEvent.fo_id}
          event={selectedEvent}
          caseId={caseId}
          onClose={() => setSelectedEvent(null)}
          onFilterIn={(field, value)  => addFilter(field, value, false)}
          onFilterOut={(field, value) => addFilter(field, value, true)}
          onFlagged={(foId, flagged) => {
            setEvents(prev => prev.map(e => e.fo_id === foId ? { ...e, is_flagged: flagged } : e))
            setSelectedEvent(prev => prev?.fo_id === foId ? { ...prev, is_flagged: flagged } : prev)
          }}
        />
      )}

      {/* AI explain result panel */}
      {explainResult && (
        <div
          className="fixed inset-0 z-40 flex items-end justify-center pointer-events-none"
          style={{ paddingBottom: '1rem' }}
        >
          <div
            className="pointer-events-auto bg-white border border-purple-200 rounded-xl shadow-2xl p-5 w-full max-w-lg mx-4"
            style={{ maxHeight: '60vh', overflowY: 'auto' }}
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <Brain size={15} className="text-purple-500" />
                <span className="font-semibold text-sm text-gray-800">AI Event Explanation</span>
                {explainResult.events_count != null && (
                  <span className="badge bg-purple-100 text-purple-700 text-[10px]">
                    {explainResult.events_count} event{explainResult.events_count !== 1 ? 's' : ''}
                  </span>
                )}
                {explainResult.model_used && (
                  <span className="text-[10px] text-gray-500 ml-auto">{explainResult.model_used}</span>
                )}
              </div>
              <button
                onClick={() => { setExplainResult(null); setCheckedFoIds(new Set()) }}
                className="text-gray-500 hover:text-gray-600 ml-2"
              >
                <X size={14} />
              </button>
            </div>

            {explainResult.error ? (
              <p className="text-sm text-red-600">{explainResult.error}</p>
            ) : (
              <p className="text-sm text-gray-700 leading-relaxed whitespace-pre-wrap">
                {explainResult.explanation}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Keyboard shortcuts overlay */}
      {showHelp && (
        <div
          className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center"
          onClick={() => setShowHelp(false)}
        >
          <div
            className="bg-white rounded-xl shadow-2xl p-6 w-80 max-w-[90vw]"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Keyboard size={16} className="text-brand-accent" />
                <h3 className="font-semibold text-brand-text">Keyboard Shortcuts</h3>
              </div>
              <button onClick={() => setShowHelp(false)} className="btn-ghost p-1 text-gray-500">
                <X size={14} />
              </button>
            </div>
            <div className="space-y-3">
              {SHORTCUTS.map(({ keys, desc }) => (
                <div key={desc} className="flex items-center justify-between gap-4">
                  <span className="text-sm text-gray-600">{desc}</span>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    {keys.map((k, ki) => (
                      <span key={k} className="flex items-center gap-1">
                        {ki > 0 && <span className="text-[10px] text-gray-500">/</span>}
                        <kbd className="kbd">{k}</kbd>
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
            <div className="mt-5 pt-4 border-t border-gray-200">
              <p className="text-xs text-gray-500 leading-relaxed">
                Hover any row and click{' '}
                <span className="inline-flex items-center justify-center w-4 h-4 rounded bg-green-100 text-green-700 text-[9px] font-bold">+</span>
                {' '}to filter in or{' '}
                <span className="inline-flex items-center justify-center w-4 h-4 rounded bg-red-100 text-red-600 text-[9px] font-bold">−</span>
                {' '}to exclude a value.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

/* ── Sortable + resizable table header ── */
function SortableTh({ colId, label, sortField, sortOrder, onSort, width, onResizeStart, onResizeDblClick, onToggleExists }) {
  const thRef  = useRef(null)
  const active = sortField === colId
  const esField = COLUMN_ES_FIELD[colId]
  return (
    <th
      ref={thRef}
      style={{ width, minWidth: 48, overflow: 'hidden' }}
      className="sticky top-0 z-10 relative text-left px-3 py-2.5 text-[11px] font-bold text-gray-600 uppercase tracking-wider cursor-pointer select-none hover:text-brand-text transition-colors group bg-gray-50"
      onClick={() => onSort(colId)}
      title={esField ? `ES field: ${esField}` : undefined}
    >
      <span className="flex items-center gap-0.5 overflow-hidden">
        <span className="truncate">{label}</span>
        {active
          ? <span className="text-brand-accent flex-shrink-0">{sortOrder === 'asc' ? ' ↑' : ' ↓'}</span>
          : <span className="text-gray-500 flex-shrink-0"> ↕</span>}
        {esField && onToggleExists && (
          <>
            <button
              type="button"
              onClick={e => { e.stopPropagation(); onToggleExists(esField, false) }}
              className="opacity-0 group-hover:opacity-100 ml-1 px-1 rounded text-[9px] font-mono text-gray-500 hover:text-green-700 hover:bg-green-50 transition-all"
              title={`Only events where ${esField} exists (_exists_:${esField})`}
            >
              ∃
            </button>
            <button
              type="button"
              onClick={e => { e.stopPropagation(); onToggleExists(esField, true) }}
              className="opacity-0 group-hover:opacity-100 px-1 rounded text-[9px] font-mono text-gray-500 hover:text-red-700 hover:bg-red-50 transition-all"
              title={`Only events where ${esField} is missing (NOT _exists_:${esField})`}
            >
              ∅
            </button>
          </>
        )}
      </span>
      {/* Drag-to-resize handle — double-click to auto-fit */}
      <div
        className="absolute right-0 top-0 bottom-0 w-2 cursor-col-resize z-10 flex items-center justify-center group/handle"
        onMouseDown={e => onResizeStart(e, colId, thRef.current)}
        onDoubleClick={e => onResizeDblClick?.(e, colId, thRef.current)}
        onClick={e => e.stopPropagation()}
      >
        <div className="w-px h-4 bg-gray-300 opacity-0 group-hover:opacity-100 group/handle-hover:opacity-100 hover:!opacity-100 hover:bg-brand-accent transition-all" />
      </div>
    </th>
  )
}

/* ── Lucene Cheatsheet ── */
const CHEATSHEET = [
  {
    label: 'Basic matching',
    color: 'sky',
    rows: [
      { q: 'powershell',                     desc: 'Bare term — all fields'              },
      { q: 'evtx.event_id:4624',             desc: 'Exact field match'                   },
      { q: 'message:"lateral movement"',     desc: 'Exact phrase'                        },
      { q: 'process.name:power*',            desc: 'Suffix wildcard'                     },
      { q: 'host.hostname:DC0?',             desc: 'Single-char wildcard'                },
      { q: 'process.name:*shell',            desc: 'Leading wildcard (slower)'           },
    ],
  },
  {
    label: 'Boolean & grouping',
    color: 'violet',
    rows: [
      { q: 'evtx.event_id:4625 AND host.hostname:DC*',        desc: 'AND (default)'      },
      { q: 'evtx.event_id:(4625 OR 4771 OR 4776)',            desc: 'OR group'           },
      { q: 'NOT evtx.event_id:4672',                          desc: 'Exclude'            },
      { q: '(evtx.event_id:4624 OR 4625) AND NOT user.name:SYSTEM', desc: 'Complex'     },
    ],
  },
  {
    label: 'Field exists / missing',
    color: 'emerald',
    rows: [
      { q: '_exists_:process.command_line',     desc: 'Non-empty column (only rows with this field)' },
      { q: 'NOT _exists_:process.command_line', desc: 'Field missing / empty'                        },
      { q: '_exists_:network.dst_ip AND _exists_:network.dst_port', desc: 'Both fields present'      },
    ],
  },
  {
    label: 'Ranges',
    color: 'amber',
    rows: [
      { q: 'evtx.event_id:[4624 TO 4634]',   desc: 'Inclusive numeric range'            },
      { q: 'timestamp:[2024-01-01 TO 2024-03-31]', desc: 'Date range'                   },
      { q: 'http.status_code:>400',           desc: 'Greater-than'                      },
      { q: 'network.dst_port:<1024',          desc: 'Less-than'                         },
    ],
  },
  {
    label: 'Inline regex  /pattern/',
    color: 'rose',
    rows: [
      { q: 'message:/cmd\\.exe/',             desc: 'Literal dot in regex'               },
      { q: 'process.cmdline:/(invoke|iex|bypass)/', desc: 'Alternation'                 },
      { q: 'process.name:/power.*(shell|shel)/', desc: 'Prefix match'                   },
      { q: 'evtx.event_id:/4[6-9][0-9]{2}/', desc: 'Character classes & quantifiers'   },
    ],
  },
  {
    label: 'DFIR quick picks',
    color: 'emerald',
    rows: [
      { q: 'evtx.event_id:4625',                         desc: 'Failed logins'          },
      { q: 'evtx.event_id:4624',                         desc: 'Successful logins'      },
      { q: 'evtx.event_id:4688',                         desc: 'Process creation'       },
      { q: 'evtx.event_id:4104',                         desc: 'PowerShell script block'},
      { q: 'evtx.event_id:(4698 OR 4702)',               desc: 'Scheduled task'         },
      { q: 'evtx.event_id:7045',                         desc: 'Service installed'      },
      { q: 'evtx.event_id:(1102 OR 104)',                desc: 'Log cleared'            },
      { q: 'artifact_type:hayabusa AND hayabusa.level:(critical OR high)', desc: 'Hayabusa alerts' },
      { q: 'artifact_type:mft AND mft.is_deleted:true',  desc: 'Deleted files (MFT)'   },
      { q: 'artifact_type:prefetch',                     desc: 'Program execution'      },
      { q: 'artifact_type:lnk',                         desc: 'Recent / LNK files'     },
      { q: 'artifact_type:registry',                    desc: 'Registry events'        },
      { q: 'is_flagged:true',                            desc: 'Flagged events'         },
    ],
  },
  {
    label: 'Module results',
    color: 'violet',
    rows: [
      { q: 'artifact_type:yara',          desc: 'YARA rule matches'          },
      { q: 'artifact_type:regripper',     desc: 'Registry analysis (Regripper)' },
      { q: 'artifact_type:wintriage',     desc: 'Wintriage detections'       },
      { q: 'artifact_type:volatility',    desc: 'Memory forensics (Volatility)' },
      { q: 'artifact_type:oletools',      desc: 'OLE / VBA macro analysis'   },
      { q: 'artifact_type:pe_analysis',   desc: 'PE header & import analysis'},
      { q: 'artifact_type:grep_search',   desc: 'Pattern search hits'        },
      { q: 'artifact_type:browser',       desc: 'Browser history, logins'    },
      { q: 'artifact_type:access_log',    desc: 'Web access log analysis'    },
      { q: 'artifact_type:cuckoo',        desc: 'Cuckoo sandbox results'     },
    ],
  },
]

const CHIP_COLORS = {
  sky:     'bg-sky-50 text-sky-700 border-sky-200',
  violet:  'bg-violet-50 text-violet-700 border-violet-200',
  amber:   'bg-amber-50 text-amber-700 border-amber-200',
  rose:    'bg-rose-50 text-rose-700 border-rose-200',
  emerald: 'bg-emerald-50 text-emerald-700 border-emerald-200',
}

/* ── Field Explorer panel — tabs for Fields + Lucene syntax ── */
function FieldExplorer({ fieldMap, onInsert, onUseSnippet, onAggregate, onClose }) {
  const [tab, setTab] = useState('fields')
  const [filter, setFilter] = useState('')
  const groups = fieldMap?.groups || []
  const filtered = filter
    ? groups.map(g => ({
        ...g,
        fields: g.fields.filter(f => f.name.toLowerCase().includes(filter.toLowerCase())),
      })).filter(g => g.fields.length > 0)
    : groups
  const total = fieldMap?.total ?? 0
  return (
    <div className="mt-2 border border-gray-200 rounded-xl bg-white shadow-card-md overflow-hidden fade-in">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-100 bg-gray-50">
        <Layers size={13} className="text-gray-500" />
        <div className="flex items-center gap-1 ml-1">
          <button
            type="button"
            onClick={() => setTab('fields')}
            className={`px-2 py-1 rounded text-xs font-semibold transition-colors ${
              tab === 'fields' ? 'bg-white border border-gray-200 text-brand-text' : 'text-gray-500 hover:text-brand-text'
            }`}
          >Fields <span className="text-gray-400 font-normal">({total})</span></button>
          <button
            type="button"
            onClick={() => setTab('syntax')}
            className={`px-2 py-1 rounded text-xs font-semibold transition-colors ${
              tab === 'syntax' ? 'bg-white border border-gray-200 text-brand-text' : 'text-gray-500 hover:text-brand-text'
            }`}
          >Lucene syntax</button>
        </div>
        {tab === 'fields' && (
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter fields…"
            className="ml-auto h-7 px-2 text-xs border border-gray-200 rounded-md outline-none focus:border-gray-400 focus:ring-2 focus:ring-gray-200 w-48"
          />
        )}
        <button onClick={onClose} className={`icon-btn h-7 w-7 ${tab === 'fields' ? '' : 'ml-auto'}`} title="Close"><X size={13} /></button>
      </div>

      {tab === 'syntax' ? (
        <LuceneCheatsheet onUse={onUseSnippet} />
      ) : (
      <div className="max-h-72 overflow-y-auto p-3 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {filtered.length === 0 && (
          <div className="col-span-3 text-xs text-gray-500 italic py-6 text-center">No fields match</div>
        )}
        {filtered.map(g => (
          <div key={g.prefix} className="border border-gray-100 rounded-lg p-2">
            <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500 mb-1.5 px-1">{g.prefix}</div>
            <div className="space-y-0.5">
              {g.fields.map(f => (
                <div key={f.name} className="flex items-center gap-1 group/field">
                  <button
                    type="button"
                    disabled={!f.searchable}
                    onClick={() => f.searchable && onInsert(f.name)}
                    className={`flex-1 text-left text-[11px] font-mono px-1.5 py-0.5 rounded flex items-center justify-between gap-2 ${
                      f.searchable
                        ? 'text-gray-700 hover:bg-brand-accentlight hover:text-brand-text cursor-pointer'
                        : 'text-gray-400 cursor-not-allowed'
                    }`}
                    title={f.searchable ? `Insert ${f.name}:` : 'Not directly searchable (object)'}
                  >
                    <span className="truncate">{f.name}</span>
                    <span className="text-[9px] text-gray-400 flex-shrink-0">{f.type}</span>
                  </button>
                  {f.searchable && onAggregate && (
                    <button
                      type="button"
                      onClick={() => onAggregate(f.name)}
                      className="opacity-0 group-hover/field:opacity-100 transition-opacity text-[9px] px-1 py-0.5 rounded hover:bg-brand-accentlight text-gray-500 hover:text-brand-text"
                      title={`Aggregate by ${f.name}`}
                    >
                      <BarChart2 size={9} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
      )}
    </div>
  )
}

/* ── Aggregate panel ── */
const AGG_OPTIONS = [
  { id: 'terms',         label: 'Top values (count)' },
  { id: 'cardinality',   label: 'Distinct count' },
  { id: 'sum',           label: 'Sum'         },
  { id: 'avg',           label: 'Average'     },
  { id: 'min',           label: 'Min'         },
  { id: 'max',           label: 'Max'         },
  { id: 'stats',         label: 'Stats (count/min/max/avg/sum)' },
  { id: 'percentiles',   label: 'Percentiles (50/75/95/99)' },
  { id: 'date_histogram',label: 'Over time' },
]
const INTERVALS = ['5m','15m','1h','6h','1d','7d','30d']

// Mirror api/agg_rules.py so the UI can validate BEFORE submitting (and explain).
const NUMERIC_TYPES = new Set([
  'long','integer','short','byte','double','float','half_float','scaled_float','unsigned_long',
])
// Which agg works on which field type. Returns true when compatible.
function aggSupportsType(agg, type) {
  if (!type) return true            // unknown mapping → let the backend decide
  if (agg === 'terms' || agg === 'cardinality') return true
  if (agg === 'date_histogram') return type === 'date'
  // sum/avg/min/max/stats/percentiles
  return NUMERIC_TYPES.has(type)
}
// One-line, human reason a field can't be used with the current agg.
function incompatReason(agg, type) {
  if (agg === 'date_histogram') return `needs a date field — this is '${type}'`
  return `needs a numeric field — this is '${type}'`
}
const AGG_HELP = [
  { agg: 'Group by (terms)',  use: 'Top values of a field — e.g. busiest hosts, top users.', fields: 'Any field (text, keyword, ip, number, date).' },
  { agg: 'Distinct count',    use: 'How many unique values — e.g. distinct IPs contacted.', fields: 'Any field.' },
  { agg: 'Sum / Average / Min / Max / Stats / Percentiles', use: 'Math over a number — e.g. avg response size, max bytes.', fields: 'Numeric only (long, double, …). Not ip/keyword.' },
  { agg: 'Over time (date_histogram)', use: 'Counts bucketed by time — the activity curve.', fields: 'A date field only (e.g. timestamp).' },
]

function AggregatePanel({ caseId, query, fieldMap, state, setState, result, loading, onRun, onClose }) {
  // name → ES mapping type, so we can validate + annotate field choices.
  const fieldTypes = useMemo(() => {
    const m = {}
    for (const g of (fieldMap?.groups || [])) for (const f of g.fields) m[f.name] = f.type
    return m
  }, [fieldMap])
  const allSearchable = (fieldMap?.groups || []).flatMap(g => g.fields.filter(f => f.searchable))
  const isNumericAgg = ['sum','avg','min','max','stats','percentiles'].includes(state.agg)
  const isDateAgg    = state.agg === 'date_histogram'
  const showInterval = isDateAgg
  const showSize     = state.agg === 'terms'
  const isTerms      = state.agg === 'terms'
  const [draftField, setDraftField] = useState('')
  const [draftSub, setDraftSub]     = useState('')
  const [showAll, setShowAll]       = useState(false)
  const [showHelp, setShowHelp]     = useState(false)

  // Fields offered in the picker: compatible-only by default, all on request.
  const compatibleFields = allSearchable
    .filter(f => showAll || aggSupportsType(state.agg, f.type))
    .map(f => f.name)
  // Selected fields that won't work with the current agg → block Run + explain.
  const badFields = state.fields.filter(f => !aggSupportsType(state.agg, fieldTypes[f]))

  function addField(f) {
    const name = (f || draftField).trim()
    if (!name) return
    setState(s => ({ ...s, fields: [...new Set([...s.fields, name])] }))
    setDraftField('')
  }
  function removeField(name) {
    setState(s => ({ ...s, fields: s.fields.filter(x => x !== name) }))
  }
  function addSubCard(f) {
    const name = (f || draftSub).trim()
    if (!name) return
    setState(s => ({ ...s, subCard: [...new Set([...(s.subCard || []), name])] }))
    setDraftSub('')
  }
  function removeSubCard(name) {
    setState(s => ({ ...s, subCard: (s.subCard || []).filter(x => x !== name) }))
  }

  return (
    <div className="mt-2 border border-gray-200 rounded-xl bg-white shadow-card-md overflow-hidden fade-in">
      {/* Controls */}
      <div className="px-3 py-2.5 border-b border-gray-100 bg-gray-50 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <Sigma size={13} className="text-gray-500" />
          <span className="text-xs font-semibold text-brand-text">Aggregate</span>
          {query && <span className="text-[10px] text-gray-500 italic">filtered by current search</span>}

          <select
            value={state.agg}
            onChange={e => setState(s => ({ ...s, agg: e.target.value }))}
            className="ml-2 h-7 px-2 text-xs border border-gray-200 rounded-md outline-none bg-white focus:border-gray-400"
          >
            {AGG_OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
          </select>

          {showSize && (
            <select
              value={state.size}
              onChange={e => setState(s => ({ ...s, size: Number(e.target.value) }))}
              className="h-7 px-2 text-xs border border-gray-200 rounded-md bg-white"
              title="Top N values per level"
            >
              {[5, 10, 20, 50, 100, 200].map(n => <option key={n} value={n}>top {n}</option>)}
            </select>
          )}
          {showInterval && (
            <select
              value={state.interval}
              onChange={e => setState(s => ({ ...s, interval: e.target.value }))}
              className="h-7 px-2 text-xs border border-gray-200 rounded-md bg-white"
            >
              {INTERVALS.map(iv => <option key={iv} value={iv}>{iv}</option>)}
            </select>
          )}

          <button
            type="button"
            onClick={onRun}
            disabled={!state.fields.length || badFields.length > 0 || loading}
            className="btn-primary text-xs h-7 px-3 disabled:opacity-50"
            title={badFields.length ? 'Fix incompatible field(s) first' : ''}
          >
            {loading ? <Loader2 size={11} className="animate-spin" /> : 'Run'}
          </button>
          <button
            type="button"
            onClick={() => setShowHelp(h => !h)}
            className={`icon-btn h-7 w-7 ml-auto ${showHelp ? 'text-brand-accent' : ''}`}
            title="How aggregations work"
          ><HelpCircle size={14} /></button>
          <button onClick={onClose} className="icon-btn h-7 w-7" title="Close"><X size={13} /></button>
        </div>

        {/* Help */}
        {showHelp && (
          <div className="border border-blue-100 bg-blue-50/60 rounded-md p-2.5 text-[11px] text-gray-600 space-y-1.5">
            <p className="font-semibold text-brand-text">Pick an aggregation, then a field of a matching type.</p>
            {AGG_HELP.map(h => (
              <div key={h.agg} className="grid grid-cols-[10rem_1fr] gap-2">
                <span className="font-semibold text-gray-700">{h.agg}</span>
                <span>{h.use} <span className="text-gray-400">— {h.fields}</span></span>
              </div>
            ))}
            <p className="text-gray-400 pt-1">The field picker lists only compatible fields. Toggle “show all” to see everything (incompatible picks are blocked before running).</p>
          </div>
        )}

        {/* Incompatible-field warning */}
        {badFields.length > 0 && (
          <div className="border border-amber-200 bg-amber-50 rounded-md p-2 text-[11px] text-amber-800">
            {badFields.map(f => (
              <div key={f} className="font-mono">
                <span className="font-semibold">{f}</span> — {incompatReason(state.agg, fieldTypes[f])}
              </div>
            ))}
          </div>
        )}

        {/* Fields cascade chips */}
        <div className="flex items-start gap-2 flex-wrap">
          <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mt-1.5">
            {isTerms ? 'Group by →' : 'Field'}
          </span>
          <div className="flex items-center gap-1 flex-wrap flex-1">
            {state.fields.map((f, i) => {
              const bad = !aggSupportsType(state.agg, fieldTypes[f])
              return (
                <span
                  key={f}
                  title={bad ? incompatReason(state.agg, fieldTypes[f]) : (fieldTypes[f] || '')}
                  className={`inline-flex items-center gap-1 text-[11px] font-mono px-2 py-1 rounded ${
                    bad ? 'bg-amber-50 text-amber-800 ring-1 ring-amber-300' : 'bg-brand-accentlight text-brand-text'
                  }`}
                >
                  {i > 0 && <ChevronDown size={10} className="text-gray-400 -rotate-90" />}
                  {f}
                  <button onClick={() => removeField(f)} className="text-gray-500 hover:text-red-600 ml-0.5"><X size={10} /></button>
                </span>
              )
            })}
            {(isTerms || state.fields.length === 0) && (
              <>
                <input
                  list="agg-fields"
                  value={draftField}
                  onChange={e => setDraftField(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter' && draftField.trim()) { e.preventDefault(); addField() } }}
                  placeholder={state.fields.length === 0 ? 'field (e.g. process.executable_name)' : '+ add nested level'}
                  className="h-7 px-2 text-xs font-mono border border-gray-200 rounded-md outline-none focus:border-gray-400 focus:ring-2 focus:ring-gray-200 w-52"
                />
                <datalist id="agg-fields">
                  {compatibleFields.map(n => <option key={n} value={n} />)}
                </datalist>
                <button
                  type="button"
                  onClick={() => addField()}
                  disabled={!draftField.trim()}
                  className="btn-ghost text-xs h-7 px-2 disabled:opacity-40"
                >+</button>
                <label className="text-[10px] text-gray-500 flex items-center gap-1 cursor-pointer select-none ml-1">
                  <input type="checkbox" checked={showAll} onChange={e => setShowAll(e.target.checked)} className="scale-90" />
                  show all fields
                </label>
              </>
            )}
          </div>
        </div>

        {/* Sub-cardinality chips (only for terms agg) */}
        {isTerms && state.fields.length > 0 && (
          <div className="flex items-start gap-2 flex-wrap">
            <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mt-1.5" title="For each bucket, count distinct values of these fields">
              Unique per bucket
            </span>
            <div className="flex items-center gap-1 flex-wrap flex-1">
              {(state.subCard || []).map(f => (
                <span key={f} className="inline-flex items-center gap-1 bg-purple-50 text-purple-700 text-[11px] font-mono px-2 py-1 rounded">
                  ∪ {f}
                  <button onClick={() => removeSubCard(f)} className="text-gray-500 hover:text-red-600 ml-0.5"><X size={10} /></button>
                </span>
              ))}
              <input
                list="agg-fields"
                value={draftSub}
                onChange={e => setDraftSub(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && draftSub.trim()) { e.preventDefault(); addSubCard() } }}
                placeholder="+ count distinct (e.g. user.name)"
                className="h-7 px-2 text-xs font-mono border border-gray-200 rounded-md outline-none focus:border-gray-400 focus:ring-2 focus:ring-gray-200 w-52"
              />
            </div>
          </div>
        )}
      </div>

      {/* Result */}
      <div className="max-h-96 overflow-y-auto p-3">
        {!result && !loading && (
          <p className="text-xs text-gray-500 italic text-center py-4">
            Pick a field, optionally add more levels for a cascade, then Run. Add "unique per bucket" fields to count distinct values (e.g. distinct users per host).
          </p>
        )}
        {result?.error && (
          <div className="border border-red-200 bg-red-50 rounded-md p-3 text-xs text-red-700">
            <p className="font-semibold mb-1">Aggregation failed</p>
            <p className="font-mono break-words">{result.error}</p>
          </div>
        )}
        {result && !result.error && <AggResult result={result} />}
      </div>
    </div>
  )
}

function AggResult({ result, isNumericAgg }) {
  // Scalar (sum/avg/min/max/cardinality)
  if (typeof result.value === 'number' || result.value === null) {
    return (
      <div className="text-center py-4">
        <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">{result.agg} of {result.field}</div>
        <div className="text-[32px] font-bold tabular-nums text-brand-text">
          {result.value == null ? '—' : Number(result.value).toLocaleString(undefined, { maximumFractionDigits: 2 })}
        </div>
        <div className="text-[11px] text-gray-500 mt-1">across {result.total.toLocaleString()} matching events</div>
      </div>
    )
  }
  // Stats card
  if (result.count != null && result.min != null) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 py-2">
        {[['count', result.count], ['min', result.min], ['max', result.max], ['avg', result.avg], ['sum', result.sum]].map(([k, v]) => (
          <div key={k} className="text-center border border-gray-200 rounded-lg p-3">
            <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">{k}</div>
            <div className="text-lg font-bold tabular-nums text-brand-text">
              {v == null ? '—' : Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 })}
            </div>
          </div>
        ))}
      </div>
    )
  }
  // Percentiles
  if (result.values) {
    return (
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 py-2">
        {Object.entries(result.values).map(([pct, v]) => (
          <div key={pct} className="text-center border border-gray-200 rounded-lg p-3">
            <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-1">p{Math.round(Number(pct))}</div>
            <div className="text-lg font-bold tabular-nums text-brand-text">
              {v == null ? '—' : Number(v).toLocaleString(undefined, { maximumFractionDigits: 2 })}
            </div>
          </div>
        ))}
      </div>
    )
  }
  // Buckets (terms cascade / histogram / date_histogram)
  const buckets = result.buckets || []
  if (!buckets.length) return <p className="text-xs text-gray-500 italic text-center py-4">No buckets.</p>
  const isTerms = result.agg === 'terms'
  return (
    <div>
      <div className="text-[10px] text-gray-500 mb-2 flex items-center gap-2 flex-wrap">
        <span>{buckets.length} buckets · {result.total.toLocaleString()} events</span>
        {result.sum_other_doc_count > 0 && <span>(+{result.sum_other_doc_count.toLocaleString()} in other values)</span>}
        {isTerms && result.fields?.length > 1 && (
          <span className="bg-brand-accentlight text-brand-text px-1.5 py-0.5 rounded font-mono text-[10px]">
            {result.fields.join(' → ')}
          </span>
        )}
      </div>
      {isTerms
        ? <BucketTree buckets={buckets} depth={0} />
        : <FlatBuckets buckets={buckets} labelKey="key" />
      }
    </div>
  )
}

function FlatBuckets({ buckets, labelKey }) {
  const max = Math.max(...buckets.map(b => b.count || 0))
  return (
    <div className="space-y-1">
      {buckets.map((b, i) => {
        const pct = max ? Math.round((b.count / max) * 100) : 0
        return (
          <div key={i} className="flex items-center gap-2 text-[11px]">
            <span className="font-mono text-gray-700 truncate w-56" title={String(b[labelKey])}>{String(b[labelKey])}</span>
            <div className="flex-1 h-3 bg-gray-100 rounded relative overflow-hidden">
              <div className="h-full bg-brand-accent rounded transition-all" style={{ width: `${pct}%` }} />
            </div>
            <span className="font-mono tabular-nums text-gray-700 w-16 text-right">{b.count.toLocaleString()}</span>
          </div>
        )
      })}
    </div>
  )
}

function BucketTree({ buckets, depth }) {
  const max = Math.max(...buckets.map(b => b.count || 0))
  return (
    <div className={depth === 0 ? 'space-y-0.5' : 'space-y-0.5 ml-4 border-l border-gray-100 pl-3 mt-1 mb-1.5'}>
      {buckets.map((b, i) => <BucketNode key={i} bucket={b} max={max} depth={depth} />)}
    </div>
  )
}

function BucketNode({ bucket, max, depth }) {
  const [open, setOpen] = useState(depth === 0 && (bucket.children?.length ?? 0) <= 5)
  const hasChildren = Array.isArray(bucket.children) && bucket.children.length > 0
  const uniques = bucket.uniques || {}
  const uniqueKeys = Object.keys(uniques)
  const pct = max ? Math.round((bucket.count / max) * 100) : 0
  return (
    <div>
      <div className="flex items-center gap-2 text-[11px]">
        <button
          type="button"
          onClick={() => hasChildren && setOpen(v => !v)}
          className={`flex-shrink-0 w-4 ${hasChildren ? 'text-gray-500 hover:text-brand-text cursor-pointer' : 'text-transparent cursor-default'}`}
          title={hasChildren ? (open ? 'Collapse' : 'Expand') : ''}
        >
          {hasChildren ? (open ? '▾' : '▸') : '·'}
        </button>
        <span className="font-mono text-gray-700 truncate w-56" title={String(bucket.value)}>
          {String(bucket.value)}
        </span>
        <div className="flex-1 h-3 bg-gray-100 rounded relative overflow-hidden">
          <div className="h-full bg-brand-accent rounded transition-all" style={{ width: `${pct}%` }} />
        </div>
        <span className="font-mono tabular-nums text-gray-700 w-16 text-right">{bucket.count.toLocaleString()}</span>
      </div>
      {uniqueKeys.length > 0 && (
        <div className="ml-6 mt-0.5 mb-0.5 flex flex-wrap gap-1">
          {uniqueKeys.map(k => (
            <span key={k} className="inline-flex items-center gap-1 bg-purple-50 text-purple-700 text-[10px] font-mono px-1.5 py-0.5 rounded">
              <span className="opacity-60">{k}:</span>
              <span className="font-semibold tabular-nums">{Number(uniques[k]).toLocaleString()}</span>
              <span className="text-[9px] opacity-70">unique</span>
            </span>
          ))}
        </div>
      )}
      {hasChildren && open && <BucketTree buckets={bucket.children} depth={depth + 1} />}
    </div>
  )
}

function LuceneCheatsheet({ onUse }) {
  const [filter, setFilter] = useState('')
  const filtered = filter
    ? CHEATSHEET.map(s => ({
        ...s,
        rows: s.rows.filter(r =>
          r.q.toLowerCase().includes(filter.toLowerCase()) ||
          r.desc.toLowerCase().includes(filter.toLowerCase())
        ),
      })).filter(s => s.rows.length > 0)
    : CHEATSHEET

  return (
    <div className="border-t border-gray-100">
      <div className="px-3 py-2 border-b border-gray-100 bg-white flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Lucene syntax</span>
        <span className="text-[10px] text-gray-400">click to insert</span>
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter examples…"
          className="ml-auto h-7 px-2 text-xs border border-gray-200 rounded-md outline-none focus:border-gray-400 focus:ring-2 focus:ring-gray-200 w-48"
        />
      </div>
      <div className="max-h-96 overflow-y-auto bg-white">
        {filtered.length === 0 && (
          <p className="text-xs text-gray-500 italic py-6 text-center">No examples match</p>
        )}
        {filtered.map(section => (
          <div key={section.label} className="border-b border-gray-100 last:border-b-0">
            <div className="sticky top-0 bg-gray-50 px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-500 border-b border-gray-100">
              {section.label}
            </div>
            <div className="divide-y divide-gray-50">
              {section.rows.map((row, i) => (
                <button
                  key={i}
                  type="button"
                  onClick={() => onUse(row.q)}
                  className="w-full flex items-start gap-3 text-left px-3 py-2 hover:bg-brand-accentlight transition-colors group"
                >
                  <code className="text-[11px] font-mono text-brand-text flex-1 break-all leading-snug">
                    {row.q}
                  </code>
                  <span className="text-[11px] text-gray-500 leading-snug pt-px flex-shrink-0 max-w-[40%] text-right">
                    {row.desc}
                  </span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

/* ── AI Search Assist panel ── */
function AiSearchAssistPanel({ caseId, onApply, onClose }) {
  const [text, setText]       = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult]   = useState(null)
  const [error, setError]     = useState('')

  async function submit(e) {
    e.preventDefault()
    if (!text.trim()) return
    setLoading(true); setError(''); setResult(null)
    try {
      const res = await api.llm.searchAssist({ query: text, case_id: caseId })
      setResult(res)
    } catch (err) { setError(err.message) }
    finally { setLoading(false) }
  }

  return (
    <div className="mt-2 p-3 bg-indigo-50 border border-indigo-200 rounded-lg">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <Sparkles size={12} className="text-indigo-500" />
          <span className="text-[11px] font-semibold text-indigo-700">AI Search Assist</span>
        </div>
        <button onClick={onClose} className="text-indigo-400 hover:text-indigo-600"><X size={12} /></button>
      </div>
      <form onSubmit={submit} className="flex gap-2">
        <input
          autoFocus
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="Describe what you want to find…"
          className="input flex-1 text-xs py-1"
        />
        <button type="submit" disabled={!text.trim() || loading} className="btn-primary text-xs px-3 py-1">
          {loading ? <Loader2 size={11} className="animate-spin" /> : <Sparkles size={11} />}
        </button>
      </form>
      {error && <p className="text-[11px] text-red-600 mt-1.5">{error}</p>}
      {result && (
        <div className="mt-2 space-y-1.5">
          <code className="block text-[11px] font-mono text-brand-accent bg-white border border-gray-200 rounded px-2 py-1 break-all">{result.query}</code>
          {(result.from_ts || result.to_ts) && (
            <div className="text-[10px] text-indigo-700 font-mono bg-indigo-50 rounded px-2 py-1">
              {result.from_ts && <span>From: {new Date(result.from_ts).toLocaleString()}</span>}
              {result.from_ts && result.to_ts && <span className="mx-1">→</span>}
              {result.to_ts && <span>To: {new Date(result.to_ts).toLocaleString()}</span>}
            </div>
          )}
          {result.explanation && <p className="text-[11px] text-indigo-600 italic">{result.explanation}</p>}
          <button onClick={() => onApply(result.query, result.from_ts, result.to_ts)} className="btn-primary text-xs px-3 py-1 w-full justify-center">
            Apply
          </button>
        </div>
      )}
    </div>
  )
}

/* ── Filter +/− buttons ── */
function FilterButtons({ field, value, onIn, onOut }) {
  return (
    <span className="inline-flex gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0 ml-1">
      <button
        type="button"
        onClick={e => { e.stopPropagation(); onIn(field, value) }}
        className="w-4 h-4 rounded flex items-center justify-center bg-green-100 text-green-700 hover:bg-green-200 transition-colors"
        title={`Filter in: ${field}:"${value}"`}
      >
        <Plus size={8} />
      </button>
      <button
        type="button"
        onClick={e => { e.stopPropagation(); onOut(field, value) }}
        className="w-4 h-4 rounded flex items-center justify-center bg-red-100 text-red-600 hover:bg-red-200 transition-colors"
        title={`Exclude: NOT ${field}:"${value}"`}
      >
        <Minus size={8} />
      </button>
    </span>
  )
}

/* ── Message cell — splits pipe-delimited enriched messages into readable layout ── */
function MessageCell({ message }) {
  if (!message) return <span className="text-gray-500 font-normal">—</span>
  const parts = message.split(' | ')
  if (parts.length === 1) {
    return <span className="text-[13px] font-normal text-gray-700 break-words line-clamp-2" title={message}>{message}</span>
  }
  const [primary, ...details] = parts
  return (
    <div className="min-w-0">
      <div className="text-[13px] text-brand-text font-normal truncate" title={primary}>{primary}</div>
      <div className="flex flex-wrap gap-1 mt-0.5">
        {details.map((seg, i) => {
          const colonIdx = seg.indexOf(':')
          if (colonIdx > 0) {
            const label = seg.slice(0, colonIdx).trim()
            const value = seg.slice(colonIdx + 1).trim()
            return (
              <span key={i} className="inline-flex items-center gap-1 text-[10px] bg-gray-100 rounded px-1.5 py-0.5 max-w-[26ch] truncate font-normal" title={seg}>
                <span className="text-gray-500 font-medium shrink-0">{label}</span>
                <span className="text-gray-600 truncate">{value}</span>
              </span>
            )
          }
          return (
            <span key={i} className="text-[10px] text-gray-500 bg-gray-50 rounded px-1.5 py-0.5 truncate max-w-[28ch] font-normal" title={seg}>{seg}</span>
          )
        })}
      </div>
    </div>
  )
}

/* ── Event row ── */
function EventRow({ event, index, onSelect, selected, keyboardSelected, onFilterIn, onFilterOut, rowRef, caseId, onFlagged, visibleCols, checked, onCheck }) {
  const vis  = col => visibleCols.includes(col)
  const art  = getArtifact(event)
  let ts = '—'
  if (event.timestamp) {
    try { ts = new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 19) } catch { ts = String(event.timestamp).slice(0, 19) }
  }
  const type = event.artifact_type || 'generic'
  const color = ARTIFACT_COLORS[type] || ARTIFACT_COLORS.generic

  // Resolve per-column values (check artifact sub-doc first, then top-level)
  const level      = String(art.level || event.level || '').toLowerCase()
  const eventId    = art.event_id != null ? String(art.event_id) : ''
  const host       = event.host?.hostname || ''
  const user       = event.user?.name || ''
  const process    = event.process?.name || event.process?.path?.split(/[\\/]/).pop() || ''
  const pid        = event.process?.pid != null ? String(event.process.pid) : ''
  const runCount   = art.run_count != null ? String(art.run_count) : ''
  const action     = event.network?.action || art.action || ''
  const protocol   = event.network?.protocol || art.protocol || ''
  const srcIp      = event.network?.src_ip || art.src_ip || ''
  const srcPort    = event.network?.src_port != null ? String(event.network.src_port) : (art.src_port != null ? String(art.src_port) : '')
  const dstIp      = event.network?.dst_ip || art.dst_ip || ''
  const dstPort    = event.network?.dst_port != null ? String(event.network.dst_port) : (art.dst_port != null ? String(art.dst_port) : '')
  const httpMethod = event.http?.method || ''
  const httpStatus = event.http?.status_code ? String(event.http.status_code) : ''
  const httpPath   = event.http?.request_path || ''
  const userAgent  = event.http?.user_agent || ''
  const respSize   = event.http?.response_size != null ? String(event.http.response_size) : ''
  const mitre      = getMitreValue(event, art)
  const channel    = art.channel  || event.channel  || ''
  const rule       = art.rule_title || event.rule_title || ''

  async function handleFlag(e) {
    e.stopPropagation()
    const next = !event.is_flagged
    onFlagged(event.fo_id, next)
    try {
      await api.search.flagEvent(caseId, event.fo_id)
    } catch {
      onFlagged(event.fo_id, event.is_flagged)
    }
  }

  return (
    <tr
      ref={rowRef}
      onClick={() => onSelect(event, index)}
      className={`border-b cursor-pointer transition-colors text-xs group ${
        selected
          ? 'bg-brand-accentlight border-brand-accent/20'
          : keyboardSelected
          ? 'bg-blue-50 border-blue-200'
          : event.is_flagged
          ? 'bg-red-50 hover:bg-red-100 border-red-100'
          : 'border-gray-100 hover:bg-gray-50'
      }`}
    >
      {/* Checkbox for AI explain */}
      <td className="px-2 py-2 w-6 text-center">
        <input
          type="checkbox"
          checked={!!checked}
          onChange={e => { e.stopPropagation(); onCheck() }}
          onClick={e => e.stopPropagation()}
          className="rounded border-gray-300 accent-brand-accent cursor-pointer"
        />
      </td>
      {/* Note indicator — always visible */}
      {event.analyst_note ? (
        <td className="px-1 py-2 w-4 text-center">
          <span title={event.analyst_note} className="text-brand-accent opacity-60 hover:opacity-100 transition-opacity text-[9px]">●</span>
        </td>
      ) : <td className="px-1 py-2 w-4" />}
      {/* Flag — always visible */}
      <td className="px-2 py-2 w-6 text-center">
        <button
          onClick={handleFlag}
          className={`transition-colors flex-shrink-0 ${
            event.is_flagged
              ? 'text-red-500 hover:text-red-400'
              : 'text-gray-500 hover:text-red-400'
          }`}
          title={event.is_flagged ? 'Unflag event' : 'Flag event'}
        >
          <Flag size={11} />
        </button>
      </td>

      {vis('timestamp') && (
        <td className="px-3 py-2 text-gray-500 font-mono whitespace-nowrap tabular-nums">{ts}</td>
      )}

      {vis('os') && (
        <td className="px-3 py-2">
          {event.os ? (
            <div className="flex items-center">
              <span className={`badge ${OS_COLORS[event.os] || 'bg-gray-100 text-gray-600'}`}>{event.os}</span>
              <FilterButtons field="os" value={event.os} onIn={onFilterIn} onOut={onFilterOut} />
            </div>
          ) : null}
        </td>
      )}

      {vis('type') && (
        <td className="px-3 py-2">
          <div className="flex items-center gap-1">
            <span className={`badge ${color}`}>{type}</span>
            <FilterButtons field="artifact_type" value={type} onIn={onFilterIn} onOut={onFilterOut} />
          </div>
        </td>
      )}

      {vis('level') && (
        <td className="px-3 py-2">
          {level ? (
            <span className={`badge text-[10px] px-1.5 py-0.5 font-semibold uppercase tracking-wide ${LEVEL_COLORS[level] || 'bg-gray-100 text-gray-500'}`}>
              {level}
            </span>
          ) : null}
        </td>
      )}

      {vis('event_id') && (
        <td className="px-3 py-2 font-mono text-gray-500">
          {eventId ? (
            <div className="flex items-center">
              <span>{eventId}</span>
              <FilterButtons field={`${type}.event_id`} value={eventId} onIn={onFilterIn} onOut={onFilterOut} />
            </div>
          ) : null}
        </td>
      )}

      {vis('host') && (
        <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
          <div className="flex items-center min-w-0">
            <span className="truncate">{host}</span>
            {host && <FilterButtons field="host.hostname" value={host} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('user') && (
        <td className="px-3 py-2 text-gray-500 max-w-[6rem]">
          <div className="flex items-center min-w-0">
            <span className="truncate">{user}</span>
            {user && <FilterButtons field="user.name" value={user} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('process') && (
        <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
          <div className="flex items-center min-w-0">
            <span className="truncate">{process}</span>
            {process && <FilterButtons field="process.name" value={process} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('action') && (
        <td className="px-3 py-2">
          {action && (
            <span className={`badge text-[10px] px-1.5 py-0.5 font-semibold uppercase ${
              action === 'ALLOW' ? 'bg-green-100 text-green-700' :
              action === 'DROP'  ? 'bg-red-100 text-red-700'    :
              action === 'BLOCK' ? 'bg-red-100 text-red-700'    :
              'bg-gray-100 text-gray-600'
            }`}>
              {action}
            </span>
          )}
        </td>
      )}

      {vis('protocol') && (
        <td className="px-3 py-2 font-mono text-gray-500">
          <div className="flex items-center">
            <span className="truncate">{protocol}</span>
            {protocol && <FilterButtons field="network.protocol" value={protocol} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('src_ip') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[8rem]">
          <div className="flex items-center">
            <span className="truncate">{srcIp}</span>
            {srcIp && <FilterButtons field="network.src_ip" value={srcIp} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('src_port') && (
        <td className="px-3 py-2 font-mono text-gray-500 tabular-nums">
          <div className="flex items-center">
            <span>{srcPort !== '-' ? srcPort : ''}</span>
            {srcPort && srcPort !== '-' && <FilterButtons field="network.src_port" value={srcPort} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('dst_ip') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[8rem]">
          <div className="flex items-center">
            <span className="truncate">{dstIp}</span>
            {dstIp && <FilterButtons field="network.dst_ip" value={dstIp} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('dst_port') && (
        <td className="px-3 py-2 font-mono text-gray-500 tabular-nums">
          <div className="flex items-center">
            <span>{dstPort !== '-' ? dstPort : ''}</span>
            {dstPort && dstPort !== '-' && <FilterButtons field="network.dst_port" value={dstPort} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('run_count') && (
        <td className="px-3 py-2 tabular-nums text-center">
          {runCount && (
            <span className="badge bg-amber-50 text-amber-700 border border-amber-200 font-semibold text-[10px]">
              ×{runCount}
            </span>
          )}
        </td>
      )}

      {vis('pid') && (
        <td className="px-3 py-2 font-mono text-gray-500 text-[10px]">
          <div className="flex items-center">
            <span>{pid}</span>
            {pid && <FilterButtons field="process.pid" value={pid} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('http_method') && (
        <td className="px-3 py-2">
          {httpMethod && (
            <span className={`badge text-[10px] px-1.5 py-0.5 font-mono font-semibold ${
              httpMethod === 'GET'                        ? 'bg-green-100 text-green-700' :
              httpMethod === 'POST'                       ? 'bg-blue-100 text-blue-700'  :
              httpMethod === 'DELETE'                     ? 'bg-red-100 text-red-700'    :
              httpMethod === 'PUT' || httpMethod === 'PATCH' ? 'bg-amber-100 text-amber-700' :
              'bg-gray-100 text-gray-700'
            }`}>{httpMethod}</span>
          )}
        </td>
      )}

      {vis('http_status') && (
        <td className="px-3 py-2 font-mono font-semibold">
          {httpStatus && (
            <span className={
              httpStatus.startsWith('2') ? 'text-green-600' :
              httpStatus.startsWith('3') ? 'text-blue-500'  :
              httpStatus.startsWith('4') ? 'text-amber-600' :
              httpStatus.startsWith('5') ? 'text-red-600'   :
              'text-gray-500'
            }>{httpStatus}</span>
          )}
        </td>
      )}

      {vis('http_path') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[12rem]">
          <span className="truncate block text-[10px]" title={httpPath}>{httpPath}</span>
        </td>
      )}

      {vis('user_agent') && (
        <td className="px-3 py-2 text-gray-500 max-w-[12rem]">
          <span className="truncate block text-[10px]" title={userAgent}>{userAgent}</span>
        </td>
      )}

      {vis('resp_size') && (
        <td className="px-3 py-2 font-mono tabular-nums text-gray-500 text-[10px]">
          {respSize ? Number(respSize).toLocaleString() : ''}
        </td>
      )}

      {vis('cmdline') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[17rem]">
          <div className="flex items-center">
            <span className="truncate text-[10px]" title={event.process?.command_line}>{event.process?.command_line || ''}</span>
            {event.process?.command_line && <FilterButtons field="process.command_line" value={event.process.command_line} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('proc_path') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[12rem]">
          <div className="flex items-center">
            <span className="truncate text-[10px]" title={event.process?.path}>{event.process?.path || ''}</span>
            {event.process?.path && <FilterButtons field="process.path" value={event.process.path} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('parent_proc') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[10rem]">
          <div className="flex items-center">
            <span className="truncate text-[10px]" title={event.process?.parent_name}>{event.process?.parent_name || ''}</span>
            {event.process?.parent_name && <FilterButtons field="process.parent_name" value={event.process.parent_name} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('parent_pid') && (
        <td className="px-3 py-2 font-mono tabular-nums text-gray-500 text-[10px]">
          <div className="flex items-center">
            <span>{event.process?.parent_pid != null ? event.process.parent_pid : ''}</span>
            {event.process?.parent_pid != null && <FilterButtons field="process.parent_pid" value={String(event.process.parent_pid)} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('host_ip') && (
        <td className="px-3 py-2 text-gray-500 font-mono text-[10px] max-w-[10rem]">
          <div className="flex items-center">
            <span className="truncate" title={event.host?.ip}>{event.host?.ip || ''}</span>
            {event.host?.ip && <FilterButtons field="host.ip" value={event.host.ip} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('host_fqdn') && (
        <td className="px-3 py-2 text-gray-500 max-w-[12rem]">
          <div className="flex items-center">
            <span className="truncate text-[10px]" title={event.host?.fqdn}>{event.host?.fqdn || ''}</span>
            {event.host?.fqdn && <FilterButtons field="host.fqdn" value={event.host.fqdn} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('user_domain') && (
        <td className="px-3 py-2 text-gray-500 max-w-[10rem]">
          <div className="flex items-center">
            <span className="truncate text-[10px]" title={event.user?.domain}>{event.user?.domain || ''}</span>
            {event.user?.domain && <FilterButtons field="user.domain" value={event.user.domain} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('user_sid') && (
        <td className="px-3 py-2 text-gray-500 font-mono max-w-[14rem]">
          <div className="flex items-center">
            <span className="truncate text-[10px]" title={event.user?.sid}>{event.user?.sid || ''}</span>
            {event.user?.sid && <FilterButtons field="user.sid" value={event.user.sid} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('bytes') && (
        <td className="px-3 py-2 font-mono tabular-nums text-gray-500 text-[10px]">
          {event.network?.bytes != null ? Number(event.network.bytes).toLocaleString() : ''}
        </td>
      )}

      {vis('mitre') && (
        <td className="px-3 py-2 max-w-[9rem]">
          {mitre && (
            <div className="flex flex-wrap gap-0.5">
              {mitre.split(', ').slice(0, 2).map(t => (
                <button
                  key={t}
                  onClick={e => { e.stopPropagation(); onFilterIn('tags', t) }}
                  className="text-[10px] px-1.5 py-0.5 rounded-full bg-orange-100 text-orange-700 hover:bg-orange-200 transition-colors font-medium flex-shrink-0 truncate max-w-[8rem]"
                  title={t}
                >
                  {t}
                </button>
              ))}
              {mitre.split(', ').length > 2 && (
                <span className="text-[10px] text-gray-500">+{mitre.split(', ').length - 2}</span>
              )}
            </div>
          )}
        </td>
      )}

      {vis('channel') && (
        <td className="px-3 py-2 text-gray-500 max-w-[7rem]">
          <div className="flex items-center">
            <span className="truncate">{channel}</span>
            {channel && <FilterButtons field={`${type}.channel`} value={channel} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('rule') && (
        <td className="px-3 py-2 text-gray-600 max-w-[9rem]">
          <div className="flex items-center">
            <span className="truncate">{rule}</span>
            {rule && <FilterButtons field={`${type}.rule_title`} value={rule} onIn={onFilterIn} onOut={onFilterOut} />}
          </div>
        </td>
      )}

      {vis('message') && (
        <td className="px-3 py-2 text-brand-text min-w-[280px] max-w-[520px]">
          <MessageCell message={event.message} />
        </td>
      )}

      {vis('tags') && (
        <td className="px-3 py-2">
          <div className="flex items-center gap-1 flex-wrap">
            {event.tags?.map(t => (
              <button
                key={t}
                onClick={e => { e.stopPropagation(); onFilterIn('tags', t) }}
                className="text-[10px] px-1.5 py-0.5 rounded-full bg-purple-100 text-purple-700 hover:bg-purple-200 transition-colors font-medium flex-shrink-0"
                title={`Filter: tags:"${t}"`}
              >
                {t}
              </button>
            ))}
          </div>
        </td>
      )}

      {vis('raw_data') && (() => {
        const line = _rawPreview(event.raw)
        return (
          <td className="px-3 py-2">
            <span className="font-mono text-[10px] text-gray-500 block whitespace-nowrap" title={line}>
              {line || ''}
            </span>
          </td>
        )
      })()}
    </tr>
  )
}
