import { useState, useEffect, useCallback, useRef } from 'react'
import {
  FileText, HardDrive, Database, Activity, File, Search,
  ChevronRight, ChevronDown, Folder, FolderOpen, Loader2,
  X, ArrowLeft, AlertTriangle, Lock, CheckCircle, RefreshCw,
} from 'lucide-react'
import { api } from '../api/client'

// ── Category icons ────────────────────────────────────────────────────────────
function FileIcon({ category, size = 13 }) {
  switch (category) {
    case 'text':       return <FileText size={size} className="text-blue-500" />
    case 'disk_image': return <HardDrive size={size} className="text-orange-500" />
    case 'database':   return <Database size={size} className="text-teal-500" />
    case 'pcap':       return <Activity size={size} className="text-purple-500" />
    case 'evtx':       return <File size={size} className="text-red-500" />
    default:           return <File size={size} className="text-gray-500" />
  }
}

// ── File content viewer ───────────────────────────────────────────────────────
function ContentViewer({ caseId, file, onClose }) {
  const [content, setContent] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState('')
  const [filter, setFilter]   = useState('')

  useEffect(() => {
    setLoading(true)
    setError('')
    api.caseFiles.content(caseId, file.job_id)
      .then(r => setContent(r))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [caseId, file.job_id])

  // Format JSON if applicable
  let displayContent = content?.content || ''
  let isJson = false
  if (file.filename.match(/\.(json|jsonl|ndjson)$/i) && displayContent) {
    // For JSONL, pretty-print first line; for JSON, format the whole thing
    if (file.filename.match(/\.(jsonl|ndjson)$/i)) {
      // Show raw; formatting each line would be too expensive
    } else {
      try {
        displayContent = JSON.stringify(JSON.parse(displayContent), null, 2)
        isJson = true
      } catch {
        // Not valid JSON, show raw
      }
    }
  }

  // Filter lines
  const lines = displayContent.split('\n')
  const filteredLines = filter
    ? lines.map((l, i) => ({ line: i + 1, text: l })).filter(l => l.text.toLowerCase().includes(filter.toLowerCase()))
    : lines.map((l, i) => ({ line: i + 1, text: l }))

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-200 bg-white flex-shrink-0">
        <button onClick={onClose} className="icon-btn"><ArrowLeft size={14} /></button>
        <FileIcon category={file.category} size={14} />
        <span className="text-xs font-medium text-brand-text truncate flex-1">{file.filename}</span>
        {content && (
          <span className="text-[10px] text-gray-500 flex-shrink-0">
            {(content.size_bytes / 1024).toFixed(1)} KB · {lines.length} lines
          </span>
        )}
        <div className="relative flex-shrink-0">
          <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter lines…"
            className="input text-xs pl-6 py-1 w-40"
          />
          {filter && (
            <button onClick={() => setFilter('')} className="absolute right-1.5 top-1/2 -translate-y-1/2 text-gray-500">
              <X size={10} />
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto bg-gray-950 font-mono text-xs p-3">
        {loading && (
          <div className="flex items-center gap-2 text-gray-500 mt-4 justify-center">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        )}
        {error && (
          <p className="text-red-400 p-4">{error}</p>
        )}
        {!loading && !error && (
          <>
            {filter && (
              <p className="text-gray-500 text-[10px] mb-2">
                {filteredLines.length} matching line{filteredLines.length !== 1 ? 's' : ''} (of {lines.length})
              </p>
            )}
            <table className="w-full">
              <tbody>
                {filteredLines.map(({ line, text }) => (
                  <tr key={line} className="hover:bg-white/5 group">
                    <td className="text-gray-600 pr-3 pl-1 text-right select-none w-10 border-r border-gray-800 align-top pt-px">{line}</td>
                    <td className="pl-3 whitespace-pre-wrap break-all text-gray-200 align-top pt-px">{text}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </div>
    </div>
  )
}

// ── Disk image browser ────────────────────────────────────────────────────────
function DiskImageBrowser({ caseId, file }) {
  const [path, setPath]         = useState('/')
  const [entries, setEntries]   = useState([])
  const [total, setTotal]       = useState(0)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  const browse = useCallback((newPath) => {
    setLoading(true)
    setError('')
    api.caseFiles.browse(caseId, file.job_id, newPath)
      .then(r => {
        setEntries(r.entries || [])
        setTotal(r.total || 0)
        setPath(newPath)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [caseId, file.job_id])

  useEffect(() => { browse('/') }, [browse])

  // Build breadcrumb from path
  const parts = path.replace(/\/$/, '').split('/').filter(Boolean)
  const crumbs = [
    { label: '/', path: '/' },
    ...parts.map((p, i) => ({
      label: p,
      path: '/' + parts.slice(0, i + 1).join('/') + '/',
    }))
  ]

  return (
    <div className="flex flex-col h-full">
      {/* Header + breadcrumb */}
      <div className="px-3 py-2 border-b border-gray-200 bg-white flex-shrink-0">
        <div className="flex items-center gap-1 text-xs flex-wrap">
          <HardDrive size={13} className="text-orange-500 flex-shrink-0" />
          <span className="font-medium text-brand-text truncate">{file.filename}</span>
          <span className="text-gray-500 mx-1">·</span>
          {crumbs.map((c, i) => (
            <span key={c.path} className="flex items-center gap-0.5">
              {i > 0 && <ChevronRight size={10} className="text-gray-500" />}
              <button
                onClick={() => browse(c.path)}
                className="text-brand-accent hover:text-brand-accenthover hover:underline"
              >
                {c.label}
              </button>
            </span>
          ))}
        </div>
        {total > 0 && <p className="text-[10px] text-gray-500 mt-0.5">{total} entries</p>}
      </div>

      {/* Directory listing */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center gap-2 py-8 text-gray-500 text-xs">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        )}
        {error && (
          <div className="m-3 p-3 rounded-lg bg-amber-50 border border-amber-200 text-xs text-amber-700 flex gap-2">
            <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">Directory unavailable</p>
              <p className="text-amber-600">{error}</p>
              {file.status !== 'COMPLETED' && (
                <p className="mt-1 text-amber-600">
                  The disk image is still being processed ({file.status}).
                  The file tree will appear once indexing completes.
                </p>
              )}
            </div>
          </div>
        )}
        {!loading && !error && entries.length === 0 && (
          <div className="flex flex-col items-center justify-center py-10 text-gray-500 text-xs">
            <Folder size={28} className="mb-2 text-gray-500" />
            {file.status === 'COMPLETED'
              ? 'Empty directory'
              : `Processing… (${file.status})`}
          </div>
        )}
        {!loading && entries.length > 0 && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
              <tr>
                <th className="text-left px-3 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">Name</th>
                <th className="text-right px-3 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Size</th>
                <th className="text-left px-3 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-40">Modified</th>
              </tr>
            </thead>
            <tbody>
              {path !== '/' && (
                <tr
                  className="border-b border-gray-50 hover:bg-blue-50/50 cursor-pointer"
                  onClick={() => {
                    const parent = path.replace(/[^/]+\/$/, '') || '/'
                    browse(parent)
                  }}
                >
                  <td className="px-3 py-1.5 flex items-center gap-2">
                    <FolderOpen size={13} className="text-yellow-500" />
                    <span className="text-gray-500">..</span>
                  </td>
                  <td /><td />
                </tr>
              )}
              {entries.map((entry, i) => (
                <tr
                  key={i}
                  className="border-b border-gray-50 hover:bg-blue-50/50 cursor-pointer"
                  onClick={() => entry.is_dir && browse(entry.path.endsWith('/') ? entry.path : entry.path + '/')}
                >
                  <td className="px-3 py-1.5 flex items-center gap-2">
                    {entry.is_dir
                      ? <Folder size={13} className="text-yellow-500 flex-shrink-0" />
                      : <File   size={13} className="text-gray-500 flex-shrink-0" />
                    }
                    <span className={`truncate ${entry.is_dir ? 'text-brand-text font-medium' : 'text-gray-700'}`}>
                      {entry.name}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-right text-gray-500 tabular-nums">
                    {entry.is_dir ? '—' : entry.size ? _fmtSize(entry.size) : '0 B'}
                  </td>
                  <td className="px-3 py-1.5 text-gray-500 tabular-nums">
                    {entry.mtime ? new Date(entry.mtime).toISOString().replace('T', ' ').slice(0, 19) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

function _fmtSize(bytes) {
  if (bytes < 1024)       return `${bytes} B`
  if (bytes < 1048576)    return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1073741824) return `${(bytes / 1048576).toFixed(1)} MB`
  return `${(bytes / 1073741824).toFixed(2)} GB`
}

// ── File search panel ─────────────────────────────────────────────────────────
function FileSearchPanel({ caseId, onOpenFile }) {
  const [query, setQuery]   = useState('')
  const [regex, setRegex]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError]   = useState('')

  async function doSearch(e) {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      const r = await api.caseFiles.search(caseId, { query, regex })
      setResult(r)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-4 space-y-4">
      <div>
        <h3 className="text-sm font-semibold text-brand-text mb-1">Search File Contents</h3>
        <p className="text-xs text-gray-500">Search within all readable files stored in this case (JSON, logs, scripts, configs…)</p>
      </div>
      <form onSubmit={doSearch} className="space-y-2">
        <div className="relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder='Search text or regex… e.g. "admin", "192\.168\.", "password"'
            className="input pl-8 text-xs w-full"
            autoFocus
          />
        </div>
        <div className="flex items-center justify-between">
          <label className="flex items-center gap-1.5 text-xs text-gray-600 cursor-pointer">
            <input type="checkbox" checked={regex} onChange={e => setRegex(e.target.checked)} className="rounded" />
            Regex pattern
          </label>
          <button type="submit" disabled={!query.trim() || loading} className="btn-primary text-xs px-3">
            {loading ? <Loader2 size={12} className="animate-spin" /> : <Search size={12} />}
            {loading ? 'Searching…' : 'Search'}
          </button>
        </div>
      </form>

      {error && <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>}

      {result && (
        <div className="space-y-3">
          <p className="text-xs text-gray-500">
            {result.files_matched} of {result.files_searched} files matched
          </p>
          {result.results.length === 0 && (
            <p className="text-xs text-gray-500 italic">No matches found.</p>
          )}
          {result.results.map(r => (
            <div key={r.job_id} className="card p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-brand-text flex items-center gap-1">
                  <FileText size={12} className="text-blue-500" />
                  {r.filename}
                </span>
                <div className="flex items-center gap-2">
                  {!r.skipped && (
                    <span className="badge bg-brand-accentlight text-brand-accent text-[10px]">
                      {r.match_count} match{r.match_count !== 1 ? 'es' : ''}
                    </span>
                  )}
                  {!r.skipped && (
                    <button
                      onClick={() => onOpenFile({ job_id: r.job_id, filename: r.filename, category: 'text', status: 'COMPLETED' })}
                      className="btn-ghost text-xs text-brand-accent"
                    >
                      View
                    </button>
                  )}
                </div>
              </div>
              {r.skipped
                ? <p className="text-[10px] text-amber-600">{r.reason}</p>
                : r.matches.slice(0, 5).map((m, i) => (
                    <div key={i} className="bg-gray-50 rounded p-2 font-mono text-[10px]">
                      <span className="text-gray-500 mr-2">:{m.line}</span>
                      <span className="text-brand-text">{m.text}</span>
                    </div>
                  ))
              }
              {!r.skipped && r.match_count > 5 && (
                <p className="text-[10px] text-gray-500">+{r.match_count - 5} more matches</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Reingest modal ────────────────────────────────────────────────────────────
function ReingestModal({ caseId, file, onClose, onDone }) {
  const [plugins, setPlugins]     = useState([])
  const [selected, setSelected]   = useState('')
  const [busy, setBusy]           = useState(false)
  const [error, setError]         = useState('')
  const overlayRef = useRef(null)

  useEffect(() => {
    api.plugins.list()
      .then(r => setPlugins((r.plugins || []).map(p => p.name).sort()))
      .catch(() => {})
  }, [])

  // Pre-fill with existing hint if any
  useEffect(() => {
    if (file?.plugin_hint) setSelected(file.plugin_hint)
  }, [file])

  async function submit() {
    setBusy(true)
    setError('')
    try {
      await api.ingest.reingestJob(caseId, file.job_id, selected || null)
      onDone()
      onClose()
    } catch (err) {
      setError(err.message || 'Re-ingest failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40"
      onClick={e => { if (e.target === overlayRef.current) onClose() }}
    >
      <div className="bg-white rounded-lg shadow-xl w-80 p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-semibold text-sm text-brand-text">Re-ingest with plugin</h3>
          <button onClick={onClose} className="icon-btn"><X size={14} /></button>
        </div>

        <p className="text-xs text-gray-500 mb-3 truncate">
          <span className="font-mono text-brand-text">{file.filename}</span>
        </p>

        <div className="mb-3">
          <label className="block text-xs font-medium text-gray-600 mb-1">Parser</label>
          <select
            className="w-full text-xs border border-gray-200 rounded px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-brand-accent"
            value={selected}
            onChange={e => setSelected(e.target.value)}
          >
            <option value="">Auto-detect (default)</option>
            {plugins.map(p => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
          {selected && (
            <p className="text-[10px] text-brand-accent mt-1">
              Will force <span className="font-mono">{selected}</span> regardless of file type
            </p>
          )}
          {!selected && (
            <p className="text-[10px] text-gray-400 mt-1">
              Parser chosen automatically from file extension and content
            </p>
          )}
        </div>

        {error && (
          <p className="text-xs text-red-500 mb-2">{error}</p>
        )}

        <div className="flex gap-2 justify-end">
          <button onClick={onClose} className="btn-ghost text-xs">Cancel</button>
          <button onClick={submit} disabled={busy} className="btn-primary text-xs">
            {busy ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
            Re-ingest
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
const STATUS_COLORS = {
  COMPLETED:  'text-green-600',
  FAILED:     'text-red-600',
  RUNNING:    'text-brand-accent',
  PENDING:    'text-amber-600',
  UPLOADING:  'text-sky-500',
  SKIPPED:    'text-gray-500',
  CANCELLED:  'text-gray-400 line-through',
}

export default function CaseFiles({ caseId }) {
  const [files, setFiles]               = useState([])
  const [loading, setLoading]           = useState(true)
  const [activeView, setActiveView]     = useState(null)   // { type: 'content'|'diskimage'|'search', file? }
  const [filter, setFilter]             = useState('')
  const [reingestFile, setReingestFile] = useState(null)
  const [cancelling, setCancelling]     = useState(false)

  const [bkKey, setBkKey]       = useState('')
  const [bkHasKey, setBkHasKey] = useState(false)
  const [bkSaved, setBkSaved]   = useState(false)
  const [bkSaving, setBkSaving] = useState(false)
  const [bkError, setBkError]   = useState('')

  function loadFiles() {
    api.caseFiles.list(caseId)
      .then(r => setFiles(r.files || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadFiles()
  }, [caseId])

  const activeJobs = files.filter(f => ['PENDING', 'UPLOADING', 'RUNNING'].includes(f.status))

  async function cancelAllIngestion() {
    if (!activeJobs.length) return
    setCancelling(true)
    try {
      await api.ingest.cancelCaseIngestion(caseId)
      await loadFiles()
    } catch (err) {
      console.error('Cancel failed:', err)
    } finally {
      setCancelling(false)
    }
  }

  const hasDiskImages = files.some(f => f.category === 'disk_image')

  useEffect(() => {
    if (!hasDiskImages) return
    api.cases.get(caseId)
      .then(c => setBkHasKey(!!c.bitlocker_key_set))
      .catch(() => {})
  }, [caseId, hasDiskImages])

  async function saveBkKey() {
    if (!bkKey.trim()) return
    setBkSaving(true)
    setBkError('')
    try {
      await api.cases.update(caseId, { bitlocker_recovery_key: bkKey.trim() })
      setBkHasKey(true)
      setBkSaved(true)
      setBkKey('')
      setTimeout(() => setBkSaved(false), 2500)
    } catch (err) {
      setBkError(err.message || 'Failed to save key')
    } finally {
      setBkSaving(false)
    }
  }

  const shown = filter
    ? files.filter(f => f.filename.toLowerCase().includes(filter.toLowerCase()))
    : files

  // ── Main content area ───────────────────────────────────────────────────────
  if (activeView?.type === 'content') {
    return (
      <ContentViewer
        caseId={caseId}
        file={activeView.file}
        onClose={() => setActiveView(null)}
      />
    )
  }

  if (activeView?.type === 'diskimage') {
    return (
      <div className="flex flex-col h-full">
        <div className="px-3 py-2 border-b border-gray-200 flex-shrink-0">
          <button onClick={() => setActiveView(null)} className="flex items-center gap-1 text-xs text-gray-500 hover:text-brand-accent">
            <ArrowLeft size={12} /> Back to files
          </button>
        </div>
        <div className="flex-1 overflow-hidden">
          <DiskImageBrowser caseId={caseId} file={activeView.file} />
        </div>
      </div>
    )
  }

  if (activeView?.type === 'search') {
    return (
      <div className="flex flex-col h-full">
        <div className="px-3 py-2 border-b border-gray-200 flex-shrink-0">
          <button onClick={() => setActiveView(null)} className="flex items-center gap-1 text-xs text-gray-500 hover:text-brand-accent">
            <ArrowLeft size={12} /> Back to files
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <FileSearchPanel
            caseId={caseId}
            onOpenFile={file => setActiveView({ type: 'content', file })}
          />
        </div>
      </div>
    )
  }

  // ── File list ───────────────────────────────────────────────────────────────
  return (
    <>
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="px-4 py-2.5 border-b border-gray-200 bg-white flex items-center gap-2 flex-shrink-0">
        <div className="relative flex-1">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter files…"
            className="input pl-7 text-xs w-full"
          />
        </div>
        <button
          onClick={() => setActiveView({ type: 'search' })}
          className="btn-ghost text-xs flex items-center gap-1.5"
        >
          <Search size={12} /> Search Contents
        </button>
        {activeJobs.length > 0 && (
          <button
            onClick={cancelAllIngestion}
            disabled={cancelling}
            className="btn-ghost text-xs flex items-center gap-1.5 text-red-500 hover:text-red-700 hover:bg-red-50 border border-red-200"
            title={`Cancel ${activeJobs.length} active job${activeJobs.length > 1 ? 's' : ''}`}
          >
            {cancelling
              ? <Loader2 size={12} className="animate-spin" />
              : <X size={12} />}
            Stop ({activeJobs.length})
          </button>
        )}
      </div>

      {/* BitLocker recovery key banner — shown only when disk images are present */}
      {hasDiskImages && (
        <div className="mx-4 mt-3 mb-1 p-3 rounded-lg border border-amber-200 bg-amber-50 flex items-center gap-3 flex-shrink-0">
          <Lock size={14} className="text-amber-600 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-xs font-semibold text-amber-800">BitLocker Recovery Key</p>
            <p className="text-[10px] text-amber-600 mt-0.5">
              {bkHasKey ? 'Key configured — paste below to update' : 'Required to extract encrypted partitions (e.g. 000000-000000-…)'}
            </p>
          </div>
          {bkSaved && !bkError && (
            <span className="flex items-center gap-1 text-[11px] text-green-700 font-medium flex-shrink-0">
              <CheckCircle size={12} /> Saved
            </span>
          )}
          {bkError && (
            <span className="text-[11px] text-red-600 font-medium flex-shrink-0">{bkError}</span>
          )}
          <input
            type="password"
            value={bkKey}
            onChange={e => setBkKey(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && saveBkKey()}
            placeholder={bkHasKey ? 'New key…' : '000000-000000-…'}
            className="input text-xs w-52 flex-shrink-0"
          />
          <button
            onClick={saveBkKey}
            disabled={!bkKey.trim() || bkSaving}
            className="btn-outline text-xs flex-shrink-0"
          >
            {bkSaving ? 'Saving…' : 'Save'}
          </button>
        </div>
      )}

      {/* File list */}
      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="flex items-center justify-center gap-2 py-10 text-gray-500 text-xs">
            <Loader2 size={14} className="animate-spin" /> Loading files…
          </div>
        )}
        {!loading && shown.length === 0 && (
          <div className="flex flex-col items-center justify-center py-10 text-gray-500 text-xs">
            <File size={28} className="mb-2 text-gray-500" />
            {filter ? 'No files match your filter.' : 'No files ingested yet.'}
          </div>
        )}
        {!loading && shown.length > 0 && (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-50 border-b border-gray-200 z-10">
              <tr>
                <th className="text-left px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">File</th>
                <th className="text-left px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">Status</th>
                <th className="text-right px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-20">Events</th>
                <th className="text-left px-3 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider w-24">Plugin</th>
                <th className="px-3 py-2 w-28"></th>
              </tr>
            </thead>
            <tbody>
              {shown.map(file => (
                <tr key={file.job_id} className="border-b border-gray-50 hover:bg-gray-50/80">
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-2">
                      <FileIcon category={file.category} size={13} />
                      <div className="min-w-0">
                        <p className="font-medium text-brand-text truncate">{file.filename}</p>
                        {file.source_zip && (
                          <p className="text-[10px] text-gray-500 truncate">from {file.source_zip}</p>
                        )}
                      </div>
                    </div>
                  </td>
                  <td className={`px-3 py-2 font-mono text-[11px] ${STATUS_COLORS[file.status] || 'text-gray-500'}`}>
                    {file.status}
                  </td>
                  <td className="px-3 py-2 text-right text-gray-500 tabular-nums">
                    {file.events_indexed > 0 ? file.events_indexed.toLocaleString() : '—'}
                  </td>
                  <td className="px-3 py-2 text-gray-500 font-mono text-[10px] truncate max-w-[120px]">
                    <span title={file.plugin_used || ''}>{file.plugin_used || '—'}</span>
                    {file.plugin_hint && file.plugin_hint !== file.plugin_used && (
                      <span className="ml-1 text-[10px] text-brand-accent">(hint: {file.plugin_hint})</span>
                    )}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex items-center justify-end gap-1">
                      {file.is_disk_image && file.status === 'COMPLETED' && (
                        <button
                          onClick={() => setActiveView({ type: 'diskimage', file })}
                          className="btn-ghost text-xs text-orange-600 hover:text-orange-800"
                        >
                          <Folder size={11} /> Browse
                        </button>
                      )}
                      {file.is_readable && file.status === 'COMPLETED' && (
                        <button
                          onClick={() => setActiveView({ type: 'content', file })}
                          className="btn-ghost text-xs text-brand-accent"
                        >
                          <FileText size={11} /> View
                        </button>
                      )}
                      {['COMPLETED', 'FAILED', 'SKIPPED'].includes(file.status) && (
                        <button
                          onClick={() => setReingestFile(file)}
                          className="btn-ghost text-xs text-gray-400 hover:text-brand-accent"
                          title="Re-ingest with a different parser"
                        >
                          <RefreshCw size={11} />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>

    {reingestFile && (
      <ReingestModal
        caseId={caseId}
        file={reingestFile}
        onClose={() => setReingestFile(null)}
        onDone={loadFiles}
      />
    )}
    </>
  )
}
