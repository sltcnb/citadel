/**
 * IngestPanel — slide-in evidence ingestion panel with two tabs:
 *   • Upload  — chunked direct upload (same logic as Ingest.jsx)
 *   • S3 Import — browse Import or Triage S3 bucket, multi-select, batch pull
 *
 * Job list is shared between tabs and always visible at the bottom.
 * Active S3 transfers are reported to UploadContext so the global sidebar
 * indicator stays accurate while the panel is closed.
 */
import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Upload, Cloud, X, RefreshCw, AlertTriangle,
  ChevronRight, ChevronDown, Folder, File, Loader2, Database, Download, Trash2,
  HardDrive, Play, Crosshair, FolderOpen, MonitorSmartphone, Zap,
} from 'lucide-react'
import PanelHelp from './shared/PanelHelp'
import { ResizableDrawer } from './shared/resizableDrawer'
import ArtifactSelector from './shared/ArtifactSelector'
import { api } from '../api/client'
import { useUpload } from '../contexts/UploadContext'
import { formatBytes as fmtSize } from '../utils/format'

// ── Constants ─────────────────────────────────────────────────────────────────

const ACCEPTED_TYPES = [
  '.evtx', '.evt', '.plaso', '.pf', '.lnk', '.dat', '.hive',
  '.pcap', '.pcapng', '.cap', '.log', '.json', '.ndjson', '.jsonl',
  '.sqlite', '.db', '.sqlite3', '.sqlitedb', '.db3', '.esedb', '.edb',
  '.dmp', '.raw', '.lime', '.mem', '.vmem', '.vmdk', '.dd', '.img',
  '.e01', '.ex01', '.001', '.plist', '.asl', '.utmp', '.utmpx', '.wtmp',
  '.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx', '.ppt', '.pptm', '.pptx',
  '.rtf', '.mht', '.exe', '.dll', '.sys', '.scr', '.so', '.elf', '.bin',
  '.zip', '.tar', '.gz', '.7z', '.rar', '.ab',
  '.ps1', '.bat', '.vbs', '.js', '.txt', '.csv', '.msi', '.jar', '.pdf', '.xml',
]
const ACCEPT_ATTR   = ACCEPTED_TYPES.join(',')
const TERMINAL      = new Set(['COMPLETED', 'FAILED', 'SKIPPED'])
const STUCK_MS      = 5 * 60 * 1000
const CHUNK_SIZE    = 50 * 1024 * 1024   // 50 MB per upload chunk

// ── Helpers ───────────────────────────────────────────────────────────────────

function useElapsed(iso) {
  const [e, setE] = useState(0)
  useEffect(() => {
    if (!iso) return
    const tick = () => setE(Date.now() - new Date(iso).getTime())
    tick()
    const id = setInterval(tick, 10_000)
    return () => clearInterval(id)
  }, [iso])
  return e
}

// 1-second resolution timer — used for the RUNNING elapsed display
function useElapsedFine(iso) {
  const [e, setE] = useState(0)
  useEffect(() => {
    if (!iso) return
    const tick = () => setE(Date.now() - new Date(iso).getTime())
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [iso])
  return e
}

function fmtElapsed(ms) {
  if (ms <= 0) return '0s'
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ${s % 60}s`
  return `${Math.floor(m / 60)}h ${m % 60}m`
}

// ── JobCard ───────────────────────────────────────────────────────────────────

function JobCard({ jobId, jobData, onRetry, onDelete }) {
  const [retrying,     setRetrying]     = useState(false)
  const [deleting,     setDeleting]     = useState(false)
  const [expanded,     setExpanded]     = useState(false)
  const [eventsPerSec, setEventsPerSec] = useState(null)
  const lastSnapRef = useRef(null)

  const elapsed    = useElapsed(jobData?.created_at)
  const runElapsed = useElapsedFine(jobData?.started_at)
  const job = jobData

  // Compute events/s from successive polling values (poll interval ≈ 3 s)
  useEffect(() => {
    if (!job || job.status !== 'RUNNING') {
      lastSnapRef.current = null
      setEventsPerSec(null)
      return
    }
    const now    = Date.now()
    const events = parseInt(job.events_indexed || 0)
    const snap   = lastSnapRef.current
    if (snap) {
      const dt = (now - snap.time) / 1000
      if (dt > 0.5 && events >= snap.events) {
        setEventsPerSec(Math.round((events - snap.events) / dt))
      }
    }
    lastSnapRef.current = { events, time: now }
  }, [job?.events_indexed, job?.status])  // eslint-disable-line

  async function retryJob() {
    setRetrying(true)
    try { await api.ingest.retryJob(jobId); onRetry?.(jobId) }
    catch (err) { alert('Retry failed: ' + err.message) }
    finally { setRetrying(false) }
  }

  async function deleteJob() {
    if (!window.confirm(`Remove "${job.original_filename}"?\nThis deletes the file and all its indexed events.`)) return
    setDeleting(true)
    try {
      await api.ingest.deleteJob(jobId)
      onDelete?.(jobId)
    } catch (err) {
      alert('Delete failed: ' + err.message)
      setDeleting(false)
    }
  }

  if (!job) return <div className="text-gray-500 text-xs p-2">Loading…</div>

  const STATUS = {
    UPLOADING: 'text-sky-500',
    PENDING:   'text-amber-600',
    RUNNING:   'text-brand-accent',
    COMPLETED: 'text-green-600',
    FAILED:    'text-red-600',
    SKIPPED:   'text-gray-500',
  }

  const canRetry    = job.status === 'FAILED' || (job.status === 'PENDING' && elapsed > STUCK_MS)
  const eventsCount = parseInt(job.events_indexed || 0)
  const statsEntries = job.plugin_stats
    ? Object.entries(job.plugin_stats).filter(([, v]) => v != null && v !== '' && v !== 0 && v !== '0')
    : []

  return (
    <div className={`card p-3 ${job.status === 'FAILED' ? 'border-red-200' : job.status === 'RUNNING' ? 'border-brand-accent/30' : ''}`}>

      {/* ── Header row ── */}
      <div className="flex items-start justify-between mb-1 gap-2">
        <span className="text-xs text-brand-text font-medium break-all leading-snug">{job.original_filename}</span>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          <span className={`text-xs font-mono ${STATUS[job.status] || 'text-gray-500'}`}>
            {job.status}
            {job.status === 'RUNNING' && <span className="ml-1 animate-pulse">●</span>}
          </span>
          {job.status === 'COMPLETED' && (
            <a href={api.caseFiles.downloadUrl(job.case_id, job.job_id)} download={job.original_filename}
              className="btn-ghost text-xs px-1.5 py-0.5 text-gray-500 hover:text-brand-accent flex items-center gap-1"
              title="Download original file">
              <Download size={12} />
            </a>
          )}
          {canRetry && (
            <button onClick={retryJob} disabled={retrying}
              className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent hover:text-brand-accenthover flex items-center gap-1"
              title={job.status === 'PENDING' ? 'Re-queue stuck job' : 'Retry'}>
              <RefreshCw size={12} className={retrying ? 'animate-spin' : ''} />
              {job.status === 'PENDING' ? 'Re-queue' : 'Retry'}
            </button>
          )}
          {!['RUNNING', 'UPLOADING'].includes(job.status) && (
            <button onClick={deleteJob} disabled={deleting}
              className="btn-ghost text-xs px-1.5 py-0.5 text-red-400 hover:text-red-600 flex items-center gap-1"
              title="Delete this job and all its indexed events">
              {deleting ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
            </button>
          )}
        </div>
      </div>

      {/* ── Plugin + size metadata ── */}
      <div className="flex items-center gap-3 flex-wrap mb-1">
        {job.plugin_used && (
          <span className="text-[10px] text-gray-500">
            Plugin: <code className="font-mono text-gray-600">{job.plugin_used}</code>
          </span>
        )}
        {job.size_bytes > 0 && (
          <span className="text-[10px] text-gray-500">{fmtSize(job.size_bytes)}</span>
        )}
        {job.started_at && (
          <span className="text-[10px] text-gray-500">
            Started {new Date(job.started_at).toLocaleTimeString()}
          </span>
        )}
      </div>

      {/* ── UPLOADING ── */}
      {job.status === 'UPLOADING' && (
        <div className="mt-1">
          <div className="h-1 bg-gray-200 rounded overflow-hidden progress-indeterminate text-sky-500" />
          <p className="text-[10px] text-sky-500 mt-0.5 flex items-center gap-1">
            <Loader2 size={9} className="animate-spin flex-shrink-0" />
            Transferring to storage
            {job.size_bytes > 0 && ` — ${fmtSize(job.size_bytes)}`}
            {elapsed > 60_000 && ` — ${Math.floor(elapsed / 60_000)}m elapsed`}
          </p>
        </div>
      )}

      {/* ── RUNNING — rich progress panel ── */}
      {job.status === 'RUNNING' && (
        <div className="mt-1.5 space-y-1.5">
          {/* Progress bar */}
          <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden progress-indeterminate text-brand-accent" />

          {/* Key metrics row */}
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-sm font-semibold text-brand-text tabular-nums">
              {eventsCount.toLocaleString()}
            </span>
            <span className="text-[10px] text-gray-500">events indexed</span>
            {eventsPerSec !== null && (
              <span className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded ${
                eventsPerSec > 0 ? 'bg-green-50 text-green-700' : 'bg-gray-50 text-gray-500'
              }`}>
                ↑ {eventsPerSec.toLocaleString()} ev/s
              </span>
            )}
            {runElapsed > 0 && (
              <span className="text-[10px] text-gray-500 ml-auto font-mono">
                {fmtElapsed(runElapsed)}
              </span>
            )}
          </div>

          {/* Plugin stats (if any already available) */}
          {statsEntries.length > 0 && (
            <div className="flex gap-3 flex-wrap">
              {statsEntries.map(([k, v]) => (
                <span key={k} className="text-[10px] text-gray-500">
                  {k.replace(/_/g, ' ')}: <span className="text-gray-600 font-mono">{String(v)}</span>
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── COMPLETED ── */}
      {job.status === 'COMPLETED' && (
        <div className="mt-0.5">
          <p className="text-xs text-green-600">
            {eventsCount.toLocaleString()} events indexed
            {job.plugin_stats?.records_skipped > 0 && ` · ${job.plugin_stats.records_skipped} skipped`}
            {job.completed_at && job.started_at && (
              <span className="text-gray-500 text-[10px] ml-1.5">
                in {fmtElapsed(new Date(job.completed_at) - new Date(job.started_at))}
              </span>
            )}
          </p>
        </div>
      )}

      {/* ── FAILED / SKIPPED ── */}
      {job.status === 'FAILED'  && <p className="text-xs text-red-600  mt-0.5 break-all">{job.error}</p>}
      {job.status === 'SKIPPED' && <p className="text-xs text-gray-500 mt-0.5 break-all">{job.error}</p>}

      {/* ── Stuck warnings ── */}
      {job.status === 'UPLOADING' && elapsed > STUCK_MS && (
        <p className="text-[10px] text-sky-400 mt-0.5 flex items-center gap-1">
          <AlertTriangle size={10} />
          Large file — still uploading ({Math.floor(elapsed / 60_000)} min). This is normal for files over a few GB.
        </p>
      )}
      {job.status === 'PENDING' && elapsed > STUCK_MS && (
        <p className="text-[10px] text-amber-500 mt-0.5 flex items-center gap-1">
          <AlertTriangle size={10} />
          In queue {Math.floor(elapsed / 60_000)} min — worker will pick it up when free
        </p>
      )}

      {/* ── Expandable details ── */}
      <button
        onClick={() => setExpanded(p => !p)}
        className="mt-1.5 flex items-center gap-0.5 text-[10px] text-gray-500 hover:text-gray-600 transition-colors"
      >
        <ChevronDown size={10} className={`transition-transform ${expanded ? 'rotate-180' : ''}`} />
        {expanded ? 'Less' : 'Details'}
      </button>

      {expanded && (
        <div className="mt-1.5 pt-1.5 border-t border-gray-100 space-y-0.5">
          {[
            ['Job ID',       job.job_id],
            ['Created',      job.created_at  ? new Date(job.created_at).toLocaleString()  : null],
            ['Started',      job.started_at  ? new Date(job.started_at).toLocaleString()  : null],
            ['Completed',    job.completed_at? new Date(job.completed_at).toLocaleString(): null],
            ['File size',    job.size_bytes > 0 ? fmtSize(job.size_bytes) : null],
            ['Source',       job.source_zip || null],
            ['Task ID',      job.task_id     || null],
            ['Storage key',  job.minio_object_key ? '…/' + job.minio_object_key.split('/').pop() : null],
          ].filter(([, v]) => v).map(([k, v]) => (
            <div key={k} className="flex gap-2 text-[10px]">
              <span className="text-gray-500 w-20 flex-shrink-0">{k}</span>
              <span className="font-mono text-gray-600 break-all">{v}</span>
            </div>
          ))}
          {statsEntries.map(([k, v]) => (
            <div key={k} className="flex gap-2 text-[10px]">
              <span className="text-gray-500 w-20 flex-shrink-0">{k.replace(/_/g, ' ')}</span>
              <span className="font-mono text-gray-600">{String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Upload tab ────────────────────────────────────────────────────────────────

function UploadTab({ caseId, onJobsAdded }) {
  const [dragging,     setDragging]     = useState(false)
  const [uploading,    setUploading]    = useState(false)
  const [uploadPct,    setUploadPct]    = useState(0)
  const [uploadSent,   setUploadSent]   = useState(0)   // bytes sent to server so far
  const [uploadTotal,  setUploadTotal]  = useState(0)   // total bytes to send
  const [error,        setError]        = useState('')
  const inputRef  = useRef()
  const folderRef = useRef()
  const { startUpload, updateUpload, finishUpload } = useUpload()

  async function handleFiles(files) {
    if (!files.length) return
    setError('')
    setUploading(true)
    setUploadPct(0)

    const token      = localStorage.getItem('fo_token') || ''
    const base       = window.location.origin
    const uploadId   = `${caseId}-${Date.now()}`
    const label      = files.length === 1 ? files[0].name : `${files.length} files`
    startUpload(uploadId, label)

    const totalBytes = Array.from(files).reduce((s, f) => s + f.size, 0)
    setUploadTotal(totalBytes)
    setUploadSent(0)
    let sentBytes = 0
    const allJobs = []

    try {
      for (const file of files) {
        const totalChunks  = Math.max(1, Math.ceil(file.size / CHUNK_SIZE))
        const fileUploadId = crypto.randomUUID()

        for (let i = 0; i < totalChunks; i++) {
          const slice = file.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE)
          const fd    = new FormData()
          fd.append('upload_id',    fileUploadId)
          fd.append('filename',     file.name)
          fd.append('chunk_index',  i)
          fd.append('total_chunks', totalChunks)
          fd.append('chunk',        slice)

          const res = await fetch(`${base}/api/v1/cases/${caseId}/ingest/chunk`, {
            method: 'POST',
            headers: token ? { Authorization: `Bearer ${token}` } : {},
            body: fd,
          })
          if (!res.ok) {
            const body = await res.json().catch(() => ({}))
            throw new Error(body.detail || `HTTP ${res.status}`)
          }

          sentBytes += slice.size
          const pct  = Math.round((sentBytes / totalBytes) * 100)
          setUploadPct(pct)
          setUploadSent(sentBytes)
          updateUpload(uploadId, pct)

          if (i === totalChunks - 1) {
            const r = await res.json()
            allJobs.push(...(r.jobs || []))
          }
        }
      }
    } catch (err) {
      // A file may have failed mid-batch — surface it, but note that whatever
      // uploaded before it is preserved (handed off in the finally below).
      const extra = allJobs.length ? ` — ${allJobs.length} file(s) already queued were kept` : ''
      setError(`Upload failed: ${err.message}${extra}`)
    } finally {
      // ALWAYS hand off the jobs that did succeed so ingested evidence never
      // silently vanishes when a later file in the batch fails.
      if (allJobs.length) onJobsAdded(allJobs)
      setUploading(false)
      setUploadPct(0)
      finishUpload(uploadId)
    }
  }

  return (
    <div className="p-4 space-y-3">
      {/* Drop zone */}
      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => { e.preventDefault(); setDragging(false); handleFiles([...e.dataTransfer.files]) }}
        onClick={() => !uploading && inputRef.current?.click()}
        className={`${dragging ? 'drop-zone-active' : 'drop-zone-inactive'} ${uploading ? 'cursor-default' : ''}`}
      >
        <p className="text-2xl mb-2">📂</p>
        <p className="text-sm text-gray-500">
          {uploading ? `Uploading… ${uploadPct}%` : 'Drop files here or click to browse'}
        </p>
        {uploading && (
          <div className="mt-2 w-full max-w-xs mx-auto">
            <div className="h-1.5 bg-gray-200 rounded overflow-hidden">
              <div className="h-full bg-sky-500 rounded transition-all duration-300"
                style={{ width: `${uploadPct}%` }} />
            </div>
            <p className="text-[10px] text-sky-600 mt-1 font-mono tabular-nums">
              {fmtSize(uploadSent)} / {fmtSize(uploadTotal)} ({uploadPct}%)
            </p>
            <p className="text-[10px] text-gray-500 mt-0.5">
              Jobs appear in the list below when transfer completes
            </p>
          </div>
        )}
        {!uploading && <p className="text-xs text-gray-500 mt-1">Multiple files or folders supported</p>}
        <input ref={inputRef} type="file" multiple accept={ACCEPT_ATTR} className="hidden"
          onChange={e => handleFiles([...e.target.files])} />
      </div>

      {/* Folder button */}
      <div className="flex items-center gap-2">
        <button onClick={() => folderRef.current?.click()} disabled={uploading} className="btn-outline text-xs">
          📁 Upload Folder
        </button>
        <span className="text-[10px] text-gray-500">All files inside will be uploaded</span>
        <input ref={folderRef} type="file"
          // @ts-ignore
          webkitdirectory="" directory="" multiple className="hidden"
          onChange={e => handleFiles([...e.target.files])} />
      </div>

      {error && <div className="card border-red-200 p-3 text-xs text-red-600">{error}</div>}
    </div>
  )
}

// ── S3 Browser tab ────────────────────────────────────────────────────────────

function S3Tab({ caseId, onJobsAdded }) {
  const [source,    setSource]    = useState('import')   // 'import' | 'triage'
  const [prefix,    setPrefix]    = useState('')
  const [entries,   setEntries]   = useState({ folders: [], files: [] })
  const [loading,   setLoading]   = useState(false)
  const [selected,  setSelected]  = useState(new Set())
  const [importing, setImporting] = useState(false)
  const [error,     setError]     = useState('')
  const { startUpload, finishUpload } = useUpload()

  const browse = useCallback(async (pfx, src) => {
    setLoading(true)
    setError('')
    try {
      const fn = src === 'import' ? api.s3.browse : api.s3Triage.browse
      const r  = await fn(pfx, '/')
      setEntries({ folders: r.folders || [], files: r.files || [] })
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    setPrefix('')
    setSelected(new Set())
    browse('', source)
  }, [source, browse])

  function navigateTo(folderKey) {
    setPrefix(folderKey)
    setSelected(new Set())
    browse(folderKey, source)
  }

  function jumpTo(idx) {
    const parts  = prefix.split('/').filter(Boolean)
    const newPfx = idx < 0 ? '' : parts.slice(0, idx + 1).join('/') + '/'
    setPrefix(newPfx)
    setSelected(new Set())
    browse(newPfx, source)
  }

  function toggleFile(key) {
    setSelected(prev => {
      const n = new Set(prev)
      n.has(key) ? n.delete(key) : n.add(key)
      return n
    })
  }

  function toggleAll() {
    setSelected(prev =>
      prev.size === entries.files.length
        ? new Set()
        : new Set(entries.files.map(f => f.key))
    )
  }

  async function importSelected() {
    if (!selected.size || importing) return
    setImporting(true)
    setError('')
    const transferId = `s3-${Date.now()}`
    const count      = selected.size
    startUpload(transferId, `S3 → ${count} file${count > 1 ? 's' : ''} (transferring…)`)
    try {
      const fn  = source === 'import' ? api.s3.importBatch : api.s3Triage.importBatch
      const r   = await fn(caseId, [...selected])
      onJobsAdded(r.jobs || [])
      if (r.errors?.length) {
        setError(`${r.errors.length} file(s) failed: ${r.errors.map(e => e.s3_key.split('/').pop()).join(', ')}`)
      }
      setSelected(new Set())
    } catch (e) {
      setError(e.message)
    } finally {
      setImporting(false)
      finishUpload(transferId)
    }
  }

  const crumbs = prefix.split('/').filter(Boolean)
  const allFilesSelected = entries.files.length > 0 && selected.size === entries.files.length
  const someFilesSelected = selected.size > 0 && selected.size < entries.files.length

  return (
    <div className="p-4 space-y-3">
      {/* Source toggle */}
      <div className="flex gap-0.5 bg-gray-100 rounded-lg p-0.5">
        {[['import', 'Import Bucket'], ['triage', 'Triage Bucket']].map(([k, l]) => (
          <button key={k} onClick={() => setSource(k)}
            className={`flex-1 text-xs py-1 rounded-md transition-colors ${
              source === k ? 'bg-white shadow text-brand-text font-medium' : 'text-gray-500 hover:text-gray-700'
            }`}>
            {l}
          </button>
        ))}
      </div>

      {/* Breadcrumb */}
      <div className="flex items-center gap-1 text-xs flex-wrap min-h-5">
        <button onClick={() => jumpTo(-1)}
          className="text-gray-500 hover:text-brand-accent transition-colors">
          root
        </button>
        {crumbs.map((c, i) => (
          <span key={`${i}-${c}`} className="flex items-center gap-1">
            <ChevronRight size={10} className="text-gray-500" />
            <button onClick={() => jumpTo(i)}
              className={`transition-colors ${
                i === crumbs.length - 1
                  ? 'font-medium text-brand-text'
                  : 'text-gray-500 hover:text-brand-accent'
              }`}>
              {c}
            </button>
          </span>
        ))}
        <button onClick={() => browse(prefix, source)}
          className="ml-auto text-gray-500 hover:text-brand-accent p-0.5 rounded transition-colors"
          title="Refresh">
          <RefreshCw size={11} />
        </button>
      </div>

      {error && (
        <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      {/* File listing */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        {/* Column header + select-all */}
        {!loading && (entries.files.length > 0 || entries.folders.length > 0) && (
          <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-50 border-b border-gray-200">
            <input
              type="checkbox"
              checked={allFilesSelected}
              ref={el => { if (el) el.indeterminate = someFilesSelected }}
              onChange={toggleAll}
              className="w-3 h-3"
              title="Select / deselect all files"
            />
            <span className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider">Name</span>
            {selected.size > 0 && (
              <span className="ml-auto text-[10px] text-brand-accent font-semibold">
                {selected.size} selected
              </span>
            )}
            {selected.size === 0 && (
              <span className="ml-auto text-[10px] text-gray-500">Size</span>
            )}
          </div>
        )}

        <div className="overflow-y-auto" style={{ maxHeight: '240px' }}>
          {loading && (
            <div className="flex items-center justify-center h-16 text-xs text-gray-500 gap-2">
              <Loader2 size={13} className="animate-spin" /> Loading…
            </div>
          )}
          {!loading && entries.folders.length === 0 && entries.files.length === 0 && (
            <div className="flex items-center justify-center h-12 text-xs text-gray-500">
              Empty — no objects found
            </div>
          )}

          {/* Folders */}
          {entries.folders.map(f => {
            const name = f.key.slice(prefix.length).replace(/\/$/, '')
            return (
              <button key={f.key} onClick={() => navigateTo(f.key)}
                className="flex items-center gap-2.5 w-full px-3 py-2 hover:bg-gray-50 border-b border-gray-50 transition-colors text-left text-xs">
                <span className="w-3 h-3 flex-shrink-0" />
                <Folder size={13} className="text-amber-500 flex-shrink-0" />
                <span className="flex-1 truncate text-gray-700">{name}/</span>
                <ChevronRight size={11} className="text-gray-500 flex-shrink-0" />
              </button>
            )
          })}

          {/* Files */}
          {entries.files.map(f => {
            const name = f.key.slice(prefix.length)
            const sel  = selected.has(f.key)
            return (
              <div key={f.key} onClick={() => toggleFile(f.key)}
                className={`flex items-center gap-2.5 px-3 py-2 cursor-pointer border-b border-gray-50 transition-colors text-xs ${
                  sel ? 'bg-brand-accentlight' : 'hover:bg-gray-50'
                }`}>
                <input type="checkbox" checked={sel}
                  onChange={() => toggleFile(f.key)}
                  onClick={e => e.stopPropagation()}
                  className="w-3 h-3 flex-shrink-0" />
                <File size={12} className="text-gray-500 flex-shrink-0" />
                <span className="flex-1 truncate font-mono text-[10px] text-gray-700">{name}</span>
                <span className="text-gray-500 text-[10px] flex-shrink-0 ml-2">{fmtSize(f.size)}</span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Import button */}
      <button onClick={importSelected}
        disabled={!selected.size || importing}
        className="btn-primary w-full justify-center text-xs">
        {importing
          ? <><Loader2 size={13} className="animate-spin" /> Transferring S3 → storage…</>
          : <><Cloud size={13} />
              {selected.size > 0
                ? `Import ${selected.size} file${selected.size > 1 ? 's' : ''} to case`
                : 'Select files above'}
            </>
        }
      </button>
      {selected.size > 0 && (
        <p className="text-[10px] text-gray-500 text-center -mt-1">
          Large files are streamed server-side — transfer time depends on S3 bandwidth.
        </p>
      )}
    </div>
  )
}

// ── Harvest helpers ─────────────────────────────────────────────────────────

const DEFAULT_LEVELS = ['small', 'complete', 'exhaustive']

// Humanize a flat category key into a readable label: "event_logs" → "Event Logs".
function humanizeKey(key) {
  return String(key)
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, ch => ch.toUpperCase())
    .replace(/\bMft\b/i, 'MFT')
    .replace(/\bMru\b/i, 'MRU')
    .replace(/\bUsb\b/i, 'USB')
    .replace(/\bEvtx\b/i, 'EVTX')
}

// Normalize whatever listLevels() returns (array of strings, array of objects,
// or { levels: [...] }) into [{ key, label, desc }].
function normalizeLevels(raw) {
  const list = Array.isArray(raw) ? raw : raw?.levels || []
  const items = list.length ? list : DEFAULT_LEVELS
  return items.map(l => {
    if (typeof l === 'string') return { key: l, label: '', desc: '' }
    const key = l.key || l.id || l.name
    return { key, label: l.label || '', desc: l.desc || l.description || '' }
  }).filter(l => l.key)
}

// Normalize listCategories() — backend gives a FLAT dict { key: description }.
// Also tolerate an array form. → [{ key, label, desc }].
function normalizeCategories(raw) {
  const dict = raw?.categories ?? raw
  if (Array.isArray(dict)) {
    return dict.map(c => {
      if (typeof c === 'string') return { key: c, label: humanizeKey(c), desc: '' }
      const key = c.key || c.id || c.name
      return { key, label: c.label || humanizeKey(key), desc: c.desc || c.description || '' }
    }).filter(c => c.key)
  }
  if (dict && typeof dict === 'object') {
    return Object.entries(dict).map(([key, desc]) => ({
      key, label: humanizeKey(key), desc: typeof desc === 'string' ? desc : '',
    }))
  }
  return []
}

// ── Harvest tab — server-side artifact collection powered by Talon ──
// Talon runs server-side against a Windows disk image or mounted volume the
// worker can reach. Each artifact found is dispatched as a normal ingest job.
function HarvestTab({ caseId, onJobsAdded }) {
  const [levels, setLevels]         = useState([])
  const [categories, setCategories] = useState([])
  const [level, setLevel]           = useState('complete')
  const [selectedCats, setCats]     = useState(new Set())  // empty = all in level
  const [path, setPath]             = useState('')
  const [run, setRun]               = useState(null)       // { run_id, status, ... }
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState('')

  useEffect(() => {
    api.harvest.listLevels()
      .then(r => {
        const lv = normalizeLevels(r)
        setLevels(lv)
        // Keep "complete" if offered, else fall back to the first level.
        if (lv.length && !lv.some(l => l.key === 'complete')) setLevel(lv[0].key)
      })
      .catch(() => setLevels(normalizeLevels(null)))
    api.harvest.listCategories()
      .then(r => setCategories(normalizeCategories(r)))
      .catch(() => {})
  }, [])

  // Poll the active run until it finishes.
  useEffect(() => {
    if (!run?.run_id || ['completed', 'failed', 'cancelled'].includes(run.status)) return
    const t = setInterval(async () => {
      try {
        const s = await api.harvest.getRun(run.run_id)
        setRun(s)
        if (['completed', 'failed', 'cancelled'].includes(s.status)) { clearInterval(t); onJobsAdded?.() }
      } catch { /* keep polling */ }
    }, 3000)
    return () => clearInterval(t)
  }, [run?.run_id, run?.status, onJobsAdded])

  const running = run && !['completed', 'failed', 'cancelled'].includes(run.status)

  // When the depth changes we reset the explicit category selection back to
  // "defaults for this depth" (empty Set = collect everything in the level).
  function pickLevel(key) {
    if (running) return
    setLevel(key)
    setCats(new Set())
  }

  const toggleCat = key => {
    if (running) return
    setCats(prev => {
      const n = new Set(prev)
      n.has(key) ? n.delete(key) : n.add(key)
      return n
    })
  }
  const selectAll = () => !running && setCats(new Set(categories.map(c => c.key)))
  const clearCats = () => !running && setCats(new Set())

  async function start() {
    if (!path.trim()) { setError('A mounted path or disk-image path is required'); return }
    setBusy(true); setError('')
    try {
      const r = await api.harvest.startRun(caseId, {
        level, categories: [...selectedCats], mounted_path: path.trim(),
      })
      setRun(r)
    } catch (e) { setError(e.message || 'Harvest failed to start') }
    finally { setBusy(false) }
  }

  return (
    <div className="p-4 space-y-4">

      {/* ── Talon brand header ──────────────────────────────────────── */}
      <div className="card overflow-hidden">
        <div className="flex items-start gap-3 px-4 py-3 bg-brand-accent/5 border-b border-brand-accent/15">
          <div className="w-9 h-9 rounded-lg bg-brand-accent/10 border border-brand-accent/30 flex items-center justify-center flex-shrink-0">
            <Crosshair size={18} className="text-brand-accent" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-brand-text">Server-side Harvest</span>
              <span className="badge text-[10px] bg-brand-accent/10 text-brand-accent border border-brand-accent/30">
                Powered by Talon
              </span>
            </div>
            <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">
              Talon runs the acquisition <strong>server-side</strong> against a Windows
              disk image or mounted volume the worker can reach. Each artifact it
              extracts is dispatched as a normal ingest job — watch progress in the list below.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1.5 px-4 py-2 text-[11px] text-gray-500">
          <MonitorSmartphone size={12} className="text-gray-400 flex-shrink-0" />
          Source: <span className="font-medium text-gray-600">Windows disk image / mounted volume</span>
          <span className="text-gray-400">·</span>
          <span>Live multi-OS collection lives in the <strong>Collector</strong> page.</span>
        </div>
      </div>

      {/* ── Source path ─────────────────────────────────────────────── */}
      <div>
        <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 mb-1.5 flex items-center gap-1.5">
          <FolderOpen size={12} className="text-gray-400" /> Source path (on the worker)
        </h4>
        <input value={path} onChange={e => setPath(e.target.value)} disabled={running}
          placeholder="/mnt/evidence/diskimage  or  /mnt/triage"
          className="input w-full text-xs font-mono" />
      </div>

      {/* ── Depth + categories (shared component) ───────────────────── */}
      <ArtifactSelector
        levels={levels}
        level={level}
        onLevel={pickLevel}
        categories={categories}
        selected={selectedCats}
        onToggle={toggleCat}
        onSelectAll={selectAll}
        onClear={clearCats}
        onScenario={keys => !running && setCats(new Set(keys))}
        disabled={running}
      />

      {error && (
        <p className="text-[11px] text-red-500 flex items-center gap-1">
          <AlertTriangle size={11} /> {error}
        </p>
      )}

      {/* ── Actions + live status ───────────────────────────────────── */}
      <div className="flex items-center gap-2 pt-1">
        <button onClick={start} disabled={busy || running || !path.trim()} className="btn-primary text-xs">
          {busy ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />} Start harvest
        </button>
        {run && (
          <span className="text-[11px] text-gray-600 flex items-center gap-1.5">
            {running && <Loader2 size={11} className="animate-spin text-brand-accent" />}
            <span className="capitalize">{run.status}</span>
            {run.current_category && <span className="text-gray-400">· {run.current_category}</span>}
            {typeof run.total_dispatched === 'number' && <span className="text-gray-400">· {run.total_dispatched} jobs</span>}
          </span>
        )}
        {running && (
          <button onClick={() => api.harvest.cancelRun(run.run_id).catch(() => {})}
            className="btn-ghost text-[11px] text-red-500 ml-auto">Cancel</button>
        )}
      </div>
      {run?.error && <p className="text-[11px] text-red-500">{run.error}</p>}
    </div>
  )
}

// ── Main IngestPanel ──────────────────────────────────────────────────────────

const JOB_SORT_ORDER = { RUNNING: 0, UPLOADING: 1, PENDING: 2, COMPLETED: 3, SKIPPED: 4, FAILED: 5 }

export default function IngestPanel({ caseId, onClose, onComplete, autoPilot, setAutoPilot }) {
  const [tab,          setTab]          = useState('upload')
  const [jobs,         setJobs]         = useState([])
  const [jobStatuses,  setJobStatuses]  = useState({})
  const [jobDataMap,   setJobDataMap]   = useState({})
  const [filterStatus, setFilterStatus] = useState(null)   // null = All
  const [searchQuery,  setSearchQuery]  = useState('')
  const [loadError,    setLoadError]    = useState(null)
  const [totalJobs,    setTotalJobs]    = useState(null)   // server-side total
  const [serverCounts, setServerCounts] = useState(null)   // server-side status_counts

  const jobsRef     = useRef([])
  const statusesRef = useRef({})

  useEffect(() => { jobsRef.current    = jobs        }, [jobs])
  useEffect(() => { statusesRef.current = jobStatuses }, [jobStatuses])

  // Load existing jobs (mount + after a server-side harvest dispatches new ones).
  const reloadJobs = useCallback(() => {
    return api.ingest.listJobs(caseId, { limit: 2000 }).then(r => {
      const all = r.jobs || []
      setTotalJobs(r.total ?? all.length)
      setServerCounts(r.status_counts || null)
      const sm = {}, dm = {}
      all.forEach(j => { sm[j.job_id] = j.status; dm[j.job_id] = j })
      setJobStatuses(sm)
      setJobDataMap(dm)
      setJobs([...all].sort((a, b) => (JOB_SORT_ORDER[a.status] ?? 9) - (JOB_SORT_ORDER[b.status] ?? 9)).map(j => j.job_id))
    }).catch(err => setLoadError(err?.message || 'Failed to load jobs'))
  }, [caseId])
  useEffect(() => { reloadJobs() }, [reloadJobs])

  // Central batch poller — one request per 3 s for all non-terminal jobs
  useEffect(() => {
    async function poll() {
      const active = jobsRef.current.filter(id => !TERMINAL.has(statusesRef.current[id]))
      if (!active.length) return
      for (let i = 0; i < active.length; i += 100) {
        try {
          const results = await api.ingest.batchJobs(active.slice(i, i + 100))
          if (!results?.length) continue
          setJobDataMap(p => { const n = { ...p }; results.forEach(j => { n[j.job_id] = j }); return n })
          setJobStatuses(p => { const n = { ...p }; results.forEach(j => { n[j.job_id] = j.status }); return n })
        } catch { /* ignore — retries on next tick */ }
      }
    }
    poll()
    const id = setInterval(poll, 3000)
    return () => clearInterval(id)
  }, [])

  const addJobs = useCallback((newJobs) => {
    const ids = newJobs.map(j => j.job_id)
    setJobs(prev => [...ids, ...prev])
    setJobStatuses(prev => { const n = { ...prev }; ids.forEach(id => { n[id] = 'PENDING' }); return n })
    setJobDataMap(prev => { const n = { ...prev }; newJobs.forEach(j => { n[j.job_id] = j }); return n })
    onComplete?.()
  }, [onComplete])

  const handleRetry = useCallback((id) => {
    setJobStatuses(p => ({ ...p, [id]: 'PENDING' }))
  }, [])

  const handleDelete = useCallback((id) => {
    setJobs(prev => prev.filter(jid => jid !== id))
    setJobStatuses(p => { const n = { ...p }; delete n[id]; return n })
    setJobDataMap(p => { const n = { ...p }; delete n[id]; return n })
  }, [])

  const handleClearFailed = useCallback(async () => {
    const failedIds = jobsRef.current.filter(jid => statusesRef.current[jid] === 'FAILED')
    if (!failedIds.length) return
    if (!window.confirm(`Delete all ${failedIds.length} failed job${failedIds.length > 1 ? 's' : ''} and their data?`)) return
    await Promise.allSettled(failedIds.map(id => api.ingest.deleteJob(id)))
    setJobs(prev => prev.filter(jid => statusesRef.current[jid] !== 'FAILED'))
    setJobStatuses(p => { const n = { ...p }; failedIds.forEach(id => delete n[id]); return n })
    setJobDataMap(p => { const n = { ...p }; failedIds.forEach(id => delete n[id]); return n })
  }, [])

  const handleClearAll = useCallback(async () => {
    const activeStatuses = new Set(['RUNNING', 'UPLOADING'])
    const deletableIds = jobsRef.current.filter(jid => !activeStatuses.has(statusesRef.current[jid]))
    if (!deletableIds.length) return
    if (!window.confirm(`Delete all ${deletableIds.length} job${deletableIds.length > 1 ? 's' : ''} and their indexed data?\nActive jobs will be skipped.`)) return
    await api.ingest.deleteAllJobs(caseId)
    setJobs(prev => prev.filter(jid => activeStatuses.has(statusesRef.current[jid])))
    setJobStatuses(p => { const n = { ...p }; deletableIds.forEach(id => delete n[id]); return n })
    setJobDataMap(p => { const n = { ...p }; deletableIds.forEach(id => delete n[id]); return n })
  }, [caseId])

  // ── Derived counts ────────────────────────────────────────────────────────
  // Prefer server-side totals when available (handles >2000 jobs accurately);
  // fall back to client-side counts for newly added/deleted jobs in the session.
  const localCounts = Object.values(jobStatuses).reduce((acc, s) => {
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {})
  const statusCounts = serverCounts
    ? { ...serverCounts, ...Object.fromEntries(
        // Override transient statuses with local counts (active jobs change fast)
        ['RUNNING', 'UPLOADING', 'PENDING'].map(k => [k, localCounts[k] || 0])
      ) }
    : localCounts
  const activeCount = (statusCounts['RUNNING'] || 0) + (statusCounts['UPLOADING'] || 0)

  // Always sort by priority (active first, failed last), then filter by tab + search
  const sortedJobs = [...jobs].sort((a, b) =>
    (JOB_SORT_ORDER[jobStatuses[a]] ?? 9) - (JOB_SORT_ORDER[jobStatuses[b]] ?? 9)
  )
  const filteredJobs = sortedJobs.filter(jid => {
    const job = jobDataMap[jid]
    if (!job) return true
    if (filterStatus === 'ACTIVE'   && !['RUNNING', 'UPLOADING'].includes(job.status)) return false
    if (filterStatus === 'PENDING'  && job.status !== 'PENDING')                        return false
    if (filterStatus === 'COMPLETED'&& job.status !== 'COMPLETED')                      return false
    if (filterStatus === 'FAILED'   && job.status !== 'FAILED')                         return false
    if (searchQuery.trim()) {
      return (job.original_filename || '').toLowerCase().includes(searchQuery.toLowerCase())
    }
    return true
  })

  const totalDisplay = totalJobs ?? jobs.length
  const FILTER_TABS = [
    { id: null,        label: 'All',     count: totalDisplay },
    { id: 'ACTIVE',    label: 'Active',  count: activeCount },
    { id: 'PENDING',   label: 'Pending', count: statusCounts['PENDING']   || 0 },
    { id: 'COMPLETED', label: 'Done',    count: statusCounts['COMPLETED'] || 0 },
    { id: 'FAILED',    label: 'Failed',  count: statusCounts['FAILED']    || 0 },
  ].filter(f => f.id === null || f.count > 0)

  return (
    <ResizableDrawer slug="ingest" defaultWidth={580} onClose={onClose}>
        {/* ── Header + tabs ── */}
        <div className="flex items-center gap-3 px-5 py-3 border-b border-gray-200 flex-shrink-0">
          <Upload size={15} className="text-brand-accent flex-shrink-0" />
          <span className="font-semibold text-brand-text text-sm">Add Evidence</span>

          <div className="flex gap-0.5 bg-gray-100 rounded-lg p-0.5 ml-1">
            {[
              { id: 'upload',  label: 'Upload',    Icon: Upload },
              { id: 's3',      label: 'S3 Import', Icon: Cloud  },
              { id: 'harvest', label: 'Harvest',   Icon: HardDrive },
            ].map(({ id, label, Icon }) => (
              <button key={id} onClick={() => setTab(id)}
                className={`text-xs px-3 py-1 rounded-md transition-colors whitespace-nowrap inline-flex items-center gap-1.5 ${
                  tab === id
                    ? 'bg-white shadow-sm text-brand-text font-semibold'
                    : 'text-gray-500 hover:text-gray-700'
                }`}>
                <Icon size={12} />
                {label}
              </button>
            ))}
          </div>

          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg ml-auto" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>

        {/* ── Tab content ── */}
        <div className="border-b border-gray-100 flex-shrink-0">
          <div className="px-4 pt-3">
            <PanelHelp title="Ingest"
              use="Uploads evidence — files, archives, disk images — into the case for parsing, normalization and indexing."
              when="At case start, and whenever new evidence arrives."
              data={['Nothing — this is where data first enters the case']}
              tip="ZIP/TAR archives are extracted recursively; large files upload in resumable chunks." />
          </div>

          {/* Auto-AI — same toggle as the case toolbar, surfaced here so you can
              arm the autonomous investigation at the moment you add evidence. */}
          {setAutoPilot && (
            <div className="px-4 pb-3">
              <button
                onClick={() => {
                  const next = !autoPilot
                  setAutoPilot(next)
                  // Arm/disarm the SERVER-SIDE LLM auto-run too (the finalize
                  // chain reads the per-case `auto_ai` flag), so this one switch
                  // truly governs whether the LLM runs on ingest. Modules always
                  // auto-run regardless — this only gates the LLM.
                  api.cases.setAutoRun(caseId, { auto_ai: next }).catch(() => {})
                }}
                className={`w-full flex items-center gap-2 px-3 py-2 rounded-lg border text-left transition-colors ${
                  autoPilot
                    ? 'bg-purple-50 border-purple-300 text-purple-700'
                    : 'bg-white border-gray-200 text-gray-500 hover:border-gray-300'
                }`}
                title={autoPilot
                  ? 'Auto-AI is ON — the AI investigation launches automatically when this ingest finishes. Click to turn off.'
                  : 'Auto-AI is OFF — click to auto-launch the AI investigation when ingest completes.'}
              >
                <Zap size={14} className={autoPilot ? 'text-purple-600' : 'text-gray-400'} />
                <span className="flex-1">
                  <span className="text-xs font-semibold">Auto-AI: {autoPilot ? 'ON' : 'OFF'}</span>
                  <span className="block text-[10px] opacity-80 font-normal">
                    {autoPilot
                      ? 'Autonomous triage will start when these jobs finish indexing.'
                      : 'Launch the AI investigation automatically once ingest completes.'}
                  </span>
                </span>
                <span className={`w-8 h-4 rounded-full flex-shrink-0 relative transition-colors ${autoPilot ? 'bg-purple-500' : 'bg-gray-300'}`}>
                  <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${autoPilot ? 'left-4' : 'left-0.5'}`} />
                </span>
              </button>
            </div>
          )}
          {tab === 'upload'  && <UploadTab  caseId={caseId} onJobsAdded={addJobs} />}
          {tab === 's3'      && <S3Tab      caseId={caseId} onJobsAdded={addJobs} />}
          {tab === 'harvest' && <HarvestTab caseId={caseId} onJobsAdded={reloadJobs} />}
        </div>

        {/* ── Shared job list — always visible, scrollable ── */}
        <div className="flex flex-col flex-1 min-h-0">
          {/* Filter + search bar — sticky above the scrollable list */}
          {jobs.length > 0 && (
            <div className="px-4 pt-3 pb-2 border-b border-gray-100 flex-shrink-0 space-y-2">
              {/* Status filter pills */}
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mr-0.5">
                  Filter
                </span>
                {FILTER_TABS.map(f => (
                  <button
                    key={String(f.id)}
                    onClick={() => setFilterStatus(f.id)}
                    className={`text-[10px] px-2 py-0.5 rounded-full border transition-colors font-medium ${
                      filterStatus === f.id
                        ? f.id === 'FAILED'
                          ? 'bg-red-500 text-white border-red-500'
                          : f.id === 'ACTIVE'
                            ? 'bg-brand-accent text-white border-brand-accent'
                            : 'bg-gray-700 text-white border-gray-700'
                        : f.id === 'FAILED' && f.count > 0
                          ? 'bg-red-50 text-red-500 border-red-200 hover:bg-red-100'
                          : f.id === 'ACTIVE' && f.count > 0
                            ? 'bg-brand-accentlight text-brand-accent border-brand-accent/30 hover:bg-brand-accent/10'
                            : 'bg-white text-gray-500 border-gray-200 hover:border-gray-400 hover:text-gray-700'
                    }`}
                  >
                    <span>{f.label}</span>
                    <span className={`ml-1.5 tabular-nums ${filterStatus === f.id ? 'opacity-80' : 'opacity-60'}`}>
                      {f.count}
                    </span>
                  </button>
                ))}
                {activeCount > 0 ? (
                  <span className="ml-auto text-[10px] text-brand-accent animate-pulse font-medium">
                    {activeCount} running
                  </span>
                ) : (
                  <div className="ml-auto flex items-center gap-2">
                    {(statusCounts['FAILED'] || 0) >= 2 && (
                      <button onClick={handleClearFailed}
                        className="text-[10px] text-red-400 hover:text-red-600 flex items-center gap-1 transition-colors">
                        <Trash2 size={10} />
                        Clear failed
                      </button>
                    )}
                    {jobs.length > 0 && (
                      <button onClick={handleClearAll}
                        className="text-[10px] text-gray-400 hover:text-red-600 flex items-center gap-1 transition-colors">
                        <Trash2 size={10} />
                        Remove all
                      </button>
                    )}
                  </div>
                )}
              </div>
              {/* Filename search — only shown when there are enough jobs to warrant it */}
              {jobs.length >= 5 && (
                <div className="relative">
                  <input
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    placeholder="Search by filename…"
                    className="input w-full text-xs py-1 pr-7"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
                      title="Clear search"
                    >
                      <X size={11} />
                    </button>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="flex-1 overflow-y-auto p-4 min-h-0">
            {jobs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 gap-2 text-gray-500">
                <Database size={28} />
                {loadError
                  ? <p className="text-xs text-red-400">{loadError}</p>
                  : <p className="text-xs">No jobs yet — upload or import from S3</p>
                }
              </div>
            ) : filteredJobs.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-24 gap-1.5 text-gray-500">
                <p className="text-xs">No jobs match this filter</p>
                <button onClick={() => { setFilterStatus(null); setSearchQuery('') }}
                  className="text-[10px] text-brand-accent hover:underline">
                  Clear filters
                </button>
              </div>
            ) : (
              <div className="space-y-2">
                {filteredJobs.map(jid => (
                  <JobCard key={jid} jobId={jid} jobData={jobDataMap[jid]} onRetry={handleRetry} onDelete={handleDelete} />
                ))}
              </div>
            )}
          </div>
        </div>
    </ResizableDrawer>
  )
}
