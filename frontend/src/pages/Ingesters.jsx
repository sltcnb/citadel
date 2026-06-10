import { useEffect, useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Puzzle, Upload, RefreshCw, FileCode2, X,
  CheckCircle, AlertCircle, Copy, Check,
  Code2, BookOpen, Plus, ArrowRight,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { ToolByline } from './Suite'
import { api } from '../api/client'

// ── UploadZone ────────────────────────────────────────────────────────────────
function UploadZone({ onUploaded }) {
  const [dragging, setDragging] = useState(false)
  const [file, setFile]         = useState(null)
  const [status, setStatus]     = useState(null) // null | 'uploading' | 'success' | 'error'
  const [message, setMessage]   = useState('')
  const inputRef = useRef()

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) selectFile(f)
  }

  function selectFile(f) {
    if (!f.name.endsWith('.py')) {
      setStatus('error')
      setMessage('Only .py files are accepted.')
      return
    }
    setFile(f)
    setStatus(null)
    setMessage('')
  }

  async function upload() {
    if (!file) return
    setStatus('uploading')
    setMessage('')
    try {
      const fd = new FormData()
      fd.append('file', file)
      const r = await api.plugins.upload(fd)
      setStatus('success')
      setMessage(r.message)
      setFile(null)
      onUploaded(r.plugins)
    } catch (e) {
      setStatus('error')
      setMessage(e.message)
    }
  }

  return (
    <div>
      <div
        className={dragging ? 'drop-zone-active' : 'drop-zone-inactive'}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => !file && inputRef.current.click()}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".py"
          className="hidden"
          onChange={e => e.target.files[0] && selectFile(e.target.files[0])}
        />

        {file ? (
          <div className="flex items-center justify-center gap-3">
            <FileCode2 size={20} className="text-brand-accent" />
            <div className="text-left">
              <p className="text-sm font-medium text-brand-text">{file.name}</p>
              <p className="text-xs text-gray-500">{(file.size / 1024).toFixed(1)} KB</p>
            </div>
            <div className="flex gap-2 ml-4">
              <button
                onClick={e => { e.stopPropagation(); setFile(null) }}
                className="btn-ghost text-xs"
              >
                <X size={12} /> Remove
              </button>
              <button
                onClick={e => { e.stopPropagation(); upload() }}
                disabled={status === 'uploading'}
                className="btn-primary text-xs"
              >
                {status === 'uploading'
                  ? <><RefreshCw size={12} className="animate-spin" /> Uploading…</>
                  : <><Upload size={12} /> Upload Ingester</>}
              </button>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div className="w-10 h-10 rounded-xl bg-gray-100 flex items-center justify-center">
              <Upload size={18} className="text-gray-500" />
            </div>
            <p className="text-sm text-gray-500">
              Drop a <code className="text-brand-accent">*_ingester.py</code> file here
            </p>
            <p className="text-xs text-gray-500">or click to browse</p>
          </div>
        )}
      </div>

      {status === 'success' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
          <CheckCircle size={13} /> {message}
        </div>
      )}
      {status === 'error' && (
        <div className="mt-2 flex items-center gap-2 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          <AlertCircle size={13} /> {message}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Ingesters() {
  const navigate = useNavigate()
  const [plugins, setPlugins] = useState([])
  const [loading, setLoading] = useState(true)
  const [reloading, setReloading] = useState(false)

  function loadPlugins() {
    setLoading(true)
    api.plugins.list()
      .then(r => setPlugins(r.plugins || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(loadPlugins, [])

  async function reload() {
    setReloading(true)
    try {
      const r = await api.plugins.reload()
      setPlugins(r.plugins || [])
    } catch (e) {
      alert('Reload failed: ' + e.message)
    } finally {
      setReloading(false)
    }
  }

  const activeCount = plugins.length

  return (
    <PageShell>

      {/* Page header */}
      <PageHeader
        title="Ingesters"
        icon={Puzzle}
        subtitle="Parsers that convert uploaded forensic artifacts into timeline events"
        actions={
          <>
            <button
              onClick={() => navigate('/studio')}
              className="btn-primary text-xs"
            >
              <Plus size={13} /> New Ingester
            </button>
            <button onClick={reload} disabled={reloading} className="btn-outline text-xs">
              <RefreshCw size={13} className={reloading ? 'animate-spin' : ''} />
              {reloading ? 'Reloading…' : 'Reload All'}
            </button>
          </>
        }
      />

      <div className="-mt-2 mb-4"><ToolByline tool="babel" /></div>

      {/* ── Section 1: All ingesters ────────────────────────────────────────── */}
      <section className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <h2 className="section-title">Ingesters</h2>
          {!loading && (
            <span className="badge bg-green-50 text-green-700 border border-green-200">
              {activeCount} loaded
            </span>
          )}
        </div>

        {loading ? (
          <div className="space-y-3">
            {[1, 2, 3].map(i => <div key={i} className="skeleton h-16 w-full" />)}
          </div>
        ) : plugins.length === 0 ? (
          <div className="card px-4 py-6 text-sm text-gray-400">No ingesters loaded — create one in Studio or upload below.</div>
        ) : (
          <div className="space-y-2">
            {plugins.map(p => (
              <div key={p.name} className="card p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-start gap-3">
                    <div className="w-8 h-8 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                      <Puzzle size={14} className="text-brand-accent" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <span className="text-sm font-semibold text-brand-text">{p.name}</span>
                        {p.version && (
                          <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                            v{p.version}
                          </span>
                        )}
                        <span className="badge bg-green-50 text-green-700 border border-green-200">
                          <CheckCircle size={9} className="mr-1" /> active
                        </span>
                      </div>
                      <p className="text-xs text-gray-500">
                        Artifact type:{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 py-0.5 rounded text-[10px]">
                          {p.default_artifact_type}
                        </code>
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="flex flex-wrap gap-1 justify-end max-w-xs">
                      {p.supported_extensions?.map(ext => (
                        <span key={ext} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono">
                          {ext}
                        </span>
                      ))}
                      {p.handled_filenames?.slice(0, 3).map(fn => (
                        <span key={fn} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono">
                          {fn}
                        </span>
                      ))}
                      {(p.handled_filenames?.length || 0) > 3 && (
                        <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                          +{p.handled_filenames.length - 3}
                        </span>
                      )}
                    </div>
                    <button
                      onClick={() => navigate('/studio', { state: { type: 'ingester', name: p.source_file || p.name } })}
                      className="btn-ghost text-xs flex-shrink-0"
                      title="Open in Studio"
                    >
                      <Code2 size={12} /> Open
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </section>

      {/* ── Section 2: Build a custom ingester ─────────────────────────────── */}
      <section className="mb-8">
        <h2 className="section-title mb-3">Build a Custom Ingester</h2>
        <div className="card p-5 space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 text-xs">
            {[
              {
                n: 1,
                title: 'Write the parser',
                body: (
                  <>
                    Open <strong>Studio → Ingesters</strong> and create a{' '}
                    <code className="text-brand-accent bg-brand-accentlight px-1 rounded">*_ingester.py</code> file.
                    Subclass <code className="text-brand-accent bg-brand-accentlight px-1 rounded">BasePlugin</code> and
                    implement the <code className="text-brand-accent bg-brand-accentlight px-1 rounded">parse()</code> generator.
                  </>
                ),
              },
              {
                n: 2,
                title: 'Yield ParsedEvents',
                body: (
                  <>
                    Each event needs a <code className="text-brand-accent bg-brand-accentlight px-1 rounded">timestamp</code>,{' '}
                    <code className="text-brand-accent bg-brand-accentlight px-1 rounded">message</code>, and{' '}
                    <code className="text-brand-accent bg-brand-accentlight px-1 rounded">artifact_type</code>.
                    Optional: <code className="text-brand-accent bg-brand-accentlight px-1 rounded">host</code>,{' '}
                    <code className="text-brand-accent bg-brand-accentlight px-1 rounded">user</code>,{' '}
                    <code className="text-brand-accent bg-brand-accentlight px-1 rounded">extra</code> dict.
                  </>
                ),
              },
              {
                n: 3,
                title: 'Save & reload',
                body: (
                  <>
                    Save the file in Studio, then click <strong>Reload All</strong> on this page
                    (or restart the processor). Upload a matching file to any case — it will be
                    parsed by your ingester automatically.
                  </>
                ),
              },
            ].map(({ n, title, body }) => (
              <div key={n} className="flex gap-3">
                <div className="w-6 h-6 rounded-full bg-gray-200 text-gray-600 flex items-center justify-center text-[11px] font-bold flex-shrink-0 mt-0.5">
                  {n}
                </div>
                <div>
                  <p className="font-semibold text-brand-text mb-1 text-xs">{title}</p>
                  <p className="text-xs text-gray-500 leading-relaxed">{body}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="flex items-center gap-3 border-t border-gray-100 pt-4">
            <button onClick={() => navigate('/studio')} className="btn-primary text-xs">
              <Code2 size={12} /> Open Studio
            </button>
            <button onClick={() => navigate('/docs')} className="btn-outline text-xs">
              <BookOpen size={12} /> Read the Docs
            </button>
            <span className="text-xs text-gray-500 ml-auto flex items-center gap-1">
              <ArrowRight size={11} /> Save as <code className="font-mono">ingesters/*_ingester.py</code>
            </span>
          </div>
        </div>
      </section>

      {/* ── Section 3: Upload an ingester file ─────────────────────────────── */}
      <section>
        <div className="flex items-center gap-2 mb-3">
          <h2 className="section-title">Upload Ingester File</h2>
          <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">
            alternative to Studio
          </span>
        </div>
        <p className="text-xs text-gray-500 mb-4">
          Have an ingester file ready? Drop it here. The file must be named{' '}
          <code className="text-gray-500">*_ingester.py</code> and will be deployed to{' '}
          <code className="text-gray-500">/app/sluices/</code>.
          Click <strong>Reload All</strong> after uploading to activate it.
        </p>
        <UploadZone onUploaded={newPlugins => setPlugins(newPlugins || [])} />
      </section>

      {/* ── Section 4: Built-in artifact type reference ──────────────────────── */}
      <section>
        <h2 className="section-title mb-3">Built-in Artifact Types</h2>
        <p className="text-xs text-gray-500 mb-4">
          Reference for <code className="text-gray-600">artifact_type</code> values produced by each built-in ingester.
          Use these in Timeline searches (<code className="text-brand-accent">artifact_type:evtx</code>) or alert rules.
        </p>
        <div className="card overflow-hidden">
          <div className="grid grid-cols-3 bg-gray-50 border-b border-gray-200 px-4 py-2 text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
            <span>artifact_type</span>
            <span>Extensions / filenames</span>
            <span>Description</span>
          </div>
          <div className="divide-y divide-gray-100">
            {[
              { type: 'evtx',          ext: '.evtx',                       desc: 'Windows Event Logs (Security, System, Sysmon…)' },
              { type: 'hayabusa',      ext: '.jsonl / .csv',               desc: 'Hayabusa sigma-rule detection output' },
              { type: 'mft',           ext: '$MFT',                        desc: 'NTFS Master File Table — full filesystem timeline' },
              { type: 'prefetch',      ext: '.pf',                         desc: 'Windows Prefetch execution evidence' },
              { type: 'registry',      ext: 'SYSTEM/SOFTWARE/SAM/NTUSER',  desc: 'Windows Registry hives' },
              { type: 'lnk',           ext: '.lnk',                        desc: 'Shell link files — recent documents' },
              { type: 'browser',       ext: 'History/Login Data/…',        desc: 'Chrome, Edge, Firefox SQLite databases' },
              { type: 'access_log',    ext: '.log',                        desc: 'Apache/Nginx combined access log' },
              { type: 'suricata',      ext: 'eve.json',                    desc: 'Suricata NDJSON alerts + flows' },
              { type: 'zeek',          ext: '*.log (Zeek)',                desc: 'Zeek/Bro network logs' },
              { type: 'pcap',          ext: '.pcap / .pcapng',             desc: 'Packet captures — flows & DNS' },
              { type: 'syslog',        ext: '.log / syslog',               desc: 'Generic syslog (RFC 3164/5424)' },
              { type: 'auditd',        ext: 'audit.log',                   desc: 'Linux auditd kernel records' },
              { type: 'scheduled_task',ext: '.xml (Task folder)',          desc: 'Windows Scheduled Tasks' },
              { type: 'dd_file',       ext: '.dd / .raw / .img',           desc: 'Raw disk image filesystem walk' },
              { type: 'plaso',         ext: '.plaso',                      desc: 'Plaso super-timeline (L2T)' },
              { type: 'android',       ext: '.ab',                         desc: 'Android backup' },
              { type: 'ios',           ext: 'iTunes backup dir',           desc: 'iOS backup databases' },
              { type: 'shell_history', ext: '.bash_history/.zsh_history',  desc: 'Shell command history' },
              { type: 'docker_event',  ext: 'docker*.log/json',            desc: 'Docker container events' },
              { type: 'ndjson',        ext: '.ndjson / .jsonl',            desc: 'Generic NDJSON event stream' },
            ].map(({ type, ext, desc }) => (
              <div key={type} className="grid grid-cols-3 px-4 py-2 items-start hover:bg-gray-50/60 text-xs">
                <code className="font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded text-[11px] self-start">{type}</code>
                <span className="font-mono text-gray-500 text-[11px]">{ext}</span>
                <span className="text-gray-600">{desc}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </PageShell>
  )
}
