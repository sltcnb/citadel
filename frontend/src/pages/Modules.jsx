import { useEffect, useState, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Cpu, CheckCircle, XCircle, ChevronDown,
  Code2, AlertCircle, Search as SearchIcon, X, BookOpen,
  Shield, Monitor, HardDrive, Globe, Brain,
  Binary, Bug, Network, FileImage, TextSearch, Tag, ArrowRight,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts'

const CATEGORY_ICONS = {
  'Threat Hunting':     <Shield    size={13} className="text-red-500" />,
  'Windows':            <Monitor   size={13} className="text-sky-500" />,
  'Disk Forensics':     <HardDrive size={13} className="text-amber-500" />,
  'Browser Forensics':  <Globe     size={13} className="text-blue-500" />,
  'Memory Forensics':   <Brain     size={13} className="text-purple-500" />,
  'Network':            <Network   size={13} className="text-teal-500" />,
  'Binary Analysis':    <Binary    size={13} className="text-orange-500" />,
  'Malware Detection':  <Bug       size={13} className="text-red-500" />,
  'Threat Intelligence':<Tag       size={13} className="text-pink-500" />,
  'Metadata Extraction':<FileImage size={13} className="text-indigo-500" />,
  'Search':             <TextSearch size={13} className="text-gray-500" />,
}

// ── ModuleCard ────────────────────────────────────────────────────────────────
function ModuleCard({ mod, onEdit }) {
  const [open, setOpen] = useState(false)

  const acceptsAll = (mod.input_extensions || []).length === 0 && (mod.input_filenames || []).length === 0
  const allTags    = [...(mod.input_extensions || []), ...(mod.input_filenames || [])]

  return (
    <div className="card overflow-hidden">
      <button
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-gray-50 transition-colors"
        onClick={() => setOpen(v => !v)}
      >
        {/* Icon */}
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5 ${
          mod.available
            ? 'bg-brand-accentlight border border-brand-accent/20'
            : 'bg-gray-100 border border-gray-200'
        }`}>
          <Cpu size={14} className={mod.available ? 'text-brand-accent' : 'text-gray-500'} />
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-0.5">
            <span className={`text-sm font-semibold ${mod.available ? 'text-brand-text' : 'text-gray-500'}`}>
              {mod.name}
            </span>
            {mod.available ? (
              <span className="badge bg-green-50 text-green-700 border border-green-200">
                <CheckCircle size={9} className="mr-1" /> available
              </span>
            ) : (
              <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                <XCircle size={9} className="mr-1" /> unavailable
              </span>
            )}
            {mod.custom && (
              <span className="badge bg-blue-50 text-blue-600 border border-blue-100">
                custom
              </span>
            )}
          </div>
          <p className={`text-xs ${mod.available ? 'text-gray-500' : 'text-gray-500'}`}>
            {mod.description}
          </p>
          {!mod.available && mod.unavailable_reason && (
            <p className="text-[10px] text-gray-500 italic mt-0.5">{mod.unavailable_reason}</p>
          )}
        </div>

        {/* Tags + chevron */}
        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
          {acceptsAll && (
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">
              any file
            </span>
          )}
          {!acceptsAll && allTags.slice(0, 2).map(t => (
            <span key={t} className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono hidden sm:inline-flex">
              {t}
            </span>
          ))}
          {!acceptsAll && allTags.length > 2 && (
            <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
              +{allTags.length - 2}
            </span>
          )}
          <ChevronDown size={14} className={`text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} />
        </div>
      </button>

      {/* Expanded detail */}
      {open && (
        <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-3">
          <div className="grid grid-cols-2 gap-x-6 gap-y-3 text-xs">

            {/* Accepted inputs */}
            <div>
              <p className="section-title mb-1.5">Accepted inputs</p>
              {acceptsAll ? (
                <span className="text-gray-500 italic">All ingested files</span>
              ) : (
                <div className="flex flex-wrap gap-1">
                  {allTags.map(t => (
                    <span key={t} className="badge bg-white border border-gray-200 text-gray-600 font-mono">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            {/* Module ID */}
            <div>
              <p className="section-title mb-1.5">Module ID</p>
              <code className="text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded text-[11px]">
                {mod.id}
              </code>
            </div>

            {/* Tags */}
            {(mod.tags || []).length > 0 && (
              <div className="col-span-2">
                <p className="section-title mb-1.5">Tags</p>
                <div className="flex flex-wrap gap-1">
                  {mod.tags.map(t => (
                    <span key={t} className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            )}

          </div>

          {/* Custom module edit link */}
          {mod.custom && onEdit && (
            <div className="border-t border-gray-100 pt-3">
              <button
                onClick={() => onEdit(mod.id)}
                className="flex items-center gap-1.5 text-xs text-brand-accent hover:underline font-medium"
              >
                <Code2 size={12} /> Edit in Studio
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function Modules() {
  const navigate = useNavigate()
  const [modules, setModules]   = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [search, setSearch]         = useState('')
  const [showUnavailable, setShowUnavailable] = useState(true)
  const searchRef = useRef(null)

  useKeyboardShortcuts([
    { key: '/', handler: () => searchRef.current?.focus() },
  ])

  useEffect(() => {
    api.modules.list()
      .then(r => setModules(r.modules || []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }, [])

  const filteredModules = useMemo(() => {
    const q = search.toLowerCase()
    return modules.filter(m => {
      const textMatch = !q ||
        (m.name || '').toLowerCase().includes(q) ||
        (m.description || '').toLowerCase().includes(q) ||
        (m.category || '').toLowerCase().includes(q) ||
        (m.tags || []).some(t => t.toLowerCase().includes(q))
      const availabilityMatch = showUnavailable || m.available
      return textMatch && availabilityMatch
    })
  }, [modules, search, showUnavailable])

  // Group filtered modules by category, available-first within each group
  const CATEGORY_ORDER = [
    'Threat Hunting', 'Malware Detection', 'Binary Analysis', 'Windows',
    'Memory Forensics', 'Disk Forensics', 'Browser Forensics', 'Network',
    'Threat Intelligence', 'Metadata Extraction', 'Search',
  ]
  const groupedModules = useMemo(() => {
    const groups = {}
    filteredModules.forEach(m => {
      const cat = m.category || 'Other'
      if (!groups[cat]) groups[cat] = []
      groups[cat].push(m)
    })
    // Sort within each group: available first
    Object.values(groups).forEach(arr => arr.sort((a, b) => (b.available ? 1 : 0) - (a.available ? 1 : 0)))
    // Return sorted by CATEGORY_ORDER, then alphabetically for any uncategorised
    return Object.entries(groups).sort(([a], [b]) => {
      const ai = CATEGORY_ORDER.indexOf(a)
      const bi = CATEGORY_ORDER.indexOf(b)
      if (ai !== -1 && bi !== -1) return ai - bi
      if (ai !== -1) return -1
      if (bi !== -1) return 1
      return a.localeCompare(b)
    })
  }, [filteredModules])

  const available   = filteredModules.filter(m => m.available)
  const unavailable = filteredModules.filter(m => !m.available)

  function openInStudio(moduleId) {
    navigate('/studio', { state: { type: 'module', name: moduleId } })
  }

  return (
    <PageShell>

      <PageHeader
        title="Modules"
        icon={Cpu}
        subtitle="On-demand analysis tools — run against ingested source files within a case"
        actions={
          <button
            onClick={() => navigate('/studio')}
            className="btn-primary text-xs"
          >
            <Code2 size={13} /> New Module
          </button>
        }
      />


      {/* Error */}
      {error && (
        <div className="mb-4 flex items-center gap-2 text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
          <AlertCircle size={13} /> Failed to load modules: {error}
        </div>
      )}

      {/* Filter bar */}
      {!loading && !error && (
        <div className="flex items-center gap-2 mb-5 flex-wrap">
          {/* Search input */}
          <div className="relative flex-1 min-w-[200px]">
            <SearchIcon size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
            <input
              ref={searchRef}
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Filter modules… (press /)"
              className="input text-xs pl-8 pr-7"
            />
            {search && (
              <button
                onClick={() => setSearch('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
              >
                <X size={12} />
              </button>
            )}
          </div>

          {/* Show unavailable toggle */}
          <button
            onClick={() => setShowUnavailable(v => !v)}
            className={`btn-ghost text-xs gap-1.5 ${showUnavailable ? 'text-brand-accent' : 'text-gray-500'}`}
          >
            <XCircle size={13} className={showUnavailable ? 'text-brand-accent' : 'text-gray-500'} />
            {showUnavailable ? 'Showing unavailable' : 'Hiding unavailable'}
          </button>

          {/* Result count */}
          <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
            {filteredModules.length} of {modules.length}
          </span>
        </div>
      )}

      {/* Skeleton */}
      {loading && (
        <div className="space-y-3">
          {[1, 2, 3, 4].map(i => <div key={i} className="skeleton h-16 w-full" />)}
        </div>
      )}

      {!loading && !error && (
        <>
          {/* ── Stats bar ───────────────────────────────────────────────────── */}
          {filteredModules.length > 0 && (
            <div className="flex items-center gap-3 mb-5 flex-wrap">
              <span className="badge bg-green-50 text-green-700 border border-green-200">
                <CheckCircle size={9} className="mr-1" /> {available.length} available
              </span>
              {unavailable.length > 0 && (
                <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                  <XCircle size={9} className="mr-1" /> {unavailable.length} unavailable
                </span>
              )}
            </div>
          )}

          {/* ── Category groups ─────────────────────────────────────────────── */}
          {groupedModules.length === 0 ? (
            <p className="text-xs text-gray-500 italic py-8 text-center">No modules match your filter.</p>
          ) : (
            groupedModules.map(([category, mods]) => (
              <section key={category} className="mb-8">
                <div className="flex items-center gap-2 mb-3">
                  {CATEGORY_ICONS[category] && (
                    <span className="flex-shrink-0">{CATEGORY_ICONS[category]}</span>
                  )}
                  <h2 className="section-title">{category}</h2>
                  <span className="badge bg-gray-100 text-gray-500 border border-gray-200">
                    {mods.filter(m => m.available).length}/{mods.length}
                  </span>
                </div>
                <div className="space-y-2">
                  {mods.map(mod => (
                    <ModuleCard key={mod.id} mod={mod} onEdit={openInStudio} />
                  ))}
                </div>
              </section>
            ))
          )}

          {/* ── How modules work ─────────────────────────────────────────────── */}
          <section className="mb-8">
            <h2 className="section-title mb-3">How Modules Work</h2>
            <div className="card p-5 space-y-5">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 text-xs">
                {[
                  {
                    n: 1,
                    title: 'Ingest your files',
                    body: 'Upload evidence files to a case via Add Evidence. Each file is stored and available as a module source.',
                  },
                  {
                    n: 2,
                    title: 'Launch a module',
                    body: 'Open a case → click Modules in the header → select a module → choose source files → Run.',
                  },
                  {
                    n: 3,
                    title: 'Review results',
                    body: 'Detections appear in the Module Runs panel grouped by severity. Results are indexed in Elasticsearch — click "Search in Timeline" on any completed run to pivot directly to the timeline filtered by that module\'s artifact type.',
                  },
                ].map(({ n, title, body }) => (
                  <div key={n} className="flex gap-3">
                    <div className="w-6 h-6 rounded-full bg-brand-accent text-white flex items-center justify-center text-[11px] font-bold flex-shrink-0 mt-0.5">
                      {n}
                    </div>
                    <div>
                      <p className="font-semibold text-brand-text mb-1">{title}</p>
                      <p className="text-gray-500 leading-relaxed">{body}</p>
                    </div>
                  </div>
                ))}
              </div>

              <div className="border-t border-gray-100 pt-4 text-xs text-gray-500 leading-relaxed">
                <strong className="text-brand-text">Modules vs Ingesters</strong> — Ingesters parse raw uploaded
                files into timeline events at upload time. Modules are launched manually, run external
                analysis tools against already-ingested source files, and display results in their own panel —
                they do not modify the main event timeline.
              </div>
            </div>
          </section>

          {/* ── Build a custom module ─────────────────────────────────────────── */}
          <section>
            <h2 className="section-title mb-3">Build a Custom Module</h2>
            <div className="card p-5 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 text-xs">
                {[
                  {
                    n: 1,
                    title: 'Write the module',
                    body: (
                      <>
                        Open <strong>Studio</strong> and create a new{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">*_module.py</code>.
                        Expose <code className="text-brand-accent bg-brand-accentlight px-1 rounded">MODULE_NAME</code>,{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">INPUT_EXTENSIONS</code>, and a{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">run()</code> function.
                      </>
                    ),
                  },
                  {
                    n: 2,
                    title: 'Return structured hits',
                    body: (
                      <>
                        Each hit dict needs at minimum{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">level</code>,{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">rule_title</code>, and{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">timestamp</code>.
                        Optional:{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">event_id</code>,{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">computer</code>,{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">channel</code>,{' '}
                        <code className="text-brand-accent bg-brand-accentlight px-1 rounded">details_raw</code>.
                      </>
                    ),
                  },
                  {
                    n: 3,
                    title: 'Reload & run',
                    body: (
                      <>
                        Save the file in Studio. The processor picks up the module automatically.
                        Open a case → Modules — your module appears in the list.
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
                <button
                  onClick={() => navigate('/studio')}
                  className="btn-primary text-xs"
                >
                  <Code2 size={12} /> Open Studio
                </button>
                <button
                  onClick={() => navigate('/docs')}
                  className="btn-outline text-xs"
                >
                  <BookOpen size={12} /> Read the Docs
                </button>
                <span className="text-xs text-gray-500 ml-auto flex items-center gap-1">
                  <ArrowRight size={11} /> Save as <code className="font-mono">modules/*_module.py</code>
                </span>
              </div>
            </div>
          </section>
        </>
      )}
    </PageShell>
  )
}
