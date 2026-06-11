import { useState, useEffect, useMemo } from 'react'
import { Boxes, Play, ChevronRight, AlertCircle, Loader2, Terminal, RefreshCw } from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import DynamicForm, { defaultsFor, missingRequired } from '../components/DynamicForm'
import { api } from '../api/client'

/*
 * Renders the suite entirely from each tool's advertised capability manifest
 * (GET /tools/capabilities). Nothing here knows what any tool does — the tool
 * declares it, this page builds the UI. Change a tool's capabilities.yaml and
 * this page changes with it, no code edit.
 */

const PLATFORM_LABEL = {
  windows: 'Windows', linux: 'Linux', macos: 'macOS',
  android: 'Android', ios: 'iOS', cloud: 'Cloud', any: 'Any',
}

export default function Capabilities() {
  const [tools, setTools] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selTool, setSelTool] = useState(null)     // tool name
  const [selCap, setSelCap] = useState(null)       // capability key
  const [platform, setPlatform] = useState(null)   // active platform filter
  const [values, setValues] = useState({})
  const [submitted, setSubmitted] = useState(null)
  const [syncing, setSyncing] = useState(false)

  function load() {
    return api.tools.capabilities()
      .then(r => {
        const list = r.tools || []
        setTools(list)
        if (list.length && !list.find(t => t.tool === selTool)) setSelTool(list[0].tool)
      })
      .catch(e => setError(e.message))
      .finally(() => setLoading(false))
  }
  useEffect(() => { load() }, []) // eslint-disable-line react-hooks/exhaustive-deps

  function resync() {
    setSyncing(true)
    api.tools.sync()
      .then(() => load())
      .catch(e => setError(e.message))
      .finally(() => setSyncing(false))
  }

  const tool = useMemo(() => tools.find(t => t.tool === selTool) || null, [tools, selTool])

  // Capabilities visible for the active platform filter.
  const visibleCaps = useMemo(() => {
    if (!tool) return []
    if (!platform) return tool.capabilities
    return tool.capabilities.filter(c => c.platforms.includes(platform) || c.platforms.includes('any'))
  }, [tool, platform])

  const cap = useMemo(() => visibleCaps.find(c => c.key === selCap) || null, [visibleCaps, selCap])

  // Reset platform + selected capability when the tool changes.
  useEffect(() => {
    if (!tool) return
    setPlatform(tool.platforms.length > 1 ? tool.platforms[0] : null)
    setSelCap(null); setSubmitted(null)
  }, [selTool]) // eslint-disable-line react-hooks/exhaustive-deps

  function openCap(c) {
    setSelCap(c.key)
    setValues(defaultsFor(c.inputs))
    setSubmitted(null)
  }

  const missing = cap ? missingRequired(cap.inputs, values) : []

  function run() {
    // Citadel assembles exactly what it hands the tool. Execution routing per
    // tool reuses each tool's existing endpoint; this is the input contract.
    setSubmitted({ tool: tool.tool, capability: cap.key, platform, inputs: values })
  }

  return (
    <PageShell>
      <PageHeader
        title="Tool Capabilities"
        icon={Boxes}
        subtitle="Every tool advertises what it can do; Citadel renders the inputs from that declaration"
        actions={
          <button onClick={resync} disabled={syncing}
            className="btn-secondary text-xs inline-flex items-center gap-1.5"
            title="Re-register tool manifests into Redis (picks up changed capabilities.yaml)">
            <RefreshCw size={14} className={syncing ? 'animate-spin' : ''} /> Re-sync
          </button>
        }
      />

      {error && (
        <div className="flex items-center gap-2 text-sm text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-3">
          <AlertCircle size={16} /> {error}
        </div>
      )}
      {loading ? (
        <div className="flex items-center gap-2 text-gray-500 py-10"><Loader2 size={16} className="animate-spin" /> Loading capabilities…</div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-[200px_1fr] gap-4">
          {/* Tool list */}
          <div className="space-y-1">
            {tools.map(t => (
              <button
                key={t.tool}
                onClick={() => setSelTool(t.tool)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm transition-colors ${
                  selTool === t.tool ? 'bg-brand-accentlight text-brand-text font-medium' : 'text-gray-600 hover:bg-gray-50'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="capitalize">{t.tool}</span>
                  <span className="text-[10px] text-gray-400">{t.capabilities.length}</span>
                </div>
                <span className="text-[10px] text-gray-400">{t.kind}</span>
              </button>
            ))}
          </div>

          {/* Tool detail */}
          {tool && (
            <div className="space-y-4">
              <div>
                <h2 className="text-sm font-semibold text-brand-text capitalize">{tool.tool} <span className="text-gray-400 font-normal">v{tool.version}</span></h2>
                <p className="text-xs text-gray-500 mt-0.5">{tool.description}</p>
                {tool.warnings && (
                  <p className="text-[10px] text-amber-600 mt-1">⚠ manifest warnings: {tool.warnings.join('; ')}</p>
                )}
              </div>

              {/* Platform filter */}
              {tool.platforms.length > 1 && (
                <div className="flex gap-1 flex-wrap">
                  {tool.platforms.map(p => (
                    <button key={p} onClick={() => { setPlatform(p); setSelCap(null) }}
                      className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                        platform === p ? 'border-brand-accent bg-brand-accentlight text-brand-text' : 'border-gray-200 text-gray-500 hover:border-gray-300'
                      }`}>
                      {PLATFORM_LABEL[p] || p}
                    </button>
                  ))}
                </div>
              )}

              {/* Capability cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {visibleCaps.map(c => (
                  <button key={c.key} onClick={() => openCap(c)}
                    className={`text-left card p-3 hover:border-brand-accent transition-colors ${selCap === c.key ? 'border-brand-accent ring-1 ring-brand-accent/30' : ''}`}>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-brand-text">{c.label}</span>
                      <ChevronRight size={13} className="text-gray-400" />
                    </div>
                    <p className="text-[11px] text-gray-500 mt-0.5">{c.description}</p>
                    <div className="flex items-center gap-1 mt-1.5 flex-wrap">
                      {c.platforms.map(p => <span key={p} className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[9px]">{PLATFORM_LABEL[p] || p}</span>)}
                    </div>
                  </button>
                ))}
              </div>

              {/* Dynamic form for the selected capability */}
              {cap && (
                <div className="card p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    <Terminal size={14} className="text-brand-accent" />
                    <span className="text-sm font-semibold text-brand-text">{cap.label}</span>
                    {cap.output && <span className="text-[10px] text-gray-400 ml-auto">→ {cap.output}</span>}
                  </div>
                  <DynamicForm fields={cap.inputs} values={values} onChange={setValues} />
                  <div className="flex items-center gap-2 pt-1">
                    <button onClick={run} disabled={missing.length > 0}
                      className="btn-primary text-xs inline-flex items-center gap-1.5 disabled:opacity-50"
                      title={missing.length ? `Required: ${missing.join(', ')}` : ''}>
                      <Play size={13} /> Run
                    </button>
                    {missing.length > 0 && <span className="text-[10px] text-amber-600">Required: {missing.join(', ')}</span>}
                  </div>

                  {submitted && (
                    <div className="border-t border-gray-100 pt-3">
                      <p className="text-[10px] uppercase tracking-wide text-gray-400 mb-1">Input Citadel hands to the tool</p>
                      <pre className="bg-gray-900 text-gray-100 rounded-lg p-3 text-[11px] overflow-x-auto">{JSON.stringify(submitted, null, 2)}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </PageShell>
  )
}
