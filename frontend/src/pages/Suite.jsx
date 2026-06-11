import { useState, useEffect, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Boxes, PackageOpen, Split, Languages, Replace, Stamp,
  Hammer, Sparkles, Bot, FileText, ArrowRight, ExternalLink, Play, Terminal, X,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import DynamicForm, { defaultsFor, missingRequired } from '../components/DynamicForm'
import { api } from '../api/client'

const PLATFORM_LABEL = {
  windows: 'Windows', linux: 'Linux', macos: 'macOS',
  android: 'Android', ios: 'iOS', cloud: 'Cloud', any: 'Any',
}

/*
 * The Citadel suite is composed of independent, single-responsibility tools —
 * each its own repository, wired together by the platform. This page makes that
 * composition visible: what each tool does, where it sits in the pipeline, and
 * which screens surface it. A small <ToolByline> (below) marks the owning tool
 * on each feature page.
 */

// Pipeline order → groups the cards left-to-right by where work flows.
const STAGES = ['Collect', 'Ingest', 'Parse', 'Normalize', 'Detect', 'Analyze', 'Insight', 'Assist', 'Report']

export const TOOLS = [
  {
    key: 'talon', name: 'Talon', icon: PackageOpen, stage: 'Collect',
    role: 'Endpoint triage collector',
    blurb: 'Captures triage packages, memory and disk images from endpoints and pushes them to object storage over gRPC + mTLS.',
    surfaces: [{ label: 'Collector', to: '/collector' }],
    signal: 'collector',
  },
  {
    key: 'sluice', name: 'Sluice', icon: Split, stage: 'Ingest',
    role: 'Intake & routing',
    blurb: 'Receives uploaded evidence, deduplicates, and routes each artifact to the right parser. The front door of the pipeline.',
    surfaces: [{ label: 'Dashboard (upload)', to: '/' }, { label: 'Ingesters', to: '/ingesters' }],
    signal: 'sluice',
  },
  {
    key: 'babel', name: 'Babel', icon: Languages, stage: 'Parse',
    role: 'Artifact parsers',
    blurb: 'Turns raw forensic artifacts (EVTX, registry, browser, $MFT, …) into structured timeline events. Extensible via plugins.',
    surfaces: [{ label: 'Ingesters', to: '/ingesters' }, { label: 'Studio', to: '/studio' }],
    signal: 'babel',
  },
  {
    key: 'rosetta', name: 'Rosetta', icon: Replace, stage: 'Normalize',
    role: 'Canonicalizer',
    blurb: 'Maps parsed events onto the canonical schema (ECS) so every artifact type shares one queryable timeline shape.',
    surfaces: [{ label: 'Case Timeline', to: '/' }],
    signal: 'rosetta',
  },
  {
    key: 'sigil', name: 'Sigil', icon: Stamp, stage: 'Detect',
    role: 'Detection engine',
    blurb: 'Evaluates alert rules (Sigma) and YARA signatures against case data to raise detections on the timeline.',
    surfaces: [{ label: 'Alert Rules', to: '/alert-rules' }, { label: 'YARA Rules', to: '/yara-rules' }],
    signal: 'sigil',
  },
  {
    key: 'anvil', name: 'Anvil', icon: Hammer, stage: 'Analyze',
    role: 'Analysis runner',
    blurb: 'Runs analysis modules over case evidence — process trees, persistence sweeps, custom analyzers. Extensible via Studio.',
    surfaces: [{ label: 'Modules', to: '/modules' }, { label: 'Studio', to: '/studio' }],
    signal: 'anvil',
  },
  {
    key: 'augur', name: 'Augur', icon: Sparkles, stage: 'Insight',
    role: 'Anomaly & insight',
    blurb: 'Surfaces statistical anomalies and notable patterns across the timeline to focus the investigator on what stands out.',
    surfaces: [{ label: 'Case Timeline', to: '/' }, { label: 'Cross-Case Search', to: '/cross-search' }],
    signal: 'augur',
  },
  {
    key: 'pilot', name: 'Pilot', icon: Bot, stage: 'Assist',
    role: 'Investigation assistant',
    blurb: 'Optional LLM assistant: summarizes detections, drafts rules, and answers questions over case context. Configured in Settings.',
    surfaces: [{ label: 'Case Timeline', to: '/' }, { label: 'Alert Rules', to: '/alert-rules' }, { label: 'Settings', to: '/settings' }],
    signal: 'pilot',
  },
  {
    key: 'scribe', name: 'Scribe', icon: FileText, stage: 'Report',
    role: 'Notes & reporting',
    blurb: 'Captures investigator notes and renders case reports and exports for handoff and archival.',
    surfaces: [{ label: 'Case Notes', to: '/' }],
    signal: 'scribe',
  },
]

// Map a tool to a lightweight live signal. Honest: only tools with a real
// backend signal show a status; the rest show their pipeline stage.
function deriveStatus(tool, { services, babelCount, anvilCount }) {
  if (tool.signal === 'babel') {
    return babelCount != null ? { tone: 'active', text: `${babelCount} parser${babelCount === 1 ? '' : 's'}` } : null
  }
  if (tool.signal === 'anvil') {
    return anvilCount != null ? { tone: 'active', text: `${anvilCount} module${anvilCount === 1 ? '' : 's'}` } : null
  }
  if (services.has(tool.signal)) return { tone: 'active', text: 'reporting' }
  return null
}

const TONE = {
  active: 'bg-green-50 text-green-700 border-green-200',
}

export default function Suite() {
  const [services, setServices] = useState(new Set())
  const [babelCount, setBabelCount] = useState(null)
  const [anvilCount, setAnvilCount] = useState(null)
  const [manifests, setManifests] = useState({})  // tool key -> manifest
  const [selected, setSelected]   = useState(null) // tool key whose capabilities are open
  const [selCap, setSelCap]       = useState(null)
  const [platform, setPlatform]   = useState(null)
  const [values, setValues]       = useState({})
  const [submitted, setSubmitted] = useState(null)

  useEffect(() => {
    api.logs.services().then(r => setServices(new Set((r.services || []).map(s => s.service)))).catch(() => {})
    api.plugins.list().then(r => setBabelCount((r.plugins || []).length)).catch(() => {})
    api.modules.list().then(r => setAnvilCount((r.modules || r || []).length ?? null)).catch(() => {})
    api.tools.capabilities()
      .then(r => setManifests(Object.fromEntries((r.tools || []).map(t => [t.tool, t]))))
      .catch(() => {})
  }, [])

  const capCounts = useMemo(
    () => Object.fromEntries(Object.entries(manifests).map(([k, m]) => [k, (m.capabilities || []).length])),
    [manifests],
  )
  const ctx = { services, babelCount, anvilCount }
  const selManifest = selected ? manifests[selected] : null

  function openTool(key) {
    setSelected(key); setSelCap(null); setSubmitted(null)
    const m = manifests[key]
    setPlatform(m && m.platforms && m.platforms.length > 1 ? m.platforms[0] : null)
  }
  function openCap(c) { setSelCap(c.key); setValues(defaultsFor(c.inputs)); setSubmitted(null) }

  return (
    <PageShell>
      <PageHeader
        title="Suite & Capabilities"
        icon={Boxes}
        subtitle="The tools that make up Citadel, where each surfaces, and what each advertises it can do — click Capabilities on a card"
      />

      <p className="text-xs text-gray-500 mb-5 max-w-3xl">
        Citadel composes single-responsibility tools — each maintained as its own repository — into one
        investigation platform. Evidence flows left to right through the pipeline below.
      </p>

      {STAGES.map(stage => {
        const tools = TOOLS.filter(t => t.stage === stage)
        if (!tools.length) return null
        return (
          <div key={stage} className="mb-6">
            <div className="flex items-center gap-2 mb-2">
              <h2 className="section-title">{stage}</h2>
              <ArrowRight size={13} className="text-gray-300" />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
              {tools.map(t => {
                const status = deriveStatus(t, ctx)
                const Icon = t.icon
                return (
                  <div key={t.key} className="card p-4 flex flex-col">
                    <div className="flex items-start gap-3">
                      <div className="w-9 h-9 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0">
                        <Icon size={16} className="text-brand-accent" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-brand-text">{t.name}</span>
                          {status && (
                            <span className={`badge border ${TONE[status.tone]} inline-flex items-center gap-1`}>
                              <span className="w-1.5 h-1.5 rounded-full bg-green-500" /> {status.text}
                            </span>
                          )}
                          {capCounts[t.key] != null && (
                            <span className="badge bg-indigo-50 text-indigo-700 border border-indigo-200">
                              {capCounts[t.key]} capabilit{capCounts[t.key] === 1 ? 'y' : 'ies'}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-500">{t.role}</p>
                      </div>
                    </div>
                    <p className="text-xs text-gray-600 mt-2 leading-relaxed flex-1">{t.blurb}</p>
                    <div className="flex items-center gap-2 mt-3 flex-wrap">
                      <span className="text-[10px] uppercase tracking-wide text-gray-400">Surfaces in</span>
                      {t.surfaces.map(s => (
                        <Link
                          key={s.label + s.to}
                          to={s.to}
                          className="badge bg-gray-100 text-gray-700 border border-gray-200 hover:border-brand-accent hover:text-brand-accent inline-flex items-center gap-1"
                        >
                          {s.label} <ExternalLink size={9} />
                        </Link>
                      ))}
                      {manifests[t.key] && (
                        <button
                          onClick={() => openTool(t.key)}
                          className={`badge border inline-flex items-center gap-1 ${
                            selected === t.key
                              ? 'bg-brand-accent text-white border-brand-accent'
                              : 'bg-indigo-50 text-indigo-700 border-indigo-200 hover:border-brand-accent'
                          }`}
                          title="Show what this tool advertises it can do"
                        >
                          Capabilities ›
                        </button>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}

      {/* ── Inline capability panel for the selected tool ─────────────────── */}
      {selManifest && (() => {
        const caps = (selManifest.capabilities || []).filter(
          c => !platform || c.platforms.includes(platform) || c.platforms.includes('any'),
        )
        const cap = caps.find(c => c.key === selCap) || null
        const missing = cap ? missingRequired(cap.inputs, values) : []
        return (
          <div className="card p-4 mt-2 border-brand-accent/40 ring-1 ring-brand-accent/20">
            <div className="flex items-center gap-2 mb-3">
              <Boxes size={15} className="text-brand-accent" />
              <span className="text-sm font-semibold text-brand-text capitalize">{selManifest.tool}</span>
              <span className="text-[11px] text-gray-400">v{selManifest.version} · {selManifest.kind}</span>
              <button onClick={() => { setSelected(null); setSelCap(null) }} className="icon-btn h-7 w-7 ml-auto" title="Close">
                <X size={14} />
              </button>
            </div>

            {selManifest.platforms.length > 1 && (
              <div className="flex gap-1 flex-wrap mb-3">
                {selManifest.platforms.map(p => (
                  <button key={p} onClick={() => { setPlatform(p); setSelCap(null) }}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      platform === p ? 'border-brand-accent bg-brand-accentlight text-brand-text' : 'border-gray-200 text-gray-500 hover:border-gray-300'
                    }`}>
                    {PLATFORM_LABEL[p] || p}
                  </button>
                ))}
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {caps.map(c => (
                <button key={c.key} onClick={() => openCap(c)}
                  className={`text-left card p-3 hover:border-brand-accent transition-colors ${selCap === c.key ? 'border-brand-accent ring-1 ring-brand-accent/30' : ''}`}>
                  <span className="text-sm font-medium text-brand-text">{c.label}</span>
                  <p className="text-[11px] text-gray-500 mt-0.5">{c.description}</p>
                  <div className="flex gap-1 mt-1.5 flex-wrap">
                    {c.platforms.map(p => <span key={p} className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[9px]">{PLATFORM_LABEL[p] || p}</span>)}
                  </div>
                </button>
              ))}
            </div>

            {cap && (
              <div className="mt-3 border-t border-gray-100 pt-3 space-y-3">
                <div className="flex items-center gap-2">
                  <Terminal size={14} className="text-brand-accent" />
                  <span className="text-sm font-semibold text-brand-text">{cap.label}</span>
                  {cap.output && <span className="text-[10px] text-gray-400 ml-auto">→ {cap.output}</span>}
                </div>
                <DynamicForm fields={cap.inputs} values={values} onChange={setValues} />
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setSubmitted({ tool: selManifest.tool, capability: cap.key, platform, inputs: values })}
                    disabled={missing.length > 0}
                    className="btn-primary text-xs inline-flex items-center gap-1.5 disabled:opacity-50"
                    title={missing.length ? `Required: ${missing.join(', ')}` : ''}>
                    <Play size={13} /> Run
                  </button>
                  {missing.length > 0 && <span className="text-[10px] text-amber-600">Required: {missing.join(', ')}</span>}
                </div>
                {submitted && (
                  <div>
                    <p className="text-[10px] uppercase tracking-wide text-gray-400 mb-1">Input Citadel hands to the tool</p>
                    <pre className="bg-gray-900 text-gray-100 rounded-lg p-3 text-[11px] overflow-x-auto">{JSON.stringify(submitted, null, 2)}</pre>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })()}
    </PageShell>
  )
}

/* ── Tool byline ──────────────────────────────────────────────────────────
 * Drop <ToolByline tool="babel" /> at the top of a feature page to mark which
 * suite tool powers it, with a link back to the Suite overview.
 */
export function ToolByline({ tool, className = '' }) {
  const t = TOOLS.find(x => x.key === tool)
  if (!t) return null
  const Icon = t.icon
  return (
    <Link
      to="/suite"
      title={`${t.role} — see the full suite`}
      className={`inline-flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-brand-accent border border-gray-200 hover:border-brand-accent rounded-full pl-1.5 pr-2 py-0.5 ${className}`}
    >
      <Icon size={11} className="text-brand-accent" />
      <span>Powered by <span className="font-semibold">{t.name}</span></span>
    </Link>
  )
}
