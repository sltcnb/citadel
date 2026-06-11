import { useState, useEffect, useMemo, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Boxes, PackageOpen, Split, Languages, Replace, Stamp,
  Hammer, Sparkles, Bot, FileText, ArrowRight, ExternalLink, X, ChevronRight,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
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

// Pipeline order → groups the cards left-to-right by where work flows. The
// platform's pipeline definition; each tool declares which stage it's in.
const STAGES = ['Collect', 'Ingest', 'Parse', 'Normalize', 'Detect', 'Analyze', 'Insight', 'Assist', 'Report']

// Icon NAME → component. The only frontend-side mapping (you can't ship React
// components in YAML); WHICH icon a tool uses is declared in its manifest.
const ICONS = {
  PackageOpen, Split, Languages, Replace, Stamp, Hammer, Sparkles, Bot, FileText, Boxes,
}
const iconFor = (name) => ICONS[name] || Boxes

// Build the Suite tool list entirely from the fetched capability manifests —
// no hardcoded per-tool registry. icon/stage/role/blurb/surfaces all come from
// each tool's capabilities.yaml.
function toolsFromManifests(manifests) {
  return Object.values(manifests)
    .map(m => ({
      key: m.tool,
      name: m.tool.charAt(0).toUpperCase() + m.tool.slice(1),
      icon: iconFor(m.icon),
      stage: m.stage || '',
      role: m.role || m.kind || '',
      blurb: m.description || '',
      surfaces: m.surfaces || [],
    }))
}

// Lightweight live status — honest: only tools with a real backend signal show one.
function deriveStatus(tool, { services, babelCount, anvilCount }) {
  if (tool.key === 'babel') {
    return babelCount != null ? { tone: 'active', text: `${babelCount} parser${babelCount === 1 ? '' : 's'}` } : null
  }
  if (tool.key === 'anvil') {
    return anvilCount != null ? { tone: 'active', text: `${anvilCount} module${anvilCount === 1 ? '' : 's'}` } : null
  }
  if (services.has(tool.key)) return { tone: 'active', text: 'reporting' }
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
  const [selected, setSelected]   = useState(null) // tool key whose details are open
  const [platform, setPlatform]   = useState(null)

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
  const allTools = useMemo(() => toolsFromManifests(manifests), [manifests])
  // Ordered by pipeline stage so the single grid still reads left→right by flow.
  const orderedTools = useMemo(() => {
    const rank = s => { const i = STAGES.indexOf(s); return i === -1 ? 999 : i }
    return [...allTools].sort((a, b) => rank(a.stage) - rank(b.stage) || a.name.localeCompare(b.name))
  }, [allTools])
  const selManifest = selected ? manifests[selected] : null
  const panelRef = useRef(null)

  // Panel renders below the stage grid — scroll to it when a tool is opened,
  // otherwise clicking "Capabilities" looks like it does nothing.
  useEffect(() => {
    if (selected && panelRef.current) {
      panelRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [selected])

  function openTool(key) {
    if (selected === key) { setSelected(null); return }  // toggle
    setSelected(key)
    const m = manifests[key]
    setPlatform(m && m.platforms && m.platforms.length > 1 ? m.platforms[0] : null)
  }

  return (
    <PageShell>
      <PageHeader
        title="Tool Stack"
        icon={Boxes}
        subtitle="The tools that make up Citadel — what each does, where it sits in the pipeline, and which screens to use it from"
      />

      <p className="text-xs text-gray-500 mb-5 max-w-3xl">
        Citadel composes single-responsibility tools — each maintained as its own repository — into one
        investigation platform. Evidence flows left to right through the pipeline below.
      </p>

      {/* Pipeline legend — the order evidence flows through the suite */}
      <div className="flex items-center gap-1.5 flex-wrap mb-5 text-[11px] text-gray-400">
        {STAGES.filter(s => allTools.some(t => t.stage === s)).map((s, i, arr) => (
          <span key={s} className="flex items-center gap-1.5">
            <span className="font-medium text-gray-500">{s}</span>
            {i < arr.length - 1 && <ArrowRight size={11} className="text-gray-300" />}
          </span>
        ))}
      </div>

      {/* One full-width grid of every tool, ordered by pipeline stage */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {orderedTools.map(t => {
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
                    {t.stage && (
                      <span className="badge bg-gray-100 text-gray-500 border border-gray-200">{t.stage}</span>
                    )}
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
                    title="What this tool does + where to use it"
                  >
                    {selected === t.key ? 'Hide details' : 'Details ›'}
                  </button>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* ── Read-only detail panel: what the tool does + where to use it ──── */}
      {selManifest && (() => {
        const caps = (selManifest.capabilities || []).filter(
          c => !platform || (c.platforms || []).includes(platform) || (c.platforms || []).includes('any'),
        )
        const surfaces = selManifest.surfaces || []
        return (
          <div ref={panelRef} className="card p-5 mt-2 border-brand-accent/40 ring-1 ring-brand-accent/20 scroll-mt-4">
            <div className="flex items-center gap-2 mb-1">
              <Boxes size={15} className="text-brand-accent" />
              <span className="text-sm font-semibold text-brand-text capitalize">{selManifest.tool}</span>
              <span className="text-[11px] text-gray-400">v{selManifest.version} · {selManifest.kind}</span>
              <button onClick={() => setSelected(null)} className="icon-btn h-7 w-7 ml-auto" title="Close">
                <X size={14} />
              </button>
            </div>
            {selManifest.description && (
              <p className="text-xs text-gray-600 leading-relaxed mb-4 max-w-3xl">{selManifest.description}</p>
            )}

            {/* The real CTA — jump to the pages where this tool is actually used */}
            {surfaces.length > 0 && (
              <div className="mb-4">
                <p className="text-[10px] uppercase tracking-wide text-gray-400 mb-1.5">Use it in</p>
                <div className="flex gap-2 flex-wrap">
                  {surfaces.map(s => (
                    <Link key={s.label + s.to} to={s.to}
                      className="btn-outline text-xs inline-flex items-center gap-1.5">
                      {s.label} <ChevronRight size={12} />
                    </Link>
                  ))}
                </div>
              </div>
            )}

            {/* Capabilities as documentation — what it advertises, read-only */}
            {caps.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-[10px] uppercase tracking-wide text-gray-400">Advertised capabilities</p>
                  {selManifest.platforms && selManifest.platforms.length > 1 && (
                    <div className="flex gap-1 flex-wrap">
                      {selManifest.platforms.map(p => (
                        <button key={p} onClick={() => setPlatform(p)}
                          className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors ${
                            platform === p ? 'border-brand-accent bg-brand-accentlight text-brand-text' : 'border-gray-200 text-gray-500 hover:border-gray-300'
                          }`}>
                          {PLATFORM_LABEL[p] || p}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {caps.map(c => {
                    const needs = (c.inputs || []).filter(f => f.required).map(f => f.label || f.name)
                    return (
                      <div key={c.key} className="rounded-lg border border-gray-200 p-3">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-sm font-medium text-brand-text">{c.label}</span>
                          {c.output && <span className="text-[10px] text-gray-400 shrink-0">→ {c.output}</span>}
                        </div>
                        <p className="text-[11px] text-gray-500 mt-0.5">{c.description}</p>
                        {needs.length > 0 && (
                          <p className="text-[10px] text-gray-400 mt-1.5">Needs: {needs.join(', ')}</p>
                        )}
                        <div className="flex gap-1 mt-1.5 flex-wrap">
                          {(c.platforms || []).map(p => (
                            <span key={p} className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[9px]">{PLATFORM_LABEL[p] || p}</span>
                          ))}
                        </div>
                      </div>
                    )
                  })}
                </div>
                <p className="text-[11px] text-gray-400 mt-3">
                  Capabilities run inside a case from the pages above — not from here. This view is the
                  tool's advertised contract.
                </p>
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
  if (!tool) return null
  // Derive from the key — no static registry. (Bylines are tiny labels; the
  // rich per-tool data lives in the manifest, shown on the Suite page.)
  const name = tool.charAt(0).toUpperCase() + tool.slice(1)
  return (
    <Link
      to="/suite"
      title={`${name} — see the full suite`}
      className={`inline-flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-brand-accent border border-gray-200 hover:border-brand-accent rounded-full pl-1.5 pr-2 py-0.5 ${className}`}
    >
      <Boxes size={11} className="text-brand-accent" />
      <span>Powered by <span className="font-semibold">{name}</span></span>
    </Link>
  )
}
