import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import {
  Boxes, PackageOpen, Split, Languages, Replace, Stamp,
  Hammer, Sparkles, Bot, FileText, ArrowRight, ExternalLink,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'

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
    surfaces: [{ label: 'Ingesters', to: '/ingesters' }],
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
    surfaces: [{ label: 'Case Timeline', to: '/' }],
    signal: 'augur',
  },
  {
    key: 'pilot', name: 'Pilot', icon: Bot, stage: 'Assist',
    role: 'Investigation assistant',
    blurb: 'Optional LLM assistant: summarizes detections, drafts rules, and answers questions over case context. Configured in Settings.',
    surfaces: [{ label: 'Settings', to: '/settings' }],
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

  useEffect(() => {
    api.logs.services().then(r => setServices(new Set((r.services || []).map(s => s.service)))).catch(() => {})
    api.plugins.list().then(r => setBabelCount((r.plugins || []).length)).catch(() => {})
    api.modules.list().then(r => setAnvilCount((r.modules || r || []).length ?? null)).catch(() => {})
  }, [])

  const ctx = { services, babelCount, anvilCount }

  return (
    <PageShell>
      <PageHeader
        title="Suite"
        icon={Boxes}
        subtitle="The independent tools that make up Citadel, and where each surfaces in the platform"
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
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        )
      })}
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
