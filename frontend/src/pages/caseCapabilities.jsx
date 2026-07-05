/**
 * Case capability registry — the single declarative source of truth for the
 * CaseTimeline toolbar. Each capability describes WHAT a tool is and WHEN it
 * should be advertised; the page wires the actual open/close handlers by id.
 *
 * This keeps "which tools exist + their gating rules" in one auditable list
 * (instead of hard-coded JSX), so the toolbar stays agile: a capability whose
 * licence feature or required data isn't present simply doesn't render.
 *
 *   kind         'lens'  → opens an interactive analysis panel
 *                'doc'   → documentation / workflow panel
 *   requires     licence feature key that must be truthy (optional)
 *   needsEvents  hide until the case has indexed events (optional)
 */
import {
  Bell, Activity, Layers, Target, Crosshair, GitBranch, Network, Bot,
  FileText, LayoutTemplate, FileDown, Shield,
} from 'lucide-react'

export const CAPABILITY_GROUPS = [
  { key: 'detect',      label: 'Detect',      icon: <Bell size={14} /> },
  { key: 'investigate', label: 'Investigate', icon: <Crosshair size={14} /> },
  { key: 'case',        label: 'Case',        icon: <FileText size={14} /> },
]

export const CASE_CAPABILITIES = [
  // ── Detect — surface what's suspicious ──────────────────────────────────────
  { id: 'rules',     group: 'detect', kind: 'lens', requires: 'alert_rules', needsEvents: true,
    persistSlug: 'alertRules',
    label: 'Detection Rules', icon: <Bell size={13} />,
    title: 'Run the Sigma/EQL rule library against this case' },
  { id: 'anomaly',   group: 'detect', kind: 'lens', needsEvents: true,
    label: 'Anomalies', icon: <Activity size={13} />,
    title: 'Statistical z-score outliers (host × event_id × day)' },
  { id: 'baseline',  group: 'detect', kind: 'lens', needsEvents: true,
    label: 'Baseline / rare artifacts', icon: <Layers size={13} />,
    title: 'Stack a field; surface values rare across the case but present on a host' },
  { id: 'mitre',     group: 'detect', kind: 'lens', needsEvents: true,
    label: 'MITRE coverage', icon: <Target size={13} />,
    title: 'ATT&CK technique coverage for this case' },

  // ── Investigate — dig into and pivot around findings ────────────────────────
  { id: 'iocs',      group: 'investigate', kind: 'lens', needsEvents: true,
    label: 'IOCs', icon: <Crosshair size={13} />,
    title: 'Observed indicators + threat-intel matching' },
  { id: 'ptree',     group: 'investigate', kind: 'lens', needsEvents: true,
    label: 'Process Tree', icon: <GitBranch size={13} />,
    title: 'Parent→child process chains (EVTX / Sysmon / auditd)' },
  { id: 'graph',     group: 'investigate', kind: 'lens', needsEvents: true,
    label: 'Entity graph', icon: <Network size={13} />,
    title: 'Host ↔ user ↔ IP relationships (lateral movement)' },
  { id: 'killchain', group: 'investigate', kind: 'lens', needsEvents: true,
    label: 'Kill chain', icon: <Crosshair size={13} />,
    title: 'Assemble the attack story around an anchor event' },
  { id: 'copilot',   group: 'investigate', kind: 'lens',
    label: 'Co-Pilot — watch & memory', icon: <Bot size={13} />,
    title: "What's new since you last looked + cross-case IOC memory" },

  // ── Case — document, template, report, prove integrity ──────────────────────
  { id: 'notes',     group: 'case', kind: 'doc',
    label: 'Notes', icon: <FileText size={13} />,
    title: 'Free-form case notes' },
  { id: 'templates', group: 'case', kind: 'doc',
    label: 'Templates', icon: <LayoutTemplate size={13} />,
    title: 'Apply a pre-canned investigation template (ransomware / insider / phishing)' },
  { id: 'report',    group: 'case', kind: 'doc',
    label: 'Report', icon: <FileDown size={13} />,
    title: 'Generate a Markdown / HTML case report' },
  { id: 'evidence',  group: 'case', kind: 'doc',
    label: 'Evidence chain', icon: <Shield size={13} />,
    title: 'Signed chain-of-custody — verify integrity, export court-ready manifest' },
]

/**
 * One-time read of the legacy per-panel localStorage keys
 * (`fo_panel_<slug>_<caseId>`) so analysts' persisted workspaces survive the
 * move to the single `fo_panels_<caseId>` map. `persistSlug` covers the ids
 * whose historical key differed (rules → alertRules).
 */
export function readLegacyPanelState(caseId) {
  const out = {}
  for (const cap of CASE_CAPABILITIES) {
    try {
      const raw = localStorage.getItem(`fo_panel_${cap.persistSlug || cap.id}_${caseId}`)
      if (raw !== null) out[cap.id] = JSON.parse(raw) === true
    } catch { /* unreadable key — treat as closed */ }
  }
  return out
}

// Is this capability advertised for the given licence features + case state?
export function capabilityVisible(cap, { features = {}, hasEvents = false } = {}) {
  if (cap.requires && features[cap.requires] === false) return false
  if (cap.needsEvents && !hasEvents) return false
  return true
}

/**
 * Build ready-to-render toolbar groups. `wiring` maps a capability id to its
 * live `{ active, onClick }`; capabilities without wiring (or gated out) are
 * dropped, and empty groups disappear.
 */
export function buildToolbarGroups({ features, hasEvents, wiring }) {
  return CAPABILITY_GROUPS.map(group => ({
    ...group,
    items: CASE_CAPABILITIES
      .filter(cap => cap.group === group.key && capabilityVisible(cap, { features, hasEvents }) && wiring[cap.id])
      .map(cap => ({
        key: cap.id,
        label: cap.label,
        icon: cap.icon,
        title: cap.title,
        active: wiring[cap.id].active,
        onClick: wiring[cap.id].onClick,
      })),
  })).filter(group => group.items.length > 0)
}
