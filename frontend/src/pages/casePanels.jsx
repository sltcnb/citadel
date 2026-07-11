/**
 * Case panel registry — the render half of the capability contract.
 *
 * caseCapabilities.jsx declares WHAT each tool is and WHEN it's advertised;
 * this file declares HOW each capability id renders once opened. CaseTimeline
 * consumes both generically, so adding a case tool is exactly two entries:
 * one in CASE_CAPABILITIES, one in CASE_PANELS — no page wiring.
 *
 * Every renderer receives the same context:
 *   caseId     current case id
 *   close()    close this panel (clears its persisted open state)
 *   pivot(q)   push a query to the timeline and close this panel
 *   navigate   react-router navigate (for cross-page pivots)
 */
import { lazy } from 'react'
import { X, FileText, Crosshair, Bell } from 'lucide-react'
import PanelHelp from '../components/shared/PanelHelp'
import { ResizableDrawer } from '../components/shared/resizableDrawer'

// Heavy case sub-panels are lazy-loaded so they land in their own chunks and
// don't weigh down the initial CaseTimeline paint — they only load when the
// analyst actually opens the corresponding drawer. A Suspense boundary at the
// CaseTimeline render site backs these.
const AlertRules       = lazy(() => import('./AlertRules'))
const CaseNotes        = lazy(() => import('./CaseNotes'))
const IocPanel         = lazy(() => import('../components/IocPanel'))
const TemplatesPanel   = lazy(() => import('../components/case/TemplatesPanel'))
const ReportPanel      = lazy(() => import('../components/case/ReportPanel'))
const AnomalyPanel     = lazy(() => import('../components/shared/AnomalyPanel'))
const ProcessTreePanel = lazy(() => import('../components/shared/ProcessTreePanel'))
const MitrePanel       = lazy(() => import('../components/shared/MitrePanel'))
const BaselinePanel    = lazy(() => import('../components/shared/BaselinePanel'))
const EntityGraphPanel = lazy(() => import('../components/shared/EntityGraphPanel'))
const KillChainPanel   = lazy(() => import('../components/shared/KillChainPanel'))
const EvidencePanel    = lazy(() => import('../components/shared/EvidencePanel'))
const CoPilotPanel     = lazy(() => import('../components/shared/CoPilotPanel'))

function NotesDrawer({ caseId, close }) {
  return (
    <ResizableDrawer slug="notes" defaultWidth={560} onClose={close}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <FileText size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Investigation Report</span>
          </div>
          <button onClick={close} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>
        <div className="px-4 pt-3 flex-shrink-0">
          <PanelHelp
            title="Notes"
            use="Free-form, autosaved case notes and the working investigation write-up."
            when="Throughout the case — capture hypotheses, timelines and conclusions as you go; feeds the final report."
            tip="Markdown is supported. Notes are pulled into the generated case report."
          />
        </div>
        <div className="flex-1 min-h-0 overflow-hidden">
          <CaseNotes caseId={caseId} />
        </div>
    </ResizableDrawer>
  )
}

function IocsDrawer({ caseId, close, pivot }) {
  return (
    <ResizableDrawer slug="iocs" defaultWidth={480} onClose={close}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Crosshair size={16} className="text-red-500" />
            <span className="font-semibold text-brand-text">Observed IOCs</span>
          </div>
          <button onClick={close} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>
        <div className="px-4 pt-3 flex-shrink-0">
          <PanelHelp
            title="Observed IOCs"
            use="Indicators (IPs, domains, hashes, users…) extracted from this case, cross-checked against the threat-intel watchlist."
            when="To review what's notable and pivot the timeline to any indicator's occurrences."
            data={['Ingested events containing network / hash / user fields']}
            tip="Click an IOC to search the timeline for every event mentioning it."
          />
        </div>
        <div className="flex-1 overflow-hidden">
          <IocPanel caseId={caseId} onSearch={pivot} />
        </div>
    </ResizableDrawer>
  )
}

function RulesDrawer({ caseId, close, navigate }) {
  return (
    <ResizableDrawer slug="alertRules" defaultWidth={760} onClose={close} className="overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Bell size={15} className="text-yellow-500" />
            <span className="font-semibold text-brand-text text-sm">Detection Rules</span>
          </div>
          <button onClick={close} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>
        <div className="px-4 pt-3 flex-shrink-0">
          <PanelHelp
            title="Detection Rules"
            use="Runs the Sigma / EQL detection-rule library against this case and lists what matched."
            when="Early in triage — to surface known-bad patterns before manual timeline review."
            data={['Ingested events (EVTX, Sysmon, etc.) for rules to match against']}
            tip="Click a match to pivot the timeline to the events that fired it."
          />
        </div>
        <AlertRules
          caseId={caseId}
          onSearchQuery={q => {
            close()
            navigate(`/cases/${caseId}`, { state: { pivotQuery: q } })
          }}
        />
    </ResizableDrawer>
  )
}

export const CASE_PANELS = {
  rules:     ctx => <RulesDrawer {...ctx} />,
  anomaly:   ({ caseId, close, pivot }) => <AnomalyPanel caseId={caseId} onClose={close} onPivot={pivot} />,
  baseline:  ({ caseId, close, pivot }) => <BaselinePanel caseId={caseId} onClose={close} onPivot={pivot} />,
  mitre:     ({ caseId, close, pivot }) => <MitrePanel caseId={caseId} onClose={close} onPivot={pivot} />,
  iocs:      ctx => <IocsDrawer {...ctx} />,
  ptree:     ({ caseId, close, pivot }) => <ProcessTreePanel caseId={caseId} onClose={close} onPivot={pivot} />,
  graph:     ({ caseId, close, pivot }) => <EntityGraphPanel caseId={caseId} onClose={close} onPivot={pivot} />,
  killchain: ({ caseId, close, pivot }) => <KillChainPanel caseId={caseId} onClose={close} onPivot={pivot} />,
  copilot:   ({ caseId, close, pivot }) => <CoPilotPanel caseId={caseId} onClose={close} onPivot={pivot} />,
  notes:     ctx => <NotesDrawer {...ctx} />,
  templates: ({ caseId, close }) => <TemplatesPanel caseId={caseId} onClose={close} />,
  report:    ({ caseId, close }) => <ReportPanel caseId={caseId} onClose={close} />,
  evidence:  ({ caseId, close }) => <EvidencePanel caseId={caseId} onClose={close} />,
}
