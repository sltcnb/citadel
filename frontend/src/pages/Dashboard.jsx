import { useEffect, useState, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  FolderOpen, Activity, Database, Plus, Clock,
  Shield, AlertTriangle, CheckCircle, Server, HardDrive, Layers,
  Zap, RefreshCw, Sparkles, Building2, Archive, DollarSign,
  Trash2, Filter, Upload, CloudDownload, CloudUpload, RotateCcw,
} from 'lucide-react'
import { api } from '../api/client'
import { computeServiceLevels, statusColor, overallLevel } from '../lib/platformHealth'
import CaseRowActions from '../components/CaseRowActions'
import S3ArchiveImportModal from '../components/S3ArchiveImportModal'
import ConfirmDialog from '../components/ConfirmDialog'
import Toast from '../components/Toast'
import { useToast } from '../hooks/useToast'

const STATUS_CONFIG = {
  active:     { label: 'Active',      dot: 'bg-green-400',  badge: 'bg-green-100 text-green-700 border-green-200' },
  archived:   { label: 'Archived',    dot: 'bg-gray-400',   badge: 'bg-gray-100 text-gray-600 border-gray-300' },
  purged:     { label: 'Purged',      dot: 'bg-orange-400', badge: 'bg-orange-100 text-orange-700 border-orange-200' },
  restoring:  { label: 'Restoring…',  dot: 'bg-blue-400 animate-pulse', badge: 'bg-blue-50 text-blue-600 border-blue-200' },
}

function caseStatus(c, restoringId) {
  if (restoringId === c.case_id) return STATUS_CONFIG.restoring
  if (c.local_purged === 'true') return STATUS_CONFIG.purged
  return STATUS_CONFIG[c.status] || STATUS_CONFIG.active
}

const ARTIFACT_BADGES = {
  evtx:      'badge-evtx',
  prefetch:  'badge-prefetch',
  mft:       'badge-mft',
  registry:  'badge-registry',
  lnk:       'badge-lnk',
  plaso:     'badge-plaso',
  hayabusa:  'badge-hayabusa',
  antivirus: 'badge-antivirus',
  login_event: 'badge-login',
}

// AI Cost card — single tile with a 24h/7d/30d toggle. Defensive against
// missing or string-typed cost fields (was crashing when backend returned
// null for 7d/30d on cases where those windows had no usage yet).
function AiCostCard({ llmUsage, loading }) {
  const [period, setPeriod] = useState('24h')
  const fields = {
    '24h': { cost: 'last24h_cost',  calls: 'last24h_calls',  tokens: 'last24h_tokens',  actual: 'last24h_actual_cost'  },
    '7d':  { cost: 'last7d_cost',   calls: 'last7d_calls',   tokens: 'last7d_tokens',   actual: 'last7d_actual_cost'   },
    '30d': { cost: 'last30d_cost',  calls: 'last30d_calls',  tokens: 'last30d_tokens',  actual: 'last30d_actual_cost'  },
  }[period] || {}
  const rawCost  = llmUsage?.[fields.cost]
  const cost     = (typeof rawCost === 'number') ? rawCost : (rawCost == null ? null : Number(rawCost))
  const calls    = Number(llmUsage?.[fields.calls] ?? 0) || 0
  const tokens   = Number(llmUsage?.[fields.tokens] ?? 0) || 0
  const isActual = llmUsage?.[fields.actual] != null
  const tps      = period === '24h' ? (llmUsage?.last24h_tps ?? null) : null

  const valueText = cost != null && !Number.isNaN(cost)
    ? (cost === 0 ? (tps != null ? `${tps} t/s` : '$0.00') : `$${cost.toFixed(4)}`)
    : calls > 0 ? '—' : '$0.00'
  const subText = cost === 0
    ? (tps != null ? 'local · inference speed' : 'local model (free)')
    : (cost != null && !Number.isNaN(cost))
      ? `${calls.toLocaleString()} calls · ${tokens.toLocaleString()} tokens · ${isActual ? 'reported by API' : 'estimated USD'}`
      : calls > 0 ? 'model pricing unknown' : 'no calls yet'

  return (
    <div className="card p-5 hover:border-gray-300 transition-colors duration-150">
      <div className="flex items-start justify-between gap-3 mb-3">
        <p className="text-[11px] text-gray-500 font-semibold uppercase tracking-wider">AI Cost</p>
        <div className="flex items-center gap-0.5 flex-shrink-0">
          {['24h','7d','30d'].map(p => (
            <button
              key={p}
              onClick={() => setPeriod(p)}
              className={`text-[10px] px-1.5 py-0.5 rounded font-semibold transition-colors ${
                period === p
                  ? 'bg-brand-accent text-white'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              {p}
            </button>
          ))}
          <DollarSign size={12} strokeWidth={2} className="text-gray-400 ml-1" />
        </div>
      </div>
      <p className="text-[30px] font-bold text-brand-text tabular-nums leading-none tracking-tight">
        {loading ? <span className="skeleton inline-block w-20 h-8 rounded" /> : valueText}
      </p>
      <p className="text-xs text-gray-500 mt-2 truncate font-medium">{subText}</p>
    </div>
  )
}

function BigStatCard({ icon: Icon, label, value, sub, loading }) {
  return (
    <div className="card p-5 hover:border-gray-300 transition-colors duration-150">
      <div className="flex items-start justify-between gap-3 mb-3">
        <p className="text-[11px] text-gray-500 font-semibold uppercase tracking-wider">{label}</p>
        <Icon size={14} strokeWidth={2} className="text-gray-400 flex-shrink-0" />
      </div>
      <p className="text-[30px] font-bold text-brand-text tabular-nums leading-none tracking-tight">
        {loading ? <span className="skeleton inline-block w-16 h-8 rounded" /> : value}
      </p>
      {sub && <p className="text-xs text-gray-500 mt-2 truncate font-medium">{sub}</p>}
    </div>
  )
}

function ServiceCard({ icon: Icon, label, level, detail }) {
  const c = statusColor(level || 'green')
  return (
    <div className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-gray-50 transition-colors">
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${c.dot}`} />
      <span className={`text-[11px] font-medium flex-1 min-w-0 ${c.text}`}>{label}</span>
      {detail && <span className={`text-[10px] truncate max-w-[7rem] ${c.sub}`}>{detail}</span>}
    </div>
  )
}

const STATUS_TABS = [
  { key: 'active',   label: 'Active' },
  { key: 'all',      label: 'All' },
  { key: 'archived', label: 'Archived' },
]

export default function Dashboard() {
  const [cases, setCases]           = useState([])
  const [loading, setLoading]       = useState(true)
  const [metrics, setMetrics]       = useState(null)
  const [ruleCount, setRuleCount]   = useState(null)
  const [lastFetch, setLastFetch]   = useState(null)
  const [llmUsage, setLlmUsage]     = useState(null)
  const [statusTab, setStatusTab]         = useState('active')
  const [companyFilter, setCompany]       = useState('all')
  const [registeredCompanies, setRegComp] = useState([])
  const [confirm, setConfirm]       = useState(null)  // {action, caseId, caseName}
  const [busy, setBusy]             = useState(false)
  const [restoringId, setRestoringId] = useState(null)
  const [importing, setImporting]   = useState(false)
  const [s3Open, setS3Open]         = useState(false)
  const [toast, showToast]          = useToast()
  const importRef                   = useRef(null)
  const navigate = useNavigate()

  function load() {
    setLoading(true)
    setLastFetch(new Date())
    Promise.all([
      api.cases.list().then(r => setCases(r.cases || [])).catch(() => {}),
      api.metrics.dashboard().then(setMetrics).catch(() => {}),
      api.alertRules.listLibrary().then(r => setRuleCount((r.rules || r).length)).catch(() => {}),
      api.llm.getUsage().then(setLlmUsage).catch(() => {}),
      api.companies.list().then(d => setRegComp(d.companies || [])).catch(() => {}),
    ]).finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function doImport(file) {
    setImporting(true)
    try {
      const r = await api.export.importArchive(file)
      showToast(`Imported "${r.case_name || 'case'}" — ${r.events_imported?.toLocaleString() ?? 0} events`)
      load()
      if (r.case_id) navigate(`/cases/${r.case_id}`)
    } catch (err) {
      showToast(err.message || 'Import failed', 'error')
    } finally {
      setImporting(false)
      if (importRef.current) importRef.current.value = ''
    }
  }

  async function doArchive(caseId) {
    setBusy(true)
    try { await api.cases.update(caseId, { status: 'archived' }); load() }
    catch { /* ignore */ }
    finally { setBusy(false); setConfirm(null) }
  }
  async function doDelete(caseId) {
    setBusy(true)
    try { await api.cases.delete(caseId); load() }
    catch { /* ignore */ }
    finally { setBusy(false); setConfirm(null) }
  }

  async function doUploadS3(caseId) {
    setBusy(true)
    try {
      const r = await api.export.uploadArchive(caseId)
      showToast(`Backed up — ${r.event_count?.toLocaleString() ?? 0} events`)
      load()
    } catch (err) { showToast(err.message || 'Upload failed', 'error') }
    finally { setBusy(false); setConfirm(null) }
  }

  async function doPurge(caseId) {
    setBusy(true)
    try {
      const r = await api.export.archivePurge(caseId)
      showToast(`Archived & purged — ${r.event_count?.toLocaleString() ?? 0} events`)
      load()
    } catch (err) { showToast(err.message || 'Purge failed', 'error') }
    finally { setBusy(false); setConfirm(null) }
  }

  async function doRestore(caseId) {
    setBusy(true)
    setRestoringId(caseId)
    setConfirm(null)
    try {
      const r = await api.export.restoreArchive(caseId)
      showToast(`Restored — ${r.events_imported?.toLocaleString() ?? 0} events`)
      load()
    } catch (err) { showToast(err.message || 'Restore failed', 'error') }
    finally { setBusy(false); setRestoringId(null) }
  }

  async function doUnarchive(caseId) {
    try {
      await api.cases.update(caseId, { status: 'active' })
      showToast('Case set back to active')
      load()
    } catch (err) { showToast(err.message || 'Unarchive failed', 'error') }
  }

  const totalEvents    = cases.reduce((s, c) => s + (c.event_count || 0), 0)
  const activeCases    = cases.filter(c => c.status === 'active').length

  const avgAgeDays     = useMemo(() => {
    const active = cases.filter(c => c.status === 'active' && c.created_at)
    if (!active.length) return null
    const now = Date.now()
    const total = active.reduce((s, c) => s + (now - new Date(c.created_at).getTime()) / 86400000, 0)
    return Math.round(total / active.length)
  }, [cases])

  const companies      = useMemo(() => ['all', ...new Set(cases.map(c => c.company).filter(Boolean))], [cases])
  const companiesCount = registeredCompanies.length
  const companiesInUse = companies.length - 1
  const activeJobs     = metrics?.cases?.active_jobs ?? 0
  const failedJobs     = metrics?.cases?.failed_jobs ?? 0
  const aiCalls        = llmUsage?.last24h_calls ?? llmUsage?.total_calls ?? 0
  const aiTokens       = llmUsage?.last24h_tokens ?? llmUsage?.total_tokens ?? 0
  const aiCost         = llmUsage?.last24h_cost ?? llmUsage?.estimated_cost_usd ?? null
  const aiCostIsActual = llmUsage?.last24h_actual_cost != null
  const aiCalls7d      = llmUsage?.last7d_calls  ?? 0
  const aiCalls30d     = llmUsage?.last30d_calls ?? 0
  const aiPrompt24h    = llmUsage?.last24h_prompt || 0
  const aiCompl24h     = llmUsage?.last24h_completion || 0
  const aiTps          = llmUsage?.last24h_tps ?? null

  const filteredCases = useMemo(() => {
    let list = cases
    if (statusTab !== 'all') list = list.filter(c => c.status === statusTab)
    if (companyFilter !== 'all') list = list.filter(c => c.company === companyFilter)
    return list
  }, [cases, statusTab, companyFilter])

  const statusCounts = useMemo(() => ({
    all:      cases.length,
    active:   cases.filter(c => c.status === 'active').length,
    archived: cases.filter(c => c.status === 'archived').length,
  }), [cases])

  const _levels  = metrics ? computeServiceLevels(metrics) : null
  const services = _levels ? [
    { icon: Database,  label: 'Elasticsearch', level: _levels.elasticsearch,
      detail: metrics.elasticsearch ? `${(metrics.elasticsearch.total_docs || 0).toLocaleString()} docs` : 'unreachable' },
    { icon: Server,    label: 'Redis',   level: _levels.redis,
      detail: metrics.redis ? `${metrics.redis.connected_clients} clients` : 'unreachable' },
    { icon: Layers,    label: 'Workers', level: _levels.workers,
      detail: metrics.celery ? `${metrics.celery.registered_workers} worker${metrics.celery.registered_workers !== 1 ? 's' : ''}, ${metrics.celery.active_tasks} active` : 'unreachable' },
    { icon: HardDrive, label: 'Storage', level: _levels.minio,
      detail: metrics.minio ? `${metrics.minio.bucket_count} buckets` : 'unreachable' },
    { icon: Zap,       label: 'API',     level: _levels.api,
      detail: metrics.api ? `${(metrics.api.error_rate_pct || 0)}% error rate` : null },
  ] : []

  const _overall = overallLevel(services)
  const allOk    = _overall === 'green'
  const hasIssue = _overall !== 'green'

  const queuedJobs = metrics?.celery?.queue_lengths
    ? Object.entries(metrics.celery.queue_lengths).filter(([, v]) => v > 0)
    : []

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-6 lg:py-8 space-y-6 lg:space-y-8 fade-in">

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-[28px] sm:text-[32px] font-bold text-brand-text tracking-tight leading-none">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-2">
            DFIR case management
            {lastFetch && (
              <span className="ml-2 text-xs text-gray-400">
                · updated {lastFetch.toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <input
            ref={importRef}
            type="file"
            accept=".citadel"
            className="hidden"
            onChange={e => { const f = e.target.files?.[0]; if (f) doImport(f) }}
          />
          <button
            className="btn-outline text-xs flex items-center gap-1.5"
            onClick={() => importRef.current?.click()}
            disabled={importing}
            title="Import a local .citadel archive as a new case"
          >
            {importing ? <RefreshCw size={13} className="animate-spin" /> : <Upload size={13} />}
            {importing ? 'Importing…' : 'Import Archive'}
          </button>
          <button
            className="btn-outline text-xs flex items-center gap-1.5"
            onClick={() => setS3Open(true)}
            title="Browse archive S3 and import a .citadel as a new case"
          >
            <CloudDownload size={13} />
            Import from S3
          </button>
          <button onClick={load} disabled={loading} className="btn-ghost text-xs">
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {/* Stats rows */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <BigStatCard icon={FolderOpen}   label="Total Cases"     value={cases.length}                loading={loading} />
        <BigStatCard icon={Activity}     label="Active Cases"    value={activeCases}                  loading={loading}
          sub={avgAgeDays != null ? `avg ${avgAgeDays}d open` : undefined} />
        <BigStatCard icon={Archive}      label="Archived Cases"  value={statusCounts.archived ?? 0}   loading={loading}
          sub={cases.length > 0 && statusCounts.archived > 0 ? `${Math.round((statusCounts.archived / cases.length) * 100)}% of total` : undefined} />
        <BigStatCard icon={Building2}    label="Companies"       value={companiesCount || '—'}        loading={loading}
          sub={companiesCount > 0 ? (companiesInUse > 0 ? `${companiesInUse} assigned to cases` : 'none assigned to cases yet') : 'no companies registered'} />
        <BigStatCard icon={Database}     label="Total Events"    value={totalEvents.toLocaleString()} loading={loading}
          sub={activeJobs > 0 ? `${activeJobs} job${activeJobs !== 1 ? 's' : ''} running` : failedJobs > 0 ? `${failedJobs} failed` : undefined} />
        <BigStatCard icon={Shield}       label="Detection Rules" value={ruleCount ?? '—'}             loading={loading} />
        <AiCostCard llmUsage={llmUsage} loading={loading} />
        <BigStatCard
          icon={Sparkles}
          label="Total AI Calls"
          value={Number(llmUsage?.total_calls ?? 0).toLocaleString()}
          loading={loading}
          sub={`${Number(llmUsage?.total_tokens ?? 0).toLocaleString()} tokens lifetime`}
        />
      </div>

      {/* Main content: cases + sidebar */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 lg:gap-8">

        {/* Cases list (spans 2/3) */}
        <div className="xl:col-span-2 space-y-4 order-2 xl:order-1">
          {/* Header + filters */}
          <div className="flex items-center gap-2 flex-wrap">
            <h2 className="text-sm font-semibold text-brand-text mr-auto">Cases</h2>

            {/* Company filter */}
            {companies.length > 1 && (
              <div className="relative">
                <Filter size={11} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
                <select
                  value={companyFilter}
                  onChange={e => setCompany(e.target.value)}
                  className="input pl-7 pr-6 text-xs appearance-none cursor-pointer h-8"
                >
                  {companies.map(c => (
                    <option key={c} value={c}>{c === 'all' ? 'All companies' : c}</option>
                  ))}
                </select>
              </div>
            )}

            {/* Status tabs */}
            <div className="flex items-center bg-white border border-gray-200 rounded-lg overflow-hidden shadow-sm">
              {STATUS_TABS.map(({ key, label }) => (
                <button key={key}
                  onClick={() => setStatusTab(key)}
                  className={`px-2.5 py-1 text-xs font-medium transition-colors border-r border-gray-100 last:border-r-0 ${
                    statusTab === key ? 'bg-brand-accent text-white' : 'text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  {label}
                  <span className={`ml-1 text-[10px] ${statusTab === key ? 'text-white/70' : 'text-gray-500'}`}>
                    {statusCounts[key]}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {loading ? (
            <div className="space-y-2">
              {[1,2,3].map(i => <div key={i} className="skeleton h-20 w-full rounded-xl" />)}
            </div>
          ) : filteredCases.length === 0 ? (
            <div className="card px-4 py-6 flex items-center gap-4">
              <span className="text-sm text-gray-500">
                {cases.length === 0 ? 'No cases yet' : 'No cases match filter'}
              </span>
              {cases.length > 0 && (
                <button className="btn-ghost text-xs" onClick={() => { setStatusTab('all'); setCompany('all') }}>
                  Clear filters
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-2">
              {filteredCases.map(c => {
                const st = caseStatus(c, restoringId)
                return (
                  <div key={c.case_id} className="card-hover p-5 group"
                    onClick={() => navigate(`/cases/${c.case_id}`)}>
                    <div className="flex items-center gap-5">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2.5 mb-2">
                          <span className={`status-dot ${st.dot}`} />
                          <h3 className="text-[15px] font-semibold text-brand-text truncate tracking-tight">{c.name}</h3>
                          {c.company && <span className="text-xs text-gray-500 font-medium px-2 py-0.5 bg-gray-100 rounded">{c.company}</span>}
                        </div>
                        <div className="flex items-center gap-4 flex-wrap text-xs text-gray-500">
                          <span className="flex items-center gap-1.5">
                            <Database size={11} strokeWidth={2} />{(c.event_count || 0).toLocaleString()} events
                          </span>
                          <span className="flex items-center gap-1.5">
                            <Clock size={11} strokeWidth={2} />{new Date(c.created_at).toLocaleDateString()}
                          </span>
                          {c.analyst && <span className="font-medium">@{c.analyst}</span>}
                        </div>
                      </div>
                      <div className="flex flex-wrap gap-1 max-w-32 justify-end">
                        {(c.artifact_types || []).slice(0, 4).map(at => (
                          <span key={at} className={`badge ${ARTIFACT_BADGES[at] || 'badge-generic'}`}>{at}</span>
                        ))}
                        {(c.artifact_types || []).length > 4 && (
                          <span className="badge badge-generic">+{(c.artifact_types || []).length - 4}</span>
                        )}
                      </div>
                      <CaseRowActions
                        c={c}
                        restoring={restoringId === c.case_id}
                        onArchive={id => doArchive(id)}
                        onUpload={id => doUploadS3(id)}
                        onPurge={(id, name) => setConfirm({ action: 'purge', caseId: id, caseName: name })}
                        onRestore={(id) => setConfirm({ action: 'restore', caseId: id, caseName: c.name })}
                        onUnarchive={id => doUnarchive(id)}
                        onDelete={(id, name) => setConfirm({ action: 'delete', caseId: id, caseName: name })}
                        onNavigate={id => navigate(`/cases/${id}`)}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right sidebar: platform health — sticky, fills viewport height */}
        <div className="flex flex-col gap-4 xl:sticky xl:top-4 xl:max-h-[calc(100vh-7rem)] xl:overflow-y-auto order-1 xl:order-2">

          {/* Platform Health */}
          <div className="card p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="section-title">Platform Health</h2>
              {services.length > 0 && (
                <span className={`flex items-center gap-1 text-[10px] font-medium ${allOk ? 'text-green-600' : 'text-amber-600'}`}>
                  {allOk
                    ? <><CheckCircle size={10} /> OK</>
                    : <><AlertTriangle size={10} /> Degraded</>
                  }
                </span>
              )}
            </div>
            {services.length === 0 ? (
              <div className="space-y-1">
                {[1,2,3,4,5].map(i => <div key={i} className="skeleton h-7 w-full rounded-lg" />)}
              </div>
            ) : (
              <div>
                {services.map(s => <ServiceCard key={s.label} {...s} />)}
              </div>
            )}
          </div>

          {/* System resources — compact 3-col grid */}
          {metrics?.system && (
            <div className="card p-4">
              <h3 className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-2">Resources</h3>
              <div className="grid grid-cols-3 gap-2">
                {[
                  { label: 'CPU',    pct: metrics.system.cpu_percent,    color: 'bg-brand-accent' },
                  { label: 'Memory', pct: metrics.system.memory_percent, color: 'bg-purple-500' },
                  { label: 'Disk',   pct: metrics.system.disk_percent,   color: 'bg-amber-500' },
                ].map(({ label, pct, color }) => (
                  <div key={label} className="flex flex-col gap-1">
                    <div className="flex justify-between items-center">
                      <span className="text-[10px] text-gray-500">{label}</span>
                      <span className={`text-[10px] font-semibold ${(pct || 0) > 90 ? 'text-red-600' : (pct || 0) > 70 ? 'text-amber-600' : 'text-brand-text'}`}>{pct ?? '--'}%</span>
                    </div>
                    <div className="h-1 bg-gray-200 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full transition-all ${(pct || 0) > 90 ? 'bg-red-500' : (pct || 0) > 70 ? 'bg-amber-500' : color}`}
                        style={{ width: `${Math.min(100, pct || 0)}%` }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* AI token breakdown (24h) */}
          {llmUsage && aiTokens > 0 && (
            <div className="card p-3 space-y-2">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <Sparkles size={11} className="text-violet-500" />
                  <h3 className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest">Tokens 24h</h3>
                </div>
                {aiCost != null && aiCost > 0 && (
                  <span className="text-[10px] font-semibold text-emerald-600">${aiCost.toFixed(4)}</span>
                )}
                {aiCost === 0 && aiTps != null && (
                  <span className="text-[10px] font-semibold text-blue-500">{aiTps} t/s</span>
                )}
              </div>
              <div className="flex justify-between text-[10px]">
                <span className="text-blue-500">In {aiPrompt24h.toLocaleString()}</span>
                <span className="text-violet-500">Out {aiCompl24h.toLocaleString()}</span>
              </div>
              <div className="h-1 bg-gray-200 rounded-full overflow-hidden flex">
                <div className="h-full bg-blue-400 rounded-l-full"
                  style={{ width: `${aiTokens > 0 ? Math.round((aiPrompt24h / aiTokens) * 100) : 0}%` }} />
                <div className="h-full bg-violet-400 rounded-r-full"
                  style={{ width: `${aiTokens > 0 ? Math.round((aiCompl24h / aiTokens) * 100) : 0}%` }} />
              </div>
            </div>
          )}

          {/* Queue backlog */}
          {queuedJobs.length > 0 && (
            <div className="card p-3 border-amber-200 bg-amber-50">
              <div className="flex items-center gap-1.5 mb-1.5">
                <AlertTriangle size={11} className="text-amber-600 flex-shrink-0" />
                <span className="text-[10px] font-semibold text-amber-700 uppercase tracking-widest">Queue Backlog</span>
              </div>
              <div className="space-y-0.5">
                {queuedJobs.map(([name, count]) => (
                  <div key={name} className="flex justify-between text-[11px]">
                    <span className="text-amber-600 font-mono truncate">{name}</span>
                    <span className="font-semibold text-amber-700 ml-2">{count}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      </div>

      {confirm && (() => {
        const ACTIONS = {
          delete: {
            title: 'Delete case',
            icon:  <Trash2 size={14} className="text-red-500" />,
            msg:   `Delete "${confirm.caseName}"? All events and files permanently removed. Cannot be undone.`,
            label: 'Delete', cls: 'btn-danger', fn: doDelete,
          },
          archive: {
            title: 'Archive case',
            icon:  <Archive size={14} className="text-amber-500" />,
            msg:   `Mark "${confirm.caseName}" as archived?`,
            label: 'Archive', cls: 'btn-outline', fn: doArchive,
          },
          upload_s3: {
            title: 'Upload to archive S3',
            icon:  <CloudUpload size={14} className="text-blue-500" />,
            msg:   `Upload "${confirm.caseName}" to the configured archive S3? Local data is kept — this creates a restorable backup.`,
            label: 'Upload', cls: 'btn-primary', fn: doUploadS3,
          },
          purge: {
            title: 'Archive + purge local data',
            icon:  <HardDrive size={14} className="text-orange-500" />,
            msg:   `Upload "${confirm.caseName}" to archive S3 then delete all local Elasticsearch indices and MinIO files? The case will not be searchable until restored.`,
            label: 'Archive & Purge', cls: 'btn-danger', fn: doPurge,
          },
          restore: {
            title: 'Restore from archive',
            icon:  <RotateCcw size={14} className="text-green-500" />,
            msg:   `Re-index "${confirm.caseName}" from archive S3? All events will be restored into Elasticsearch.`,
            label: 'Restore', cls: 'btn-primary', fn: doRestore,
          },
        }
        const cfg = ACTIONS[confirm.action]
        if (!cfg) return null
        return (
          <ConfirmDialog
            title={cfg.title} icon={cfg.icon} message={cfg.msg}
            confirmLabel={cfg.label} confirmClass={cfg.cls}
            onConfirm={() => cfg.fn(confirm.caseId)}
            onCancel={() => setConfirm(null)}
            busy={busy} maxWidth={420}
          />
        )
      })()}

      {s3Open && (
        <S3ArchiveImportModal
          onClose={() => setS3Open(false)}
          onImported={msg => { showToast(msg); load() }}
        />
      )}

      <Toast toast={toast} />
    </div>
  )
}
