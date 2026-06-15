import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Plus, Trash2, ChevronDown, ChevronUp, Pencil, Check, X,
  AlertTriangle, Loader2, Search, Play, CheckCircle, Clock, RefreshCw,
  ExternalLink, Filter, ShieldAlert, Building2, Bot, Sparkles, FileCode, Bell,
} from 'lucide-react'
import { api } from '../api/client'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { useKeyboardShortcuts } from '../hooks/useKeyboardShortcuts'
import { useCompanies } from './UserManagement'
import RuleDrawer, {
  CategoryBadge, SigmaLevelBadge,
  CATEGORY_ORDER, CATEGORY_STYLES,
} from '../components/RuleDrawer'
import AlertRuleFilterBar from '../components/AlertRuleFilterBar'
import { filterAlertRules, ruleProvenance } from '../lib/alertRuleFilters'

// ── AI Analysis panel (shown inside RunOnCaseModal after a firing result) ──────
function AiAnalysisPanel({ rule, result }) {
  const [loading,  setLoading]  = useState(false)
  const [analysis, setAnalysis] = useState(null)
  const [error,    setError]    = useState('')

  async function analyze() {
    setLoading(true)
    setError('')
    setAnalysis(null)
    try {
      const sampleEvents = result.match?.sample_events || []
      const res = await api.alertRules.analyzeResult({
        rule_name:    rule.name,
        rule_query:   rule.query,
        match_count:  result.match?.match_count || 0,
        sample_events: sampleEvents,
      })
      setAnalysis(res.analysis || res.message || JSON.stringify(res))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="border border-indigo-200 rounded-lg bg-indigo-50 p-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-700">
          <Bot size={13} /> AI Analysis
        </div>
        {!analysis && (
          <button onClick={analyze} disabled={loading} className="btn-primary text-xs py-1 px-2.5">
            {loading ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
            {loading ? 'Analyzing…' : 'Analyze with AI'}
          </button>
        )}
      </div>
      {error && <p className="text-xs text-red-600">{error}</p>}
      {analysis && (
        <div className="text-xs text-indigo-900 leading-relaxed whitespace-pre-wrap bg-white border border-indigo-100 rounded-lg p-3 max-h-64 overflow-y-auto">
          {analysis}
        </div>
      )}
    </div>
  )
}

// ── Run on Case modal ─────────────────────────────────────────────────────────
function RunOnCaseModal({ rule, cases, onClose }) {
  const navigate = useNavigate()
  const [running, setRunning]     = useState(false)
  const [result, setResult]       = useState(null)
  const [error, setError]         = useState('')
  const [selectedCase, setSelectedCase] = useState('')

  async function run() {
    if (!selectedCase) return
    setRunning(true)
    setResult(null)
    setError('')
    try {
      const r = await api.alertRules.runSingleRule(selectedCase, rule.id)
      setResult(r)
    } catch (err) {
      setError(err.message)
    } finally {
      setRunning(false)
    }
  }

  function goToSearch(q) {
    onClose()
    navigate(`/cases/${selectedCase}`, { state: { pivotQuery: q } })
  }

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl w-full max-w-md shadow-2xl flex flex-col"
        style={{ maxHeight: '90vh' }}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 dark:border-gray-700 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Play size={15} className="text-brand-accent" />
            <span className="font-semibold text-brand-text text-sm">Run Rule on Case</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1"><X size={14} /></button>
        </div>

        <div className="p-5 space-y-4 overflow-y-auto flex-1">
          {/* Rule summary */}
          <div className="bg-gray-50 rounded-lg p-3 border border-gray-200">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <p className="text-xs font-semibold text-brand-text">{rule.name}</p>
              {rule.category && <CategoryBadge category={rule.category} />}
              {rule.sigma_level && <SigmaLevelBadge level={rule.sigma_level} />}
            </div>
            <code className="block text-xs text-gray-500 font-mono break-all">{rule.query}</code>
          </div>

          {/* Case picker */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Target Case</label>
            <select className="input" value={selectedCase} onChange={e => setSelectedCase(e.target.value)}>
              <option value="">Select a case…</option>
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.name}</option>
              ))}
            </select>
          </div>

          <button onClick={run} disabled={!selectedCase || running} className="btn-primary w-full justify-center">
            {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />}
            {running ? 'Running…' : 'Run Rule'}
          </button>

          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">{error}</p>
          )}

          {result && (
            <div className={`rounded-lg border p-3 space-y-2 ${result.fired ? 'border-red-200 bg-red-50' : 'border-green-200 bg-green-50'}`}>
              {result.fired ? (
                <>
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-semibold text-red-700 flex items-center gap-1">
                      <AlertTriangle size={12} /> {result.match.match_count.toLocaleString()} matches found
                    </p>
                    <button
                      onClick={() => goToSearch(rule.query)}
                      className="flex items-center gap-1 text-xs text-brand-accent hover:text-brand-accenthover font-medium"
                    >
                      View all in Search <ExternalLink size={11} />
                    </button>
                  </div>
                  {result.match.sample_events?.map((ev, i) => (
                    <button
                      key={i}
                      onClick={() => ev.fo_id ? goToSearch(`fo_id:${ev.fo_id}`) : goToSearch(rule.query)}
                      className="w-full text-left bg-white hover:bg-blue-50 rounded border border-red-100 hover:border-blue-300 p-2 transition-colors group"
                      title="Click to view this event in Search"
                    >
                      <div className="flex items-center justify-between gap-1">
                        <p className="text-[10px] text-gray-500 font-mono flex items-center gap-1">
                          <Clock size={9} />{ev.timestamp || '—'}
                        </p>
                        <ExternalLink size={9} className="text-gray-500 group-hover:text-blue-400 flex-shrink-0 transition-colors" />
                      </div>
                      <p className="text-xs text-gray-700 mt-0.5">{ev.message || '—'}</p>
                    </button>
                  ))}
                  {/* AI Analysis (only shown after a firing result) */}
                  <AiAnalysisPanel rule={rule} result={result} />
                </>
              ) : (
                <p className="text-xs text-green-700 flex items-center gap-1">
                  <CheckCircle size={12} /> No matches — rule did not fire
                </p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Library rule card ─────────────────────────────────────────────────────────
function LibraryRuleCard({ rule, cases, onDelete, onUpdated, onEdit }) {
  const [expanded, setExpanded]     = useState(false)
  const [showRun,  setShowRun]      = useState(false)
  const [editCo,   setEditCo]       = useState(false)
  const [coSel,    setCoSel]        = useState(rule.companies || [])
  const [coSearch, setCoSearch]     = useState('')
  const [coSaving, setCoSaving]     = useState(false)
  const companyList                 = useCompanies()

  async function saveCompanies() {
    setCoSaving(true)
    try {
      const updated = await api.alertRules.updateLibraryRule(rule.id, { companies: coSel })
      onUpdated?.(updated)
      setEditCo(false)
    } catch (err) {
      alert('Failed to save: ' + err.message)
    } finally {
      setCoSaving(false)
    }
  }

  return (
    <>
      {showRun && <RunOnCaseModal rule={rule} cases={cases} onClose={() => setShowRun(false)} />}
      <div className="card overflow-hidden">
        <div className="flex items-center gap-3 px-4 py-3">
          <AlertTriangle size={15} className="text-amber-500 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-medium text-brand-text text-sm">{rule.name}</span>
              {rule.category    && <CategoryBadge category={rule.category} />}
              {rule.sigma_level && <SigmaLevelBadge level={rule.sigma_level} />}
              {rule.artifact_type && (
                <span className={`badge badge-${rule.artifact_type}`}>{rule.artifact_type}</span>
              )}
              <span className="text-xs text-gray-500">threshold ≥{rule.threshold}</span>
              {(() => {
                const isSigma  = rule.rule_type === 'sigma' || (!rule.rule_type && !!rule.sigma_yaml)
                const isCustom = rule.rule_type === 'custom'
                if (isSigma) return (
                  <span className="badge bg-indigo-50 text-indigo-600 border-indigo-200 text-[10px]">
                    <FileCode size={9} className="mr-0.5" /> Sigma
                  </span>
                )
                if (isCustom) return (
                  <span className="badge bg-emerald-50 text-emerald-600 border-emerald-200 text-[10px]">
                    Custom
                  </span>
                )
                return (
                  <span className="badge bg-gray-50 text-gray-500 border-gray-200 text-[10px]">
                    Legacy
                  </span>
                )
              })()}
            </div>
            {(rule.companies || []).length > 0 && (
              <div className="flex flex-wrap gap-1 mt-0.5">
                {(rule.companies).map(c => (
                  <span key={c} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px]">
                    <Building2 size={8} className="inline mr-0.5" />{c}
                  </span>
                ))}
              </div>
            )}
            {rule.description && (
              <p className="text-xs text-gray-500 truncate">{rule.description}</p>
            )}
          </div>
          <div className="flex items-center gap-1 flex-shrink-0">
            <button
              onClick={() => setShowRun(true)}
              className="btn-ghost px-2 py-1.5 text-xs text-brand-accent hover:text-brand-accenthover"
              title="Run on a case"
            >
              <Play size={13} />
            </button>
            <button
              onClick={() => onEdit(rule)}
              className="btn-ghost px-2 py-1.5 text-xs"
              title="Edit rule"
            >
              <Pencil size={13} />
            </button>
            <button
              onClick={() => setExpanded(v => !v)}
              className="btn-ghost px-2 py-1.5 text-xs"
            >
              {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
            <button
              onClick={() => onDelete(rule.id)}
              className="btn-danger px-2 py-1.5"
              title="Delete rule"
            >
              <Trash2 size={13} />
            </button>
          </div>
        </div>

        {expanded && (
          <div className="border-t border-gray-100 bg-gray-50 px-4 py-3 space-y-3">
            {/* ES Query */}
            <div>
              <p className="text-xs text-gray-500 mb-1">Elasticsearch Query</p>
              <code className="block text-xs font-mono text-brand-text bg-white border border-gray-200
                               rounded px-3 py-2 break-all">
                {rule.query}
              </code>
            </div>
            {/* Sigma YAML */}
            {rule.sigma_yaml && (
              <div>
                <p className="text-xs text-gray-500 mb-1 flex items-center gap-1">
                  <FileCode size={11} /> Sigma YAML
                </p>
                <pre className="text-[11px] font-mono text-gray-700 bg-white border border-gray-200
                                 rounded px-3 py-2 overflow-x-auto max-h-48 overflow-y-auto">
                  {rule.sigma_yaml}
                </pre>
              </div>
            )}
            {/* Tags */}
            {rule.sigma_tags?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {rule.sigma_tags.map(t => (
                  <span key={t} className="badge bg-gray-100 text-gray-500 border border-gray-200 font-mono">
                    {t}
                  </span>
                ))}
              </div>
            )}
            {/* Company scope editor */}
            {companyList.length > 0 && (
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <p className="text-xs text-gray-500 flex items-center gap-1">
                    <Building2 size={11} /> Company Scope
                  </p>
                  {!editCo && (
                    <button onClick={() => { setEditCo(true); setCoSel(rule.companies || []) }}
                      className="text-[10px] text-brand-accent hover:underline">edit</button>
                  )}
                </div>
                {editCo ? (
                  <div className="space-y-1.5">
                    {companyList.length > 6 && (
                      <input className="input text-xs" placeholder="Filter…"
                        value={coSearch} onChange={e => setCoSearch(e.target.value)} />
                    )}
                    <div className="flex flex-wrap gap-2 border border-gray-200 rounded-lg px-3 py-2 max-h-28 overflow-y-auto bg-white">
                      {companyList.filter(c => c.toLowerCase().includes(coSearch.toLowerCase())).map(c => (
                        <label key={c} className="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
                          <input type="checkbox"
                            checked={coSel.includes(c)}
                            onChange={e => setCoSel(prev => e.target.checked ? [...prev, c] : prev.filter(x => x !== c))}
                            className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
                          />
                          {c}
                        </label>
                      ))}
                    </div>
                    <div className="flex gap-2">
                      <button onClick={saveCompanies} disabled={coSaving}
                        className="btn-primary text-xs py-1 px-2">
                        {coSaving ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />} Save
                      </button>
                      <button onClick={() => setEditCo(false)} className="btn-ghost text-xs py-1 px-2">Cancel</button>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-gray-500 italic">
                    {(rule.companies || []).length === 0 ? 'Platform-wide (all companies)' : (rule.companies).join(', ')}
                  </p>
                )}
              </div>
            )}
            {rule.created_at && (
              <p className="text-xs text-gray-500">
                Added {new Date(rule.created_at).toLocaleDateString()}
              </p>
            )}
          </div>
        )}
      </div>
    </>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function AlertLibrary() {
  const [rules, setRules]     = useState([])
  const [cases, setCases]     = useState([])
  const [loading, setLoading] = useState(true)
  const [seeding, setSeeding]   = useState(false)
  const [seedMsg, setSeedMsg]   = useState(null)
  const [drawerRule,    setDrawerRule]    = useState(null)   // null=closed, false=create, obj=edit
  const [search, setSearch]             = useState('')

  // Standalone Sigma validator
  const [showValidator, setShowValidator]     = useState(false)
  const [validatorYaml, setValidatorYaml]     = useState('')
  const [validating, setValidating]           = useState(false)
  const [validatorResult, setValidatorResult] = useState(null)  // {ok, parsed} | {ok, msg}

  async function runSigmaValidate() {
    if (!validatorYaml.trim()) return
    setValidating(true)
    setValidatorResult(null)
    try {
      const r = await api.alertRules.parseSigma({ yaml: validatorYaml })
      setValidatorResult({ ok: true, parsed: r })
    } catch (err) {
      setValidatorResult({ ok: false, msg: err.message })
    } finally {
      setValidating(false)
    }
  }
  const [artifactFilter, setArtifactFilter] = useState('all')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [provenanceFilter, setProvenanceFilter] = useState('custom')
  const searchRef = useRef(null)

  useKeyboardShortcuts([
    { key: '/', handler: () => searchRef.current?.focus() },
  ])

  const filteredRules = useMemo(
    () => filterAlertRules(rules, { search, provenance: provenanceFilter, category: categoryFilter, artifact: artifactFilter }),
    [rules, search, provenanceFilter, categoryFilter, artifactFilter]
  )

  // Group rules by MITRE category, preserving CATEGORY_ORDER then "Other".
  function groupByCategory(list) {
    const groups = new Map()
    for (const cat of CATEGORY_ORDER) {
      const items = list.filter(r => (r.category || 'Other') === cat)
      if (items.length > 0) groups.set(cat, items)
    }
    const known = new Set(CATEGORY_ORDER)
    const uncategorized = list.filter(r => !known.has(r.category || 'Other'))
    if (uncategorized.length > 0) {
      groups.set('Other', [...(groups.get('Other') || []), ...uncategorized])
    }
    return groups
  }

  // Sigma rules are community-imported noise — fold them into a collapsed
  // section so custom/legacy rules stay front-and-center. They still render
  // grouped, just behind one click (open by default if the user explicitly
  // filtered to Sigma).
  const primaryRules = useMemo(() => filteredRules.filter(r => ruleProvenance(r) !== 'sigma'), [filteredRules])
  const sigmaRules   = useMemo(() => filteredRules.filter(r => ruleProvenance(r) === 'sigma'), [filteredRules])
  const groupedRules      = useMemo(() => groupByCategory(primaryRules), [primaryRules])
  const groupedSigmaRules = useMemo(() => groupByCategory(sigmaRules),   [sigmaRules])

  const hasFilters = !!(search || artifactFilter !== 'all' || categoryFilter !== 'all' || provenanceFilter !== 'custom')

  const loadRules = useCallback(() => {
    api.alertRules.listLibrary()
      .then(r => setRules(r.rules || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    loadRules()
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})
  }, [loadRules])

  async function seedDefaults(replace = false) {
    setSeeding(true)
    setSeedMsg(null)
    try {
      const r = await api.alertRules.seedLibrary(replace)
      setSeedMsg(r)
      loadRules()
      setTimeout(() => setSeedMsg(null), 4000)
    } catch (err) {
      console.error(err)
    } finally {
      setSeeding(false)
    }
  }

  function handleUpdated(updated) {
    setRules(prev => prev.map(r => r.id === updated.id ? updated : r))
  }

  async function deleteRule(id) {
    if (!confirm('Delete this rule?')) return
    try {
      await api.alertRules.deleteLibraryRule(id)
      setRules(prev => prev.filter(r => r.id !== id))
    } catch (err) {
      console.error(err)
    }
  }

  function clearFilters() {
    setSearch('')
    setArtifactFilter('all')
    setCategoryFilter('all')
    setProvenanceFilter('custom')
  }

  return (
    <PageShell>
      <PageHeader
        title="Detection Rules"
        icon={Bell}
        subtitle="Sigma-based detection rules. Run on any case, or use 'Run Alerts' on a case timeline to fire all rules."
      />


      {/* Library section */}
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-3">
          <Search size={14} className="text-gray-500" />
          <h2 className="font-semibold text-brand-text">Library</h2>
          {!loading && (
            <span className="badge-pill bg-gray-100 text-gray-600">{rules.length}</span>
          )}
          <div className="ml-auto flex items-center gap-2">
            {seedMsg && (
              <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-3 py-1 flex items-center gap-1">
                <CheckCircle size={11} />
                {seedMsg.added > 0
                  ? `${seedMsg.added} rule${seedMsg.added !== 1 ? 's' : ''} added (${seedMsg.total} total)`
                  : 'Already up to date'}
              </span>
            )}
            <button
              onClick={() => setDrawerRule(false)}
              className="btn-primary text-xs"
            >
              <Plus size={13} /> New Rule
            </button>
            <button
              onClick={() => { setShowValidator(v => !v); setValidatorResult(null) }}
              className={`btn-ghost text-xs ${showValidator ? 'text-brand-accent' : ''}`}
            >
              <Check size={13} /> Validate
            </button>
            <button
              onClick={() => seedDefaults(false)}
              disabled={seeding}
              className="btn-outline text-xs"
              title="Append any built-in defaults not already in the library"
            >
              {seeding ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
              Load Defaults
            </button>
          </div>
        </div>

        {/* ── Sigma YAML validator ──────────────────────────────────────── */}
        {showValidator && (
          <div className="card p-4 mb-4 border border-brand-accent/20 bg-brand-soft/30">
            <p className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1.5">
              <Check size={12} className="text-brand-accent" /> Sigma YAML Validator
            </p>
            <textarea
              value={validatorYaml}
              onChange={e => { setValidatorYaml(e.target.value); setValidatorResult(null) }}
              placeholder={`title: Example Rule\nstatus: experimental\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    selection:\n        CommandLine|contains: 'suspicious'\n    condition: selection`}
              spellCheck={false}
              className="w-full font-mono text-xs bg-gray-950 text-green-400 rounded-lg p-3 h-40 resize-none outline-none focus:ring-1 focus:ring-brand-accent/40 border border-gray-200 mb-2"
            />
            <div className="flex items-start gap-3 flex-wrap">
              <button
                onClick={runSigmaValidate}
                disabled={validating || !validatorYaml.trim()}
                className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50 flex-shrink-0"
              >
                {validating ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />}
                {validating ? 'Parsing…' : 'Validate'}
              </button>
              {validatorResult && (
                validatorResult.ok ? (
                  <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2 space-y-0.5">
                    <p className="flex items-center gap-1 font-semibold"><Check size={11} /> Valid Sigma rule</p>
                    {validatorResult.parsed?.name && <p className="text-gray-600">Name: <span className="font-medium">{validatorResult.parsed.name}</span></p>}
                    {validatorResult.parsed?.query && <code className="block text-[10px] text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded mt-1">{validatorResult.parsed.query}</code>}
                  </div>
                ) : (
                  <p className="text-xs text-red-600 flex items-center gap-1.5 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
                    <AlertTriangle size={11} /> {validatorResult.msg}
                  </p>
                )
              )}
            </div>
          </div>
        )}

        {/* Rule drawer (create + edit) */}
        {drawerRule !== null && (
          <RuleDrawer
            rule={drawerRule || null}
            onClose={() => setDrawerRule(null)}
            onSaved={result => {
              if (drawerRule) {
                // edit — result is a single updated rule
                setRules(prev => prev.map(r => r.id === result.id ? result : r))
              } else {
                // create — result is an array (importSigma) or single object
                const arr = Array.isArray(result) ? result : [result]
                setRules(prev => [...prev, ...arr])
              }
            }}
          />
        )}

        {/* Filter bar */}
        {!loading && rules.length > 0 && (
          <div className="mb-3">
            <AlertRuleFilterBar
              rules={rules}
              search={search}           onSearchChange={setSearch}
              provenance={provenanceFilter} onProvenanceChange={setProvenanceFilter}
              category={categoryFilter}     onCategoryChange={setCategoryFilter}
              artifact={artifactFilter}     onArtifactChange={setArtifactFilter}
              onClear={clearFilters}
              searchRef={searchRef}
            />
          </div>
        )}

        {/* Rule list */}
        {loading ? (
          <div className="space-y-2">
            {[1, 2, 3].map(i => <div key={i} className="skeleton h-14 w-full" />)}
          </div>
        ) : rules.length === 0 ? (
          <div className="card px-4 py-6 flex items-center gap-4">
            <span className="text-sm text-gray-400">No rules in library.</span>
            <button onClick={() => seedDefaults(false)} disabled={seeding} className="btn-outline text-xs">
              {seeding ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
              Load Default Rules
            </button>
          </div>
        ) : filteredRules.length === 0 ? (
          <div className="card px-4 py-6 flex items-center gap-4">
            <span className="text-sm text-gray-400">No rules match the current filters.</span>
            <button onClick={clearFilters} className="btn-ghost text-xs">
              <X size={12} /> Clear filters
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {[...groupedRules.entries()].map(([cat, items]) => (
              <div key={cat}>
                <div className="flex items-center gap-2 mb-2">
                  <CategoryBadge category={cat} />
                  <span className="text-xs text-gray-500">{items.length}</span>
                </div>
                <div className="space-y-2">
                  {items.map(rule => (
                    <LibraryRuleCard
                      key={rule.id}
                      rule={rule}
                      cases={cases}
                      onDelete={deleteRule}
                      onUpdated={handleUpdated}
                      onEdit={r => setDrawerRule(r)}
                    />
                  ))}
                </div>
              </div>
            ))}

            {/* Sigma rules — community detections, folded away by default */}
            {sigmaRules.length > 0 && (
              <details open={provenanceFilter === 'sigma'} className="border border-gray-200 rounded-xl overflow-hidden">
                <summary className="cursor-pointer select-none px-4 py-3 bg-gray-50 hover:bg-gray-100 transition-colors flex items-center gap-2 text-sm">
                  <ChevronDown size={14} className="text-gray-400" />
                  <span className="font-semibold text-gray-600">Sigma rules</span>
                  <span className="badge-pill bg-gray-100 text-gray-500">{sigmaRules.length}</span>
                  <span className="text-xs text-gray-400 ml-1">community detections — click to expand</span>
                </summary>
                <div className="px-4 py-4 space-y-4 border-t border-gray-100">
                  {[...groupedSigmaRules.entries()].map(([cat, items]) => (
                    <div key={cat}>
                      <div className="flex items-center gap-2 mb-2">
                        <CategoryBadge category={cat} />
                        <span className="text-xs text-gray-500">{items.length}</span>
                      </div>
                      <div className="space-y-2">
                        {items.map(rule => (
                          <LibraryRuleCard
                            key={rule.id}
                            rule={rule}
                            cases={cases}
                            onDelete={deleteRule}
                            onUpdated={handleUpdated}
                            onEdit={r => setDrawerRule(r)}
                          />
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            )}
          </div>
        )}
      </div>
    </PageShell>
  )
}
