import { useState, useEffect } from 'react'
import { AlertTriangle, Plus, Trash2, Play, CheckCircle, Loader2,
         ChevronDown, ChevronUp, Sparkles, Brain, RefreshCw, Clock,
         ExternalLink } from 'lucide-react'
import { api } from '../api/client'
import { severityStyle } from '../utils/severity'
import { ProvenancePills } from '../components/AlertRuleFilterBar'
import { filterAlertRules } from '../lib/alertRuleFilters'

// ── Shared AI analysis block ───────────────────────────────────────────────────

function AnalysisResult({ analysis, onReanalyze, analyzing }) {
  if (analyzing) {
    return (
      <div className="flex items-center gap-1.5 text-[10px] text-purple-500 mt-2">
        <Loader2 size={10} className="animate-spin" /> Analyzing…
      </div>
    )
  }
  if (!analysis) return null
  return (
    <div className="mt-2 p-2 rounded bg-purple-50 border border-purple-200 space-y-1.5">
      <div className="flex items-center gap-1">
        <Brain size={10} className="text-purple-500" />
        <span className="text-[10px] font-semibold text-purple-700">AI Analysis</span>
        <span className="ml-auto text-[10px] text-gray-500">{analysis.model_used}</span>
        <button onClick={onReanalyze} title="Re-analyze" className="ml-1 text-gray-500 hover:text-purple-500 transition-colors">
          <RefreshCw size={9} />
        </button>
      </div>
      {analysis.summary && <p className="text-[10px] text-gray-700">{analysis.summary}</p>}
      {analysis.severity && (
        <span className={`badge text-[10px] ${severityStyle(analysis.severity)}`}>{analysis.severity}</span>
      )}
      {(analysis.recommendations || []).length > 0 && (
        <div>
          <p className="text-[10px] text-gray-500 font-semibold uppercase tracking-wider mb-0.5">Actions</p>
          {analysis.recommendations.slice(0, 3).map((r, k) => (
            <p key={k} className="text-[10px] text-gray-600">• {r}</p>
          ))}
        </div>
      )}
      {(analysis.mitre_techniques || []).length > 0 && (
        <div className="flex flex-wrap gap-1 pt-0.5">
          {analysis.mitre_techniques.slice(0, 5).map((t, k) => (
            <span key={k} className="badge bg-indigo-50 text-indigo-600 border-indigo-200 text-[10px]">{t}</span>
          ))}
        </div>
      )}
      {analysis.analyzed_at && (
        <p className="text-[10px] text-gray-500 flex items-center gap-0.5 pt-0.5">
          <Clock size={8} /> {new Date(analysis.analyzed_at).toLocaleString()}
        </p>
      )}
    </div>
  )
}

// ── Inline single-run result (used by both library and case-specific rules) ───

function SingleRunResult({ result, rule, caseId, analysis, analyzing, onAnalyze }) {
  if (!result || result.error) return null

  function openInSearch(query) {
    window.open(`/cases/${caseId}?q=${encodeURIComponent(query)}`, '_blank')
  }

  return (
    <div className={`border-t px-4 py-3 text-xs space-y-2 ${result.fired ? 'bg-yellow-50 border-yellow-200' : 'bg-green-50 border-green-200'}`}>
      <div className="flex items-center gap-2">
        {result.fired
          ? <><AlertTriangle size={12} className="text-yellow-600" /><span className="font-semibold text-yellow-700">{result.match_count.toLocaleString()} match{result.match_count !== 1 ? 'es' : ''} found</span></>
          : <><CheckCircle size={12} className="text-green-600" /><span className="font-semibold text-green-700">No matches — all clear</span></>
        }
      </div>

      {result.fired && (
        <>
          {/* View all in search — opens new tab */}
          {caseId && (
            <button
              onClick={() => openInSearch(rule.query)}
              className="w-full flex items-center justify-between bg-brand-accent/10 hover:bg-brand-accent/20 border border-brand-accent/30 rounded-lg px-3 py-1.5 transition-colors"
            >
              <span className="text-[11px] font-medium text-brand-accent">
                View all {result.match_count.toLocaleString()} events in Search
              </span>
              <ExternalLink size={11} className="text-brand-accent flex-shrink-0" />
            </button>
          )}

          {/* Sample events */}
          {result.sample_events?.length > 0 && (
            <div className="space-y-1">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Sample events</p>
              {result.sample_events.map((ev, j) => (
                <button
                  key={j}
                  onClick={() => caseId && openInSearch(ev.fo_id ? `fo_id:"${ev.fo_id}"` : rule.query)}
                  className="w-full text-left text-[10px] text-gray-700 font-mono bg-white border border-yellow-200 rounded px-2 py-1 truncate hover:bg-blue-50 hover:border-blue-200 cursor-pointer"
                  title="Click to view in search (new tab)"
                >
                  <span className="text-gray-500 mr-2">{ev.timestamp?.slice(0, 19).replace('T', ' ')}</span>
                  {ev.message}
                </button>
              ))}
              {result.match_count > result.sample_events.length && (
                <p className="text-[10px] text-gray-500 italic">…and {result.match_count - result.sample_events.length} more</p>
              )}
            </div>
          )}

          {/* AI analysis */}
          {analysis ? (
            <AnalysisResult analysis={analysis} onReanalyze={onAnalyze} analyzing={analyzing} />
          ) : analyzing ? (
            <AnalysisResult analysis={null} onReanalyze={null} analyzing={true} />
          ) : (
            <button
              onClick={onAnalyze}
              className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-purple-500 transition-colors"
            >
              <Brain size={10} /> AI Analysis
            </button>
          )}
        </>
      )}
    </div>
  )
}

// ── Library rules list (collapsible) ─────────────────────────────────────────

function LibraryRulesList({ rules, caseId, onSearchQuery }) {
  const [open, setOpen]             = useState(false)
  const [runningId, setRunningId]   = useState(null)
  const [results, setResults]       = useState({}) // ruleId → {fired, match_count, sample_events} | {error}
  const [analyses, setAnalyses]     = useState({})
  const [analyzingIds, setAnalyzingIds] = useState(new Set())

  async function runRule(rule) {
    setRunningId(rule.id)
    try {
      const r = await api.alertRules.runSingleRule(caseId, rule.id)
      setResults(p => ({
        ...p,
        [rule.id]: {
          fired:         r.fired,
          match_count:   r.match?.match_count ?? 0,
          sample_events: r.match?.sample_events || [],
        },
      }))
    } catch {
      setResults(p => ({ ...p, [rule.id]: { error: true } }))
    } finally {
      setRunningId(null)
    }
  }

  async function analyzeRule(rule) {
    const res = results[rule.id]
    if (!res || !res.fired) return
    setAnalyzingIds(prev => new Set([...prev, rule.id]))
    try {
      const r = await api.alertRules.analyzeResult({
        rule_name: rule.name, rule_query: rule.query,
        match_count: res.match_count, sample_events: res.sample_events || [],
      })
      setAnalyses(p => ({ ...p, [rule.id]: r.analysis }))
    } catch {
      // LLM not configured — silently skip
    } finally {
      setAnalyzingIds(prev => { const s = new Set(prev); s.delete(rule.id); return s })
    }
  }

  return (
    <div className="mb-4 border border-gray-200 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2.5 bg-gray-50 hover:bg-gray-100 transition-colors text-xs"
      >
        <span className="flex items-center gap-1.5 font-semibold text-gray-600">
          <Play size={9} className="text-brand-accent" />
          Library Rules
        </span>
        <span className="flex items-center gap-2 text-gray-500">
          <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">{rules.length} rules</span>
          {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
        </span>
      </button>

      {open && (
        <div className="max-h-[500px] overflow-y-auto divide-y divide-gray-100">
          {rules.map(rule => {
            const result    = results[rule.id]
            const isRunning = runningId === rule.id
            const analysis  = analyses[rule.id]
            const analyzing = analyzingIds.has(rule.id)
            return (
              <div key={rule.id}>
                <div className="flex items-center gap-2 px-3 py-2 text-xs">
                  <AlertTriangle size={9} className="text-amber-500 flex-shrink-0" />
                  <span className="text-gray-700 truncate flex-1">{rule.name}</span>
                  {rule.artifact_type && (
                    <span className="text-[10px] text-gray-500 flex-shrink-0">{rule.artifact_type}</span>
                  )}
                  {result && !result.error && (
                    result.fired
                      ? <span className="badge bg-yellow-100 text-yellow-700 border border-yellow-200 text-[10px] flex-shrink-0">
                          {result.match_count} hit{result.match_count !== 1 ? 's' : ''}
                        </span>
                      : <span className="badge bg-green-50 text-green-600 border border-green-200 text-[10px] flex-shrink-0">
                          clean
                        </span>
                  )}
                  {result?.error && <span className="text-[10px] text-red-400 flex-shrink-0">err</span>}
                  <button
                    onClick={() => runRule(rule)}
                    disabled={isRunning || !!runningId}
                    title={`Run "${rule.name}" against this case`}
                    className="flex-shrink-0 p-1 rounded hover:bg-gray-100 text-gray-500 hover:text-brand-accent disabled:opacity-40 transition-colors"
                  >
                    {isRunning ? <Loader2 size={10} className="animate-spin" /> : <Play size={10} />}
                  </button>
                </div>

                {/* Inline run result */}
                {result && !result.error && (
                  <div className="px-3 pb-3">
                    <SingleRunResult
                      result={result}
                      rule={rule}
                      caseId={caseId}
                      analysis={analysis}
                      analyzing={analyzing}
                      onAnalyze={() => analyzeRule(rule)}
                    />
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AlertRules({ caseId, onSearchQuery }) {
  const [rules, setRules]               = useState([])
  const [libraryRules, setLibraryRules] = useState([])
  const [loading, setLoading]           = useState(true)
  const [checking, setChecking]         = useState(false)
  const [run, setRun]                   = useState(null)
  const [showForm, setShowForm]         = useState(false)
  const [form, setForm]                 = useState({ name:'', description:'', artifact_type:'', query:'', threshold:1 })
  const [expandedMatch, setExpandedMatch] = useState(null)
  // Rule type filter
  const [ruleTypeFilter, setRuleTypeFilter] = useState('all')
  // "Check All" analyses
  const [analyses, setAnalyses]           = useState({})
  const [analyzingIds, setAnalyzingIds]   = useState(new Set())
  // Case-specific rule single-run state
  const [runningCaseRuleId, setRunningCaseRuleId]   = useState(null)
  const [caseRuleResults, setCaseRuleResults]       = useState({})
  const [caseRuleAnalyses, setCaseRuleAnalyses]     = useState({})
  const [analyzingCaseRuleIds, setAnalyzingCaseRuleIds] = useState(new Set())
  // AI rule generation
  const [aiDesc, setAiDesc]             = useState('')
  const [generating, setGenerating]     = useState(false)
  const [showAiForm, setShowAiForm]     = useState(false)

  // ── Load on mount ─────────────────────────────────────────────────────────

  useEffect(() => {
    api.alertRules.list(caseId)
      .then(r => setRules(r.rules || []))
      .catch(() => {})
      .finally(() => setLoading(false))

    api.alertRules.listLibrary()
      .then(r => setLibraryRules(r.rules || []))
      .catch(() => {})

    api.alertRules.lastRun(caseId)
      .then(saved => {
        if (saved?.ran_at) {
          setRun(saved)
          setAnalyses(saved.analyses || {})
        }
      })
      .catch(() => {})
  }, [caseId])

  // ── Rule management ───────────────────────────────────────────────────────

  async function createRule(e) {
    e.preventDefault()
    if (!form.name.trim() || !form.query.trim()) return
    const r = await api.alertRules.create(caseId, form)
    setRules(p => [...p, r])
    setForm({ name:'', description:'', artifact_type:'', query:'', threshold:1 })
    setShowForm(false)
  }

  async function deleteRule(id) {
    await api.alertRules.delete(caseId, id)
    setRules(p => p.filter(r => r.id !== id))
  }

  async function runCaseRule(rule) {
    setRunningCaseRuleId(rule.id)
    try {
      const r = await api.alertRules.runSingleCaseRule(caseId, rule.id)
      setCaseRuleResults(p => ({
        ...p,
        [rule.id]: {
          fired:         r.fired,
          match_count:   r.match?.match_count ?? 0,
          sample_events: r.match?.sample_events || [],
        },
      }))
    } catch {
      setCaseRuleResults(p => ({ ...p, [rule.id]: { error: true } }))
    } finally {
      setRunningCaseRuleId(null)
    }
  }

  async function analyzeCaseRule(rule) {
    const res = caseRuleResults[rule.id]
    if (!res || !res.fired) return
    setAnalyzingCaseRuleIds(prev => new Set([...prev, rule.id]))
    try {
      const r = await api.alertRules.analyzeResult({
        rule_name: rule.name, rule_query: rule.query,
        match_count: res.match_count, sample_events: res.sample_events || [],
      })
      setCaseRuleAnalyses(p => ({ ...p, [rule.id]: r.analysis }))
    } catch {
      // LLM not configured — skip silently
    } finally {
      setAnalyzingCaseRuleIds(prev => { const s = new Set(prev); s.delete(rule.id); return s })
    }
  }

  // ── Check All + auto-analyze ──────────────────────────────────────────────

  async function checkRules() {
    setChecking(true)
    setAnalyses({})
    try {
      const types = ruleTypeFilter !== 'all' ? [ruleTypeFilter] : []
      const freshRun = await api.alertRules.runLibrary(caseId, types)
      setRun(freshRun)
      if (freshRun.matches?.length) analyzeAll(freshRun.matches)
    } catch (e) { alert('Check failed: ' + e.message) }
    finally { setChecking(false) }
  }

  async function analyzeAll(matches) {
    await Promise.allSettled(matches.map(m => runAnalysis(m.rule.id, m.rule, m)))
  }

  async function runAnalysis(ruleId, rule, match) {
    setAnalyzingIds(prev => new Set([...prev, ruleId]))
    try {
      const r = await api.alertRules.reanalyzeMatch(caseId, ruleId)
      setAnalyses(prev => ({ ...prev, [ruleId]: r.analysis }))
    } catch {
      // LLM not configured — skip
    } finally {
      setAnalyzingIds(prev => { const s = new Set(prev); s.delete(ruleId); return s })
    }
  }

  // ── AI rule generation ────────────────────────────────────────────────────

  async function generateRule(e) {
    e.preventDefault()
    if (!aiDesc.trim()) return
    setGenerating(true)
    try {
      const r = await api.llm.generateRule({ description: aiDesc })
      setForm({
        name:          r.name || aiDesc.slice(0, 60),
        description:   r.description || '',
        artifact_type: r.artifact_type || '',
        query:         r.query || '',
        threshold:     r.threshold || 1,
      })
      setShowAiForm(false)
      setShowForm(true)
      setAiDesc('')
    } catch (err) {
      alert('AI generation failed: ' + err.message)
    } finally {
      setGenerating(false)
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  const matches = run?.matches || []
  const filteredLibraryRules = filterAlertRules(libraryRules, { provenance: ruleTypeFilter })

  // "Check All" match card (has AnalysisBlock for library rules)
  function CheckAllMatchCard({ m, i }) {
    const analysis    = analyses[m.rule.id]
    const isAnalyzing = analyzingIds.has(m.rule.id)
    return (
      <div className="mt-2 border border-yellow-200 rounded-lg overflow-hidden">
        <button
          onClick={() => setExpandedMatch(expandedMatch === i ? null : i)}
          className="w-full flex items-center justify-between px-3 py-2 text-xs bg-yellow-50 hover:bg-yellow-100 transition-colors"
        >
          <span className="font-medium text-yellow-700">{m.rule.name}</span>
          <div className="flex items-center gap-2">
            {isAnalyzing && <Loader2 size={10} className="text-purple-500 animate-spin" />}
            {analysis && !isAnalyzing && <Brain size={10} className="text-purple-500" title="AI analysis available" />}
            <span className="badge bg-yellow-100 text-yellow-700 border border-yellow-200">
              {m.match_count.toLocaleString()} match{m.match_count !== 1 ? 'es' : ''}
            </span>
            {expandedMatch === i ? <ChevronUp size={12} className="text-gray-500" /> : <ChevronDown size={12} className="text-gray-500" />}
          </div>
        </button>
        {expandedMatch === i && (
          <div className="px-3 py-3 space-y-2 bg-white">
            <button
              onClick={() => window.open(`/cases/${caseId}?q=${encodeURIComponent(m.rule.query)}`, '_blank')}
              className="w-full flex items-center justify-between bg-brand-accent/10 hover:bg-brand-accent/20 border border-brand-accent/30 rounded-lg px-3 py-1.5 transition-colors"
            >
              <span className="text-[11px] font-medium text-brand-accent">
                View all {m.match_count.toLocaleString()} events in Search
              </span>
              <ExternalLink size={11} className="text-brand-accent flex-shrink-0" />
            </button>
            {m.sample_events?.map((ev, j) => (
              <button
                key={j}
                onClick={() => window.open(`/cases/${caseId}?q=${encodeURIComponent(ev.fo_id ? `fo_id:${ev.fo_id}` : m.rule.query)}`, '_blank')}
                className="w-full text-left bg-white hover:bg-blue-50 rounded border border-gray-200 hover:border-blue-300 px-2.5 py-2 transition-colors group cursor-pointer"
              >
                <div className="flex items-center justify-between gap-2 mb-0.5">
                  <span className="text-[10px] text-gray-500 font-mono">{ev.timestamp?.slice(0,19).replace('T',' ')}</span>
                  <ExternalLink size={9} className="text-gray-500 group-hover:text-blue-400 flex-shrink-0 transition-colors" />
                </div>
                <p className="text-[10px] text-brand-text">{ev.message}</p>
              </button>
            ))}
            <AnalysisResult
              analysis={analysis}
              analyzing={isAnalyzing}
              onReanalyze={() => runAnalysis(m.rule.id, m.rule, m)}
            />
            {!analysis && !isAnalyzing && (
              <button
                onClick={() => runAnalysis(m.rule.id, m.rule, m)}
                className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-purple-500 transition-colors"
              >
                <Brain size={10} /> AI Analysis
              </button>
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <div className="p-4">

      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <div>
          <h1 className="text-base font-bold text-brand-text">Detection Rules</h1>
          <p className="text-xs text-gray-500 mt-0.5">Define suspicious patterns and check them on demand</p>
        </div>
        <div className="flex gap-2 flex-wrap justify-end">
          <button onClick={() => setShowAiForm(v => !v)} className="btn-ghost text-xs">
            <Sparkles size={13} className="text-purple-500" /> AI Generate
          </button>
          <button onClick={() => setShowForm(v => !v)} className="btn-ghost text-xs">
            <Plus size={13} /> New Rule
          </button>
          <button onClick={checkRules} disabled={checking || filteredLibraryRules.length === 0} className="btn-primary text-xs"
            title={`Run ${filteredLibraryRules.length} ${ruleTypeFilter !== 'all' ? ruleTypeFilter + ' ' : ''}library rules against this case`}>
            {checking
              ? <><Loader2 size={12} className="animate-spin" /> Checking…</>
              : <><Play size={12} /> {ruleTypeFilter !== 'all' ? `Check ${ruleTypeFilter.charAt(0).toUpperCase() + ruleTypeFilter.slice(1)}` : 'Check All'} ({filteredLibraryRules.length})</>}
          </button>
        </div>
      </div>

      {/* AI generate form */}
      {showAiForm && (
        <form onSubmit={generateRule} className="card p-4 mb-4 space-y-3 border border-purple-200 bg-purple-50">
          <p className="text-xs font-semibold text-purple-700 flex items-center gap-1.5">
            <Sparkles size={12} /> AI Rule Generation
          </p>
          <p className="text-[10px] text-gray-500">Describe what you want to detect in plain language.</p>
          <div className="flex gap-2">
            <input autoFocus value={aiDesc} onChange={e => setAiDesc(e.target.value)}
              placeholder="e.g. detect failed RDP logins followed by a successful one"
              className="input flex-1 text-xs" required />
            <button type="submit" disabled={generating || !aiDesc.trim()} className="btn-primary text-xs whitespace-nowrap">
              {generating ? <Loader2 size={12} className="animate-spin" /> : <><Sparkles size={12} /> Generate</>}
            </button>
            <button type="button" onClick={() => setShowAiForm(false)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      )}

      {/* Manual create form */}
      {showForm && (
        <form onSubmit={createRule} className="card p-4 mb-4 space-y-3">
          <p className="text-xs font-semibold text-gray-700">New Alert Rule</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Name *</label>
              <input value={form.name} onChange={e => setForm(p => ({...p, name: e.target.value}))}
                placeholder="Brute Force Detection" className="input w-full text-xs" required />
            </div>
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Artifact Type</label>
              <input value={form.artifact_type} onChange={e => setForm(p => ({...p, artifact_type: e.target.value}))}
                placeholder="evtx (leave empty for all)" className="input w-full text-xs" />
            </div>
          </div>
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">
              ES Query * <span className="text-gray-500 normal-case font-normal">(query_string syntax)</span>
            </label>
            <input value={form.query} onChange={e => setForm(p => ({...p, query: e.target.value}))}
              placeholder='evtx.event_id:4625 OR evtx.event_id:4771'
              className="input w-full text-xs font-mono" required />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Description</label>
              <input value={form.description} onChange={e => setForm(p => ({...p, description: e.target.value}))}
                placeholder="What this rule detects" className="input w-full text-xs" />
            </div>
            <div>
              <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Min Matches</label>
              <input type="number" min="1" value={form.threshold}
                onChange={e => setForm(p => ({...p, threshold: parseInt(e.target.value) || 1}))}
                className="input w-full text-xs" />
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button type="submit" className="btn-primary text-xs"><Plus size={12} /> Create Rule</button>
            <button type="button" onClick={() => setShowForm(false)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      )}

      {/* Check All results */}
      {run?.rules_checked !== undefined && (
        <div className={`card p-4 mb-4 ${matches.length > 0 ? 'border-yellow-300 bg-yellow-50' : 'border-green-300 bg-green-50'}`}>
          <div className="flex items-center gap-2 mb-2">
            {matches.length > 0
              ? <AlertTriangle size={14} className="text-yellow-600" />
              : <CheckCircle size={14} className="text-green-600" />}
            <span className="text-sm font-semibold text-gray-800">
              {matches.length > 0
                ? `${matches.length} rule${matches.length !== 1 ? 's' : ''} triggered`
                : 'All clear — no rules triggered'}
            </span>
            <span className="text-xs text-gray-500 ml-auto flex items-center gap-1">
              <Clock size={10} />
              {run.ran_at ? new Date(run.ran_at).toLocaleString() : 'just now'}
              <span className="ml-1">{run.rules_checked} rules checked</span>
            </span>
          </div>
          {matches.map((m, i) => (
            <CheckAllMatchCard key={m.rule.id} m={m} i={i} />
          ))}
        </div>
      )}

      {/* Rule type filter pills */}
      {libraryRules.length > 0 && (
        <div className="flex items-center gap-1 mb-2 flex-wrap">
          <ProvenancePills value={ruleTypeFilter} onChange={setRuleTypeFilter} size="xs" />
          <span className="text-[10px] text-gray-500 ml-auto self-center">
            {filteredLibraryRules.length} / {libraryRules.length} rules
          </span>
        </div>
      )}

      {/* Library rules — collapsible */}
      {filteredLibraryRules.length > 0 && (
        <LibraryRulesList rules={filteredLibraryRules} caseId={caseId} onSearchQuery={onSearchQuery} />
      )}

      {/* Case-specific rules */}
      {loading ? (
        <div className="space-y-2">{[1,2].map(i => <div key={i} className="skeleton h-14 w-full" />)}</div>
      ) : rules.length === 0 ? (
        <div className="card p-6 text-center">
          <p className="text-gray-500 text-xs">No case-specific rules — use AI Generate or New Rule to add ad-hoc rules for this case only.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {rules.map(rule => (
            <div key={rule.id} className="card overflow-hidden">
              {/* Rule header */}
              <div className="p-3 flex items-start gap-3">
                <div className="w-7 h-7 rounded-lg bg-yellow-50 border border-yellow-200 flex items-center justify-center flex-shrink-0 mt-0.5">
                  <AlertTriangle size={12} className="text-yellow-600" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-sm font-semibold text-gray-800">{rule.name}</span>
                    {rule.artifact_type && (
                      <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">{rule.artifact_type}</span>
                    )}
                    <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">≥{rule.threshold}</span>
                  </div>
                  {rule.description && <p className="text-xs text-gray-500 mb-1">{rule.description}</p>}
                  <code className="text-[10px] text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded">{rule.query}</code>
                </div>
                <div className="flex items-center gap-1 flex-shrink-0">
                  {(() => {
                    const res = caseRuleResults[rule.id]
                    if (!res) return null
                    return res.error
                      ? <span className="text-[10px] text-red-400">err</span>
                      : res.fired
                        ? <span className="badge bg-yellow-100 text-yellow-700 border border-yellow-200 text-[10px]">{res.match_count} hit{res.match_count !== 1 ? 's' : ''}</span>
                        : <span className="badge bg-green-50 text-green-600 border border-green-200 text-[10px]">clean</span>
                  })()}
                  <button
                    onClick={() => runCaseRule(rule)}
                    disabled={!!runningCaseRuleId}
                    title={`Run "${rule.name}" against this case`}
                    className="btn-ghost p-1.5 text-gray-500 hover:text-brand-accent disabled:opacity-40"
                  >
                    {runningCaseRuleId === rule.id ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
                  </button>
                  <button onClick={() => deleteRule(rule.id)} className="btn-ghost p-1.5 text-gray-500 hover:text-red-500">
                    <Trash2 size={13} />
                  </button>
                </div>
              </div>

              {/* Inline run result (with view-in-search + AI analysis) */}
              <SingleRunResult
                result={caseRuleResults[rule.id]}
                rule={rule}
                caseId={caseId}
                analysis={caseRuleAnalyses[rule.id]}
                analyzing={analyzingCaseRuleIds.has(rule.id)}
                onAnalyze={() => analyzeCaseRule(rule)}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
