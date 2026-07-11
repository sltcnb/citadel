import { useState, useEffect, useRef, useLayoutEffect } from 'react'
import {
  X,
  Sparkles,
  Loader2,
  AlertTriangle,
  ChevronRight,
  Shield,
  Search,
  Lightbulb,
  TrendingUp,
  Copy,
  CheckCircle,
  Trash2,
  Bot,
  ExternalLink,
  Zap,
  Flag,
  ListChecks,
  FileBarChart,
  ThumbsUp,
  ThumbsDown,
} from 'lucide-react'
import { api } from '../api/client'
import { RISK_CONFIG } from '../utils/severity'
import PanelHelp from './shared/PanelHelp'

function RiskGauge({ score, level }) {
  const cfg = RISK_CONFIG[level] || RISK_CONFIG.unknown
  const pct = score != null ? Math.round((score / 10) * 100) : 0
  return (
    <div className={`rounded-xl border p-4 ${cfg.bg} ${cfg.border}`}>
      <div className="flex items-center justify-between mb-3">
        <span className={`text-xs font-semibold uppercase tracking-widest ${cfg.color}`}>Risk Level</span>
        <span className={`text-2xl font-bold ${cfg.color}`}>{score ?? '—'}<span className="text-sm font-normal text-gray-500">/10</span></span>
      </div>
      <div className="h-2 bg-white/60 rounded-full overflow-hidden mb-2">
        <div className={`h-full rounded-full transition-all duration-700 ${cfg.bar}`} style={{ width: `${pct}%` }} />
      </div>
      <span className={`text-sm font-semibold ${cfg.color}`}>{cfg.label}</span>
    </div>
  )
}

function Tag({ children, color = 'gray' }) {
  const cls = {
    red:    'bg-red-100 text-red-700 border-red-200',
    orange: 'bg-orange-100 text-orange-700 border-orange-200',
    blue:   'bg-blue-100 text-blue-700 border-blue-200',
    gray:   'bg-gray-100 text-gray-600 border-gray-200',
  }[color] || 'bg-gray-100 text-gray-600 border-gray-200'
  return <span className={`inline-flex items-center px-2 py-0.5 rounded-full border text-[11px] font-medium ${cls}`}>{children}</span>
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <button onClick={copy} className="p-1 rounded hover:bg-gray-100 text-gray-500 hover:text-gray-600 transition-colors flex-shrink-0" title="Copy query">
      {copied ? <CheckCircle size={12} className="text-green-500" /> : <Copy size={12} />}
    </button>
  )
}

// Per-step row — tool-aware. Used by both the live (streaming) card and the
// persisted AgentRunBlock so the look is identical regardless of source.
function AgentStepRow({ step: s, onPivot }) {
  const action = s.action || 'search'
  const invalid = s.query_status === 'invalid'
  const hits = s.result_count
  const isFinal = action === 'conclude'
  const isError = action === 'error'

  const actionColor =
    isFinal ? 'bg-emerald-100 text-emerald-700' :
    isError ? 'bg-red-100   text-red-700' :
    action === 'set_hypotheses'    ? 'bg-pink-100    text-pink-800' :
    action === 'search'            ? 'bg-blue-100    text-blue-700' :
    action === 'aggregate'         ? 'bg-indigo-100  text-indigo-700' :
    action === 'inspect'           ? 'bg-purple-100  text-purple-700' :
    action === 'detection_rules'   ? 'bg-yellow-100  text-yellow-800' :
    action === 'watchlist'         ? 'bg-amber-100   text-amber-800' :
    action === 'module_runs'       ? 'bg-teal-100    text-teal-800' :
    action === 'launch_module'     ? 'bg-orange-100  text-orange-800' :
    action === 'read_module_result'? 'bg-teal-100    text-teal-800' :
    action === 'entity_graph'      ? 'bg-sky-100     text-sky-800' :
    action === 'stack_rare'        ? 'bg-fuchsia-100 text-fuchsia-800' :
    action === 'cti_seen_before'   ? 'bg-rose-100    text-rose-800' :
                                      'bg-gray-100    text-gray-600'
  const actionIcon =
    isFinal                 ? <Sparkles size={9}/> :
    isError                 ? <AlertTriangle size={9}/> :
    action === 'set_hypotheses' ? <ListChecks size={9}/> :
    action === 'search'     ? <Search size={9}/> :
    action === 'aggregate'  ? <TrendingUp size={9}/> :
    action === 'inspect'    ? <Zap size={9}/> :
    action === 'launch_module' ? <Bot size={9}/> :
    action === 'entity_graph'  ? <Search size={9}/> :
    action === 'stack_rare'    ? <TrendingUp size={9}/> :
    action === 'cti_seen_before' ? <Shield size={9}/> :
                                  <ChevronRight size={9}/>

  return (
    <div className={`border rounded-lg ${isFinal ? 'border-emerald-200 bg-emerald-50/40' : 'border-gray-200'}`}>
      <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-gray-100 flex-wrap">
        <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-gray-100 text-gray-600">
          Step {s.step}
        </span>
        <span className={`text-[10px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded flex items-center gap-1 ${actionColor}`}>
          {actionIcon} {action}
        </span>
        {invalid && (
          <span className="text-[10px] font-semibold text-red-700 bg-red-100 px-1.5 py-0.5 rounded">invalid</span>
        )}
        {!invalid && typeof hits === 'number' && action !== 'inspect' && (
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded tabular-nums ${
            hits === 0 ? 'bg-gray-100 text-gray-500'
                       : hits > 10000 ? 'bg-amber-100 text-amber-700'
                                       : 'bg-emerald-100 text-emerald-700'
          }`}>
            {hits.toLocaleString()} {hits === 1 ? 'hit' : 'hits'}
          </span>
        )}
        {/* Pivot button — only meaningful for search */}
        {action === 'search' && !invalid && hits > 0 && onPivot && (
          <button
            onClick={() => onPivot(s.query)}
            className="ml-auto text-[10px] text-brand-accent hover:underline flex items-center gap-1"
            title="Pivot timeline to this query"
          >
            Pivot <ExternalLink size={9}/>
          </button>
        )}
      </div>

      <div className="px-3 py-2 space-y-1.5">
        {s.thought && (
          <p className="text-[11px] text-gray-700 italic">{s.thought}</p>
        )}

        {/* search */}
        {action === 'search' && s.query && (
          <>
            {s.auto_broadened && (
              <p className="text-[10px] text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-0.5">
                Auto-broadened from <code className="font-mono">{s.broadened_from}</code> (original returned 0 hits)
              </p>
            )}
            <code className="block text-[10px] font-mono text-gray-600 bg-gray-50 border border-gray-100 rounded px-2 py-1 break-all">
              {s.query}
            </code>
          </>
        )}
        {action === 'search' && (s.sample || []).length > 0 && (
          <div className="space-y-0.5 mt-1">
            {s.sample.map((line, j) => (
              <p key={j} className="text-[10px] text-gray-600 truncate" title={line}>{line}</p>
            ))}
          </div>
        )}

        {/* entity_graph / stack_rare / cti_seen_before — generic sample-line list */}
        {['entity_graph', 'stack_rare', 'cti_seen_before'].includes(action) && (s.sample || []).length > 0 && (
          <div className="space-y-0.5 mt-1">
            {s.sample.map((line, j) => (
              <p key={j} className="text-[10px] font-mono text-gray-600 truncate" title={line}>{line}</p>
            ))}
          </div>
        )}

        {/* aggregate — render top-N table */}
        {action === 'aggregate' && (
          <>
            <div className="text-[10px] text-gray-500">
              Top values of <code className="font-mono">{s.agg_field}</code>
              {s.agg_query && s.agg_query !== '*' && (
                <> in <code className="font-mono">{s.agg_query}</code></>
              )}
            </div>
            <div className="space-y-0.5">
              {(s.agg_buckets || []).map((b, j) => {
                const max = Math.max(1, ...(s.agg_buckets || []).map(x => x.count || 0))
                const pct = Math.max(4, Math.round((b.count / max) * 100))
                return (
                  <div key={j} className="flex items-center gap-2 text-[10px]">
                    <span className="font-mono text-gray-700 w-44 truncate" title={String(b.value)}>{String(b.value)}</span>
                    <div className="flex-1 h-1.5 bg-gray-100 rounded overflow-hidden">
                      <div className="h-full bg-indigo-400" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="tabular-nums text-gray-700 w-14 text-right">{b.count.toLocaleString()}</span>
                    {onPivot && (
                      <button
                        onClick={() => onPivot(`${s.agg_field}:"${String(b.value).replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`)}
                        className="text-[10px] text-brand-accent hover:underline"
                        title={`Pivot timeline to ${s.agg_field}:${b.value}`}
                      >
                        →
                      </button>
                    )}
                  </div>
                )
              })}
              {(!s.agg_buckets || s.agg_buckets.length === 0) && (
                <p className="text-[10px] text-gray-500 italic">No buckets returned.</p>
              )}
            </div>
          </>
        )}

        {/* set_hypotheses — list declared theories */}
        {action === 'set_hypotheses' && (s.hypotheses || []).length > 0 && (
          <div className="space-y-1">
            {s.hypotheses.map((h, j) => (
              <div key={j} className="border border-pink-200 bg-pink-50/60 rounded px-2 py-1 text-[11px]">
                <div><span className="font-bold mr-1">{h.id || `H${j+1}`}</span> {h.claim}</div>
                {h.test_plan && <div className="text-[10px] text-gray-600 italic mt-0.5">Test: {h.test_plan}</div>}
              </div>
            ))}
          </div>
        )}

        {/* launch_module — surface run_id */}
        {action === 'launch_module' && (
          <div className="text-[11px]">
            <span className="font-semibold">module:</span> <code className="font-mono">{s.module_id}</code>
            {s.run_id && <> · <span className="font-semibold">run_id:</span> <code className="font-mono">{s.run_id}</code></>}
            {s.note && <p className="text-[10px] text-gray-600 italic mt-0.5">{s.note}</p>}
          </div>
        )}

        {/* read_module_result — top hits */}
        {action === 'read_module_result' && (
          <div className="text-[10px] space-y-0.5">
            <div className="text-gray-600">
              <strong>{s.module_id}</strong> · <code className="font-mono">{s.run_id}</code> · <strong>{(s.total_hits || 0).toLocaleString()}</strong> hits
            </div>
            {(s.sample_hits || []).slice(0,5).map((h, j) => (
              <div key={j} className="px-2 py-0.5 bg-gray-50 rounded">
                <span className="font-semibold uppercase text-[9px] mr-1">{h.level}</span>
                <span className="font-mono">{h.rule}</span>: {h.message}
              </div>
            ))}
          </div>
        )}

        {/* detection_rules / watchlist / module_runs — generic list */}
        {(action === 'detection_rules' || action === 'watchlist' || action === 'module_runs') && (
          <div className="text-[10px] space-y-0.5">
            {action === 'detection_rules' && (s.matches || []).slice(0,8).map((m, j) => (
              <div key={j} className="flex items-center gap-1.5">
                <span className="font-semibold uppercase text-[9px] bg-yellow-100 text-yellow-800 px-1 rounded">{m.level}</span>
                <span className="font-mono flex-1 truncate">{m.rule_name}</span>
                <span className="tabular-nums text-gray-600">{m.match_count}</span>
              </div>
            ))}
            {action === 'watchlist' && (s.entries || []).slice(0,8).map((e, j) => (
              <div key={j} className="flex items-center gap-1.5">
                <span className="font-semibold uppercase text-[9px] bg-amber-100 text-amber-800 px-1 rounded">{e.kind}</span>
                <span className="font-mono flex-1 truncate">{e.label || e.value}</span>
                <span className="tabular-nums text-gray-600">{e.hits ?? '?'}</span>
              </div>
            ))}
            {action === 'module_runs' && (s.runs || []).slice(0,8).map((r, j) => (
              <div key={j} className="flex items-center gap-1.5">
                <span className="font-mono flex-1 truncate">{r.module_id}</span>
                <span className="text-[9px] text-gray-500">{r.status}</span>
                <span className="tabular-nums text-gray-700">{(r.total_hits || 0).toLocaleString()} hits</span>
              </div>
            ))}
          </div>
        )}

        {/* inspect — render compact event */}
        {action === 'inspect' && (
          <div className="text-[10px] space-y-0.5">
            <div className="text-gray-500">Inspecting <code className="font-mono">{s.fo_id}</code></div>
            {s.event ? (
              <pre className="font-mono text-[10px] text-gray-700 bg-gray-50 border border-gray-100 rounded p-2 whitespace-pre-wrap overflow-x-auto max-h-48">
                {JSON.stringify(s.event, null, 2)}
              </pre>
            ) : (
              <p className="text-[10px] text-gray-500 italic">No event returned.</p>
            )}
          </div>
        )}

        {invalid && s.query_error && (
          <p className="text-[10px] text-red-700 font-mono break-all">
            {s.query_error}
          </p>
        )}

        {/* conclude */}
        {isFinal && s.incident_confirmed && (
          <div className={`-mx-3 -mt-2 mb-2 px-3 py-1.5 border-b text-[11px] font-semibold ${
            s.incident_confirmed === 'yes'          ? 'bg-red-50 border-red-200 text-red-800' :
            s.incident_confirmed === 'partial'      ? 'bg-amber-50 border-amber-200 text-amber-800' :
            s.incident_confirmed === 'no'           ? 'bg-emerald-100 border-emerald-200 text-emerald-800' :
                                                       'bg-gray-100 border-gray-200 text-gray-700'
          }`}>
            {s.incident_confirmed === 'yes'          ? '✅ Incident CONFIRMED' :
             s.incident_confirmed === 'partial'      ? '⚠️ Partially confirmed' :
             s.incident_confirmed === 'no'           ? '❎ Incident NOT confirmed' :
                                                        '❓ Inconclusive — no determinative evidence'}
          </div>
        )}
        {isFinal && s.verdict && (
          <p className="text-xs text-emerald-900 font-medium">{s.verdict}</p>
        )}
        {isFinal && s.linked_summary && (
          <div className="text-[11px] text-gray-700 mt-1 leading-relaxed">
            <span className="font-semibold text-gray-600 uppercase tracking-wider text-[9px] block mb-0.5">What's linked</span>
            {s.linked_summary}
          </div>
        )}
        {isFinal && typeof s.confidence === 'number' && (
          <div className="flex items-center gap-2 mt-1">
            <span className="text-[10px] uppercase tracking-wider text-gray-500 font-semibold">Confidence</span>
            <div className="flex-1 h-1.5 bg-gray-100 rounded overflow-hidden">
              <div
                className={`h-full rounded ${
                  s.confidence >= 75 ? 'bg-emerald-500' :
                  s.confidence >= 50 ? 'bg-amber-500' :
                                       'bg-red-400'
                }`}
                style={{ width: `${Math.max(2, Math.min(100, s.confidence))}%` }}
              />
            </div>
            <span className="text-[11px] font-semibold tabular-nums text-gray-700 w-10 text-right">
              {Math.round(s.confidence)}%
            </span>
          </div>
        )}
        {/* #8 calibrated confidence — flags an overconfident/under-evidenced verdict */}
        {isFinal && s.calibration && (s.calibration.low_confidence || s.calibration.needs_more_data) && (
          <div className="mt-1.5 flex items-start gap-1.5 rounded bg-amber-50 border border-amber-200 px-2 py-1">
            <AlertTriangle size={11} className="text-amber-600 mt-0.5 flex-shrink-0" />
            <span className="text-[10px] text-amber-800 leading-snug">
              {s.calibration.needs_more_data
                ? 'Low evidence for the leading verdict — treat as tentative; collect more before acting.'
                : `Calibrated confidence: ${s.calibration.band || 'low'}.`}
              {s.calibration.rationale ? ` ${s.calibration.rationale}` : ''}
            </span>
          </div>
        )}
        {isFinal && (s.hypotheses || []).length > 0 && (
          <div className="mt-2 space-y-1.5">
            <p className="text-[9px] font-semibold text-gray-500 uppercase tracking-widest">Hypotheses</p>
            {s.hypotheses.map((h, j) => {
              const c = ({
                supported: 'bg-red-50 border-red-200 text-red-800',
                refuted:   'bg-emerald-50 border-emerald-200 text-emerald-800',
                partial:   'bg-amber-50 border-amber-200 text-amber-800',
                untested:  'bg-gray-50 border-gray-200 text-gray-700',
              })[h.status] || 'bg-gray-50 border-gray-200 text-gray-700'
              return (
                <div key={j} className={`border rounded p-1.5 ${c}`}>
                  <div className="flex items-center gap-1.5 text-[10px] font-bold mb-0.5">
                    <span className="bg-white/60 px-1 rounded">{h.id || `H${j+1}`}</span>
                    <span className="uppercase tracking-wider">{h.status || 'untested'}</span>
                  </div>
                  <p className="text-[11px] mb-1">{h.claim}</p>
                  {(h.for_evidence || []).length > 0 && (
                    <div className="text-[10px] mt-0.5"><span className="font-semibold">FOR:</span> {h.for_evidence.join(' · ')}</div>
                  )}
                  {(h.against_evidence || []).length > 0 && (
                    <div className="text-[10px] mt-0.5"><span className="font-semibold">AGAINST:</span> {h.against_evidence.join(' · ')}</div>
                  )}
                  {h.missing && (
                    <div className="text-[10px] mt-0.5 italic">Missing: {h.missing}</div>
                  )}
                </div>
              )
            })}
          </div>
        )}
        {isFinal && (s.evidence || []).length > 0 && (
          <ul className="space-y-0.5 mt-1">
            {s.evidence.map((e, j) => (
              <li key={j} className="text-[11px] text-gray-700 flex items-start gap-1.5">
                <span className="text-emerald-600 flex-shrink-0 mt-0.5">•</span>
                <span>{e}</span>
              </li>
            ))}
          </ul>
        )}
        {isFinal && (s.indicators || []).length > 0 && (
          <div className="mt-1">
            <p className="text-[9px] font-semibold text-gray-500 uppercase tracking-widest mb-1">IOCs surfaced</p>
            <div className="flex flex-wrap gap-1">
              {s.indicators.map((ind, j) => (
                <span key={j} className="text-[10px] font-mono bg-white border border-gray-200 rounded px-1.5 py-0.5">{ind}</span>
              ))}
            </div>
          </div>
        )}
        {isFinal && (s.mitre_techniques || []).length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1">
            {s.mitre_techniques.map((t, j) => <Tag key={j} color="red">{t}</Tag>)}
          </div>
        )}
        {isFinal && (s.next_steps || []).length > 0 && (
          <div className="mt-1">
            <p className="text-[9px] font-semibold text-gray-500 uppercase tracking-widest mb-1">Recommended next steps</p>
            <ul className="space-y-0.5">
              {s.next_steps.map((t, j) => (
                <li key={j} className="text-[11px] text-gray-700 flex items-start gap-1.5">
                  <span className="text-purple-500 flex-shrink-0 mt-0.5">→</span>
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

// Collapses the step-by-step investigation path by default. Conclude
// (and any error steps) is always shown — that's the answer. Investigation
// trace is one click away for analysts who want the receipts.
function AgentRunBody({ run, onPivot }) {
  const allSteps     = run.steps || []
  const concludeStep = allSteps.find(s => s.action === 'conclude')
  const traceSteps   = allSteps.filter(s => s.action !== 'conclude')
  const [showTrace, setShowTrace] = useState(false)

  return (
    <>
      {concludeStep && <AgentStepRow step={concludeStep} onPivot={onPivot} />}
      {traceSteps.length > 0 && (
        <>
          <button
            onClick={() => setShowTrace(v => !v)}
            className="w-full flex items-center justify-center gap-1.5 text-[10px] uppercase tracking-wider font-semibold text-gray-500 hover:text-gray-700 py-1.5 border-y border-dashed border-gray-200 transition-colors"
          >
            <ChevronRight size={11} className={`transition-transform ${showTrace ? 'rotate-90' : ''}`} />
            {showTrace ? 'Hide' : 'Show'} investigation trace ({traceSteps.length} step{traceSteps.length === 1 ? '' : 's'})
          </button>
          {showTrace && traceSteps.map((s, i) => (
            <AgentStepRow key={i} step={s} onPivot={onPivot} />
          ))}
        </>
      )}
      {/* If for some reason there's no conclude (still running, cancelled),
          fall back to showing every step. */}
      {!concludeStep && traceSteps.length === 0 && allSteps.map((s, i) => (
        <AgentStepRow key={i} step={s} onPivot={onPivot} />
      ))}
    </>
  )
}

function AgentRunBlock({ run, idx, onDelete, onSearchQuery, caseId, onFollowup, onOpenReport }) {
  const concluded = run.stopped_reason === 'concluded'
  const final = run.final || {}
  const hasIndicators = (final.indicators || []).length > 0
  const eventCount = (run.steps || []).reduce(
    (n, s) => n + (s.sample_ids?.length || 0) + (s.action === 'inspect' && s.fo_id ? 1 : 0),
    0,
  )

  const [flagging,   setFlagging]   = useState(false)
  const [flagResult, setFlagResult] = useState(null)
  const [promoting,   setPromoting]   = useState(false)
  const [promoteResult, setPromoteResult] = useState(null)
  const [actionErr,  setActionErr]  = useState(null)
  const [followupText, setFollowupText] = useState('')
  const [showFollowup, setShowFollowup] = useState(false)
  const [feedback, setFeedback] = useState(run.feedback?.verdict || null)

  async function sendFeedback(verdict) {
    let reason = ''
    if (verdict === 'down') {
      reason = window.prompt('What did the agent get wrong? (optional)') ?? ''
    }
    const prev = feedback
    setFeedback(verdict)   // optimistic
    try {
      await api.cases.aiAgentFeedback(caseId, idx, { verdict, reason })
    } catch (e) {
      setFeedback(prev)
      setActionErr(e.message || 'Feedback failed')
    }
  }

  async function flagEvidence() {
    if (!confirm(`Flag all ${eventCount} event(s) surfaced during this run? They'll appear in the case's flagged filter.`)) return
    setFlagging(true); setActionErr(null)
    try {
      const r = await api.cases.aiAgentFlag(caseId, idx)
      setFlagResult(r)
    } catch (e) {
      setActionErr(e.message || 'Flag failed')
    } finally { setFlagging(false) }
  }

  async function promoteIocs() {
    if (!confirm(`Promote ${final.indicators?.length || 0} indicator(s) to the global watchlist? They'll be auto-classified (IP / domain / hash / cmdline / custom).`)) return
    setPromoting(true); setActionErr(null)
    try {
      const r = await api.cases.aiAgentPromote(caseId, idx)
      setPromoteResult(r)
    } catch (e) {
      setActionErr(e.message || 'Promote failed')
    } finally { setPromoting(false) }
  }

  return (
    <div className="border border-purple-200 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-purple-50 border-b border-purple-100">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-purple-900 truncate flex items-center gap-1.5">
            <Bot size={11} className="text-purple-600" />
            {run.is_followup && <span className="text-[9px] bg-purple-200 text-purple-800 px-1.5 py-0.5 rounded font-bold">FOLLOW-UP</span>}
            Autopilot: {run.circumstance || 'Investigation'}
          </p>
          <p className="text-[10px] text-purple-600/80 mt-0.5">
            {run.model_used} · {run.step_count}/{run.max_steps} steps · {concluded ? 'concluded' : 'step cap reached'}
            {run.analyzed_at && <> · {new Date(run.analyzed_at).toLocaleString()}</>}
          </p>
        </div>
        <div className="flex items-center gap-1 ml-2 flex-shrink-0">
          <button
            onClick={() => sendFeedback('up')}
            className={`icon-btn ${feedback === 'up' ? 'text-emerald-600 bg-emerald-100 rounded' : 'text-purple-400 hover:text-emerald-600'}`}
            title="This run was useful"
          >
            <ThumbsUp size={12} />
          </button>
          <button
            onClick={() => sendFeedback('down')}
            className={`icon-btn ${feedback === 'down' ? 'text-red-600 bg-red-100 rounded' : 'text-purple-400 hover:text-red-500'}`}
            title="This run missed the mark"
          >
            <ThumbsDown size={12} />
          </button>
          {onDelete && (
            <button onClick={() => onDelete(idx)} className="icon-btn text-purple-500 hover:text-red-500" title="Delete">
              <Trash2 size={12} />
            </button>
          )}
        </div>
      </div>

      <div className="p-4 space-y-2">
        <AgentRunBody run={run} onPivot={onSearchQuery} />

        {/* Hero CTA — when concluded, jump straight to the full Report
            (auto-written by the agent into case:{id}:ai:report). */}
        {concluded && onOpenReport && (
          <button
            onClick={onOpenReport}
            className="w-full mt-2 flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-emerald-50 border border-emerald-300 text-emerald-800 hover:bg-emerald-100 transition-colors text-xs font-semibold"
          >
            <FileBarChart size={13} />
            View full report
            <ExternalLink size={11} />
          </button>
        )}

        {/* Promote-to-actions row — only on concluded runs */}
        {concluded && (
          <div className="border-t border-purple-100 pt-3 mt-2 space-y-2">
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider">
              Close the loop
            </p>
            <div className="grid grid-cols-3 gap-2">
              <button
                onClick={flagEvidence}
                disabled={flagging || eventCount === 0}
                className="btn-secondary text-xs flex items-center justify-center gap-1.5"
                title="Flag every event surfaced during this run so it shows up in the case's flagged filter"
              >
                {flagging
                  ? <><Loader2 size={11} className="animate-spin" /> Flagging…</>
                  : <><Flag size={11} /> Flag {eventCount}</>}
              </button>
              <button
                onClick={promoteIocs}
                disabled={promoting || !hasIndicators}
                className="btn-secondary text-xs flex items-center justify-center gap-1.5"
                title="Push the agent's IOCs to the global watchlist"
              >
                {promoting
                  ? <><Loader2 size={11} className="animate-spin" /> …</>
                  : <><ListChecks size={11} /> Promote {final.indicators?.length || 0}</>}
              </button>
              <button
                onClick={() => setShowFollowup(v => !v)}
                disabled={!onFollowup}
                className={`text-xs flex items-center justify-center gap-1.5 rounded-lg border transition-colors ${
                  showFollowup
                    ? 'bg-purple-100 text-purple-800 border-purple-300'
                    : 'bg-white text-purple-700 border-purple-200 hover:bg-purple-50'
                }`}
                title="Ask the agent a follow-up question that builds on this run"
              >
                <ChevronRight size={11} className={showFollowup ? 'rotate-90 transition-transform' : 'transition-transform'} />
                Follow up
              </button>
            </div>

            {showFollowup && (
              <div className="border border-purple-200 rounded-lg p-2 bg-purple-50/40 space-y-1.5">
                <textarea
                  value={followupText}
                  onChange={e => setFollowupText(e.target.value)}
                  rows={2}
                  placeholder="e.g. now check whether the same user logged in from another host within 10 minutes"
                  className="w-full text-[11px] border border-purple-200 rounded px-2 py-1.5 resize-none outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-200"
                />
                <div className="flex justify-end gap-1">
                  <button
                    onClick={() => { setShowFollowup(false); setFollowupText('') }}
                    className="btn-ghost text-[11px] text-gray-600"
                  >Cancel</button>
                  <button
                    onClick={() => {
                      if (!followupText.trim()) return
                      onFollowup?.(idx, followupText.trim())
                      setFollowupText(''); setShowFollowup(false)
                    }}
                    disabled={!followupText.trim()}
                    className="btn-primary text-[11px] bg-purple-600 hover:bg-purple-700 border-purple-600 flex items-center gap-1"
                  >
                    <Bot size={10} /> Run follow-up
                  </button>
                </div>
              </div>
            )}

            {flagResult && (
              <p className="text-[10px] text-emerald-700 bg-emerald-50 border border-emerald-200 rounded px-2 py-1">
                Flagged {flagResult.flagged} · skipped {flagResult.skipped}
              </p>
            )}
            {promoteResult && (
              <p className="text-[10px] text-emerald-700 bg-emerald-50 border border-emerald-200 rounded px-2 py-1">
                Added {promoteResult.added} watchlist entr{promoteResult.added === 1 ? 'y' : 'ies'} · skipped {promoteResult.skipped}
              </p>
            )}
            {actionErr && (
              <p className="text-[10px] text-red-700 bg-red-50 border border-red-200 rounded px-2 py-1">
                {actionErr}
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function InvestigationBlock({ inv, idx, onDelete, onSearchQuery }) {
  return (
    <div className="border border-gray-200 rounded-xl overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2.5 bg-gray-50 border-b border-gray-100">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium text-brand-text truncate">{inv.circumstance || 'Investigation'}</p>
          <p className="text-[10px] text-gray-500 mt-0.5">{inv.model_used} · {inv.analyzed_at ? new Date(inv.analyzed_at).toLocaleString() : ''}</p>
        </div>
        <button onClick={() => onDelete(idx)} className="icon-btn text-gray-500 hover:text-red-500 ml-2 flex-shrink-0" title="Delete">
          <Trash2 size={12} />
        </button>
      </div>
      <div className="p-4 space-y-4">
        {inv.narrative && (
          <div className="bg-brand-accent/5 border border-brand-accent/20 rounded-xl p-3">
            <p className="text-xs font-semibold text-brand-accent uppercase tracking-widest mb-2">Analysis</p>
            <p className="text-sm text-gray-700 leading-relaxed">{inv.narrative}</p>
          </div>
        )}
        {inv.suggested_queries?.length > 0 && (
          <div>
            <div className="flex items-center gap-1.5 mb-2">
              <Search size={12} className="text-gray-500" />
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest">Suggested Queries</p>
            </div>
            <div className="space-y-2">
              {inv.suggested_queries.map((q, i) => {
                // Backend pre-runs each query and attaches result_count so
                // analysts see hit counts before clicking. Zero-hit queries
                // are de-emphasized; invalid ones get a clear error chip.
                const hits = q.result_count
                const invalid = q.query_status === 'invalid'
                const empty   = !invalid && (hits === 0)
                return (
                  <div
                    key={i}
                    className={`border rounded-lg p-2.5 transition-colors ${
                      invalid ? 'border-red-200 bg-red-50/40' :
                      empty   ? 'border-gray-200 bg-gray-50/50 opacity-70' :
                                'border-gray-200 hover:border-brand-accent/40'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-xs font-semibold text-brand-text">{q.label}</span>
                        {invalid ? (
                          <span className="text-[10px] font-semibold text-red-700 bg-red-100 px-1.5 py-0.5 rounded">
                            invalid
                          </span>
                        ) : typeof hits === 'number' ? (
                          <span
                            className={`text-[10px] font-semibold px-1.5 py-0.5 rounded tabular-nums ${
                              hits === 0
                                ? 'bg-gray-100 text-gray-500'
                                : hits > 10000
                                  ? 'bg-amber-100 text-amber-700'
                                  : 'bg-emerald-100 text-emerald-700'
                            }`}
                            title={hits === 0 ? 'No events match this query in the current case' :
                                   hits > 10000 ? 'Very broad — consider narrowing before pivoting' :
                                   'Click Search to pivot the timeline'}
                          >
                            {hits.toLocaleString()} {hits === 1 ? 'hit' : 'hits'}
                          </span>
                        ) : null}
                      </div>
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <CopyButton text={q.query} />
                        {onSearchQuery && !invalid && (
                          <button
                            onClick={() => onSearchQuery(q.query)}
                            disabled={empty}
                            className={`text-[11px] font-medium ${
                              empty
                                ? 'text-gray-400 cursor-not-allowed'
                                : 'text-brand-accent hover:underline'
                            }`}
                          >
                            Search →
                          </button>
                        )}
                      </div>
                    </div>
                    <code className="text-[11px] text-gray-600 bg-gray-50 rounded-lg px-2 py-1 block font-mono break-all">
                      {q.query}
                    </code>
                    {q.explanation && <p className="text-[11px] text-gray-500 mt-1.5">{q.explanation}</p>}
                    {invalid && q.query_error && (
                      <p className="text-[10px] text-red-700 mt-1 font-mono break-all">
                        {q.query_error}
                      </p>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
        {inv.indicators?.length > 0 && (
          <div>
            <div className="flex items-center gap-1.5 mb-2">
              <TrendingUp size={12} className="text-gray-500" />
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest">What to Look For</p>
            </div>
            <ul className="space-y-1">
              {inv.indicators.map((ind, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                  <span className="text-brand-accent flex-shrink-0 mt-0.5">•</span>
                  <span>{ind}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
        {inv.mitre_techniques?.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-2">MITRE ATT&CK</p>
            <div className="flex flex-wrap gap-1.5">
              {inv.mitre_techniques.map((t, i) => <Tag key={i} color="red">{t}</Tag>)}
            </div>
          </div>
        )}
        {inv.escalation_triggers?.length > 0 && (
          <div className="bg-red-50 border border-red-200 rounded-xl p-3">
            <div className="flex items-center gap-1.5 mb-2">
              <AlertTriangle size={12} className="text-red-600" />
              <p className="text-xs font-semibold text-red-700 uppercase tracking-widest">Escalation Triggers</p>
            </div>
            <ul className="space-y-1">
              {inv.escalation_triggers.map((t, i) => (
                <li key={i} className="text-sm text-red-700">{t}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

export default function CaseAiPanel({ caseId, onClose, onSearchQuery, onOpenReport }) {
  const [loading, setLoading]        = useState(true)
  // Scrollable content container — we reset its scroll to the top once
  // loading finishes so the panel always opens on Autopilot (top), not
  // wherever the browser landed by default.
  const scrollRef = useRef(null)
  useLayoutEffect(() => {
    if (!loading && scrollRef.current) scrollRef.current.scrollTop = 0
  }, [loading])

  // ── Risk assessment state
  const [analysis, setAnalysis]       = useState(null)
  const [analyzing, setAnalyzing]     = useState(false)
  const [analyzeErr, setAnalyzeErr]   = useState(null)

  // ── Investigation state
  // The scenario/context is SAVED per case (localStorage) so it survives panel
  // close, reload, and browser restart — analysts don't retype it.
  const _circKey = `fo_ai_circ_${caseId}`
  const [circumstance, setCircumstance]       = useState(() => {
    try { return localStorage.getItem(`fo_ai_circ_${caseId}`) || '' } catch { return '' }
  })
  useEffect(() => {
    try {
      if (circumstance) localStorage.setItem(_circKey, circumstance)
      else localStorage.removeItem(_circKey)
    } catch { /* ignore quota/availability */ }
  }, [circumstance, _circKey])
  const [investigations, setInvestigations]   = useState([])
  const [investigating, setInvestigating]     = useState(false)
  const [investigateErr, setInvestigateErr]   = useState(null)

  // ── Autopilot agent state
  const [agentRuns, setAgentRuns]   = useState([])
  const [agentErr,  setAgentErr]    = useState(null)
  // Language for the autopilot's auto-drafted report. The analyst picks the real
  // report language at generation time (Report tab, persisted as fo_report_lang);
  // we reuse that choice here so the quick auto-draft matches, falling back to
  // browser locale then English. No selector lives in this panel anymore.
  const SUPPORTED_LANGS = ['en','fr','es','de','it','pt','nl','ja','zh']
  const language = (() => {
    const saved = localStorage.getItem('fo_report_lang') || localStorage.getItem('fo_ai_report_lang')
    if (saved && SUPPORTED_LANGS.includes(saved)) return saved
    const auto = (navigator.language || 'en').slice(0,2).toLowerCase()
    return SUPPORTED_LANGS.includes(auto) ? auto : 'en'
  })()
  // Background-run state. Maps run_id → { meta, steps, since }. Multiple
  // can be in flight (e.g. follow-up while another is still running). Each
  // polls /progress every 2s; auto-stops once the meta.status leaves
  // "running".
  const [liveRuns, setLiveRuns] = useState({})
  // Abnormal run endings (stalled / crashed) — shown as dismissible notices.
  const [agentNotices, setAgentNotices] = useState([])
  const agentBusy = Object.values(liveRuns).some(r => r.meta?.status === 'running')

  // Load persisted results + in-flight runs on open
  useEffect(() => {
    Promise.all([
      api.cases.aiResults(caseId).catch(() => null),
      api.cases.aiAgentActive(caseId).catch(() => null),
    ])
      .then(([res, active]) => {
        if (res?.analysis)       setAnalysis(res.analysis)
        if (res?.investigations) setInvestigations(res.investigations)
        if (res?.agent_runs)     setAgentRuns(res.agent_runs)
        // Attach any in-flight runs — analyst can refresh / reopen and still
        // see them progressing.
        if (active?.runs?.length) {
          const m = {}
          for (const r of active.runs) {
            if (r.status === 'running') m[r.run_id] = { meta: r, steps: [], since: 0 }
          }
          if (Object.keys(m).length) setLiveRuns(m)
        }
      })
      .finally(() => setLoading(false))
  }, [caseId])

  // Poll progress for every in-flight run while the panel is open
  useEffect(() => {
    const active = Object.values(liveRuns).filter(r => r.meta?.status === 'running')
    if (active.length === 0) return undefined
    let cancelled = false
    const tick = async () => {
      await Promise.all(active.map(async r => {
        try {
          const p = await api.cases.aiAgentProgress(caseId, r.meta.run_id, r.since)
          if (cancelled) return
          setLiveRuns(prev => {
            const cur = prev[r.meta.run_id]
            if (!cur) return prev
            // Dedupe by step number — `r.since` is captured from the effect
            // closure and goes stale across setInterval ticks, so the same
            // progress slice gets fetched repeatedly. Filtering by step.step
            // is bulletproof regardless of polling drift.
            const seen = new Set((cur.steps || []).map(s => s.step))
            const fresh = (p.steps || []).filter(s => !seen.has(s.step))
            const newSteps = [...(cur.steps || []), ...fresh]
            const newMeta  = p.meta || cur.meta
            return { ...prev, [r.meta.run_id]: { meta: newMeta, steps: newSteps, since: p.next_since } }
          })
          // If this run just finished, fetch the persisted record so it
          // joins the regular agentRuns list.
          if (p.meta && p.meta.status !== 'running') {
            // Abnormal endings (worker died on API restart, LLM crash) never
            // reach the persisted list — surface them instead of vanishing.
            if (['stalled', 'error'].includes(p.meta.status)) {
              setAgentNotices(prev => [...prev, {
                run_id: r.meta.run_id,
                circumstance: r.meta.circumstance,
                error: p.meta.error || `Run ${p.meta.status}`,
              }])
            }
            const fresh = await api.cases.aiResults(caseId).catch(() => null)
            if (!cancelled && fresh?.agent_runs) setAgentRuns(fresh.agent_runs)
            setLiveRuns(prev => {
              const next = { ...prev }
              delete next[r.meta.run_id]
              return next
            })
          }
        } catch { /* polling-tolerant — keep going */ }
      }))
    }
    tick()  // immediate poll on mount/dep-change
    const h = setInterval(tick, 2000)
    return () => { cancelled = true; clearInterval(h) }
  }, [Object.keys(liveRuns).join(','), caseId])

  async function runAnalysis() {
    setAnalyzing(true)
    setAnalyzeErr(null)
    try {
      const res = await api.cases.aiAnalyze(caseId)
      setAnalysis(res)
    } catch (e) {
      setAnalyzeErr(e.message || 'Analysis failed')
    } finally {
      setAnalyzing(false)
    }
  }

  async function runInvestigation() {
    if (!circumstance.trim()) return
    setInvestigating(true)
    setInvestigateErr(null)
    try {
      const res = await api.cases.aiInvestigate(caseId, circumstance.trim())
      setInvestigations(prev => [res, ...prev])
      // Keep `circumstance` (was clearing previously) so the analyst can
      // tweak + rerun without retyping the whole scenario.
    } catch (e) {
      setInvestigateErr(e.message || 'Investigation failed')
    } finally {
      setInvestigating(false)
    }
  }

  async function _startAgent(circ, parentRunIdx) {
    setAgentErr(null)
    try {
      // No client-side step cap — backend's AGENT_MAX_STEPS (50) is the
      // real safety net. Agent stops at conclusion, not at budget.
      const { run_id } = await api.cases.aiAgentStart(caseId, circ, undefined, parentRunIdx, language)
      // Seed a live entry so the poll-effect picks it up immediately
      setLiveRuns(prev => ({
        ...prev,
        [run_id]: {
          meta: { run_id, status: 'running', circumstance: circ,
                  step_count: 0, started_at: new Date().toISOString() },
          steps: [], since: 0,
        },
      }))
    } catch (e) {
      setAgentErr(e.message || 'Autopilot failed to start')
    }
  }

  async function runAgent() {
    if (!circumstance.trim()) return
    // Keep `circumstance` so analyst can tweak + rerun without retyping.
    await _startAgent(circumstance.trim(), null)
  }

  async function runFollowup(parentIdx, circ) {
    if (!circ) return
    await _startAgent(circ, parentIdx)
  }

  async function cancelAgent(runId) {
    try {
      await api.cases.aiAgentCancel(caseId, runId)
      // Optimistic UI — mark the run as 'cancelling' so the spinner stops
      setLiveRuns(prev => {
        const cur = prev[runId]
        if (!cur) return prev
        return { ...prev, [runId]: { ...cur, meta: { ...cur.meta, status: 'cancelling' } } }
      })
    } catch (e) {
      setAgentErr(e.message || 'Cancel failed')
    }
  }

  async function clearAnalysis(opts = {}) {
    const includeReport = !!opts.includeReport
    const what = includeReport
      ? 'Clear ALL AI state (risk assessment + suggestions + agent runs + auto-generated report)?'
      : 'Clear AI working data (risk + suggestions + agent runs)? The generated Report is kept.'
    if (!confirm(what)) return
    setAnalysis(null)
    setInvestigations([])
    setAgentRuns([])
    await api.cases.aiDeleteResults(caseId, includeReport).catch(() => {})
  }

  async function clearAgentRuns() {
    if (!confirm('Clear the Autopilot run history? The generated Report (if any) is kept.')) return
    setAgentRuns([])
    await api.cases.aiDeleteAgentRuns(caseId).catch(() => {})
  }

  async function deleteInvestigation(idx) {
    await api.cases.aiDeleteInvestigation(caseId, idx).catch(() => {})
    setInvestigations(prev => prev.filter((_, i) => i !== idx))
  }

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="panel-drawer md:w-[640px]"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Sparkles size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">AI Analysis</span>
          </div>
          <div className="flex items-center gap-1">
            {/* Clear buttons always visible — analyst doesn't need to wait
                until there's content. Backend tolerates DELETE on empty
                keys (it's a no-op), so clicking when empty is harmless. */}
            <button
              onClick={clearAgentRuns}
              disabled={agentRuns.length === 0}
              className="btn-ghost text-xs text-purple-600 hover:text-purple-800 gap-1 disabled:opacity-40 disabled:cursor-not-allowed"
              title={agentRuns.length === 0
                ? 'No Autopilot runs to clear'
                : 'Clear Autopilot run history (keeps the generated Report)'}
            >
              <Trash2 size={11} /> Clear runs
            </button>
            <button
              onClick={() => clearAnalysis({ includeReport: false })}
              disabled={!analysis && investigations.length === 0 && agentRuns.length === 0}
              className="btn-ghost text-xs text-red-500 hover:text-red-700 gap-1 disabled:opacity-40 disabled:cursor-not-allowed"
              title="Clear AI working data (analysis + suggestions + runs). Report stays."
            >
              <Trash2 size={11} /> Clear AI
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" aria-label="Close"><X size={16} /></button>
          </div>
        </div>

        {loading ? (
          <div className="flex-1 flex items-center justify-center">
            <Loader2 size={20} className="animate-spin text-gray-500" />
          </div>
        ) : (
          <div
            ref={scrollRef}
            className="flex-1 overflow-y-auto"
          >
            <div className="px-5 pt-4">
              <PanelHelp title="Pilot — AI investigation"
                use="Runs an autonomous AI investigation: it forms competing hypotheses, pivots through the case data with tools, and concludes with a calibrated verdict."
                when="For a fast first-pass read on a case, or to investigate a specific scenario you describe."
                data={['Ingested events to investigate','An LLM provider configured in Settings → AI']}
                tip="Give it a concrete scenario — vague prompts produce vague verdicts." />
            </div>

            {/* ── AI Autopilot (hero/top-centered) — first in source order so
                the panel naturally scrolls to the top of this section on
                open. Risk Assessment is rendered below as a quick-score
                companion. */}
            <section className="px-5 pt-6 pb-5 border-b border-gray-100 bg-gradient-to-b from-purple-50/40 to-transparent">
              {/* Centered hero header */}
              <div className="text-center mb-5">
                <div className="inline-flex items-center gap-2 mb-1">
                  <Bot size={18} className="text-purple-700" />
                  <h2 className="text-lg font-bold text-brand-text tracking-tight">AI Autopilot</h2>
                </div>
                <p className="text-[11px] text-gray-500 mt-0.5">
                  Autonomous DFIR investigator — runs its own queries, drills into hits, concludes on its own.
                </p>
              </div>

              <div className="mb-3 max-w-xl mx-auto">
                <label className="text-[10px] uppercase tracking-wider font-semibold text-gray-500 block mb-1.5 text-center">
                  Investigation context
                </label>
                <textarea
                  value={circumstance}
                  onChange={e => setCircumstance(e.target.value)}
                  rows={4}
                  placeholder="e.g. The user may have executed a malicious executable downloaded from the browser. Looking for persistence, lateral movement, or data exfiltration."
                  className="w-full text-sm border border-gray-200 rounded-xl px-3 py-2.5 resize-none outline-none focus:border-purple-400 focus:ring-2 focus:ring-purple-200 transition-colors placeholder-gray-400 bg-white shadow-sm"
                />
                <p className="text-[10px] text-gray-500 mt-1 text-center italic">
                  The context stays here after each run — rerun, refine, or build follow-ups on the same investigation.
                  Report language is chosen when you generate the report (Report tab).
                </p>
              </div>
              <div className="grid grid-cols-2 gap-2 mb-4 max-w-xl mx-auto">
                <button
                  onClick={runInvestigation}
                  disabled={investigating || agentBusy || !circumstance.trim()}
                  className="btn-secondary text-xs justify-center flex items-center gap-1.5"
                  title="One-shot — LLM proposes queries you execute manually"
                >
                  {investigating
                    ? <><Loader2 size={12} className="animate-spin" /> Suggesting…</>
                    : <><Lightbulb size={12} /> Suggest Queries</>
                  }
                </button>
                <button
                  onClick={runAgent}
                  disabled={investigating || agentBusy || !circumstance.trim()}
                  className="btn-primary text-xs justify-center flex items-center gap-2 bg-purple-600 hover:bg-purple-700 border-purple-600 shadow-sm"
                  title="Multi-step — LLM runs queries, observes results, drills deeper, auto-writes the report. Survives panel close."
                >
                  {agentBusy
                    ? <><Loader2 size={13} className="animate-spin" /> Investigating…</>
                    : <><Bot size={13} /> Run Autopilot</>
                  }
                </button>
              </div>
              {(investigateErr || agentErr) && (
                <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5 mb-4">
                  <AlertTriangle size={12} /> {investigateErr || agentErr}
                </div>
              )}

              {/* Live in-progress agents — one card per in-flight run.
                  Runs survive panel close + reopen because progress is
                  persisted server-side and polled on mount. */}
              {Object.values(liveRuns).map(r => {
                const cancelling = r.meta?.status === 'cancelling'
                return (
                  <div key={r.meta.run_id} className="border-2 border-purple-300 border-dashed rounded-xl mb-4 bg-purple-50/30">
                    <div className="flex items-center justify-between px-4 py-2.5 border-b border-purple-200 bg-purple-50">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-purple-900 truncate flex items-center gap-1.5">
                          <Loader2 size={11} className="animate-spin text-purple-600" />
                          {cancelling ? 'Cancelling: ' : 'Autopilot live: '}
                          {r.meta.circumstance}
                        </p>
                        <p className="text-[10px] text-purple-600/80 mt-0.5">
                          {r.steps.length} step{r.steps.length === 1 ? '' : 's'} · running in background
                          · safe to close the panel
                        </p>
                      </div>
                      <button
                        onClick={() => cancelAgent(r.meta.run_id)}
                        disabled={cancelling}
                        className="btn-ghost text-[11px] text-purple-700 hover:text-red-600 flex items-center gap-1"
                        title="Cooperative cancel — stops at the next inter-step boundary"
                      >
                        <X size={11} /> {cancelling ? 'Cancelling…' : 'Stop'}
                      </button>
                    </div>
                    <div className="p-3 space-y-2">
                      {r.steps.map((s, i) => (
                        <AgentStepRow key={i} step={s} onPivot={q => { onSearchQuery?.(q); onClose() }} />
                      ))}
                      {r.steps.length === 0 && (
                        <div className="text-[11px] text-purple-700 italic px-2 py-3">
                          Asking the model for its first move…
                        </div>
                      )}
                    </div>
                  </div>
                )
              })}

              {/* Abnormal endings — stalled (API restart) or crashed runs */}
              {agentNotices.map((n, i) => (
                <div key={n.run_id || i} className="flex items-start gap-2 mb-3 px-3 py-2 rounded-lg bg-amber-50 border border-amber-300 text-amber-800">
                  <AlertTriangle size={13} className="flex-shrink-0 mt-0.5" />
                  <div className="flex-1 min-w-0 text-xs">
                    <p className="font-medium truncate">Autopilot run ended abnormally: {n.circumstance}</p>
                    <p className="text-[11px] mt-0.5">{n.error}</p>
                  </div>
                  <button
                    onClick={() => setAgentNotices(prev => prev.filter(x => x.run_id !== n.run_id))}
                    className="icon-btn text-amber-600 hover:text-amber-800"
                  >
                    <X size={12} />
                  </button>
                </div>
              ))}

              {/* Persisted runs */}
              {agentRuns.length > 0 && (
                <div className="space-y-3 mb-4">
                  {agentRuns.map((run, i) => (
                    <AgentRunBlock
                      key={i}
                      run={run}
                      idx={i}
                      caseId={caseId}
                      onSearchQuery={q => { onSearchQuery?.(q); onClose() }}
                      onFollowup={runFollowup}
                      onOpenReport={onOpenReport}
                    />
                  ))}
                </div>
              )}

              {investigations.length > 0 && (
                <div className="space-y-3">
                  {investigations.map((inv, i) => (
                    <InvestigationBlock
                      key={i}
                      inv={inv}
                      idx={i}
                      onDelete={deleteInvestigation}
                      onSearchQuery={q => { onSearchQuery?.(q); onClose() }}
                    />
                  ))}
                </div>
              )}
            </section>

            {/* ── Risk Assessment — secondary quick-score companion ── */}
            <section className="px-5 py-5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Shield size={14} className="text-brand-accent" />
                  <h3 className="text-sm font-semibold text-brand-text">Risk Assessment</h3>
                  {analysis && <span className="text-[10px] text-gray-500">· saved</span>}
                </div>
                <button
                  onClick={runAnalysis}
                  disabled={analyzing}
                  className="btn-primary text-xs"
                >
                  {analyzing
                    ? <><Loader2 size={12} className="animate-spin" /> Analyzing…</>
                    : <><Sparkles size={12} /> {analysis ? 'Re-analyze' : 'Analyze Case'}</>
                  }
                </button>
              </div>

              {analyzeErr && (
                <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5 mb-3">
                  <AlertTriangle size={12} /> {analyzeErr}
                </div>
              )}

              {!analysis && !analyzing && (
                <p className="text-xs text-gray-500 italic">
                  Click "Analyze Case" to generate a risk assessment. Results are saved automatically.
                </p>
              )}

              {analysis && (
                <div className="space-y-4">
                  <RiskGauge score={analysis.risk_score} level={analysis.risk_level} />

                  {analysis.executive_summary && (
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-1.5">Summary</p>
                      <p className="text-sm text-gray-700 leading-relaxed">{analysis.executive_summary}</p>
                    </div>
                  )}

                  {analysis.key_findings?.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-2">Key Findings</p>
                      <ul className="space-y-1.5">
                        {analysis.key_findings.map((f, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                            <ChevronRight size={13} className="text-brand-accent flex-shrink-0 mt-0.5" />
                            <span>{f}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {analysis.mitre_techniques?.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-2">MITRE ATT&CK</p>
                      <div className="flex flex-wrap gap-1.5">
                        {analysis.mitre_techniques.map((t, i) => <Tag key={i} color="red">{t}</Tag>)}
                      </div>
                    </div>
                  )}

                  {analysis.recommended_actions?.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold text-gray-500 uppercase tracking-widest mb-2">Recommended Actions</p>
                      <ol className="space-y-1.5 list-none">
                        {analysis.recommended_actions.map((a, i) => (
                          <li key={i} className="flex items-start gap-2 text-sm text-gray-700">
                            <span className="flex-shrink-0 w-4 h-4 rounded-full bg-brand-accent/10 text-brand-accent text-[10px] font-bold flex items-center justify-center mt-0.5">{i+1}</span>
                            <span>{a}</span>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}

                  <p className="text-[10px] text-gray-500">
                    Confidence: {analysis.confidence} · {analysis.model_used} · {analysis.analyzed_at ? new Date(analysis.analyzed_at).toLocaleString() : ''}
                  </p>
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  )
}
