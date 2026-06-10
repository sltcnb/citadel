import { useState, useRef } from 'react'
import {
  FileCode, X, Sparkles, Upload, Check, Loader2, AlertTriangle, Building2,
} from 'lucide-react'
import Editor from '@monaco-editor/react'
import { api } from '../api/client'
import { useCompanies } from '../pages/UserManagement'

// ── Shared constants ──────────────────────────────────────────────────────────

export const SIGMA_STARTER = `title: Rule Name
description: Describe what this rule detects
status: experimental
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection
level: medium
tags:
  - attack.credential_access
  - attack.t1110`

export const CUSTOM_STARTER = `# Custom alert rule
name: My Rule
description: Describe what this detects
category: Other
artifact_type: evtx
query: evtx.event_id:4625
threshold: 1`

export const CATEGORY_ORDER = [
  'Anti-Forensics', 'Authentication', 'Privilege Escalation', 'Persistence',
  'Execution', 'Lateral Movement', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Command & Control', 'Exfiltration', 'Other',
]

export const CATEGORY_STYLES = {
  'Anti-Forensics':    { bg: 'bg-rose-100 text-rose-700 border-rose-200',        dot: 'bg-rose-400'    },
  'Authentication':    { bg: 'bg-blue-100 text-blue-700 border-blue-200',         dot: 'bg-blue-400'    },
  'Privilege Escalation': { bg: 'bg-orange-100 text-orange-700 border-orange-200', dot: 'bg-orange-400' },
  'Persistence':       { bg: 'bg-yellow-100 text-yellow-700 border-yellow-200',   dot: 'bg-yellow-500'  },
  'Execution':         { bg: 'bg-purple-100 text-purple-700 border-purple-200',   dot: 'bg-purple-400'  },
  'Lateral Movement':  { bg: 'bg-cyan-100 text-cyan-700 border-cyan-200',         dot: 'bg-cyan-400'    },
  'Defense Evasion':   { bg: 'bg-slate-100 text-slate-700 border-slate-200',      dot: 'bg-slate-400'   },
  'Credential Access': { bg: 'bg-red-100 text-red-700 border-red-200',            dot: 'bg-red-400'     },
  'Discovery':         { bg: 'bg-teal-100 text-teal-700 border-teal-200',         dot: 'bg-teal-400'    },
  'Command & Control': { bg: 'bg-indigo-100 text-indigo-700 border-indigo-200',   dot: 'bg-indigo-400'  },
  'Exfiltration':      { bg: 'bg-pink-100 text-pink-700 border-pink-200',         dot: 'bg-pink-400'    },
  'Other':             { bg: 'bg-gray-100 text-gray-600 border-gray-200',         dot: 'bg-gray-400'    },
}

export const SIGMA_LEVEL_STYLES = {
  critical: 'bg-red-100 text-red-700 border-red-200',
  high:     'bg-orange-100 text-orange-700 border-orange-200',
  medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
  low:      'bg-blue-100 text-blue-700 border-blue-200',
  info:     'bg-gray-100 text-gray-600 border-gray-200',
}

export function _alertRuleToCode(rule) {
  if (rule.sigma_yaml) return rule.sigma_yaml
  return [
    '# Custom alert rule',
    `name: ${rule.name || ''}`,
    `description: ${rule.description || ''}`,
    `category: ${rule.category || ''}`,
    `artifact_type: ${rule.artifact_type || ''}`,
    `query: ${rule.query || ''}`,
    `threshold: ${rule.threshold ?? 1}`,
  ].join('\n') + '\n'
}

export function _parseCustomYaml(text) {
  const get = k => {
    const m = text.match(new RegExp(`^${k}:\\s*(.+)$`, 'm'))
    return m ? m[1].replace(/^["']|["']$/g, '').trim() : ''
  }
  return {
    name: get('name'), description: get('description'), category: get('category'),
    artifact_type: get('artifact_type'), query: get('query'),
    threshold: parseInt(get('threshold'), 10) || 1, sigma_yaml: '',
  }
}

// ── Badges ────────────────────────────────────────────────────────────────────

export function CategoryBadge({ category }) {
  if (!category) return null
  const style = CATEGORY_STYLES[category] || CATEGORY_STYLES['Other']
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-medium border rounded-full px-2 py-0.5 ${style.bg}`}>
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot}`} />
      {category}
    </span>
  )
}

export function SigmaLevelBadge({ level }) {
  if (!level) return null
  const cls = SIGMA_LEVEL_STYLES[level.toLowerCase()] || SIGMA_LEVEL_STYLES.info
  return (
    <span className={`inline-flex items-center text-[10px] font-medium border rounded-full px-2 py-0.5 ${cls}`}>
      {level}
    </span>
  )
}

// ── Rule Drawer ───────────────────────────────────────────────────────────────
// rule=null → create, rule=object → edit
// inline=true → renders inside editor zone instead of as modal overlay
export default function RuleDrawer({ rule = null, onClose, onSaved, inline = false }) {
  const isEdit        = !!rule
  const fileRef       = useRef(null)
  const monacoRef     = useRef(null)   // { editor, monaco }
  const lintTimer     = useRef(null)
  const companyList   = useCompanies()

  const initialKind = rule ? (rule.sigma_yaml ? 'sigma' : 'custom') : 'sigma'
  const [kind,       setKind]       = useState(initialKind)
  const [yamlText,   setYamlText]   = useState(() => rule ? _alertRuleToCode(rule) : SIGMA_STARTER)
  const [companies,  setCompanies]  = useState(rule?.companies || [])
  const [coSearch,   setCoSearch]   = useState('')
  const [saving,     setSaving]     = useState(false)
  const [error,      setError]      = useState('')
  const [preview,    setPreview]    = useState(null)
  const [previewing, setPreviewing] = useState(false)

  const [showAI,    setShowAI]    = useState(false)
  const [aiDesc,    setAiDesc]    = useState('')
  const [aiCtx,     setAiCtx]     = useState('')
  const [aiLoading, setAiLoading] = useState(false)
  const [aiError,   setAiError]   = useState('')

  function handleKindChange(k) {
    setKind(k)
    setYamlText(k === 'sigma' ? SIGMA_STARTER : CUSTOM_STARTER)
    setPreview(null)
  }

  function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => { setYamlText(ev.target.result || ''); setKind('sigma'); setPreview(null) }
    reader.readAsText(file)
    e.target.value = ''
  }

  async function generateWithAI() {
    if (!aiDesc.trim()) return
    setAiLoading(true); setAiError('')
    try {
      const res = await api.alertRules.generateSigmaRule({ description: aiDesc, context: aiCtx })
      setYamlText(res.yaml || ''); setKind('sigma'); setShowAI(false); setAiDesc(''); setAiCtx('')
    } catch (err) { setAiError(err.message) }
    finally { setAiLoading(false) }
  }

  async function runPreview() {
    if (!yamlText.trim()) return
    setPreviewing(true); setError('')
    try {
      const r = await api.alertRules.parseSigma({ yaml: yamlText })
      setPreview(r)
    } catch (err) { setError(err.message); setPreview(null) }
    finally { setPreviewing(false) }
  }

  async function doSave() {
    if (!yamlText.trim()) return
    setSaving(true); setError('')
    try {
      const isSigma = kind === 'sigma' || /^\s*title:\s*/m.test(yamlText)
      if (isEdit) {
        if (isSigma) {
          const parsed = await api.alertRules.parseSigma({ yaml: yamlText })
          const updated = await api.alertRules.updateLibraryRule(rule.id, {
            name: parsed.name, description: parsed.description, category: parsed.category,
            artifact_type: parsed.artifact_type, query: parsed.query,
            sigma_yaml: yamlText, companies,
          })
          onSaved(updated)
        } else {
          const parsed = _parseCustomYaml(yamlText)
          if (!parsed.name || !parsed.query) throw new Error('Custom rule needs name: and query: fields')
          const updated = await api.alertRules.updateLibraryRule(rule.id, { ...parsed, companies })
          onSaved(updated)
        }
      } else {
        if (isSigma) {
          const res = await api.alertRules.importSigma({ yaml: yamlText, companies })
          if (res.imported > 0) {
            onSaved(res.rules)
          } else {
            const reasons = res.skip_reasons?.map(r => r.reason) || []
            setError(reasons.join(' · ') || 'Rule could not be imported')
            setSaving(false); return
          }
        } else {
          const parsed = _parseCustomYaml(yamlText)
          if (!parsed.name || !parsed.query) throw new Error('Custom rule needs name: and query: fields')
          const created = await api.alertRules.createLibraryRule({ ...parsed, companies })
          onSaved([created])
        }
      }
      onClose()
    } catch (err) { setError(err.message) }
    finally { setSaving(false) }
  }

  function onEditorMount(editor, monaco) {
    monacoRef.current = { editor, monaco }
  }

  function scheduleLint(text) {
    clearTimeout(lintTimer.current)
    lintTimer.current = setTimeout(async () => {
      const ref = monacoRef.current
      if (!ref || !text.trim()) return
      const { editor, monaco } = ref
      const model = editor.getModel()
      if (!model) return
      const isSigma = kind === 'sigma' || /^\s*title:\s*/m.test(text)
      if (!isSigma) { monaco.editor.setModelMarkers(model, 'sigma', []); return }
      try {
        await api.alertRules.parseSigma({ yaml: text })
        monaco.editor.setModelMarkers(model, 'sigma', [])
      } catch (err) {
        const msg = err.message || 'Parse error'
        const lineMatch = msg.match(/line\s+(\d+)/i)
        const line = lineMatch ? Math.max(1, parseInt(lineMatch[1])) : 1
        const col = model.getLineContent(line)?.length || 0
        monaco.editor.setModelMarkers(model, 'sigma', [{
          severity: monaco.MarkerSeverity.Error,
          message: msg,
          startLineNumber: line,
          startColumn: 1,
          endLineNumber: line,
          endColumn: col + 1,
        }])
      }
    }, 900)
  }

  const drawerInner = (
    <div
      className={inline
        ? "flex flex-col h-full bg-white"
        : "bg-white border border-gray-200 rounded-xl w-full max-w-5xl shadow-2xl flex flex-col"}
      style={inline ? undefined : { height: '88vh' }}
    >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <FileCode size={15} className="text-brand-accent" />
            <span className="font-semibold text-brand-text text-sm">
              {isEdit ? `Edit: ${rule.name}` : 'New Detection Rule'}
            </span>
            {isEdit && rule.sigma_level && <SigmaLevelBadge level={rule.sigma_level} />}
            {isEdit && rule.category    && <CategoryBadge category={rule.category} />}
          </div>
          <button onClick={onClose} className="btn-ghost p-1"><X size={14} /></button>
        </div>

        {/* Body: Monaco left + Metadata right */}
        <div className="flex flex-1 min-h-0 overflow-hidden">

          {/* Editor column */}
          <div className="flex flex-col flex-1 min-w-0 overflow-hidden">

            {/* Toolbar */}
            <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-100 flex-shrink-0 bg-gray-50/60">
              {!isEdit && (
                <div className="flex gap-1 p-0.5 bg-gray-100 rounded-lg">
                  {[['sigma', 'Sigma YAML'], ['custom', 'Custom Query']].map(([k, lbl]) => (
                    <button key={k} onClick={() => handleKindChange(k)}
                      className={`text-xs px-2.5 py-1 rounded-md font-medium transition-colors ${
                        kind === k ? 'bg-white text-brand-accent shadow-sm' : 'text-gray-500 hover:text-gray-700'
                      }`}>{lbl}
                    </button>
                  ))}
                </div>
              )}
              <div className="ml-auto flex items-center gap-1.5">
                <button
                  onClick={() => setShowAI(v => !v)}
                  className={`btn-outline text-xs py-1 px-2.5 ${showAI ? 'bg-indigo-50 border-indigo-300 text-indigo-700' : ''}`}
                >
                  <Sparkles size={12} className="text-indigo-500" /> AI Generate
                </button>
                <input ref={fileRef} type="file" accept=".yml,.yaml" className="hidden" onChange={handleFile} />
                <button onClick={() => fileRef.current?.click()} className="btn-outline text-xs py-1 px-2.5">
                  <Upload size={12} /> Import .yml
                </button>
              </div>
            </div>

            {/* AI gen panel */}
            {showAI && (
              <div className="flex-shrink-0 border-b border-indigo-100 bg-indigo-50/60 px-4 py-3 space-y-2.5">
                <div className="flex items-center gap-1.5">
                  <Sparkles size={13} className="text-indigo-500" />
                  <span className="text-xs font-semibold text-indigo-700">Generate Sigma rule with AI</span>
                  <button onClick={() => setShowAI(false)} className="ml-auto btn-ghost p-0.5 text-indigo-400"><X size={12} /></button>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <input value={aiDesc} onChange={e => setAiDesc(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !e.shiftKey && generateWithAI()}
                    placeholder="What should this rule detect?" className="input text-xs" autoFocus />
                  <input value={aiCtx} onChange={e => setAiCtx(e.target.value)}
                    placeholder="Hints: EventID, field names, malware family…" className="input text-xs" />
                </div>
                {aiError && <p className="text-xs text-red-600 flex items-center gap-1"><AlertTriangle size={11} />{aiError}</p>}
                <button onClick={generateWithAI} disabled={!aiDesc.trim() || aiLoading} className="btn-primary text-xs">
                  {aiLoading ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
                  {aiLoading ? 'Generating…' : 'Generate'}
                </button>
              </div>
            )}

            {/* Monaco — inline uses flex-1 container; modal uses explicit height */}
            {inline ? (
              <div className="flex-1 overflow-hidden min-h-0">
                <Editor
                  height="100%"
                  language="yaml"
                  value={yamlText}
                  onChange={v => { const t = v ?? ''; setYamlText(t); setPreview(null); scheduleLint(t) }}
                  onMount={onEditorMount}
                  theme="vs-dark"
                  loading={<div className="flex items-center justify-center h-full text-gray-500 text-xs bg-[#1e1e1e]">Loading editor…</div>}
                  options={{
                    fontSize: 13,
                    fontFamily: '"JetBrains Mono", "Fira Code", ui-monospace, Menlo, Monaco, monospace',
                    minimap: { enabled: false },
                    lineNumbers: 'on',
                    folding: true,
                    wordWrap: 'on',
                    scrollBeyondLastLine: false,
                    padding: { top: 12, bottom: 12 },
                    bracketPairColorization: { enabled: true },
                  }}
                />
              </div>
            ) : (
              <Editor
                height="calc(88vh - 180px)"
                language="yaml"
                value={yamlText}
                onChange={v => { const t = v ?? ''; setYamlText(t); setPreview(null); scheduleLint(t) }}
                onMount={onEditorMount}
                theme="vs-dark"
                loading={<div className="flex items-center justify-center h-full text-gray-500 text-xs bg-[#1e1e1e]">Loading editor…</div>}
                options={{
                  fontSize: 13,
                  fontFamily: '"JetBrains Mono", "Fira Code", ui-monospace, Menlo, Monaco, monospace',
                  minimap: { enabled: false },
                  lineNumbers: 'on',
                  folding: true,
                  wordWrap: 'on',
                  scrollBeyondLastLine: false,
                  padding: { top: 12, bottom: 12 },
                  bracketPairColorization: { enabled: true },
                }}
              />
            )}
          </div>

          {/* Metadata panel */}
          <div className="w-72 flex-shrink-0 border-l border-gray-200 bg-gray-50/30 overflow-y-auto p-4 space-y-5">

            {/* Sigma preview */}
            {(kind === 'sigma' || (isEdit && rule?.sigma_yaml)) && (
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-xs font-semibold text-gray-700">Rule Preview</p>
                  <button onClick={runPreview} disabled={previewing}
                    className="text-[10px] text-brand-accent hover:underline flex items-center gap-0.5">
                    {previewing ? <Loader2 size={10} className="animate-spin" /> : null}
                    Parse YAML
                  </button>
                </div>
                {preview ? (
                  <div className="rounded-lg border border-gray-200 bg-white px-3 py-2.5 space-y-1.5 text-xs">
                    {preview.name && <p className="font-semibold text-gray-800 leading-tight">{preview.name}</p>}
                    {preview.description && <p className="text-gray-500 text-[11px] leading-snug">{preview.description}</p>}
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {preview.category    && <CategoryBadge category={preview.category} />}
                      {preview.sigma_level && <SigmaLevelBadge level={preview.sigma_level} />}
                    </div>
                    {preview.query && (
                      <div className="mt-1">
                        <p className="text-[10px] text-gray-500 mb-0.5">ES Query</p>
                        <code className="block text-[10px] text-indigo-600 bg-indigo-50 rounded px-2 py-1 break-all leading-relaxed">{preview.query}</code>
                      </div>
                    )}
                    {preview.sigma_tags?.filter(t => t.startsWith('attack.')).length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {preview.sigma_tags.filter(t => t.startsWith('attack.')).slice(0, 5).map(t => (
                          <span key={t} className="badge bg-blue-50 text-blue-600 border-blue-200 text-[10px]">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-[11px] text-gray-500 italic">Click "Parse YAML" to preview</p>
                )}
              </div>
            )}

            {/* Custom rule hints */}
            {kind === 'custom' && !isEdit && (
              <div className="text-[11px] text-gray-500 bg-white border border-gray-200 rounded-lg px-3 py-2.5 space-y-1 leading-snug">
                <p className="font-semibold text-gray-700 text-xs">Custom rule fields</p>
                {[
                  ['name',          'Display name for the rule'],
                  ['query',         'Lucene query run against events'],
                  ['category',      'MITRE category label'],
                  ['artifact_type', 'evtx, sysmon, auth, etc.'],
                  ['threshold',     'Min matches to fire (default 1)'],
                ].map(([k, desc]) => (
                  <p key={k}><code className="text-[10px] text-brand-accent">{k}:</code> {desc}</p>
                ))}
              </div>
            )}

            {/* Company scope — badges always visible; checkboxes when list loaded */}
            {(companyList.length > 0 || companies.length > 0) && (
              <div>
                <label className="text-xs font-semibold text-gray-700 mb-1.5 flex items-center gap-1">
                  <Building2 size={12} className="text-cyan-600" /> Company Scope
                </label>
                <p className="text-[10px] text-gray-500 mb-1.5">Leave empty = platform-wide</p>
                {companyList.length > 0 && (
                  <>
                    {companyList.length > 6 && (
                      <input className="input text-xs mb-1.5" placeholder="Filter companies…"
                        value={coSearch} onChange={e => setCoSearch(e.target.value)} />
                    )}
                    <div className="flex flex-wrap gap-1.5 border border-gray-200 rounded-lg px-3 py-2 max-h-36 overflow-y-auto bg-white">
                      {companyList.filter(c => c.toLowerCase().includes(coSearch.toLowerCase())).map(c => (
                        <label key={c} className="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer w-full">
                          <input type="checkbox"
                            checked={companies.includes(c)}
                            onChange={e => setCompanies(prev => e.target.checked ? [...prev, c] : prev.filter(x => x !== c))}
                            className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent flex-shrink-0"
                          />
                          {c}
                        </label>
                      ))}
                    </div>
                  </>
                )}
                {companies.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {companies.map(c => (
                      <span key={c} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px]">
                        <Building2 size={8} className="inline mr-0.5" />{c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                <AlertTriangle size={11} className="mt-0.5 flex-shrink-0" />
                <span className="leading-snug">{error}</span>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3.5 border-t border-gray-200 flex-shrink-0 flex items-center gap-2">
          <button onClick={doSave} disabled={!yamlText.trim() || saving} className="btn-primary text-xs">
            {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
            {isEdit ? 'Save Changes' : 'Create Rule'}
          </button>
          {!isEdit && kind === 'sigma' && (
            <p className="text-[10px] text-gray-500">Sigma YAML with a <code>title:</code> field will be auto-parsed on save</p>
          )}
          <button onClick={onClose} className="btn-ghost text-xs ml-auto">Cancel</button>
        </div>
    </div>
  )

  if (inline) return drawerInner
  return (
    <div
      className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      {drawerInner}
    </div>
  )
}
