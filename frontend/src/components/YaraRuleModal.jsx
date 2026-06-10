import { useState, useRef } from 'react'
import {
  FileCode, X, Upload, Check, Loader2, AlertTriangle, Sparkles, Building2,
} from 'lucide-react'
import Editor from '@monaco-editor/react'
import { api } from '../api/client'
import { useCompanies } from '../pages/UserManagement'

// ── YARA Monaco language (registered once) ────────────────────────────────────
let _yaraRegistered = false
function ensureYaraLang(monaco) {
  if (_yaraRegistered) return
  _yaraRegistered = true
  monaco.languages.register({ id: 'yara' })
  monaco.languages.setMonarchTokensProvider('yara', {
    keywords: [
      'rule', 'private', 'global', 'meta', 'strings', 'condition',
      'and', 'or', 'not', 'all', 'any', 'of', 'them', 'for', 'in',
      'at', 'filesize', 'entrypoint', 'true', 'false', 'import', 'include', 'none',
    ],
    tokenizer: {
      root: [
        [/\/\/[^\n]*/, 'comment'],
        [/\/\*/, 'comment', '@comment'],
        [/"[^"]*"/, 'string'],
        [/\{[\s0-9a-fA-F?()|]+\}/, 'string.escape'],   // hex string
        [/\/[^/\n]+\/[si]*/, 'regexp'],                 // regex
        [/\$[a-zA-Z_]\w*(\*)?/, 'variable'],            // string identifier
        [/#[a-zA-Z_]\w*/, 'variable.predefined'],       // string count
        [/@[a-zA-Z_]\w*/, 'variable.predefined'],       // string offset
        [/\b(?:rule|private|global|meta|strings|condition|and|or|not|all|any|of|them|for|in|at|filesize|entrypoint|true|false|import|include|none)\b/, 'keyword'],
        [/0x[0-9a-fA-F]+[KM]?/, 'number.hex'],
        [/[0-9]+[KM]?/, 'number'],
        [/[a-zA-Z_]\w*/, 'identifier'],
        [/[{}()\[\]]/, '@brackets'],
        [/[<>=!:+\-*\/&|^~?]/, 'operator'],
        [/[;,.]/, 'delimiter'],
      ],
      comment: [
        [/[^/*]+/, 'comment'],
        [/\*\//, 'comment', '@pop'],
        [/[/*]/, 'comment'],
      ],
    },
  })
  monaco.editor.defineTheme('yara-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'keyword',            foreground: '569cd6', fontStyle: 'bold' },
      { token: 'variable',           foreground: '9cdcfe' },
      { token: 'variable.predefined', foreground: '4ec9b0' },
      { token: 'string',             foreground: 'ce9178' },
      { token: 'string.escape',      foreground: 'd7ba7d' },
      { token: 'regexp',             foreground: 'd16969' },
      { token: 'comment',            foreground: '6a9955' },
      { token: 'number',             foreground: 'b5cea8' },
      { token: 'number.hex',         foreground: 'b5cea8' },
    ],
    colors: {},
  })
}

export default function YaraRuleModal({ rule = null, onClose, onSaved, openAI = false, inline = false }) {
  const isEdit      = !!(rule?.id)
  const fileRef     = useRef(null)
  const monacoRef   = useRef(null)   // { editor, monaco } — inline Monaco instance
  const lintTimer   = useRef(null)
  const companyList = useCompanies()

  const [name, setName]             = useState(rule?.name        || '')
  const [desc, setDesc]             = useState(rule?.description || '')
  const [tags, setTags]             = useState((rule?.tags || []).join(', '))
  const [companies, setCompanies]   = useState(rule?.companies   || [])
  const [coSearch, setCoSearch]     = useState('')
  const [content, setContent]       = useState(rule?.content     || '')
  const [saving, setSaving]         = useState(false)
  const [validating, setValid]      = useState(false)
  const [validResult, setVR]        = useState(null)
  const [error, setError]           = useState('')

  const [aiOpen, setAiOpen]         = useState(openAI)
  const [aiPrompt, setAiPrompt]     = useState('')
  const [aiContext, setAiContext]    = useState('')
  const [aiGenerating, setAiGen]    = useState(false)
  const [aiError, setAiError]       = useState('')
  const [aiModelUsed, setAiModel]   = useState('')

  async function generateWithAI() {
    if (!aiPrompt.trim()) return
    setAiGen(true)
    setAiError('')
    try {
      const r = await api.yaraRules.generateYara({ description: aiPrompt, context: aiContext })
      setContent(r.content || '')
      if (r.name && !name) setName(r.name)
      if (r.description && !desc) setDesc(r.description)
      if (r.tags?.length && !tags) setTags(r.tags.join(', '))
      setAiModel(r.model_used || '')
      setVR(null)
      setAiOpen(false)
    } catch (err) {
      setAiError(err.message)
    } finally {
      setAiGen(false)
    }
  }

  function handleFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      setContent(ev.target.result || '')
      if (!name) setName(file.name.replace(/\.yar(a)?$/i, ''))
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  async function validate() {
    if (!content.trim()) return
    setValid(true)
    setVR(null)
    try {
      const r = await api.modules.validateYara(content)
      setVR({ ok: r.valid, msg: r.message || (r.valid ? 'Syntax OK' : 'Invalid syntax') })
    } catch (err) {
      setVR({ ok: false, msg: err.message })
    } finally {
      setValid(false)
    }
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
      try {
        const r = await api.modules.validateYara(text)
        if (r.valid) {
          monaco.editor.setModelMarkers(model, 'yara', [])
        } else {
          const msg = r.message || 'Invalid syntax'
          const lineMatch = msg.match(/line\s+(\d+)/i)
          const line = lineMatch ? Math.max(1, parseInt(lineMatch[1])) : 1
          const colEnd = (model.getLineContent(line)?.length || 0) + 1
          monaco.editor.setModelMarkers(model, 'yara', [{
            severity: monaco.MarkerSeverity.Error,
            message: msg,
            startLineNumber: line, startColumn: 1,
            endLineNumber: line,   endColumn: colEnd,
          }])
        }
      } catch {}
    }, 900)
  }

  // Auto-validate textarea changes in modal mode
  function scheduleTextareaLint(text) {
    clearTimeout(lintTimer.current)
    lintTimer.current = setTimeout(async () => {
      if (!text.trim()) return
      try {
        const r = await api.modules.validateYara(text)
        setVR({ ok: r.valid, msg: r.message || (r.valid ? 'Syntax OK' : 'Invalid syntax') })
      } catch {}
    }, 900)
  }

  async function save() {
    if (!name.trim())    { setError('Name is required'); return }
    if (!content.trim()) { setError('Rule content is required'); return }
    setSaving(true)
    setError('')
    try {
      const tagList = tags.split(',').map(t => t.trim()).filter(Boolean)
      const body    = { name: name.trim(), description: desc.trim(), tags: tagList, companies, content }
      const saved   = isEdit
        ? await api.yaraRules.update(rule.id, body)
        : await api.yaraRules.create(body)
      onSaved(saved)
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }

  const header = (
    <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 flex-shrink-0">
      <div className="flex items-center gap-2">
        <FileCode size={16} className="text-brand-accent" />
        <h2 className="text-sm font-semibold">{isEdit ? 'Edit YARA Rule' : 'New YARA Rule'}</h2>
      </div>
      <button onClick={onClose} className="icon-btn"><X size={14} /></button>
    </div>
  )

  const footer = (
    <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-end gap-2 flex-shrink-0">
      <button onClick={onClose} className="btn-outline text-xs">Cancel</button>
      <button onClick={save} disabled={saving} className="btn-primary text-xs">
        {saving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
        {isEdit ? 'Save changes' : 'Create rule'}
      </button>
    </div>
  )

  const companyScope = (
    (companyList.length > 0 || companies.length > 0) ? (
      <div>
        <label className="text-xs font-medium text-gray-600 mb-1 flex items-center gap-1">
          <Building2 size={11} /> Company Scope
          <span className="text-gray-500 font-normal ml-1">(none = platform-wide)</span>
        </label>
        {companyList.length > 0 && (
          <>
            {companyList.length > 6 && (
              <input className="input text-xs mb-1" placeholder="Filter…"
                value={coSearch} onChange={e => setCoSearch(e.target.value)} />
            )}
            <div className="flex flex-wrap gap-2 border border-gray-200 rounded-lg px-3 py-2 max-h-28 overflow-y-auto">
              {companyList.filter(c => c.toLowerCase().includes(coSearch.toLowerCase())).map(c => (
                <label key={c} className="flex items-center gap-1.5 text-xs text-gray-700 cursor-pointer">
                  <input type="checkbox"
                    checked={companies.includes(c)}
                    onChange={e => setCompanies(prev => e.target.checked ? [...prev, c] : prev.filter(x => x !== c))}
                    className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
                  />
                  {c}
                </label>
              ))}
            </div>
          </>
        )}
        {companies.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1">
            {companies.map(c => (
              <span key={c} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px]">
                <Building2 size={8} className="inline mr-0.5" />{c}
              </span>
            ))}
          </div>
        )}
      </div>
    ) : null
  )

  const aiPanel = (
    <div className="rounded-xl border border-brand-accent/30 bg-brand-soft/40 p-3">
      <button type="button" onClick={() => setAiOpen(o => !o)}
        className="flex items-center gap-2 w-full text-left">
        <Sparkles size={13} className="text-brand-accent flex-shrink-0" />
        <span className="text-xs font-medium text-brand-accent">Generate with AI</span>
        <span className="text-[10px] text-gray-500 ml-1">— describe what you want to detect</span>
        <span className="ml-auto text-[10px] text-brand-accent">{aiOpen ? '▲' : '▼'}</span>
      </button>
      {aiOpen && (
        <div className="mt-3 space-y-2">
          <div>
            <label className="text-[11px] font-medium text-gray-600 mb-1 block">What to detect *</label>
            <input value={aiPrompt} onChange={e => setAiPrompt(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !e.shiftKey && generateWithAI()}
              placeholder="e.g. Cobalt Strike beacon in memory, ransomware dropping note files"
              className="input text-xs w-full" autoFocus />
          </div>
          <div>
            <label className="text-[11px] font-medium text-gray-600 mb-1 block">Hints (optional)</label>
            <input value={aiContext} onChange={e => setAiContext(e.target.value)}
              placeholder="known strings, hex patterns, file type, malware family…"
              className="input text-xs w-full" />
          </div>
          {aiError && (
            <p className="text-xs text-red-600 flex items-center gap-1"><AlertTriangle size={11} /> {aiError}</p>
          )}
          <div className="flex items-center gap-2">
            <button onClick={generateWithAI} disabled={aiGenerating || !aiPrompt.trim()}
              className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50">
              {aiGenerating
                ? <><Loader2 size={11} className="animate-spin" /> Generating…</>
                : <><Sparkles size={11} /> Generate rule</>}
            </button>
            <button onClick={() => setAiOpen(false)} className="btn-outline text-xs">Cancel</button>
          </div>
        </div>
      )}
      {!aiOpen && aiModelUsed && (
        <p className="text-[10px] text-gray-500 mt-1.5 flex items-center gap-1">
          <Check size={10} className="text-green-500" /> Generated by {aiModelUsed} — review before saving
        </p>
      )}
    </div>
  )

  const yaraToolbar = (
    <div className="flex items-center justify-between mb-1.5 flex-shrink-0">
      <label className="text-xs font-medium text-gray-600">YARA Rule *</label>
      <div className="flex items-center gap-3">
        <button onClick={() => fileRef.current?.click()}
          className="text-xs text-brand-accent hover:underline flex items-center gap-1">
          <Upload size={11} /> Import .yar
        </button>
        <input ref={fileRef} type="file" accept=".yar,.yara" className="hidden" onChange={handleFile} />
        <button onClick={validate} disabled={validating || !content.trim()}
          className="text-xs text-gray-500 hover:text-brand-accent flex items-center gap-1 disabled:opacity-40">
          {validating ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />}
          Validate
        </button>
      </div>
    </div>
  )

  const YARA_PLACEHOLDER = `rule ExampleMalware {\n    meta:\n        description = "Detects example malware"\n        author = "analyst"\n    strings:\n        $s1 = "malicious_string" ascii\n        $b1 = { DE AD BE EF }\n    condition:\n        any of them\n}`

  if (inline) {
    return (
      <div className="flex flex-col h-full bg-white">
        {header}

        {/* Metadata fields — scrollable, capped height */}
        <div className="flex-shrink-0 overflow-y-auto p-4 space-y-3 border-b border-gray-100" style={{ maxHeight: '45%' }}>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-gray-600 mb-1 block">Rule name *</label>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder="e.g. Detect_Cobalt_Strike" className="input text-xs w-full" />
            </div>
            <div>
              <label className="text-xs font-medium text-gray-600 mb-1 block">Tags</label>
              <input value={tags} onChange={e => setTags(e.target.value)}
                placeholder="malware, apt, ransomware" className="input text-xs w-full" />
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600 mb-1 block">Description</label>
            <input value={desc} onChange={e => setDesc(e.target.value)}
              placeholder="What does this rule detect?" className="input text-xs w-full" />
          </div>
          {companyScope}
          {aiPanel}
        </div>

        {/* YARA Monaco editor — fills remaining height */}
        <div className="flex flex-col flex-1 min-h-0">
          <div className="flex items-center justify-between px-4 py-1.5 border-b border-gray-100 flex-shrink-0 bg-gray-50/60">
            <label className="text-xs font-medium text-gray-600">YARA Rule *</label>
            <div className="flex items-center gap-3">
              <button onClick={() => fileRef.current?.click()}
                className="text-xs text-brand-accent hover:underline flex items-center gap-1">
                <Upload size={11} /> Import .yar
              </button>
              <input ref={fileRef} type="file" accept=".yar,.yara" className="hidden" onChange={handleFile} />
            </div>
          </div>
          <div className="flex-1 overflow-hidden min-h-0">
            <Editor
              height="100%"
              language="yara"
              theme="yara-dark"
              value={content}
              onChange={v => { const t = v ?? ''; setContent(t); scheduleLint(t) }}
              onMount={onEditorMount}
              beforeMount={ensureYaraLang}
              loading={<div className="h-full bg-[#1e1e1e] flex items-center justify-center text-gray-500 text-xs">Loading…</div>}
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
          {error && (
            <div className="flex-shrink-0 px-4 py-1.5 border-t border-red-100 bg-red-50">
              <p className="text-xs text-red-600 flex items-center gap-1.5">
                <AlertTriangle size={11} /> {error}
              </p>
            </div>
          )}
        </div>

        {footer}
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl mx-4 flex flex-col max-h-[92vh]">
        {header}
        <div className="overflow-y-auto flex-1 p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-xs font-medium text-gray-600 mb-1 block">Rule name *</label>
              <input value={name} onChange={e => setName(e.target.value)}
                placeholder="e.g. Detect_Cobalt_Strike" className="input text-xs w-full" />
            </div>
            <div>
              <label className="text-xs font-medium text-gray-600 mb-1 block">Tags</label>
              <input value={tags} onChange={e => setTags(e.target.value)}
                placeholder="malware, apt, ransomware" className="input text-xs w-full" />
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-gray-600 mb-1 block">Description</label>
            <input value={desc} onChange={e => setDesc(e.target.value)}
              placeholder="What does this rule detect?" className="input text-xs w-full" />
          </div>
          {companyScope}
          {aiPanel}
          <div>
            {yaraToolbar}
            <textarea
              value={content}
              onChange={e => { const t = e.target.value; setContent(t); setVR(null); scheduleTextareaLint(t) }}
              className="w-full font-mono text-xs bg-gray-950 text-green-400 rounded-lg p-3 h-56 resize-none outline-none focus:ring-1 focus:ring-brand-accent/40 border border-gray-200"
              placeholder={YARA_PLACEHOLDER}
              spellCheck={false}
            />
            {validResult && (
              <p className={`text-xs mt-1 flex items-center gap-1.5 ${validResult.ok ? 'text-green-600' : 'text-red-600'}`}>
                {validResult.ok ? <Check size={11} /> : <AlertTriangle size={11} />}
                {validResult.msg}
              </p>
            )}
          </div>
          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {error}
            </p>
          )}
        </div>
        {footer}
      </div>
    </div>
  )
}
