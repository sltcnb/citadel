import { useState, useEffect, useRef } from 'react'
import {
  FileCode, Plus, Trash2, Pencil, X, Upload, Download,
  Check, Loader2, AlertTriangle, Search, Code2, ChevronDown, ChevronUp, Sparkles, Building2,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'
import { useCompanies } from './UserManagement'
import YaraRuleModal from '../components/YaraRuleModal'

// ── Rule card ──────────────────────────────────────────────────────────────────

function RuleCard({ rule, onEdit, onDelete }) {
  const [expanded, setExpanded] = useState(false)
  const [deleting, setDeleting] = useState(false)

  async function confirmDelete() {
    if (!confirm(`Delete rule "${rule.name}"?`)) return
    setDeleting(true)
    try {
      await api.yaraRules.delete(rule.id)
      onDelete(rule.id)
    } catch (err) {
      alert('Delete failed: ' + err.message)
      setDeleting(false)
    }
  }

  return (
    <div className="card overflow-hidden">
      <div
        className="flex items-center gap-3 px-4 py-3 cursor-pointer hover:bg-gray-50 transition-colors"
        onClick={() => setExpanded(e => !e)}
      >
        <FileCode size={14} className="text-brand-accent flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-brand-text truncate">{rule.name}</p>
          {rule.description && (
            <p className="text-[11px] text-gray-500 truncate mt-0.5">{rule.description}</p>
          )}
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0">
          {(rule.companies || []).slice(0, 2).map(c => (
            <span key={c} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px]">
              <Building2 size={8} className="inline mr-0.5" />{c}
            </span>
          ))}
          {(rule.tags || []).slice(0, 3).map(t => (
            <span key={t} className="badge-pill bg-brand-soft text-brand-accent text-[10px] px-1.5">{t}</span>
          ))}
          <button
            onClick={e => { e.stopPropagation(); onEdit(rule) }}
            className="icon-btn ml-1"
            title="Edit"
          >
            <Pencil size={12} />
          </button>
          <button
            onClick={e => { e.stopPropagation(); confirmDelete() }}
            disabled={deleting}
            className="icon-btn text-red-400 hover:text-red-600"
            title="Delete"
          >
            {deleting ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
          </button>
          {expanded ? <ChevronUp size={12} className="text-gray-500" /> : <ChevronDown size={12} className="text-gray-500" />}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-gray-100">
          <pre className="font-mono text-[11px] text-green-400 bg-gray-950 px-4 py-3 overflow-x-auto whitespace-pre-wrap max-h-72 leading-relaxed">
            {rule.content}
          </pre>
          <div className="px-4 py-2 bg-gray-50 border-t border-gray-100 flex items-center justify-between">
            <span className="text-[11px] text-gray-500">
              {rule.content.split('\n').length} lines
              {rule.updated_at && ` · Updated ${new Date(rule.updated_at).toLocaleDateString()}`}
            </span>
            <button
              onClick={e => { e.stopPropagation(); onEdit(rule) }}
              className="text-[11px] text-brand-accent hover:underline flex items-center gap-1"
            >
              <Pencil size={10} /> Edit
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function YaraLibrary() {
  const [rules, setRules]         = useState([])
  const [loading, setLoading]     = useState(true)
  const [search, setSearch]       = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editRule, setEditRule]   = useState(null)
  const [modalOpenAI, setModalOpenAI] = useState(false)
  const importRef = useRef(null)

  // Standalone validator state
  const [showValidator, setShowValidator]   = useState(false)
  const [validatorText, setValidatorText]   = useState('')
  const [validating, setValidating]         = useState(false)
  const [validatorResult, setValidatorResult] = useState(null)   // {ok, msg}

  async function runValidate() {
    if (!validatorText.trim()) return
    setValidating(true)
    setValidatorResult(null)
    try {
      const r = await api.modules.validateYara(validatorText)
      setValidatorResult({ ok: r.valid, msg: r.message || (r.valid ? 'Syntax OK — rule is valid' : 'Syntax error') })
    } catch (err) {
      setValidatorResult({ ok: false, msg: err.message })
    } finally {
      setValidating(false)
    }
  }

  useEffect(() => { load() }, [])

  async function load() {
    setLoading(true)
    try {
      const r = await api.yaraRules.list()
      setRules(r.rules || [])
    } catch (err) {
      console.error('Failed to load YARA rules:', err)
    } finally {
      setLoading(false)
    }
  }

  function openCreate() {
    setEditRule(null)
    setModalOpenAI(false)
    setShowModal(true)
  }

  function openCreateWithAI() {
    setEditRule(null)
    setModalOpenAI(true)
    setShowModal(true)
  }

  function openEdit(rule) {
    setEditRule(rule)
    setModalOpenAI(false)
    setShowModal(true)
  }

  function handleImportFile(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = ev => {
      // Open modal pre-filled with imported content (no id = create mode)
      setEditRule({
        name:        file.name.replace(/\.yar(a)?$/i, ''),
        description: '',
        tags:        [],
        content:     ev.target.result || '',
      })
      setShowModal(true)
    }
    reader.readAsText(file)
    e.target.value = ''
  }

  const filtered = search.trim()
    ? rules.filter(r =>
        r.name.toLowerCase().includes(search.toLowerCase()) ||
        (r.description || '').toLowerCase().includes(search.toLowerCase()) ||
        (r.tags || []).some(t => t.toLowerCase().includes(search.toLowerCase()))
      )
    : rules

  return (
    <PageShell>

      {/* Header */}
      <PageHeader
        title="YARA Rules Library"
        icon={FileCode}
        subtitle="Store and manage YARA rules. Rules are automatically available to the YARA Scanner module."
      />

      {/* Toolbar */}
      <div className="card p-3 mb-4 flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-1 min-w-36">
          <Search size={13} className="text-gray-500 flex-shrink-0" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search rules, tags…"
            className="flex-1 text-xs outline-none bg-transparent placeholder-gray-400"
          />
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => importRef.current?.click()} className="btn-outline text-xs flex items-center gap-1.5">
            <Upload size={12} /> Import .yar
          </button>
          <input ref={importRef} type="file" accept=".yar,.yara" className="hidden" onChange={handleImportFile} />

          {rules.length > 0 && (
            <a
              href={api.yaraRules.exportUrl()}
              className="btn-outline text-xs flex items-center gap-1.5"
              download="yara_library.yar"
            >
              <Download size={12} /> Export all
            </a>
          )}

          <button onClick={openCreateWithAI} className="btn-ghost text-xs flex items-center gap-1.5">
            <Sparkles size={12} className="text-brand-accent" /> Generate with AI
          </button>
          <button
            onClick={() => { setShowValidator(v => !v); setValidatorResult(null) }}
            className={`btn-ghost text-xs flex items-center gap-1.5 ${showValidator ? 'text-brand-accent' : ''}`}
          >
            <Check size={12} /> Validate
          </button>
          <button onClick={openCreate} className="btn-primary text-xs flex items-center gap-1.5">
            <Plus size={12} /> New rule
          </button>
        </div>
      </div>

      {/* ── Standalone YARA validator ─────────────────────────────────────── */}
      {showValidator && (
        <div className="card p-4 mb-4 border border-brand-accent/20 bg-brand-soft/30">
          <p className="text-xs font-semibold text-gray-700 mb-2 flex items-center gap-1.5">
            <Check size={12} className="text-brand-accent" /> YARA Rule Validator
          </p>
          <textarea
            value={validatorText}
            onChange={e => { setValidatorText(e.target.value); setValidatorResult(null) }}
            placeholder={`rule Example {\n    strings:\n        $s1 = "test"\n    condition:\n        any of them\n}`}
            spellCheck={false}
            className="w-full font-mono text-xs bg-gray-950 text-green-400 rounded-lg p-3 h-40 resize-none outline-none focus:ring-1 focus:ring-brand-accent/40 border border-gray-200 mb-2"
          />
          <div className="flex items-center gap-3">
            <button
              onClick={runValidate}
              disabled={validating || !validatorText.trim()}
              className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50"
            >
              {validating ? <Loader2 size={11} className="animate-spin" /> : <Check size={11} />}
              {validating ? 'Validating…' : 'Validate'}
            </button>
            {validatorResult && (
              <p className={`text-xs flex items-center gap-1.5 ${validatorResult.ok ? 'text-green-600' : 'text-red-600'}`}>
                {validatorResult.ok ? <Check size={12} /> : <AlertTriangle size={12} />}
                {validatorResult.msg}
              </p>
            )}
          </div>
        </div>
      )}

      {/* Count */}
      {!loading && rules.length > 0 && (
        <p className="text-xs text-gray-500 mb-3">
          <span className="font-medium text-brand-text">{rules.length}</span> rule{rules.length !== 1 ? 's' : ''} in library
          {search && <> · <span className="font-medium text-brand-text">{filtered.length}</span> matching</>}
        </p>
      )}

      {/* List */}
      {loading ? (
        <div className="flex items-center justify-center py-16 text-gray-500">
          <Loader2 size={18} className="animate-spin mr-2" /> Loading…
        </div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-gray-500">
          <Code2 size={36} className="mx-auto mb-3 opacity-25" />
          {search ? (
            <p className="text-sm">No rules match "<span className="font-medium">{search}</span>"</p>
          ) : (
            <>
              <p className="text-sm font-medium mb-1">No YARA rules yet</p>
              <p className="text-xs text-gray-500 mb-4">Import an existing .yar file or write a rule from scratch.</p>
              <button onClick={openCreate} className="btn-primary text-xs mx-auto flex items-center gap-1.5">
                <Plus size={12} /> Create first rule
              </button>
            </>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map(rule => (
            <RuleCard
              key={rule.id}
              rule={rule}
              onEdit={openEdit}
              onDelete={id => setRules(prev => prev.filter(r => r.id !== id))}
            />
          ))}
        </div>
      )}

      {/* Modal */}
      {showModal && (
        <YaraRuleModal
          rule={editRule}
          openAI={modalOpenAI}
          onClose={() => { setShowModal(false); setEditRule(null); setModalOpenAI(false) }}
          onSaved={saved => {
            if (editRule?.id) {
              setRules(prev => prev.map(r => r.id === saved.id ? saved : r))
            } else {
              setRules(prev => [saved, ...prev])
            }
          }}
        />
      )}
    </PageShell>
  )
}
