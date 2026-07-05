import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  X, Loader2, Trash2, Plus, LayoutTemplate, ChevronRight, Copy, Pencil,
  ExternalLink, Play,
} from 'lucide-react'
import { api } from '../../api/client'
import { ResizableDrawer } from '../shared/resizableDrawer'
import PanelHelp from '../shared/PanelHelp'
import { currentUser } from '../../utils/caseConstants'

// ─────────────────────────────────────────────────────────────────────────────
// TemplatesPanel — apply a pre-canned investigation kit (ransomware / insider /
// phishing). Lists `/case-templates`, applies via `/cases/{id}/apply-template`.
// Side-effects on apply: seeds watchlist IOCs, adds case tags, seeds notes
// skeleton (only if notes empty).
// ─────────────────────────────────────────────────────────────────────────────
// Inline editor for create / edit / clone of a custom case template.
const WL_KINDS = ['cmdline', 'regex', 'domain', 'ip', 'hash', 'filename', 'user', 'host']
function TemplateEditor({ editor, saving, error, onChange, onSave, onCancel, setWlRow, addWlRow, removeWlRow }) {
  if (editor.loading) {
    return (
      <div className="card p-4 flex items-center justify-center gap-2 text-xs text-gray-500">
        <Loader2 size={12} className="animate-spin" /> Loading template…
      </div>
    )
  }
  const upd = (patch) => onChange(prev => ({ ...prev, ...patch }))
  return (
    <div className="card p-4 space-y-3 border-indigo-200 bg-indigo-50/30">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-gray-900">
          {editor.editingId ? 'Edit template' : 'New template'}
        </span>
        <button onClick={onCancel} className="btn-ghost p-1 rounded" title="Close editor"><X size={13} /></button>
      </div>

      {error && <div className="text-[11px] text-red-700 bg-red-50 border border-red-200 rounded p-2">{error}</div>}

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Name</label>
        <input value={editor.name} onChange={e => upd({ name: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5" placeholder="e.g. BEC investigation" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Description</label>
        <input value={editor.description} onChange={e => upd({ description: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Tags (comma-separated)</label>
        <input value={editor.tags} onChange={e => upd({ tags: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5" placeholder="phishing, bec" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Watchlist IOCs</label>
        <div className="space-y-1.5">
          {editor.watchlist.map((w, i) => (
            <div key={i} className="flex items-center gap-1.5">
              <select value={w.kind} onChange={e => setWlRow(i, { kind: e.target.value })}
                className="text-[11px] border border-gray-300 rounded px-1.5 py-1 bg-white">
                {WL_KINDS.map(k => <option key={k} value={k}>{k}</option>)}
              </select>
              <input value={w.value} onChange={e => setWlRow(i, { value: e.target.value })}
                className="flex-1 min-w-0 text-[11px] border border-gray-300 rounded px-2 py-1" placeholder="value" />
              <input value={w.label} onChange={e => setWlRow(i, { label: e.target.value })}
                className="flex-1 min-w-0 text-[11px] border border-gray-300 rounded px-2 py-1" placeholder="label (optional)" />
              <button onClick={() => removeWlRow(i)} className="btn-ghost p-1 rounded text-gray-400 hover:text-red-600" title="Remove row"><Trash2 size={11} /></button>
            </div>
          ))}
        </div>
        <button onClick={addWlRow} className="text-[10px] text-brand-accent hover:underline flex items-center gap-1 mt-1.5">
          <Plus size={10} /> Add IOC
        </button>
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Rule categories (comma-separated)</label>
        <input value={editor.rule_categories} onChange={e => upd({ rule_categories: e.target.value })}
          className="w-full text-xs border border-gray-300 rounded px-2 py-1.5 font-mono"
          placeholder="sigma_hq/01_initial_access, sigma_hq/02_execution" />
      </div>

      <div>
        <label className="block text-[10px] font-medium text-gray-500 mb-1">Notes (markdown)</label>
        <textarea value={editor.notes} onChange={e => upd({ notes: e.target.value })} rows={6}
          className="w-full text-[11px] border border-gray-300 rounded px-2 py-1.5 font-mono" />
      </div>

      <div className="flex items-center justify-end gap-2 pt-1">
        <button onClick={onCancel} className="btn-ghost text-xs">Cancel</button>
        <button onClick={onSave} disabled={saving} className="btn-primary text-xs flex items-center gap-1.5">
          {saving ? <><Loader2 size={11} className="animate-spin" /> Saving…</> : 'Save template'}
        </button>
      </div>
    </div>
  )
}

export default function TemplatesPanel({ caseId, onClose }) {
  const navigate = useNavigate()
  const isAdmin = currentUser()?.role === 'admin'
  const [list, setList]         = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)

  // Per-template expanded state: { [tplId]: { loading, checks, tags, notes } }
  const [expanded, setExpanded] = useState({})
  // Per-template seed status
  const [seeding, setSeeding]   = useState(null)
  const [seedResult, setSeedResult] = useState(null)

  // Editor state. `editor` is null when closed; otherwise the working draft.
  // `editor.editingId` = id being updated (null = create / clone).
  const [editor, setEditor]   = useState(null)
  const [saving, setSaving]   = useState(false)
  const [editorErr, setEditorErr] = useState(null)

  function refresh() {
    return api.caseTemplates.list()
      .then(r => setList(r.templates || []))
      .catch(e => setError(e.message || 'Failed to load templates.'))
  }

  useEffect(() => {
    refresh().finally(() => setLoading(false))
  }, [])

  const EMPTY_DRAFT = {
    editingId: null, name: '', description: '', tags: '',
    watchlist: [{ kind: 'cmdline', value: '', label: '' }],
    rule_categories: '', notes: '',
  }

  function openNew() {
    setEditorErr(null)
    setEditor({ ...EMPTY_DRAFT, watchlist: [{ kind: 'cmdline', value: '', label: '' }] })
  }

  async function openEdit(tplId, { clone = false } = {}) {
    setEditorErr(null)
    setEditor({ loading: true })
    try {
      const f = await api.caseTemplates.getFull(tplId)
      const wl = (f.watchlist || []).map(w => ({ kind: w.kind, value: w.value, label: w.label || '' }))
      setEditor({
        editingId: clone ? null : tplId,
        name: clone ? `${f.name} (copy)` : f.name,
        description: f.description || '',
        tags: (f.tags || []).join(', '),
        watchlist: wl.length ? wl : [{ kind: 'cmdline', value: '', label: '' }],
        rule_categories: (f.rule_categories || []).join(', '),
        notes: f.notes || '',
      })
    } catch (e) {
      setEditor(null)
      setError(e.message || 'Failed to load template for editing.')
    }
  }

  async function saveEditor() {
    if (!editor || editor.loading) return
    if (!editor.name.trim()) { setEditorErr('Name is required.'); return }
    const payload = {
      name: editor.name.trim(),
      description: editor.description.trim(),
      tags: editor.tags,
      watchlist: editor.watchlist.filter(w => w.kind && w.value.trim()),
      rule_categories: editor.rule_categories,
      notes: editor.notes,
    }
    setSaving(true); setEditorErr(null)
    try {
      if (editor.editingId) await api.caseTemplates.update(editor.editingId, payload)
      else await api.caseTemplates.create(payload)
      setEditor(null)
      await refresh()
    } catch (e) {
      setEditorErr(e.message || 'Save failed.')
    } finally {
      setSaving(false)
    }
  }

  async function deleteTemplate(tplId) {
    if (!confirm('Delete this custom template? This cannot be undone.')) return
    setError(null)
    try {
      await api.caseTemplates.remove(tplId)
      setExpanded(prev => { const n = { ...prev }; delete n[tplId]; return n })
      await refresh()
    } catch (e) {
      setError(e.message || 'Delete failed.')
    }
  }

  function setWlRow(i, patch) {
    setEditor(prev => ({ ...prev, watchlist: prev.watchlist.map((w, j) => j === i ? { ...w, ...patch } : w) }))
  }
  function addWlRow() {
    setEditor(prev => ({ ...prev, watchlist: [...prev.watchlist, { kind: 'cmdline', value: '', label: '' }] }))
  }
  function removeWlRow(i) {
    setEditor(prev => ({ ...prev, watchlist: prev.watchlist.filter((_, j) => j !== i) }))
  }

  async function toggleExpand(tplId) {
    if (expanded[tplId]) {
      setExpanded(prev => { const next = { ...prev }; delete next[tplId]; return next })
      return
    }
    // Load detail (with pre-run hit counts per check)
    setExpanded(prev => ({ ...prev, [tplId]: { loading: true } }))
    try {
      const d = await api.caseTemplates.detail(caseId, tplId)
      setExpanded(prev => ({ ...prev, [tplId]: { loading: false, ...d } }))
    } catch (e) {
      setExpanded(prev => ({ ...prev, [tplId]: { loading: false, error: e.message || 'Failed to load template' } }))
    }
  }

  async function seedAll(tplId) {
    if (!confirm(
      'Seed this case with the template?\n\n' +
      '• Adds IOCs to the GLOBAL watchlist\n' +
      '• Appends scenario tags to this case\n' +
      '• Writes the notes skeleton (only if your notes are empty)\n\n' +
      'Continue?'
    )) return
    setSeeding(tplId); setSeedResult(null); setError(null)
    try {
      const r = await api.caseTemplates.apply(caseId, tplId)
      setSeedResult(r)
    } catch (e) {
      setError(e.message || 'Seeding failed.')
    } finally {
      setSeeding(null)
    }
  }

  function pivot(q) {
    navigate(`/cases/${caseId}`, { state: { pivotQuery: q } })
    onClose()
  }

  return (
    <ResizableDrawer slug="templates" defaultWidth={640} onClose={onClose}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <LayoutTemplate size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Investigation playbooks</span>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg" title="Close panel (Esc)">
            <X size={16} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <PanelHelp
            title="Investigation playbooks"
            use="Scenario checklists (ransomware, insider, phishing…) of curated queries, run live against this case, plus optional watchlist/tags/notes seeding."
            when="At case kickoff — to apply a known methodology and see which scenario checks already have hits."
            tip="Expand a playbook to see live hit counts; click Pivot to open the timeline filtered to a check."
          />
          <div className="flex items-start justify-between gap-3">
            <p className="text-[11px] text-gray-500 leading-relaxed flex-1">
              Each playbook is a curated checklist of scenario-specific queries
              (run against this case right now — hit counts are live) plus an
              optional seed-the-watchlist + notes-skeleton bundle for analysts who
              want the magic-apply behaviour.
            </p>
            {isAdmin && !editor && (
              <button onClick={openNew} className="btn-primary text-xs flex items-center gap-1.5 flex-shrink-0 whitespace-nowrap">
                <Plus size={12} /> New template
              </button>
            )}
          </div>

          {editor && (
            <TemplateEditor
              editor={editor}
              saving={saving}
              error={editorErr}
              onChange={setEditor}
              onSave={saveEditor}
              onCancel={() => setEditor(null)}
              setWlRow={setWlRow}
              addWlRow={addWlRow}
              removeWlRow={removeWlRow}
            />
          )}

          {error && (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200">{error}</div>
          )}
          {seedResult && (
            <div className="card p-3 text-xs text-emerald-700 bg-emerald-50 border-emerald-200">
              Seeded <strong>{seedResult.template}</strong> · {seedResult.watchlist_seeded} watchlist
              entries · tags: {seedResult.tags_added.join(', ')}
              {!seedResult.notes_seeded && <em className="block mt-1 text-emerald-600/70">Notes left untouched — already populated.</em>}
            </div>
          )}

          {loading ? (
            <div className="flex items-center justify-center gap-2 text-xs text-gray-500 py-6">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : list.length === 0 ? (
            <div className="text-xs text-gray-500 italic text-center py-6">No playbooks available.</div>
          ) : (
            list.map(t => {
              const exp = expanded[t.id]
              const open = !!exp
              return (
                <div key={t.id} className="card overflow-hidden">
                  {/* Header — click to expand */}
                  <button
                    onClick={() => toggleExpand(t.id)}
                    className="w-full text-left p-4 flex items-start justify-between gap-3 hover:bg-gray-50 transition-colors"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <ChevronRight size={12} className={`text-gray-400 transition-transform ${open ? 'rotate-90' : ''}`} />
                        <span className="text-sm font-semibold text-gray-900">{t.name}</span>
                        {t.builtin
                          ? <span className="badge text-[9px] bg-gray-100 text-gray-500">built-in</span>
                          : <span className="badge text-[9px] bg-indigo-100 text-indigo-700">custom</span>}
                      </div>
                      <p className="text-[11px] text-gray-600 mt-0.5 ml-4">{t.description}</p>
                      <div className="flex flex-wrap gap-1 mt-2 ml-4">
                        {(t.tags || []).map(tag => (
                          <span key={tag} className="badge text-[10px] bg-gray-100 text-gray-600">{tag}</span>
                        ))}
                        <span className="badge text-[10px] bg-gray-100 text-gray-500">
                          {t.watchlist_count} check{t.watchlist_count === 1 ? '' : 's'}
                        </span>
                      </div>
                    </div>
                  </button>

                  {isAdmin && !editor && (
                    <div className="flex items-center gap-3 px-4 pb-2 -mt-1 ml-4">
                      {t.builtin ? (
                        <button onClick={() => openEdit(t.id, { clone: true })} className="text-[10px] text-brand-accent hover:underline flex items-center gap-1">
                          <Copy size={10} /> Clone
                        </button>
                      ) : (
                        <>
                          <button onClick={() => openEdit(t.id)} className="text-[10px] text-brand-accent hover:underline flex items-center gap-1">
                            <Pencil size={10} /> Edit
                          </button>
                          <button onClick={() => deleteTemplate(t.id)} className="text-[10px] text-red-600 hover:underline flex items-center gap-1">
                            <Trash2 size={10} /> Delete
                          </button>
                        </>
                      )}
                    </div>
                  )}

                  {/* Expanded: per-check hit counts + actions */}
                  {open && (
                    <div className="border-t border-gray-100 p-3 space-y-2 bg-gray-50/50">
                      {exp.loading ? (
                        <div className="flex items-center justify-center gap-2 text-xs text-gray-500 py-4">
                          <Loader2 size={12} className="animate-spin" /> Running checks against this case…
                        </div>
                      ) : exp.error ? (
                        <div className="text-xs text-red-700 bg-red-50 border border-red-200 rounded p-2">{exp.error}</div>
                      ) : (
                        <>
                          <p className="text-[10px] text-gray-500 mb-1">
                            Hit counts are live for this case. Click <strong>Pivot</strong> to open the
                            timeline filtered by that check.
                          </p>
                          {(exp.checks || []).map((c, i) => {
                            const hits = c.result_count
                            const empty = hits === 0
                            return (
                              <div
                                key={i}
                                className={`border rounded bg-white ${empty ? 'border-gray-200' : 'border-amber-200'}`}
                              >
                                <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-gray-100">
                                  <span className="text-xs font-medium text-brand-text flex-1 truncate">{c.label}</span>
                                  {typeof hits === 'number' ? (
                                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded tabular-nums ${
                                      empty ? 'bg-gray-100 text-gray-500' : 'bg-amber-100 text-amber-800'
                                    }`}>
                                      {hits.toLocaleString()} {hits === 1 ? 'hit' : 'hits'}
                                    </span>
                                  ) : (
                                    <span className="text-[10px] text-gray-400">—</span>
                                  )}
                                  <button
                                    onClick={() => pivot(c.query)}
                                    disabled={empty}
                                    className={`text-[10px] font-medium flex items-center gap-1 ${
                                      empty
                                        ? 'text-gray-400 cursor-not-allowed'
                                        : 'text-brand-accent hover:underline'
                                    }`}
                                  >
                                    Pivot <ExternalLink size={9} />
                                  </button>
                                </div>
                                <code className="block text-[10px] font-mono text-gray-600 px-2.5 py-1 break-all">
                                  {c.query}
                                </code>
                              </div>
                            )
                          })}

                          {/* Seed-the-watchlist button — optional, kept for the
                              old "apply" flow but no longer the default action. */}
                          <div className="pt-2 mt-2 border-t border-gray-200">
                            <p className="text-[10px] text-gray-500 mb-1.5">
                              Optional: seed the global watchlist with these IOCs + append
                              scenario tags + drop a notes skeleton (notes only if empty).
                            </p>
                            <button
                              onClick={() => seedAll(t.id)}
                              disabled={seeding === t.id}
                              className="btn-secondary text-xs flex items-center gap-1.5 w-full justify-center"
                            >
                              {seeding === t.id
                                ? <><Loader2 size={11} className="animate-spin" /> Seeding…</>
                                : <><Play size={11} /> Seed watchlist + tags + notes</>
                              }
                            </button>
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </div>
              )
            })
          )}
        </div>
    </ResizableDrawer>
  )
}
