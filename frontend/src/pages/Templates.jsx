import { useState, useEffect, useCallback } from 'react'
import {
  LayoutTemplate, Plus, Pencil, Trash2, Copy, Loader2, X, Save, AlertCircle, Lock, RotateCcw,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'
import ConfirmDialog from '../components/ConfirmDialog'
import Modal from '../components/shared/Modal'

// Investigation-template authoring page. Built-ins can be edited in place
// (the edit is stored as an override; Reset restores the shipped default) or
// cloned to a new custom template; custom templates are full CRUD. The same
// templates are applied per-case from the case's Templates panel.

const IOC_KINDS = ['cmdline', 'regex', 'domain', 'ip', 'hash', 'filename', 'user', 'host']
const BLANK = { name: '', description: '', tags: [], watchlist: [], rule_categories: [], notes: '' }

function TemplateEditor({ initial, isClone, onClose, onSaved }) {
  const [form, setForm] = useState(() => ({
    name: isClone ? `${initial?.name || ''} (copy)` : (initial?.name || ''),
    description: initial?.description || '',
    tags: (initial?.tags || []).join(', '),
    rule_categories: (initial?.rule_categories || []).join(', '),
    notes: initial?.notes || '',
    watchlist: (initial?.watchlist || []).map(w => ({ ...w })),
  }))
  const [saving, setSaving] = useState(false)
  const [error, setError]   = useState('')
  const editingId = !isClone && initial?.id ? initial.id : null

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))
  const setW = (i, k, v) => setForm(f => ({ ...f, watchlist: f.watchlist.map((w, j) => j === i ? { ...w, [k]: v } : w) }))
  const addW = () => setForm(f => ({ ...f, watchlist: [...f.watchlist, { kind: 'cmdline', value: '', label: '' }] }))
  const rmW  = i => setForm(f => ({ ...f, watchlist: f.watchlist.filter((_, j) => j !== i) }))

  async function save() {
    if (!form.name.trim()) { setError('Name is required'); return }
    setSaving(true); setError('')
    const payload = {
      name: form.name.trim(),
      description: form.description.trim(),
      tags: form.tags.split(',').map(s => s.trim()).filter(Boolean),
      rule_categories: form.rule_categories.split(',').map(s => s.trim()).filter(Boolean),
      notes: form.notes,
      watchlist: form.watchlist
        .filter(w => w.value.trim())
        .map(w => ({ kind: w.kind, value: w.value.trim(), label: (w.label || '').trim() })),
    }
    try {
      if (editingId) await api.caseTemplates.update(editingId, payload)
      else await api.caseTemplates.create(payload)
      onSaved()
    } catch (e) { setError(e.message || 'Save failed') }
    finally { setSaving(false) }
  }

  return (
    <Modal onClose={onClose} className="modal-box max-w-2xl" ariaLabel={editingId ? 'Edit template' : 'New template'}>
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200">
          <h2 className="font-semibold text-brand-text flex items-center gap-2">
            <LayoutTemplate size={16} className="text-brand-accent" />
            {editingId ? 'Edit template' : isClone ? 'Clone template' : 'New template'}
          </h2>
          <button onClick={onClose} className="icon-btn" aria-label="Close"><X size={16} /></button>
        </div>

        <div className="p-5 space-y-3 overflow-y-auto">
          {error && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertCircle size={12} /> {error}
            </p>
          )}
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Name</span>
              <input className="input w-full text-sm mt-1" value={form.name} onChange={e => set('name', e.target.value)} />
            </label>
            <label className="block">
              <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Tags (comma-separated)</span>
              <input className="input w-full text-sm mt-1" value={form.tags} onChange={e => set('tags', e.target.value)} placeholder="ransomware, exfil" />
            </label>
          </div>
          <label className="block">
            <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Description</span>
            <input className="input w-full text-sm mt-1" value={form.description} onChange={e => set('description', e.target.value)} />
          </label>

          <div>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Watchlist IOCs</span>
              <button onClick={addW} className="btn-ghost text-xs"><Plus size={12} /> Add</button>
            </div>
            <div className="space-y-1.5">
              {form.watchlist.length === 0 && <p className="text-[11px] text-gray-400">No IOCs — add the indicators this template seeds.</p>}
              {form.watchlist.map((w, i) => (
                <div key={i} className="flex items-center gap-1.5">
                  <select value={w.kind} onChange={e => setW(i, 'kind', e.target.value)} className="input text-xs py-1 w-28">
                    {IOC_KINDS.map(k => <option key={k} value={k}>{k}</option>)}
                  </select>
                  <input value={w.value} onChange={e => setW(i, 'value', e.target.value)} placeholder="value / pattern"
                    className="input text-xs py-1 flex-1 font-mono" />
                  <input value={w.label || ''} onChange={e => setW(i, 'label', e.target.value)} placeholder="label"
                    className="input text-xs py-1 w-40" />
                  <button onClick={() => rmW(i)} className="icon-btn text-red-400 hover:text-red-600"><Trash2 size={12} /></button>
                </div>
              ))}
            </div>
          </div>

          <label className="block">
            <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Rule categories (comma-separated)</span>
            <input className="input w-full text-xs mt-1 font-mono" value={form.rule_categories}
              onChange={e => set('rule_categories', e.target.value)} placeholder="sigma_hq/12_impact, sigma_hq/05_lateral_movement" />
          </label>
          <label className="block">
            <span className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider">Notes (Markdown — seeded into the case)</span>
            <textarea rows={6} className="input w-full text-xs mt-1 font-mono resize-y" value={form.notes}
              onChange={e => set('notes', e.target.value)} />
          </label>
        </div>

        <div className="flex items-center gap-2 px-5 py-3 border-t border-gray-200">
          <button onClick={save} disabled={saving} className="btn-primary text-sm">
            {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />} Save
          </button>
          <button onClick={onClose} className="btn-ghost text-sm">Cancel</button>
        </div>
    </Modal>
  )
}

export default function Templates() {
  const [templates, setTemplates] = useState([])
  const [loading, setLoading]     = useState(true)
  const [error, setError]         = useState('')
  const [editor, setEditor]       = useState(null)  // { initial, isClone } | null
  const [confirmAction, setConfirmAction] = useState(null) // { kind: 'remove' | 'reset', template } | null

  const load = useCallback(() => {
    setLoading(true)
    api.caseTemplates.list()
      .then(r => setTemplates(r.templates || []))
      .catch(e => setError(e.message || 'Failed to load templates'))
      .finally(() => setLoading(false))
  }, [])
  useEffect(() => { load() }, [load])

  async function openEditor(t, isClone) {
    if (!t) { setEditor({ initial: BLANK, isClone: false }); return }
    // Need the full object (list is a summary) — fetch it.
    try {
      const full = await api.caseTemplates.getFull(t.id)
      setEditor({ initial: full, isClone: !!isClone })
    } catch (e) { setError(e.message || 'Could not load template') }
  }

  async function remove(t) {
    try { await api.caseTemplates.remove(t.id); load() }
    catch (e) { setError(e.message || 'Delete failed') }
  }

  async function reset(t) {
    try { await api.caseTemplates.remove(t.id); load() }
    catch (e) { setError(e.message || 'Reset failed') }
  }

  return (
    <PageShell>
      <PageHeader
        title="Investigation Templates"
        icon={LayoutTemplate}
        subtitle="Reusable kits — watchlist IOCs, rule categories, and a notes skeleton — applied to a case from its Templates panel. Edit built-ins in place (Reset restores the default) or clone one to a new custom template."
      />

      <div className="card p-3 mb-4 flex items-center justify-between">
        <span className="text-xs text-gray-500">{templates.length} template{templates.length !== 1 ? 's' : ''}</span>
        <button onClick={() => openEditor(null)} className="btn-primary text-xs"><Plus size={13} /> New template</button>
      </div>

      {error && (
        <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 mb-3 flex items-center gap-1.5">
          <AlertCircle size={12} /> {error}
        </p>
      )}

      {loading ? (
        <div className="space-y-2">{[1, 2, 3].map(i => <div key={i} className="skeleton h-16 w-full" />)}</div>
      ) : (
        <div className="space-y-2">
          {templates.map(t => (
            <div key={t.id} className="card p-3 flex items-start gap-3">
              <LayoutTemplate size={15} className="text-brand-accent flex-shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-sm font-semibold text-brand-text">{t.name}</span>
                  {t.builtin
                    ? <span className="badge text-[10px] bg-gray-100 text-gray-500 border border-gray-200"><Lock size={8} className="inline mr-0.5" />built-in</span>
                    : <span className="badge text-[10px] bg-brand-accentlight text-brand-accent border border-brand-accent/30">custom</span>}
                  {t.overridden && <span className="badge text-[10px] bg-amber-50 text-amber-700 border border-amber-200">edited</span>}
                  {(t.tags || []).slice(0, 4).map(tag => (
                    <span key={tag} className="badge-pill bg-brand-soft text-brand-accent text-[10px] px-1.5">{tag}</span>
                  ))}
                </div>
                {t.description && <p className="text-[11px] text-gray-500 mt-0.5">{t.description}</p>}
                <p className="text-[10px] text-gray-400 mt-0.5">{t.watchlist_count ?? 0} watchlist IOC(s)</p>
              </div>
              <div className="flex items-center gap-1 flex-shrink-0">
                {t.builtin ? (
                  <>
                    <button onClick={() => openEditor(t, false)} className="icon-btn" title="Edit built-in"><Pencil size={13} /></button>
                    {t.overridden && (
                      <button onClick={() => setConfirmAction({ kind: 'reset', template: t })} className="icon-btn text-amber-500 hover:text-amber-700" title="Reset to built-in default"><RotateCcw size={13} /></button>
                    )}
                    <button onClick={() => openEditor(t, true)} className="btn-ghost text-xs" title="Clone to a custom template">
                      <Copy size={13} /> Clone
                    </button>
                  </>
                ) : (
                  <>
                    <button onClick={() => openEditor(t, false)} className="icon-btn" title="Edit"><Pencil size={13} /></button>
                    <button onClick={() => setConfirmAction({ kind: 'remove', template: t })} className="icon-btn text-red-400 hover:text-red-600" title="Delete"><Trash2 size={13} /></button>
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {editor && (
        <TemplateEditor
          initial={editor.initial}
          isClone={editor.isClone}
          onClose={() => setEditor(null)}
          onSaved={() => { setEditor(null); load() }}
        />
      )}

      {confirmAction && (
        <ConfirmDialog
          title={confirmAction.kind === 'reset' ? 'Reset template' : 'Delete template'}
          icon={confirmAction.kind === 'reset'
            ? <RotateCcw size={14} className="text-amber-500" />
            : <Trash2 size={14} className="text-red-500" />}
          message={confirmAction.kind === 'reset'
            ? `Reset "${confirmAction.template.name}" to its built-in default? Your edits will be discarded.`
            : `Delete template "${confirmAction.template.name}"? This can't be undone.`}
          confirmLabel={confirmAction.kind === 'reset' ? 'Reset' : 'Delete'}
          confirmClass={confirmAction.kind === 'reset' ? 'btn-outline' : 'btn-danger'}
          onConfirm={() => {
            const { kind, template } = confirmAction
            setConfirmAction(null)
            if (kind === 'reset') reset(template)
            else remove(template)
          }}
          onCancel={() => setConfirmAction(null)}
        />
      )}
    </PageShell>
  )
}
