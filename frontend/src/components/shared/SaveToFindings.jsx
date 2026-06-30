import { useState } from 'react'
import { BookmarkPlus, Check, Loader2 } from 'lucide-react'
import { api } from '../../api/client'

/**
 * SaveToFindings — one standard button every panel uses to persist its output
 * into the unified findings store. Drop it in a panel's header `actions` slot.
 *
 * Pass `kind` (ioc / anomaly / mitre / killchain / entity / proctree / …) and a
 * `buildItems()` that returns the panel's current results as finding items:
 *   [{ title, severity?, description?, evidence?, techniques?, payload?, dedup_key? }]
 *
 * `replaceKind` (default true) makes a re-save overwrite this kind's prior
 * findings, so re-running a feature doesn't pile up duplicates.
 */
export default function SaveToFindings({
  caseId,
  kind,
  buildItems,
  sourceFeature = '',
  replaceKind = true,
  label = 'Save to findings',
  onSaved,
}) {
  const [state, setState] = useState('idle') // idle | saving | done | error
  const [msg, setMsg] = useState('')

  async function save() {
    setState('saving'); setMsg('')
    try {
      const items = (buildItems() || []).filter(it => it && it.title)
      if (!items.length) { setState('error'); setMsg('Nothing to save'); return }
      const res = await api.findings.save(caseId, kind, items, { sourceFeature, replaceKind })
      setState('done'); setMsg(`${res.saved} saved`)
      onSaved?.(res)
      setTimeout(() => setState('idle'), 2500)
    } catch (e) {
      setState('error'); setMsg(e?.message || 'Save failed')
      setTimeout(() => setState('idle'), 4000)
    }
  }

  return (
    <button
      onClick={save}
      disabled={state === 'saving'}
      className="btn-ghost text-[11px] px-2 py-1 rounded-lg flex items-center gap-1"
      title="Persist these results into the case findings store (queryable, exportable, in the report)"
    >
      {state === 'saving' ? <Loader2 size={13} className="animate-spin" />
        : state === 'done' ? <Check size={13} className="text-green-600" />
        : <BookmarkPlus size={13} />}
      <span>{state === 'done' || state === 'error' ? msg : label}</span>
    </button>
  )
}
