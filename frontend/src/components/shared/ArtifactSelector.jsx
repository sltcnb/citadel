/**
 * ArtifactSelector — presentational, reusable artifact-collection picker.
 *
 * Renders two stacked controls in the Collector's visual vocabulary:
 *   1. a depth selector (cards/pills for small / complete / exhaustive levels)
 *   2. a searchable category grid (checkbox cards: key + description), with
 *      Select-all / Clear / "use depth defaults" controls.
 *
 * Pure presentation — all state lives in the parent. No API calls.
 *
 * Props:
 *   levels      [{ key, label, desc }]   selectable depth levels
 *   level       string                   currently-selected depth key
 *   onLevel     (key) => void            depth picked
 *   categories  [{ key, label, desc }]   normalized catalog
 *   selected    Set<string> | string[]   selected category keys
 *   onToggle    (key) => void            one category toggled
 *   onSelectAll () => void               select every category
 *   onClear     () => void               clear → "use depth defaults"
 *   disabled    boolean                  lock the controls (e.g. while running)
 *   clearLabel  string                   label for the clear control (default
 *                                        "Use depth defaults")
 */
import { useMemo, useState } from 'react'
import { Search, X } from 'lucide-react'

const LEVEL_HINTS = {
  small:      'Fast triage — highest-value artifacts only',
  complete:   'Balanced coverage — recommended default',
  exhaustive: 'Everything available — slowest, largest output',
}

// "complete" reads as "Intermediate" in the UI; the backend key stays `complete`.
const LEVEL_LABEL = {
  small:      'Small',
  complete:   'Intermediate',
  exhaustive: 'Exhaustive',
}

export default function ArtifactSelector({
  levels = [],
  level,
  onLevel,
  categories = [],
  selected,
  onToggle,
  onSelectAll,
  onClear,
  disabled = false,
  clearLabel = 'Use depth defaults',
}) {
  const [query, setQuery] = useState('')

  const sel = selected instanceof Set ? selected : new Set(selected || [])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return categories
    return categories.filter(
      c =>
        c.key.toLowerCase().includes(q) ||
        (c.label || '').toLowerCase().includes(q) ||
        (c.desc || '').toLowerCase().includes(q),
    )
  }, [categories, query])

  const allOn = categories.length > 0 && sel.size === categories.length

  return (
    <div className="space-y-4">

      {/* ── Depth selector ─────────────────────────────────────────── */}
      <div>
        <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 mb-1.5">
          Depth
        </h4>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {levels.map(l => {
            const active = level === l.key
            const label  = l.label || LEVEL_LABEL[l.key] || l.key
            const hint   = l.desc  || LEVEL_HINTS[l.key] || ''
            return (
              <button
                key={l.key}
                type="button"
                disabled={disabled}
                onClick={() => onLevel?.(l.key)}
                className={`flex flex-col items-start gap-0.5 py-2.5 px-3 rounded-lg border text-left transition-colors ${
                  active
                    ? 'border-brand-accent bg-brand-accent/5 text-brand-accent'
                    : 'border-gray-200 text-gray-600 hover:border-gray-300'
                } ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}
              >
                <span className="text-sm font-semibold capitalize">{label}</span>
                {hint && (
                  <span className={`text-[10px] leading-snug ${active ? 'text-brand-accent/70' : 'text-gray-500'}`}>
                    {hint}
                  </span>
                )}
              </button>
            )
          })}
        </div>
      </div>

      {/* ── Category grid ──────────────────────────────────────────── */}
      {categories.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-1.5 pb-1 border-b border-gray-100">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              Categories
              <span className="ml-1.5 font-normal normal-case tracking-normal text-gray-400">
                {sel.size === 0 ? `all in ${level}` : `${sel.size}/${categories.length}`}
              </span>
            </h4>
            <div className="flex items-center gap-3">
              <button
                type="button"
                disabled={disabled}
                className="text-[11px] text-brand-accent hover:underline disabled:opacity-50"
                onClick={onSelectAll}
              >
                {allOn ? 'Clear all' : 'Select all'}
              </button>
              <button
                type="button"
                disabled={disabled || sel.size === 0}
                className="text-[11px] text-gray-500 hover:text-gray-700 disabled:opacity-40"
                onClick={onClear}
              >
                {clearLabel}
              </button>
            </div>
          </div>

          {/* Search filter */}
          <div className="relative mb-2">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Filter categories…"
              className="input w-full text-xs pl-7 pr-7 py-1"
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
              >
                <X size={11} />
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-72 overflow-y-auto pr-0.5">
            {filtered.map(c => {
              const checked = sel.has(c.key)
              return (
                <label
                  key={c.key}
                  className={`flex items-start gap-3 p-3 rounded-lg border transition-all ${
                    disabled ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'
                  } ${
                    checked
                      ? 'border-brand-accent/40 bg-brand-accentlight'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    disabled={disabled}
                    onChange={() => onToggle?.(c.key)}
                    className="mt-0.5 accent-brand-accent cursor-pointer flex-shrink-0"
                  />
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-brand-text">{c.label}</div>
                    {c.desc && <div className="text-xs text-gray-500 mt-0.5">{c.desc}</div>}
                    <code className="text-[10px] font-mono text-gray-400">{c.key}</code>
                  </div>
                </label>
              )
            })}
            {filtered.length === 0 && (
              <p className="text-xs text-gray-500 col-span-full py-3 text-center">
                No categories match “{query}”
              </p>
            )}
          </div>
          <p className="text-[10px] text-gray-500 mt-1.5 leading-relaxed">
            Leave all unchecked to collect <strong>everything in the {level} depth</strong>.
            Checking specific categories restricts the run to just those.
          </p>
        </div>
      )}
    </div>
  )
}
