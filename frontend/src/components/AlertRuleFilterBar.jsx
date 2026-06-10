import { useRef } from 'react'
import { Search, Tag, X } from 'lucide-react'
import { CATEGORY_ORDER, CATEGORY_STYLES } from './RuleDrawer'
import { presentCategories, artifactTypes } from '../lib/alertRuleFilters'

const PROVENANCE_PILLS = [
  { id: 'all',    label: 'All rules' },
  { id: 'sigma',  label: 'Sigma' },
  { id: 'custom', label: 'Custom' },
  { id: 'legacy', label: 'Legacy' },
]

// ── ProvenancePills ───────────────────────────────────────────────────────────
// Minimal provenance selector: compact pill row used in sidebar/compact contexts.
// Props: value, onChange, size ('sm' | 'xs')

export function ProvenancePills({ value, onChange, size = 'sm' }) {
  const cls = size === 'xs'
    ? 'text-[9px] px-2 py-0.5'
    : 'text-[10px] px-2.5 py-0.5'
  return (
    <div className="flex gap-1 flex-wrap">
      {PROVENANCE_PILLS.map(p => (
        <button
          key={p.id}
          onClick={() => onChange(p.id)}
          className={`${cls} rounded-full border transition-colors font-medium ${
            value === p.id
              ? 'bg-gray-800 text-white border-gray-800'
              : 'text-gray-500 border-gray-200 hover:border-gray-400 hover:text-gray-700'
          }`}
        >
          {p.label}
        </button>
      ))}
    </div>
  )
}

// ── AlertRuleFilterBar ────────────────────────────────────────────────────────
// Full filter bar: provenance pills + category pills + search + artifact select.
// Props:
//   rules        - full unfiltered rule list (to derive available categories/artifacts)
//   search       / onSearchChange
//   provenance   / onProvenanceChange
//   category     / onCategoryChange
//   artifact     / onArtifactChange
//   onClear      - called when "Clear" is clicked
//   searchRef    - optional forwarded ref for the search input

export default function AlertRuleFilterBar({
  rules = [],
  search, onSearchChange,
  provenance, onProvenanceChange,
  category, onCategoryChange,
  artifact, onArtifactChange,
  onClear,
  searchRef: externalSearchRef,
}) {
  const internalRef = useRef(null)
  const inputRef = externalSearchRef || internalRef

  const cats      = presentCategories(rules)
  const artifacts = artifactTypes(rules)

  const hasFilters = search || provenance !== 'all' || category !== 'all' || artifact !== 'all'

  return (
    <div className="space-y-2">
      {/* Provenance pills */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {PROVENANCE_PILLS.map(p => (
          <button
            key={p.id}
            onClick={() => onProvenanceChange(p.id)}
            className={`inline-flex items-center text-[11px] font-medium border rounded-full px-2.5 py-0.5 transition-colors ${
              provenance === p.id
                ? 'bg-gray-800 text-white border-gray-800'
                : 'bg-white text-gray-500 border-gray-200 hover:border-gray-400'
            }`}
          >
            {p.label}
          </button>
        ))}
      </div>

      {/* Category pills */}
      {cats.length > 2 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          <Tag size={12} className="text-gray-500 flex-shrink-0" />
          {cats.map(cat => {
            const isActive = category === cat
            const style = cat !== 'all' ? CATEGORY_STYLES[cat] || CATEGORY_STYLES['Other'] : null
            return (
              <button
                key={cat}
                onClick={() => onCategoryChange(cat)}
                className={`inline-flex items-center gap-1 text-[11px] font-medium border rounded-full px-2.5 py-0.5 transition-colors ${
                  isActive
                    ? cat === 'all'
                      ? 'bg-gray-800 text-white border-gray-800'
                      : `${style.bg} border-current ring-1 ring-current ring-offset-1`
                    : 'bg-white text-gray-500 border-gray-200 hover:border-gray-400'
                }`}
              >
                {cat !== 'all' && <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${style.dot}`} />}
                {cat === 'all' ? 'All categories' : cat}
              </button>
            )
          })}
        </div>
      )}

      {/* Search + artifact */}
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
          <input
            ref={inputRef}
            className="input pl-8 text-xs"
            placeholder="Search rules… (press / to focus)"
            value={search}
            onChange={e => onSearchChange(e.target.value)}
          />
        </div>
        {artifacts.length > 2 && (
          <select
            className="input text-xs max-w-[140px]"
            value={artifact}
            onChange={e => onArtifactChange(e.target.value)}
          >
            {artifacts.map(a => (
              <option key={a} value={a}>{a === 'all' ? 'All artifacts' : a}</option>
            ))}
          </select>
        )}
        {hasFilters && (
          <button onClick={onClear} className="btn-ghost text-xs flex items-center gap-1">
            <X size={12} /> Clear
          </button>
        )}
      </div>
    </div>
  )
}
