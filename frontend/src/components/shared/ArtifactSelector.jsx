/**
 * ArtifactSelector — the ONE artifact-collection picker shared by the Collector
 * (live/dead-box script generation) and Harvest (server-side disk-image
 * collection). Same visual language everywhere; no duplicated grids.
 *
 * Pure presentation — all state lives in the parent. No API calls.
 *
 * Two ways to feed it categories:
 *   • flat  → `categories={[{key,label,desc,warn?}]}`   (Harvest)
 *   • grouped → `groups={[{group, items:[{key,label,desc,warn?}]}]}` (Collector)
 *
 * Props:
 *   levels      [{key,label,desc}]     OPTIONAL depth pills (omit → no depth row)
 *   level       string                 selected depth key
 *   onLevel     (key)=>void            depth picked
 *   categories  [{key,label,desc,warn}]  flat catalog (ignored if `groups` set)
 *   groups      [{group, items}]       pre-grouped catalog (renders sections)
 *   selected    Set|array              selected keys
 *   onToggle    (key)=>void            toggle one
 *   onToggleGroup (keys[])=>void       toggle a whole section (grouped mode);
 *                                      falls back to per-key onToggle if absent
 *   onSelectAll ()=>void               select/clear everything
 *   onClear     ()=>void               OPTIONAL "use depth defaults" control
 *   disabled    boolean
 *   clearLabel  string
 */
import { useMemo, useState } from 'react'
import { Search, X, AlertTriangle } from 'lucide-react'

const LEVEL_HINTS = {
  small:      'Fast triage — highest-value artifacts only',
  complete:   'Balanced coverage — recommended default',
  exhaustive: 'Everything available — slowest, largest output',
}
const LEVEL_LABEL = { small: 'Small', complete: 'Intermediate', exhaustive: 'Exhaustive' }

// Investigation scenarios → the artifact categories that matter for each. One
// click selects exactly the relevant set (intersected with what this catalog
// actually offers — works for both the live and dead-box category lists).
const SCENARIOS = [
  { key: 'ransomware', label: 'Ransomware', icon: '🔒',
    cats: ['eventlogs', 'evtx', 'prefetch', 'execution', 'mft', 'recyclebin', 'jumplists',
           'registry', 'persistence', 'antivirus', 'usb_devices', 'shimcache', 'documents'] },
  { key: 'phishing', label: 'Phishing / RMM abuse', icon: '🎣',
    cats: ['browser', 'browser_chrome', 'browser_edge', 'browser_firefox', 'downloads',
           'jumplists', 'prefetch', 'execution', 'email_outlook', 'timeline_activity', 'recyclebin'] },
  { key: 'insider', label: 'Insider / data theft', icon: '🕵️',
    cats: ['usb_devices', 'jumplists', 'recyclebin', 'browser', 'browser_chrome', 'downloads',
           'lnk', 'timeline_activity', 'cloud_onedrive', 'email_outlook', 'thumbcache', 'documents'] },
  { key: 'intrusion', label: 'Intrusion / lateral movement', icon: '🌐',
    cats: ['eventlogs', 'evtx', 'registry', 'persistence', 'execution', 'prefetch',
           'remote_access', 'rdp', 'ssh_ftp', 'network', 'sysmon'] },
  { key: 'malware', label: 'Malware execution', icon: '🐛',
    cats: ['prefetch', 'execution', 'registry', 'pe', 'persistence', 'antivirus',
           'sysmon', 'jumplists', 'shimcache', 'browser'] },
]

function CategoryCard({ c, checked, disabled, onToggle }) {
  return (
    <label
      className={`flex items-start gap-3 p-3 rounded-lg border transition-all ${
        disabled ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer'
      } ${
        checked
          ? c.warn ? 'border-amber-400 bg-amber-50' : 'border-brand-accent/40 bg-brand-accentlight'
          : 'border-gray-200 hover:border-gray-300'
      }`}
    >
      <input type="checkbox" checked={checked} disabled={disabled}
        onChange={() => onToggle?.(c.key)}
        className="mt-0.5 accent-brand-accent cursor-pointer flex-shrink-0" />
      <div className="min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="text-sm font-medium text-brand-text">{c.label}</span>
          {c.warn && <AlertTriangle size={11} className="text-amber-500 flex-shrink-0" />}
        </div>
        {c.desc && <div className="text-xs text-gray-500 mt-0.5">{c.desc}</div>}
        <code className="text-[10px] font-mono text-gray-400">{c.key}</code>
      </div>
    </label>
  )
}

export default function ArtifactSelector({
  levels = [],
  level,
  onLevel,
  categories = [],
  groups = null,
  selected,
  onToggle,
  onToggleGroup,
  onSelectAll,
  onClear,
  onScenario,
  disabled = false,
  clearLabel = 'Use depth defaults',
}) {
  const [query, setQuery] = useState('')
  const [activeScenario, setActiveScenario] = useState(null)
  const sel = selected instanceof Set ? selected : new Set(selected || [])
  const grouped = Array.isArray(groups)
  const flatAll = grouped ? groups.flatMap(g => g.items) : categories

  // Scenarios applicable to THIS catalog (≥3 of their categories are offered).
  const presentKeys = useMemo(() => new Set(flatAll.map(c => c.key)), [flatAll])
  const scenarios = useMemo(
    () => SCENARIOS
      .map(s => ({ ...s, keys: s.cats.filter(k => presentKeys.has(k)) }))
      .filter(s => s.keys.length >= 3),
    [presentKeys],
  )
  function pickScenario(s) {
    if (disabled) return
    setActiveScenario(s.key)
    if (onScenario) onScenario(s.keys)
    else s.keys.forEach(k => { if (!sel.has(k)) onToggle?.(k) })
  }

  const match = c => {
    const q = query.trim().toLowerCase()
    if (!q) return true
    return c.key.toLowerCase().includes(q) ||
      (c.label || '').toLowerCase().includes(q) ||
      (c.desc || '').toLowerCase().includes(q)
  }

  const visibleGroups = useMemo(() => {
    if (!grouped) return null
    return groups
      .map(g => ({ group: g.group, items: g.items.filter(match) }))
      .filter(g => g.items.length)
  }, [groups, grouped, query])  // eslint-disable-line
  const filteredFlat = useMemo(() => flatAll.filter(match), [flatAll, query])  // eslint-disable-line

  const allOn = flatAll.length > 0 && sel.size === flatAll.length
  const toggleSection = items => {
    const keys = items.map(i => i.key)
    if (onToggleGroup) onToggleGroup(keys)
    else keys.forEach(k => onToggle?.(k))
  }

  return (
    <div className="space-y-4">
      {/* Depth (optional) */}
      {levels.length > 0 && (
        <div>
          <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 mb-1.5">Depth</h4>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
            {levels.map(l => {
              const active = level === l.key
              const label  = l.label || LEVEL_LABEL[l.key] || l.key
              const hint   = l.desc  || LEVEL_HINTS[l.key] || ''
              return (
                <button key={l.key} type="button" disabled={disabled} onClick={() => onLevel?.(l.key)}
                  className={`flex flex-col items-start gap-0.5 py-2.5 px-3 rounded-lg border text-left transition-colors ${
                    active ? 'border-brand-accent bg-brand-accent/5 text-brand-accent'
                           : 'border-gray-200 text-gray-600 hover:border-gray-300'
                  } ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}>
                  <span className="text-sm font-semibold capitalize">{label}</span>
                  {hint && <span className={`text-[10px] leading-snug ${active ? 'text-brand-accent/70' : 'text-gray-500'}`}>{hint}</span>}
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Scenario presets — one click selects the categories that matter */}
      {scenarios.length > 0 && (onScenario || onToggle) && (
        <div>
          <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-400 mb-1.5">
            Scenario <span className="font-normal normal-case tracking-normal">— pick what you're investigating</span>
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {scenarios.map(s => (
              <button
                key={s.key} type="button" disabled={disabled}
                onClick={() => pickScenario(s)}
                title={`Select ${s.keys.length} categories relevant to ${s.label}`}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs border transition-colors ${
                  activeScenario === s.key
                    ? 'bg-brand-accent text-white border-brand-accent'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                } ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}
              >
                <span>{s.icon}</span>{s.label}
                <span className={activeScenario === s.key ? 'opacity-80' : 'text-gray-400'}>{s.keys.length}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Categories */}
      {flatAll.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-1.5 pb-1 border-b border-gray-100">
            <h4 className="text-[11px] font-semibold uppercase tracking-wider text-gray-400">
              {grouped ? 'Artifacts' : 'Categories'}
              <span className="ml-1.5 font-normal normal-case tracking-normal text-gray-400">
                {sel.size === 0 && levels.length ? `all in ${level}` : `${sel.size}/${flatAll.length}`}
              </span>
            </h4>
            <div className="flex items-center gap-3">
              <button type="button" disabled={disabled}
                className="text-[11px] text-brand-accent hover:underline disabled:opacity-50" onClick={onSelectAll}>
                {allOn ? 'Clear all' : 'Select all'}
              </button>
              {onClear && (
                <button type="button" disabled={disabled || sel.size === 0}
                  className="text-[11px] text-gray-500 hover:text-gray-700 disabled:opacity-40" onClick={onClear}>
                  {clearLabel}
                </button>
              )}
            </div>
          </div>

          <div className="relative mb-2">
            <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
            <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter…"
              className="input w-full text-xs pl-7 pr-7 py-1" />
            {query && (
              <button type="button" onClick={() => setQuery('')}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"><X size={11} /></button>
            )}
          </div>

          {grouped ? (
            <div className="space-y-4 max-h-[28rem] overflow-y-auto pr-0.5">
              {visibleGroups.map(({ group, items }) => {
                const onCount = items.filter(a => sel.has(a.key)).length
                return (
                  <div key={group}>
                    <div className="flex items-center justify-between mb-1.5">
                      <h5 className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">
                        {group} <span className="font-normal normal-case text-gray-400">{onCount}/{items.length}</span>
                      </h5>
                      <button type="button" disabled={disabled}
                        className="text-[10px] text-brand-accent hover:underline disabled:opacity-50"
                        onClick={() => toggleSection(items)}>
                        {onCount === items.length ? 'Clear section' : 'Select section'}
                      </button>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      {items.map(c => <CategoryCard key={c.key} c={c} checked={sel.has(c.key)} disabled={disabled} onToggle={onToggle} />)}
                    </div>
                  </div>
                )
              })}
              {visibleGroups.length === 0 && <p className="text-xs text-gray-500 py-3 text-center">No matches for “{query}”</p>}
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-72 overflow-y-auto pr-0.5">
              {filteredFlat.map(c => <CategoryCard key={c.key} c={c} checked={sel.has(c.key)} disabled={disabled} onToggle={onToggle} />)}
              {filteredFlat.length === 0 && <p className="text-xs text-gray-500 col-span-full py-3 text-center">No matches for “{query}”</p>}
            </div>
          )}

          {levels.length > 0 && (
            <p className="text-[10px] text-gray-500 mt-1.5 leading-relaxed">
              Leave all unchecked to collect <strong>everything in the {level} depth</strong>.
              Checking specific categories restricts the run to just those.
            </p>
          )}
        </div>
      )}
    </div>
  )
}
