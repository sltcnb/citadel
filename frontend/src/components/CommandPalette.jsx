/**
 * Cmd-K / Ctrl-K command palette — single biggest "feels modern" win.
 *
 *   ⌘K            Open palette
 *   ↑↓            Navigate
 *   Enter         Run selected command
 *   Esc           Close
 *
 * Commands come from two sources:
 *   - Static: navigation entries (every page), top-level actions
 *   - Dynamic: live case list (jump to case by name)
 *
 * Usage: mount once in App / Layout. Self-contained.
 */
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { Search, ArrowRight, Plus, Shield } from 'lucide-react'
import { api } from '../api/client'
import { NAV_ITEMS, CASE_ICON } from '../nav'
import Modal from './shared/Modal'

// Derived from the shared nav manifest so the palette can never fall behind the
// top-nav (it used to miss Stack / Templates / Logs / Account).
const NAV_COMMANDS = NAV_ITEMS.map(item => ({
  id:    `nav:${item.to}`,
  label: item.label,
  group: 'Navigate',
  to:    item.to,
  Icon:  item.icon,
}))

export default function CommandPalette() {
  const [open, setOpen]   = useState(false)
  const [query, setQuery] = useState('')
  const [idx, setIdx]     = useState(0)
  const [cases, setCases] = useState([])
  const [lastCaseId, setLastCaseId] = useState(null)
  const inputRef = useRef(null)
  const navigate = useNavigate()

  // Lazy-load cases the first time the palette opens
  useEffect(() => {
    if (!open || cases.length > 0) return
    api.cases.list().then(r => setCases(r.cases || [])).catch(() => {})
  }, [open])

  // The action commands target the "current" case — re-read it on every open
  // so it reflects the case the analyst was just in, not the one at mount.
  useEffect(() => {
    if (open) setLastCaseId(localStorage.getItem('fo-last-case') || null)
  }, [open])

  // Global hotkey: Cmd/Ctrl-K
  useEffect(() => {
    function onKey(e) {
      const isCmdK = (e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k'
      if (isCmdK) { e.preventDefault(); setOpen(v => !v); setQuery(''); setIdx(0); return }
      if (e.key === 'Escape' && open) setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open])

  useEffect(() => { if (open) setTimeout(() => inputRef.current?.focus(), 0) }, [open])

  // Build the command list (actions + nav + case jumps)
  const all = useMemo(() => {
    // Top-level actions — navigation-level only, no API mutations. "New case"
    // opens the layout's new-case form via the shared event; the case actions
    // jump to the current case (detection rules live in its Detect panel).
    const actionCmds = [
      {
        id:    'action:new-case',
        label: 'New case',
        group: 'Actions',
        Icon:  Plus,
        run:   () => window.dispatchEvent(new CustomEvent('citadel:new-case')),
      },
      ...(lastCaseId ? [
        {
          id:    'action:current-case',
          label: 'Go to current case',
          group: 'Actions',
          sub:   lastCaseId,
          to:    `/cases/${lastCaseId}`,
          Icon:  CASE_ICON,
        },
        {
          id:    'action:detect',
          label: 'Run detection rules',
          group: 'Actions',
          sub:   'on current case',
          to:    `/cases/${lastCaseId}`,
          // Deep-link straight into the Detection Rules panel — CaseTimeline
          // consumes location.state.openPanel on mount and opens the drawer.
          state: { openPanel: 'rules' },
          Icon:  Shield,
        },
      ] : []),
    ]
    const caseCmds = cases.map(c => ({
      id:    `case:${c.case_id}`,
      label: c.name,
      group: 'Cases',
      sub:   c.company || c.case_id,
      to:    `/cases/${c.case_id}`,
      Icon:  CASE_ICON,
    }))
    return [...actionCmds, ...NAV_COMMANDS, ...caseCmds]
  }, [cases, lastCaseId])

  // Filter
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return all
    return all.filter(c =>
      c.label.toLowerCase().includes(q) ||
      (c.group || '').toLowerCase().includes(q) ||
      (c.sub   || '').toLowerCase().includes(q)
    )
  }, [all, query])

  useEffect(() => { setIdx(0) }, [query, open])

  function run(cmd) {
    setOpen(false)
    if (cmd?.run) cmd.run()
    else if (cmd?.to) navigate(cmd.to, cmd.state ? { state: cmd.state } : undefined)
  }

  function onKeyDown(e) {
    if (!filtered.length) return
    if (e.key === 'ArrowDown') { e.preventDefault(); setIdx(i => (i + 1) % filtered.length) }
    else if (e.key === 'ArrowUp')   { e.preventDefault(); setIdx(i => (i - 1 + filtered.length) % filtered.length) }
    else if (e.key === 'Enter')      { e.preventDefault(); run(filtered[idx]) }
  }

  if (!open) return null

  // Group results in display order they appear
  const byGroup = []
  const seen = new Set()
  let runningIdx = 0
  for (const c of filtered) {
    if (!seen.has(c.group)) { byGroup.push({ group: c.group, items: [] }); seen.add(c.group) }
    const g = byGroup.find(g => g.group === c.group)
    g.items.push({ ...c, _i: runningIdx++ })
  }

  return (
    <Modal
      onClose={() => setOpen(false)}
      overlayClassName="fixed inset-0 z-50 bg-black/30 flex items-start justify-center pt-[15vh] px-4"
      className="w-full max-w-xl bg-white rounded-xl shadow-card-md border border-gray-200 overflow-hidden flex flex-col fade-in"
      style={{ boxShadow: '0 25px 50px -12px rgba(15,23,42,0.25)' }}
      ariaLabel="Command palette"
    >
        <div className="flex items-center gap-2 px-4 py-3 border-b border-gray-100">
          <Search size={14} className="text-gray-400" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Type a page, case, or action…"
            role="combobox"
            aria-expanded="true"
            aria-controls="cmdk-listbox"
            aria-activedescendant={filtered.length > 0 ? `cmdk-option-${idx}` : undefined}
            aria-autocomplete="list"
            aria-label="Command palette"
            className="flex-1 bg-transparent outline-none text-sm placeholder:text-gray-400 text-brand-text"
          />
          <kbd className="kbd">esc</kbd>
        </div>
        <div className="max-h-[60vh] overflow-y-auto py-1" role="listbox" id="cmdk-listbox" aria-label="Commands">
          {filtered.length === 0 && (
            <p className="text-xs text-gray-500 italic text-center py-6">No matches</p>
          )}
          {byGroup.map(g => (
            <div key={g.group} className="py-1" role="group" aria-label={g.group}>
              <div className="px-3 py-1 text-[10px] font-semibold text-gray-500 uppercase tracking-wider" aria-hidden="true">
                {g.group}
              </div>
              {g.items.map(c => {
                const active = c._i === idx
                return (
                  <button
                    key={c.id}
                    id={`cmdk-option-${c._i}`}
                    role="option"
                    aria-selected={active}
                    onClick={() => run(c)}
                    onMouseEnter={() => setIdx(c._i)}
                    className={`w-full flex items-center gap-3 px-3 py-2 text-sm transition-colors ${
                      active ? 'bg-brand-accentlight text-brand-text' : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    <c.Icon size={14} className="flex-shrink-0 text-gray-400" />
                    <span className="flex-1 truncate text-left">{c.label}</span>
                    {c.sub && <span className="text-[11px] text-gray-400 truncate max-w-[40%]">{c.sub}</span>}
                    {active && <ArrowRight size={12} className="text-brand-accent" />}
                  </button>
                )
              })}
            </div>
          ))}
        </div>
        <div className="flex items-center gap-3 px-3 py-2 border-t border-gray-100 text-[10px] text-gray-500">
          <span className="flex items-center gap-1"><kbd className="kbd">↑↓</kbd> navigate</span>
          <span className="flex items-center gap-1"><kbd className="kbd">↵</kbd> open</span>
          <span className="ml-auto flex items-center gap-1"><kbd className="kbd">⌘</kbd><kbd className="kbd">K</kbd> toggle</span>
        </div>
    </Modal>
  )
}
