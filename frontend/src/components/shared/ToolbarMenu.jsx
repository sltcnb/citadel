import { useState, useRef, useEffect } from 'react'
import { ChevronDown } from 'lucide-react'

/**
 * A grouped toolbar dropdown — collapses several related panel-launch buttons
 * into one labelled button, so the case toolbar isn't a wall of 14 buttons.
 *
 * items: [{ key, label, icon: <Icon/>, onClick, active?, title? }]
 * `active` highlights the trigger when any child panel is open.
 *
 * Closes on outside-click and Escape. Keyboard-operable.
 */
export default function ToolbarMenu({ label, icon, items = [], anyActive = false }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    function onDoc(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    function onKey(e) { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen(v => !v)}
        className={`btn-outline ${anyActive ? 'bg-brand-accentlight border-brand-accent text-brand-accent' : ''}`}
        aria-haspopup="menu"
        aria-expanded={open}
      >
        {icon}
        {label}
        <ChevronDown size={12} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div
          role="menu"
          className="absolute right-0 top-full mt-1 z-50 min-w-[200px] bg-white border border-gray-200 rounded-lg shadow-lg py-1"
        >
          {items.map(it => (
            <button
              key={it.key}
              role="menuitem"
              title={it.title || ''}
              onClick={() => { setOpen(false); it.onClick() }}
              className={`w-full flex items-center gap-2 px-3 py-1.5 text-xs text-left hover:bg-gray-50 transition-colors ${
                it.active ? 'text-brand-accent font-medium' : 'text-gray-700'
              }`}
            >
              <span className="flex-shrink-0 w-4 flex justify-center">{it.icon}</span>
              <span className="flex-1">{it.label}</span>
              {it.active && <span className="w-1.5 h-1.5 rounded-full bg-brand-accent flex-shrink-0" />}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
