import { X } from 'lucide-react'
import Modal from './shared/Modal'
import { NAV_SHORTCUTS, GLOBAL_SHORTCUTS } from '../nav'

const KBD_CLS = 'inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono font-semibold rounded border border-gray-300 bg-gray-100 text-gray-700 shadow-sm'

function Kbd({ children }) {
  return <kbd className={KBD_CLS}>{children}</kbd>
}

// Derived from the shared nav manifest so the displayed keys always match the
// bindings actually wired up in the layout.
const SHORTCUT_SECTIONS = [
  { title: 'Navigation', shortcuts: NAV_SHORTCUTS.map(s => ({ keys: s.keys, label: s.label })) },
  { title: 'Global',     shortcuts: GLOBAL_SHORTCUTS },
]

export default function KeyboardShortcutsModal({ onClose }) {
  return (
    <Modal onClose={onClose} className="modal-box w-full max-w-lg" ariaLabel="Keyboard shortcuts">
      <>
        {/* Header */}
        <div className="modal-header">
          <div className="flex items-center gap-2">
            <span className={KBD_CLS}>?</span>
            <span className="font-semibold text-brand-text text-sm">Keyboard Shortcuts</span>
          </div>
          <button onClick={onClose} className="icon-btn" aria-label="Close">
            <X size={14} />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 grid grid-cols-1 sm:grid-cols-2 gap-6">
          {SHORTCUT_SECTIONS.map(section => (
            <div key={section.title}>
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-2">
                {section.title}
              </p>
              <div className="space-y-1.5">
                {section.shortcuts.map((sc, i) => (
                  <div key={i} className="flex items-center justify-between gap-3">
                    <span className="text-xs text-gray-600">{sc.label}</span>
                    <div className="flex items-center gap-1 flex-shrink-0">
                      {sc.keys.map((k, ki) => (
                        <span key={ki} className="flex items-center gap-1">
                          {ki > 0 && (
                            <span className="text-[10px] text-gray-500">then</span>
                          )}
                          <Kbd>{k}</Kbd>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-between">
          <p className="text-[10px] text-gray-500">
            Press <Kbd>?</Kbd> anywhere to toggle this panel
          </p>
          <button onClick={onClose} className="btn-ghost text-xs">
            Close
          </button>
        </div>
      </>
    </Modal>
  )
}
