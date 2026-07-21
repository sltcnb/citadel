import { useEffect, useRef } from 'react'

// Shared modal primitive: standardizes a11y behaviour across every dialog —
//   • role="dialog" + aria-modal="true"
//   • Escape-to-close
//   • focus trap (Tab / Shift+Tab cycle within the dialog)
//   • focus restore to the previously-focused element on unmount
//   • click-outside-to-close (on the overlay itself)
//
// It is intentionally unopinionated about visuals: callers pass their existing
// overlay / box class names so the look is unchanged — this only layers on
// behaviour and the correct ARIA wiring.
const FOCUSABLE =
  'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])'

export default function Modal({
  onClose,
  overlayClassName = 'modal-overlay',
  className = 'modal-box',
  style,
  labelledBy,
  ariaLabel,
  closeOnOverlayClick = true,
  children,
}) {
  const boxRef = useRef(null)
  const restoreRef = useRef(null)

  // Keep the latest onClose without making it an effect dependency. Callers
  // routinely pass an inline arrow (`onClose={() => setOpen(false)}`), whose
  // identity changes on every parent render — so if the setup effect depended
  // on onClose it would tear down and re-run on each keystroke inside the
  // dialog, yanking focus back to the first focusable (the close button). The
  // effect must run once per mount only.
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  useEffect(() => {
    restoreRef.current = document.activeElement

    // Move focus into the dialog on open — but only if a child hasn't already
    // claimed it (e.g. an input with autoFocus). Otherwise focus the first
    // focusable, else the box itself.
    const box = boxRef.current
    if (box && !box.contains(document.activeElement)) {
      const first = box.querySelector(FOCUSABLE)
      ;(first || box).focus?.()
    }

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onCloseRef.current?.()
        return
      }
      if (e.key !== 'Tab') return
      const node = boxRef.current
      if (!node) return
      const focusable = Array.from(node.querySelectorAll(FOCUSABLE))
        .filter(el => el.offsetParent !== null || el === document.activeElement)
      if (focusable.length === 0) {
        e.preventDefault()
        node.focus?.()
        return
      }
      const firstEl = focusable[0]
      const lastEl = focusable[focusable.length - 1]
      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault()
        lastEl.focus()
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault()
        firstEl.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    return () => {
      document.removeEventListener('keydown', onKeyDown, true)
      // Restore focus to wherever it was before the dialog opened.
      const el = restoreRef.current
      if (el && typeof el.focus === 'function') el.focus()
    }
    // Mount-once: focus trap + listener are set up when the dialog opens and
    // torn down when it unmounts — never on onClose identity changes (onClose
    // is read via onCloseRef, so it is intentionally not a dependency).
  }, [])

  return (
    <div
      className={overlayClassName}
      onClick={closeOnOverlayClick ? e => { if (e.target === e.currentTarget) onClose?.() } : undefined}
    >
      <div
        ref={boxRef}
        role="dialog"
        aria-modal="true"
        aria-label={labelledBy ? undefined : ariaLabel}
        aria-labelledby={labelledBy}
        tabIndex={-1}
        className={className}
        style={style}
        onClick={e => e.stopPropagation()}
      >
        {children}
      </div>
    </div>
  )
}
