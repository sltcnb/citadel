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

  useEffect(() => {
    restoreRef.current = document.activeElement

    // Move focus into the dialog (first focusable, else the box itself).
    const box = boxRef.current
    if (box) {
      const first = box.querySelector(FOCUSABLE)
      ;(first || box).focus?.()
    }

    function onKeyDown(e) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onClose?.()
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
  }, [onClose])

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
