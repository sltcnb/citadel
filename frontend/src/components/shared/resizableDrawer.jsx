import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * useResizableWidth — give any right-hand drawer a user-draggable width that
 * survives reload. Every analyst has a different monitor and a different tab
 * open beside the panel; a fixed `w-[580px]` is wrong for half of them. This
 * lets them grab the panel's left edge and size it, once, forever.
 *
 *   const [width, handleProps] = useResizableWidth('notes', 560)
 *   <div style={{ width }}>
 *     <DrawerResizeHandle {...handleProps} />
 *     …
 *   </div>
 *
 * Width is clamped to [min, 96vw] and stored under `fo_drawerw_<slug>`.
 * Double-clicking the handle resets to the panel's default width.
 */
export function useResizableWidth(slug, defaultPx, { min = 360 } = {}) {
  const storeKey = `fo_drawerw_${slug}`
  const maxPx = () => Math.round((typeof window !== 'undefined' ? window.innerWidth : 1600) * 0.96)

  const [width, setWidth] = useState(() => {
    try {
      const raw = localStorage.getItem(storeKey)
      const n = raw ? parseInt(raw, 10) : NaN
      if (!isNaN(n) && n >= min) return Math.min(n, maxPx())
    } catch { /* ignore */ }
    return defaultPx
  })

  // Latest width, readable synchronously inside the drag listeners without
  // re-subscribing them on every pixel.
  const widthRef = useRef(width)
  widthRef.current = width
  const dragging = useRef(false)

  const persist = useCallback((w) => {
    try { localStorage.setItem(storeKey, String(w)) } catch { /* ignore */ }
  }, [storeKey])

  const onMouseDown = useCallback((e) => {
    e.preventDefault()
    const startX = e.clientX
    const startWidth = widthRef.current
    dragging.current = true

    function onMove(ev) {
      if (!dragging.current) return
      // Drawer is pinned to the right, so dragging the LEFT edge leftward
      // widens it: width grows as the cursor moves left of the grab point.
      const w = Math.max(min, Math.min(maxPx(), startWidth + (startX - ev.clientX)))
      setWidth(w)
    }
    function onUp() {
      dragging.current = false
      persist(widthRef.current)
      document.removeEventListener('mousemove', onMove)
      document.removeEventListener('mouseup', onUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMove)
    document.addEventListener('mouseup', onUp)
  }, [min, persist])

  const onDoubleClick = useCallback(() => {
    setWidth(defaultPx)
    persist(defaultPx)
  }, [defaultPx, persist])

  // Keep width within the viewport if the window shrinks below it.
  useEffect(() => {
    function onResize() { setWidth(w => Math.min(w, maxPx())) }
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  return [width, { onMouseDown, onDoubleClick, title: 'Drag to resize · double-click to reset width' }]
}

/**
 * ResizableDrawer — backdrop + right-pinned, edge-draggable drawer container
 * for panels that keep their OWN header/body markup (i.e. can't drop into
 * PanelShell). Replaces the copy-pasted
 *   <div className="panel-backdrop"><div className="absolute right-0 … w-[Npx]">
 * boilerplate and hands every such panel the same resize behaviour PanelShell
 * gives the standard ones.
 *
 *   <ResizableDrawer slug="notes" defaultWidth={560} onClose={…}>
 *     <header/> <body/>
 *   </ResizableDrawer>
 */
export function ResizableDrawer({ slug, defaultWidth = 640, onClose, className = '', children }) {
  const [width, handleProps] = useResizableWidth(slug, defaultWidth)
  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className={`absolute right-0 top-0 h-full flex flex-col ${className}`}
        style={{
          width,
          maxWidth: '96vw',
          // Token-driven surface — light + dark come from --ct-* (one source),
          // same as .panel-drawer / PanelShell.
          background: 'var(--ct-surface)',
          borderLeft: '1px solid var(--ct-border)',
          boxShadow: '-4px 0 24px rgba(0,0,0,0.10)',
        }}
        onClick={e => e.stopPropagation()}
      >
        <DrawerResizeHandle {...handleProps} />
        {children}
      </div>
    </div>
  )
}

/**
 * DrawerResizeHandle — the visible grip on a drawer's left edge. Widens on
 * hover, and carries its own tooltip so the affordance explains itself.
 */
export function DrawerResizeHandle({ onMouseDown, onDoubleClick, title }) {
  return (
    <div
      onMouseDown={onMouseDown}
      onDoubleClick={onDoubleClick}
      title={title}
      className="group absolute left-0 top-0 bottom-0 w-1.5 -ml-0.5 cursor-col-resize z-30 flex items-center justify-center"
    >
      <div className="w-px h-full bg-transparent group-hover:bg-brand-accent/40 transition-colors" />
      <div className="absolute top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity">
        <span className="block w-0.5 h-5 rounded-full bg-brand-accent" />
      </div>
    </div>
  )
}
