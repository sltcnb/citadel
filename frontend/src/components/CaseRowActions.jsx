import { useRef, useState, useEffect } from 'react'
import { Archive, Download, DownloadCloud, RefreshCw, Trash2, ChevronRight, MoreHorizontal, Upload } from 'lucide-react'

export default function CaseRowActions({
  c,
  onArchive,
  onUpload,
  onPurge,
  onRestore,
  onUnarchive,
  onDelete,
  onDownload,
  onNavigate,
  restoring = false,
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const triggerRef = useRef(null)

  useEffect(() => {
    if (!open) return
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    // Menu keyboard handling mirrors ToolbarMenu: Escape closes and returns
    // focus to the trigger; ArrowUp/Down cycle the menuitems.
    function onKey(e) {
      if (e.key === 'Escape') {
        e.stopPropagation()
        setOpen(false)
        triggerRef.current?.focus()
        return
      }
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return
      const items = Array.from(ref.current?.querySelectorAll('[role="menuitem"]') || [])
      if (!items.length) return
      e.preventDefault()
      const idx = items.indexOf(document.activeElement)
      const next = e.key === 'ArrowDown'
        ? (idx + 1) % items.length
        : (idx - 1 + items.length) % items.length
      items[next]?.focus()
    }
    document.addEventListener('mousedown', handler)
    document.addEventListener('keydown', onKey)
    // Move focus into the menu so keyboard users land on the first action.
    ref.current?.querySelector('[role="menuitem"]')?.focus()
    return () => {
      document.removeEventListener('mousedown', handler)
      document.removeEventListener('keydown', onKey)
    }
  }, [open])

  function stop(e) { e.stopPropagation() }

  const isActive   = c.status === 'active'
  const isArchived = c.status === 'archived'
  const isPurged   = c.local_purged === 'true'
  const hasS3      = !!c.archive_key

  const items = []

  if (hasS3) {
    items.push({
      icon: restoring ? <RefreshCw size={12} className="animate-spin" /> : <DownloadCloud size={12} />,
      label: isPurged ? 'Restore from S3' : 'Re-index from S3',
      onClick: () => { setOpen(false); onRestore?.(c.case_id) },
      cls: 'text-indigo-600',
      disabled: restoring,
    })
  }

  if (isActive && !isPurged) {
    items.push({
      icon: <Archive size={12} />,
      label: 'Archive',
      onClick: () => { setOpen(false); onArchive?.(c.case_id) },
      cls: 'text-amber-600',
    })
    items.push({
      icon: <Download size={12} />,
      label: 'Download archive',
      onClick: () => { setOpen(false); onDownload?.(c.case_id) },
      cls: 'text-emerald-600',
    })
    items.push({
      icon: <Upload size={12} />,
      label: 'Upload to S3',
      onClick: () => { setOpen(false); onUpload?.(c.case_id) },
      cls: 'text-sky-600',
    })
    items.push({
      icon: <DownloadCloud size={12} />,
      label: 'Archive & Purge',
      onClick: () => { setOpen(false); onPurge?.(c.case_id, c.name) },
      cls: 'text-violet-600',
    })
  }

  if (isArchived && !isPurged) {
    items.push({
      icon: <RefreshCw size={12} />,
      label: 'Unarchive',
      onClick: () => { setOpen(false); onUnarchive?.(c.case_id) },
      cls: 'text-green-600',
    })
    items.push({
      icon: <Download size={12} />,
      label: 'Download archive',
      onClick: () => { setOpen(false); onDownload?.(c.case_id) },
      cls: 'text-emerald-600',
    })
    items.push({
      icon: <Upload size={12} />,
      label: 'Upload to S3',
      onClick: () => { setOpen(false); onUpload?.(c.case_id) },
      cls: 'text-sky-600',
    })
    items.push({
      icon: <DownloadCloud size={12} />,
      label: 'Archive & Purge',
      onClick: () => { setOpen(false); onPurge?.(c.case_id, c.name) },
      cls: 'text-violet-600',
    })
  }

  return (
    <div className="flex items-center gap-1 flex-shrink-0" onClick={stop}>

      {/* ··· overflow menu */}
      {items.length > 0 && (
        <div ref={ref} className="relative">
          <button
            ref={triggerRef}
            className="icon-btn text-gray-400 hover:text-gray-600"
            title="More actions"
            aria-label="More actions"
            aria-haspopup="menu"
            aria-expanded={open}
            onClick={e => { stop(e); setOpen(v => !v) }}
          >
            <MoreHorizontal size={13} />
          </button>

          {open && (
            <div role="menu" aria-label="Case actions"
              className="absolute right-0 top-full mt-1 w-44 bg-white border border-gray-200 rounded-lg shadow-lg py-1 z-50">
              {items.map((item, i) => (
                <button
                  key={i}
                  role="menuitem"
                  disabled={item.disabled}
                  onClick={item.onClick}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 text-xs hover:bg-gray-50 transition-colors disabled:opacity-40 ${item.cls}`}
                >
                  {item.icon}
                  {item.label}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Delete */}
      <button
        className="icon-btn text-gray-400 hover:text-red-500"
        title="Delete"
        aria-label="Delete case"
        onClick={e => { stop(e); onDelete?.(c.case_id, c.name) }}
      >
        <Trash2 size={13} />
      </button>

      {/* Navigate */}
      <button
        className="icon-btn text-gray-400 hover:text-brand-accent"
        title="Open case"
        aria-label="Open case"
        onClick={e => { stop(e); onNavigate?.(c.case_id) }}
      >
        <ChevronRight size={13} />
      </button>
    </div>
  )
}
