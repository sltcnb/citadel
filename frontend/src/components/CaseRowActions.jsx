import { useRef, useState, useEffect } from 'react'
import { Archive, DownloadCloud, RefreshCw, Trash2, ChevronRight, MoreHorizontal, Upload } from 'lucide-react'

export default function CaseRowActions({
  c,
  onArchive,
  onUpload,
  onPurge,
  onRestore,
  onUnarchive,
  onDelete,
  onNavigate,
  restoring = false,
}) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    if (!open) return
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
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
            className="icon-btn text-gray-400 hover:text-gray-600"
            title="More actions"
            onClick={e => { stop(e); setOpen(v => !v) }}
          >
            <MoreHorizontal size={13} />
          </button>

          {open && (
            <div className="absolute right-0 top-full mt-1 w-44 bg-white border border-gray-200 rounded-lg shadow-lg py-1 z-50">
              {items.map((item, i) => (
                <button
                  key={i}
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
        onClick={e => { stop(e); onDelete?.(c.case_id, c.name) }}
      >
        <Trash2 size={13} />
      </button>

      {/* Navigate */}
      <button
        className="icon-btn text-gray-400 hover:text-brand-accent"
        onClick={e => { stop(e); onNavigate?.(c.case_id) }}
      >
        <ChevronRight size={13} />
      </button>
    </div>
  )
}
