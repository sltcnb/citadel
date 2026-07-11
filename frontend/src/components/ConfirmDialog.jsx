import { X } from 'lucide-react'
import Modal from './shared/Modal'

export default function ConfirmDialog({
  title,
  icon,
  message,
  confirmLabel,
  confirmClass = 'btn-outline',
  onConfirm,
  onCancel,
  busy = false,
  maxWidth = 420,
}) {
  return (
    <Modal onClose={onCancel} className="modal-box" style={{ maxWidth }} ariaLabel={typeof title === 'string' ? title : 'Confirm'}>
      <div className="modal-header">
        <div className="flex items-center gap-2">
          {icon}
          <span className="text-sm font-semibold text-brand-text">{title}</span>
        </div>
        <button className="icon-btn" aria-label="Close" onClick={onCancel}><X size={14} /></button>
      </div>
      <div className="p-5">
        <p className="text-sm text-gray-600 mb-5">{message}</p>
        <div className="flex gap-3 justify-end">
          <button className="btn-ghost" onClick={onCancel}>Cancel</button>
          <button className={confirmClass} disabled={busy} onClick={onConfirm}>
            {busy ? 'Working…' : confirmLabel}
          </button>
        </div>
      </div>
    </Modal>
  )
}
