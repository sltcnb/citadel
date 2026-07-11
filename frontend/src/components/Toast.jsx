import { AlertTriangle, CheckCircle } from 'lucide-react'

export default function Toast({ toast }) {
  if (!toast) return null
  return (
    <div
      role="status"
      aria-live={toast.type === 'error' ? 'assertive' : 'polite'}
      className={`fixed bottom-5 right-5 z-50 flex items-center gap-2 px-4 py-3
                     rounded-xl shadow-lg text-sm font-medium transition-all ${
      toast.type === 'error' ? 'bg-red-600 text-white' : 'bg-gray-900 text-white'
    }`}>
      {toast.type === 'error'
        ? <AlertTriangle size={14} />
        : <CheckCircle size={14} className="text-green-400" />}
      {toast.msg}
    </div>
  )
}
