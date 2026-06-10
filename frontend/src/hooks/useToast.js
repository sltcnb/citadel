import { useState } from 'react'

export function useToast(duration = 3200) {
  const [toast, setToast] = useState(null)

  function showToast(msg, type = 'success') {
    setToast({ msg, type })
    setTimeout(() => setToast(null), duration)
  }

  return [toast, showToast]
}
