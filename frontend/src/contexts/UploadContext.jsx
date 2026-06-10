import { createContext, useCallback, useContext, useState } from 'react'

const UploadContext = createContext(null)

export function UploadProvider({ children }) {
  const [uploads, setUploads] = useState({})  // id → { label, pct }

  const startUpload = useCallback((id, label) => {
    setUploads(u => ({ ...u, [id]: { label, pct: 0 } }))
  }, [])

  const updateUpload = useCallback((id, pct) => {
    setUploads(u => u[id] ? { ...u, [id]: { ...u[id], pct } } : u)
  }, [])

  const finishUpload = useCallback((id) => {
    setUploads(u => { const n = { ...u }; delete n[id]; return n })
  }, [])

  return (
    <UploadContext.Provider value={{ uploads, startUpload, updateUpload, finishUpload }}>
      {children}
    </UploadContext.Provider>
  )
}

export function useUpload() {
  const ctx = useContext(UploadContext)
  if (!ctx) throw new Error('useUpload must be used inside UploadProvider')
  return ctx
}
