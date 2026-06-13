import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  X, RefreshCw, CloudDownload, Folder, FileArchive, ChevronLeft,
} from 'lucide-react'
import { api } from '../api/client'
import { formatBytes } from '../utils/format'

export default function S3ArchiveImportModal({ onClose, onImported }) {
  const navigate = useNavigate()
  const [prefix, setPrefix]     = useState('')
  const [listing, setListing]   = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')
  const [importing, setImporting] = useState(null)

  useEffect(() => { browse('') }, [])

  async function browse(pfx) {
    setPrefix(pfx)
    setError('')
    setLoading(true)
    try {
      const res = await api.export.browseArchiveS3(pfx, '/')
      setListing(res)
    } catch (err) {
      setError(err.message || 'Browse failed')
      setListing(null)
    } finally {
      setLoading(false)
    }
  }

  async function doImport(key) {
    setImporting(key)
    try {
      const r = await api.export.importArchiveFromS3(key)
      onImported?.(`Imported "${r.case_name || key}" — new case created`)
      onClose()
      if (r.case_id) navigate(`/cases/${r.case_id}`)
    } catch (err) {
      setError(err.message || 'Import failed')
    } finally {
      setImporting(null)
    }
  }

  function goUp() {
    const parent = prefix.replace(/[^/]+\/$/, '')
    browse(parent)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg max-h-[80vh] flex flex-col">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <CloudDownload size={15} className="text-brand-accent" />
            <p className="font-semibold text-sm text-brand-text">Import Archive from S3</p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600">
            <X size={16} />
          </button>
        </div>

        {/* Breadcrumb */}
        <div className="flex items-center gap-1 px-5 py-2 border-b border-gray-50 text-xs text-gray-500 bg-gray-50/50">
          <button onClick={() => browse('')} className="hover:text-brand-accent font-medium">root</button>
          {prefix.split('/').filter(Boolean).map((seg, i, arr) => {
            const pfx = arr.slice(0, i + 1).join('/') + '/'
            return (
              <span key={pfx} className="flex items-center gap-1">
                <span>/</span>
                <button onClick={() => browse(pfx)} className="hover:text-brand-accent">{seg}</button>
              </span>
            )
          })}
        </div>

        {/* Listing */}
        <div className="overflow-y-auto flex-1 px-4 py-3 space-y-1">
          {loading && (
            <div className="flex items-center gap-2 text-gray-400 py-6 justify-center">
              <RefreshCw size={14} className="animate-spin" />
              <span className="text-xs">Loading…</span>
            </div>
          )}
          {error && (
            <p className="text-xs text-red-500 px-1 py-4 text-center">{error}</p>
          )}
          {!loading && !error && listing && (
            <>
              {prefix && (
                <button
                  onClick={goUp}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-gray-500 hover:bg-gray-50 transition-colors"
                >
                  <ChevronLeft size={12} /> ..
                </button>
              )}
              {listing.dirs.map(d => (
                <button
                  key={d.key}
                  onClick={() => browse(d.key)}
                  className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-xs text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  <Folder size={13} className="text-yellow-500 flex-shrink-0" />
                  <span className="truncate">{d.key.replace(prefix, '').replace(/\/$/, '')}</span>
                </button>
              ))}
              {listing.files.map(f => {
                const name = f.key.split('/').pop()
                const isCitadel = name.endsWith('.citadel')
                return (
                  <div
                    key={f.key}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs transition-colors ${isCitadel ? 'hover:bg-brand-accentlight/30' : 'opacity-50'}`}
                  >
                    <FileArchive size={13} className={`flex-shrink-0 ${isCitadel ? 'text-brand-accent' : 'text-gray-400'}`} />
                    <span className="flex-1 truncate text-gray-700">{name}</span>
                    {f.size != null && (
                      <span className="text-gray-400 flex-shrink-0">{formatBytes(f.size)}</span>
                    )}
                    {isCitadel && (
                      <button
                        onClick={() => doImport(f.key)}
                        disabled={importing === f.key}
                        className="btn-primary text-[11px] py-0.5 px-2 flex-shrink-0"
                      >
                        {importing === f.key
                          ? <RefreshCw size={10} className="animate-spin" />
                          : 'Import'}
                      </button>
                    )}
                  </div>
                )
              })}
              {listing.dirs.length === 0 && listing.files.length === 0 && (
                <p className="text-xs text-gray-400 text-center py-6">Empty folder</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
