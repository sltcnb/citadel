import { useEffect, useState } from 'react'
import {
  ShieldCheck, ShieldAlert, Loader2, RefreshCw, AlertTriangle, X,
  Download, Copy, Check, FileCheck, Lock,
} from 'lucide-react'
import { api } from '../../api/client'
import PanelHelp from './PanelHelp'

/**
 * Right-side drawer: court-ready signed evidence chain (tamper-evident
 * chain-of-custody).
 *
 *   GET  /cases/{id}/evidence/seals
 *   GET  /cases/{id}/evidence/verify
 *   GET  /cases/{id}/evidence/manifest
 *   POST /cases/{id}/evidence/seal
 *
 * Seals are returned newest-first. The integrity banner is driven by the
 * `verify` block: green when the hash chain links cleanly, red when a link
 * has been tampered with.
 */
export default function EvidencePanel({ caseId, onClose }) {
  const [seals, setSeals]     = useState([])
  const [verify, setVerify]   = useState(null)   // { ok, broken_at, sealed_count }
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)

  const [verifying, setVerifying]   = useState(false)
  const [downloading, setDownloading] = useState(false)
  const [manifestInfo, setManifestInfo] = useState(null) // last download: { signed }

  const [copied, setCopied] = useState(null)   // sha256 just copied

  // manual seal form
  const [artId, setArtId]   = useState('')
  const [sha, setSha]       = useState('')
  const [sealing, setSealing] = useState(false)

  async function refresh() {
    setLoading(true); setError(null)
    try {
      const r = await api.evidence.seals(caseId)
      setSeals(r.seals || [])
      setVerify(r.verify || null)
    } catch (e) {
      setError(e.message || 'Failed to load evidence chain.')
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { refresh() }, [caseId])

  async function reVerify() {
    setVerifying(true); setError(null)
    try {
      const v = await api.evidence.verify(caseId)
      setVerify(v)
    } catch (e) {
      setError(e.message || 'Verification failed.')
    } finally {
      setVerifying(false)
    }
  }

  async function downloadManifest() {
    setDownloading(true); setError(null)
    try {
      const manifest = await api.evidence.manifest(caseId)
      setManifestInfo({ signed: !!manifest.signed })
      const blob = new Blob([JSON.stringify(manifest, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `custody-manifest-${caseId}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(e.message || 'Failed to build manifest.')
    } finally {
      setDownloading(false)
    }
  }

  async function copySha(value) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(value)
      setTimeout(() => setCopied(c => (c === value ? null : c)), 1500)
    } catch { /* clipboard unavailable */ }
  }

  async function sealManual(e) {
    e?.preventDefault?.()
    if (!artId.trim() || !sha.trim()) return
    setSealing(true); setError(null)
    try {
      await api.evidence.seal(caseId, {
        artifact_id: artId.trim(),
        sha256: sha.trim(),
        meta: { sealed_via: 'manual' },
      })
      setArtId(''); setSha('')
      await refresh()
    } catch (err) {
      setError(err.message || 'Failed to seal artifact.')
    } finally {
      setSealing(false)
    }
  }

  const ok = verify?.ok !== false   // treat unknown/loading as not-broken
  const sealedCount = verify?.sealed_count ?? seals.length

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="panel-drawer md:w-[860px]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <ShieldCheck size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Evidence chain of custody</span>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={refresh} disabled={loading} className="btn-secondary text-xs flex items-center gap-1.5">
              <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
              Refresh
            </button>
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <PanelHelp title="Evidence chain of custody"
            use="Verifies the tamper-evident hash-chain of sealed artifacts and exports a court-ready custody manifest."
            when="Before handing evidence to a client or court, or to prove nothing was altered."
            data={['Sealed artifacts — auto-sealed at ingest, or seal one manually here']}
            tip="Set EVIDENCE_SIGNING_KEY on the server to HMAC-sign the exported manifest." />
          {/* Integrity banner */}
          {verify && (
            ok ? (
              <div className="card p-4 border-emerald-200 bg-emerald-50 flex items-center gap-3">
                <ShieldCheck size={22} className="text-emerald-600 flex-shrink-0" />
                <div className="flex-1">
                  <div className="text-sm font-semibold text-emerald-800">
                    Chain intact — {sealedCount} artifact{sealedCount === 1 ? '' : 's'} sealed &amp; verified
                  </div>
                  <div className="text-[11px] text-emerald-700/80 mt-0.5">
                    Every seal hash links to its predecessor; no tampering detected.
                  </div>
                </div>
                <button
                  onClick={reVerify}
                  disabled={verifying}
                  className="btn-secondary text-xs flex items-center gap-1.5"
                >
                  {verifying ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                  Re-verify
                </button>
              </div>
            ) : (
              <div className="card p-4 border-red-300 bg-red-50 flex items-center gap-3">
                <ShieldAlert size={22} className="text-red-600 flex-shrink-0" />
                <div className="flex-1">
                  <div className="text-sm font-semibold text-red-800">
                    TAMPER DETECTED — chain broken at seq {verify.broken_at ?? '?'}
                  </div>
                  <div className="text-[11px] text-red-700/80 mt-0.5">
                    A seal no longer matches its recorded hash. This evidence chain cannot be trusted.
                  </div>
                </div>
                <button
                  onClick={reVerify}
                  disabled={verifying}
                  className="btn-secondary text-xs flex items-center gap-1.5"
                >
                  {verifying ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
                  Re-verify
                </button>
              </div>
            )
          )}

          {error && (
            <div className="card p-3 text-xs text-red-700 bg-red-50 border-red-200 flex items-center gap-2">
              <AlertTriangle size={14} /> {error}
            </div>
          )}

          {/* Actions */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={downloadManifest}
              disabled={downloading}
              className="btn-primary text-xs flex items-center gap-1.5"
            >
              {downloading ? <Loader2 size={12} className="animate-spin" /> : <Download size={12} />}
              Download manifest
            </button>
            {manifestInfo && (
              <span className={`text-[11px] flex items-center gap-1 ${manifestInfo.signed ? 'text-emerald-700' : 'text-gray-500'}`}>
                {manifestInfo.signed
                  ? <><Lock size={11} /> Signed manifest (HMAC)</>
                  : <><FileCheck size={11} /> Hash-chain-only manifest</>}
              </span>
            )}
          </div>

          {/* Seals table */}
          <div className="card overflow-hidden">
            <div className="px-3 py-2 border-b border-gray-100 flex items-center justify-between">
              <h3 className="text-[11px] font-semibold text-gray-700 uppercase tracking-wide">Sealed artifacts</h3>
              <span className="text-[10px] text-gray-500">{seals.length.toLocaleString()} seals</span>
            </div>

            {loading ? (
              <div className="p-6 flex items-center justify-center text-sm text-gray-500 gap-2">
                <Loader2 size={14} className="animate-spin" /> Loading…
              </div>
            ) : seals.length === 0 ? (
              <div className="p-5 space-y-3">
                <div className="text-center text-xs text-gray-500">
                  No sealed evidence yet — artifacts are sealed at ingest, or seal one manually.
                </div>
                <form onSubmit={sealManual} className="border-t border-gray-100 pt-3 space-y-2">
                  <div className="text-[10px] uppercase tracking-wide text-gray-500 font-medium">Manual seal</div>
                  <input
                    className="input h-8 text-xs w-full"
                    placeholder="artifact_id"
                    value={artId}
                    onChange={e => setArtId(e.target.value)}
                  />
                  <input
                    className="input h-8 text-xs w-full font-mono"
                    placeholder="sha256"
                    value={sha}
                    onChange={e => setSha(e.target.value)}
                  />
                  <button
                    type="submit"
                    disabled={sealing || !artId.trim() || !sha.trim()}
                    className="btn-primary text-xs flex items-center gap-1.5"
                  >
                    {sealing ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
                    Seal
                  </button>
                </form>
              </div>
            ) : (
              <table className="w-full text-[11px]">
                <thead className="bg-gray-50 text-gray-600">
                  <tr>
                    <Th>Artifact</Th>
                    <Th>SHA-256</Th>
                    <Th>Sealed at</Th>
                    <Th>Sealed by</Th>
                    <Th>Seal hash</Th>
                  </tr>
                </thead>
                <tbody>
                  {seals.map((s, i) => (
                    <tr key={s.seal_hash || s.artifact_id || i} className="border-t border-gray-100 hover:bg-gray-50">
                      <Td className="max-w-[140px] truncate" title={s.artifact_id}>{s.artifact_id || '—'}</Td>
                      <Td>
                        <div className="flex items-center gap-1">
                          <span className="font-mono max-w-[160px] truncate inline-block align-bottom" title={s.sha256}>
                            {s.sha256 || '—'}
                          </span>
                          {s.sha256 && (
                            <button
                              onClick={() => copySha(s.sha256)}
                              className="text-gray-400 hover:text-brand-accent"
                              title="Copy SHA-256"
                            >
                              {copied === s.sha256 ? <Check size={11} className="text-emerald-600" /> : <Copy size={11} />}
                            </button>
                          )}
                        </div>
                      </Td>
                      <Td className="text-gray-500 whitespace-nowrap">{fmtTime(s.sealed_at)}</Td>
                      <Td className="text-gray-500">{s.sealed_by || '—'}</Td>
                      <Td>
                        <span className="font-mono text-gray-500" title={s.seal_hash}>
                          {short(s.seal_hash)}
                        </span>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function Th({ children }) {
  return <th className="px-2 py-1.5 text-[10px] font-semibold uppercase tracking-wide text-left">{children}</th>
}
function Td({ children, className = '', title }) {
  return <td className={`px-2 py-1.5 ${className}`} title={title}>{children}</td>
}
function short(h) {
  if (!h) return '—'
  return h.length > 12 ? `${h.slice(0, 12)}…` : h
}
function fmtTime(t) {
  if (!t) return '—'
  const d = new Date(t)
  return Number.isNaN(d.getTime()) ? String(t) : d.toLocaleString()
}
