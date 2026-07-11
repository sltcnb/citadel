import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { X, Flag, Tag, Plus, Minus, Save, Search, Shield, AlertTriangle, Brain, Loader2, Clock, Download, FileText, Check, ChevronUp, ChevronDown, Code2, Copy, Bookmark } from 'lucide-react'
import { useResizableWidth, DrawerResizeHandle } from './resizableDrawer'
import PanelHelp from './PanelHelp'
import { api, getToken } from '../../api/client'
import { extractIocs, iocSearchQuery } from '../../utils/ioc'
import { getMitre, TACTIC_COLORS } from '../../utils/mitre'

// `source_file` is the MinIO object key the ingest worker stored:
// `cases/<case>/<job>/<path/to/original.log>`. Analysts only care about the
// original file the event was parsed from, so strip the bookkeeping prefix and
// show the basename ("sso.log") — full key available on hover.
function sourceFileName(srcFile) {
  if (!srcFile || typeof srcFile !== 'string') return ''
  let s = srcFile.split(/[?#]/)[0]                  // drop any query/fragment
  const m = s.match(/^cases\/[^/]+\/[^/]+\/(.+)$/)  // strip cases/<case>/<job>/
  if (m) s = m[1]
  const parts = s.split('/').filter(Boolean)
  return parts.length ? parts[parts.length - 1] : s
}

// ── Find-in-panel highlight ───────────────────────────────────────────────────

function Highlight({ text, query }) {
  if (!query || text == null) return <>{String(text ?? '')}</>
  const str = String(text)
  const lower = str.toLowerCase()
  const q = query.toLowerCase()
  if (!q || !lower.includes(q)) return <>{str}</>
  const parts = []
  let i = 0
  while (i < str.length) {
    const idx = lower.indexOf(q, i)
    if (idx === -1) { parts.push(str.slice(i)); break }
    if (idx > i) parts.push(str.slice(i, idx))
    parts.push(
      <mark key={idx} data-match className="bg-yellow-200 text-gray-900 rounded-sm px-px">
        {str.slice(idx, idx + q.length)}
      </mark>
    )
    i = idx + q.length
  }
  return <>{parts}</>
}

export default function EventDetail({ event: initialEvent, caseId, onClose, onFilterIn, onFilterOut, onFlagged }) {
  const [detailWidth, resizeHandle] = useResizableWidth('eventDetail', 440, { min: 320 })
  const [event, setEvent]             = useState(initialEvent)
  const [note, setNote]               = useState(event.analyst_note || '')
  const [tagInput, setTagInput]       = useState('')
  const [saving, setSaving]           = useState(false)
  const [noteSaved, setNoteSaved]     = useState(false)
  const [explaining, setExplaining]   = useState(false)
  const [explanation, setExplanation] = useState(null)
  const [downloading, setDownloading] = useState(false)
  const [actionError, setActionError] = useState('')

  // Find in panel
  const [findOpen,   setFindOpen]   = useState(false)
  const [findText,   setFindText]   = useState('')
  const [matchIndex, setMatchIndex] = useState(0)
  const [matchCount, setMatchCount] = useState(0)
  const panelBodyRef = useRef(null)
  const findInputRef = useRef(null)

  const navigate = useNavigate()

  // Open find bar with Ctrl+F / Cmd+F
  useEffect(() => {
    function onKey(e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault()
        setFindOpen(true)
        setTimeout(() => findInputRef.current?.select(), 0)
      }
      if (e.key === 'Escape' && findOpen) {
        setFindOpen(false)
        setFindText('')
      }
      if ((e.key === 'Enter' || e.key === 'F3') && findOpen && matchCount > 0) {
        e.preventDefault()
        setMatchIndex(i => e.shiftKey ? (i - 1 + matchCount) % matchCount : (i + 1) % matchCount)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [findOpen, matchCount])

  // After each render, update active mark + count
  useEffect(() => {
    if (!panelBodyRef.current) return
    const marks = Array.from(panelBodyRef.current.querySelectorAll('[data-match]'))
    setMatchCount(marks.length)
    marks.forEach((m, i) => {
      if (i === matchIndex % Math.max(marks.length, 1)) {
        m.setAttribute('data-active', '')
        m.scrollIntoView({ block: 'nearest', behavior: 'smooth' })
      } else {
        m.removeAttribute('data-active')
      }
    })
  })

  // Reset match index when query changes
  useEffect(() => { setMatchIndex(0) }, [findText])

  async function explainEvent() {
    setExplaining(true)
    setExplanation(null)
    try {
      const r = await api.llm.explainEvents({ events: [event] })
      setExplanation(r)
    } catch (err) {
      setExplanation({ error: err.message })
    } finally {
      setExplaining(false)
    }
  }

  const mitre = getMitre(event)
  const iocs  = extractIocs(event.message)

  async function toggleFlag() {
    setActionError('')
    try {
      const r = await api.search.flagEvent(caseId, event.fo_id)
      setEvent(p => ({ ...p, is_flagged: r.is_flagged }))
      onFlagged?.(event.fo_id, r.is_flagged)
    } catch (err) {
      setActionError(err?.message || 'Failed to flag event')
    }
  }

  async function togglePin() {
    setActionError('')
    try {
      const r = await api.search.pinEvent(caseId, event.fo_id, {})
      setEvent(p => ({ ...p, is_pinned: r.is_pinned }))
    } catch (err) {
      setActionError(err?.message || 'Failed to pin event')
    }
  }

  async function saveNote() {
    setSaving(true)
    setActionError('')
    try {
      await api.search.noteEvent(caseId, event.fo_id, note)
      setEvent(p => ({ ...p, analyst_note: note }))
      setNoteSaved(true)
      setTimeout(() => setNoteSaved(false), 2000)
    } catch (err) {
      setActionError(err?.message || 'Failed to save note')
    } finally {
      setSaving(false)
    }
  }

  async function addTag(e) {
    e.preventDefault()
    if (!tagInput.trim()) return
    setActionError('')
    const tags = [...(event.tags || []), tagInput.trim()]
    try {
      await api.search.tagEvent(caseId, event.fo_id, tags)
      setEvent(p => ({ ...p, tags }))
      setTagInput('')
    } catch (err) {
      setActionError(err?.message || 'Failed to add tag')
    }
  }

  async function removeTag(tag) {
    setActionError('')
    const tags = (event.tags || []).filter(t => t !== tag)
    try {
      await api.search.tagEvent(caseId, event.fo_id, tags)
      setEvent(p => ({ ...p, tags }))
    } catch (err) {
      setActionError(err?.message || 'Failed to remove tag')
    }
  }

  async function downloadFile() {
    if (!event.ingest_job_id || downloading) return
    setDownloading(true)
    try {
      const archiveMember = event.raw?.archive_member
      const url = archiveMember
        ? `/api/v1/cases/${caseId}/files/${event.ingest_job_id}/extract?member=${encodeURIComponent(archiveMember)}`
        : `/api/v1/cases/${caseId}/files/${event.ingest_job_id}/download`
      const token = getToken()
      const res = await fetch(url, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }))
        throw new Error(err.detail || `HTTP ${res.status}`)
      }
      const blob = await res.blob()
      const blobUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = blobUrl
      // Use the artifact filename, or the last segment of the archive path, or job id
      const fallback = archiveMember
        ? archiveMember.split('/').pop()
        : event.ingest_job_id
      a.download = artifactData.filename || fallback
      a.click()
      URL.revokeObjectURL(blobUrl)
    } catch (err) {
      console.error('File download failed:', err)
    } finally {
      setDownloading(false)
    }
  }

  function downloadEventJSON() {
    const blob = new Blob([JSON.stringify(event, null, 2)], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `event-${event.fo_id || 'unknown'}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  function pivot(query) {
    navigate(`/cases/${caseId}`, { state: { pivotQuery: query } })
  }

  function pivotTimeWindow(minutes) {
    if (!event.timestamp) return
    const center = new Date(event.timestamp)
    const from = new Date(center.getTime() - minutes * 60_000).toISOString()
    const to   = new Date(center.getTime() + minutes * 60_000).toISOString()
    navigate(`/cases/${caseId}`, { state: { pivotQuery: `timestamp:[${from} TO ${to}]` } })
  }

  const ts = event.timestamp
    ? new Date(event.timestamp).toISOString().replace('T', ' ').slice(0, 23)
    : '—'

  const artifactData = event[event.artifact_type] || {}

  const ARTIFACT_COLOR = {
    evtx:     'badge-evtx',
    prefetch: 'badge-prefetch',
    mft:      'badge-mft',
    registry: 'badge-registry',
    lnk:      'badge-lnk',
    plaso:    'badge-plaso',
    hayabusa: 'badge-hayabusa',
    antivirus: 'badge-antivirus',
    login_event: 'badge-login',
  }

  // Build filter field mappings for the artifact-specific group
  const artifactFilterFields = Object.fromEntries(
    Object.entries(artifactData)
      .filter(([, v]) => v !== null && v !== undefined && v !== '' && typeof v !== 'object')
      .map(([k]) => [k, `${event.artifact_type}.${k}`])
  )

  return (
    <div
      className="relative flex-shrink-0 bg-white border-l border-gray-200 flex flex-col overflow-hidden"
      style={{ width: detailWidth }}
    >
      <DrawerResizeHandle {...resizeHandle} />
      {/* Find bar */}
      {findOpen && (
        <div className="flex items-center gap-1.5 px-2 py-1.5 bg-yellow-50 border-b border-yellow-200 flex-shrink-0">
          <Search size={11} className="text-yellow-600 flex-shrink-0" />
          <input
            ref={findInputRef}
            value={findText}
            onChange={e => setFindText(e.target.value)}
            placeholder="Find in event…"
            className="flex-1 bg-transparent text-xs outline-none text-gray-700 placeholder:text-gray-400"
            autoFocus
          />
          {findText && (
            <span className="text-[10px] text-gray-500 flex-shrink-0 font-mono">
              {matchCount === 0 ? '0/0' : `${(matchIndex % Math.max(matchCount, 1)) + 1}/${matchCount}`}
            </span>
          )}
          <button onClick={() => setMatchIndex(i => (i - 1 + Math.max(matchCount,1)) % Math.max(matchCount,1))}
            className="p-0.5 rounded hover:bg-yellow-200 text-gray-500 disabled:opacity-30"
            disabled={matchCount === 0} title="Previous (Shift+Enter)">
            <ChevronUp size={11} />
          </button>
          <button onClick={() => setMatchIndex(i => (i + 1) % Math.max(matchCount, 1))}
            className="p-0.5 rounded hover:bg-yellow-200 text-gray-500 disabled:opacity-30"
            disabled={matchCount === 0} title="Next (Enter)">
            <ChevronDown size={11} />
          </button>
          <button onClick={() => { setFindOpen(false); setFindText('') }}
            className="p-0.5 rounded hover:bg-yellow-200 text-gray-500" title="Close (Esc)">
            <X size={11} />
          </button>
        </div>
      )}
      {/* Header */}
      <div className="p-3 border-b border-gray-200 flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            <span className={`badge ${ARTIFACT_COLOR[event.artifact_type] || 'badge-generic'}`}>
              {event.artifact_type}
            </span>
            {mitre && (
              <span
                className={`badge border text-[10px] ${TACTIC_COLORS[mitre.tactic] || 'bg-gray-100 text-gray-600 border-gray-200'}`}
                title={mitre.tactic}
              >
                <Shield size={9} className="mr-1" />
                {mitre.technique_id}
              </span>
            )}
          </div>
          <p className="text-xs text-brand-text break-words line-clamp-2 text-gray-500 italic">{event.message}</p>
          {event.source_file && (
            <p
              className="flex items-center gap-1 mt-1 text-[10px] text-gray-400 truncate"
              title={event.source_file}
            >
              <FileText size={10} className="flex-shrink-0" />
              <span className="truncate">
                from <span className="font-medium text-gray-600">{sourceFileName(event.source_file)}</span>
              </span>
            </p>
          )}
        </div>
        <button onClick={onClose} className="btn-ghost p-1 flex-shrink-0">
          <X size={14} />
        </button>
      </div>

      <div ref={panelBodyRef} className="flex-1 overflow-y-auto p-3 space-y-4 text-xs">
        <PanelHelp
          title="Event detail"
          use="The full normalized event: every field, raw payload, extracted IOCs and MITRE mapping."
          when="After clicking a timeline row — to inspect, flag/pin, tag, note, or pivot the timeline around this event."
          tip="Ctrl/⌘-F searches within the event. Drag the panel's left edge to resize it."
        />
        {/* Actions */}
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={toggleFlag}
            className={`btn text-xs ${event.is_flagged ? 'bg-red-100 text-red-700 border border-red-200' : 'btn-ghost'}`}
          >
            <Flag size={12} />
            {event.is_flagged ? 'Flagged' : 'Flag'}
          </button>
          <button
            onClick={togglePin}
            title={event.is_pinned ? 'Unpin (remove from report)' : 'Pin (include in report)'}
            className={`btn text-xs ${event.is_pinned ? 'bg-amber-100 text-amber-700 border border-amber-200' : 'btn-ghost'}`}
          >
            <Bookmark size={12} fill={event.is_pinned ? 'currentColor' : 'none'} />
            {event.is_pinned ? 'Pinned' : 'Pin'}
          </button>
          <button
            onClick={explainEvent}
            disabled={explaining}
            className="btn-ghost text-xs text-purple-600 hover:text-purple-800 border border-purple-200 rounded-lg"
            title="Explain this event with AI"
          >
            {explaining ? <Loader2 size={12} className="animate-spin" /> : <Brain size={12} />}
            {explaining ? 'Analyzing…' : 'Explain'}
          </button>
          <button
            onClick={downloadEventJSON}
            className="btn-ghost text-xs flex items-center gap-1"
            title="Download this event as JSON"
          >
            <Download size={12} /> Event JSON
          </button>
          <button
            onClick={() => { setFindOpen(v => !v); setTimeout(() => findInputRef.current?.focus(), 0) }}
            className={`btn-ghost text-xs flex items-center gap-1 ${findOpen ? 'bg-yellow-50 text-yellow-700' : ''}`}
            title="Find in event (Ctrl+F)"
          >
            <Search size={12} /> Find
          </button>
        </div>

        {/* Time window pivot */}
        {event.timestamp && (
          <div>
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
              <Clock size={9} /> Time Window
            </p>
            <div className="flex gap-1 flex-wrap">
              {[1, 3, 5, 10].map(m => (
                <button
                  key={m}
                  onClick={() => pivotTimeWindow(m)}
                  className="btn-ghost text-[10px] px-2 py-0.5 font-mono"
                  title={`Search all events within ±${m} min of this timestamp`}
                >
                  ±{m}m
                </button>
              ))}
            </div>
          </div>
        )}

        {/* CTI Match — threat-intel hit with enrichment + pivot to the events */}
        {event.cti_match && (
          <div className="rounded-lg border border-fuchsia-200 bg-fuchsia-50 p-2.5">
            <p className="text-[10px] font-semibold text-fuchsia-700 uppercase tracking-wider mb-1.5 flex items-center gap-1">
              <Shield size={9} /> Threat Intel Match
            </p>
            <div className="space-y-0.5 text-[11px]">
              <p className="text-gray-700">
                <span className="text-gray-400 w-20 inline-block">{event.cti_match.ioc_type}</span>
                <span className="font-mono text-fuchsia-700">{event.cti_match.ioc_value}</span>
              </p>
              {event.cti_match.match_count != null && (
                <p className="text-gray-700"><span className="text-gray-400 w-20 inline-block">matches</span>{Number(event.cti_match.match_count).toLocaleString()} event(s)</p>
              )}
              {event.cti_match.matched_field && (
                <p className="text-gray-700"><span className="text-gray-400 w-20 inline-block">field</span><span className="font-mono">{event.cti_match.matched_field}</span></p>
              )}
              {event.cti_match.feed_name && (
                <p className="text-gray-700"><span className="text-gray-400 w-20 inline-block">feed</span>{event.cti_match.feed_name}</p>
              )}
              {event.cti_match.threat_type && (
                <p className="text-gray-700"><span className="text-gray-400 w-20 inline-block">threat</span>{event.cti_match.threat_type}</p>
              )}
              {event.cti_match.confidence !== undefined && event.cti_match.confidence !== '' && (
                <p className="text-gray-700"><span className="text-gray-400 w-20 inline-block">confidence</span>{String(event.cti_match.confidence)}</p>
              )}
            </div>
            {(event.cti_match.pivot_query || (event.cti_match.matched_field && event.cti_match.ioc_value)) && (
              <button
                onClick={() => pivot(event.cti_match.pivot_query || `${event.cti_match.matched_field}:"${String(event.cti_match.ioc_value).replace(/\\/g,'\\\\').replace(/"/g,'\\"')}"`)}
                className="btn-ghost text-[11px] mt-2 flex items-center gap-1 text-fuchsia-600 hover:text-fuchsia-800 border border-fuchsia-200 rounded-lg"
                title="Open all events matching this indicator"
              >
                <Search size={11} /> Pivot to matching events
              </button>
            )}
          </div>
        )}

        {/* AI explanation */}
        {explanation && (
          <div className={`rounded-lg p-2.5 text-xs ${explanation.error ? 'bg-red-50 border border-red-200' : 'bg-purple-50 border border-purple-200'}`}>
            <div className="flex items-center justify-between mb-1.5">
              <p className="text-[10px] font-semibold text-purple-700 uppercase tracking-wider flex items-center gap-1">
                <Brain size={9} /> AI Explanation
                {explanation.model_used && <span className="normal-case font-normal text-gray-500 ml-1">({explanation.model_used})</span>}
              </p>
              <button onClick={() => setExplanation(null)} className="text-gray-500 hover:text-gray-600"><X size={10} /></button>
            </div>
            {explanation.error
              ? <p className="text-red-600">{explanation.error}</p>
              : <p className="text-gray-700 leading-relaxed whitespace-pre-wrap">{explanation.explanation}</p>
            }
          </div>
        )}

        {/* MITRE ATT&CK */}
        {mitre && (
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-2.5">
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
              <Shield size={9} /> MITRE ATT&amp;CK
            </p>
            <div className="flex items-start justify-between gap-2">
              <div>
                <p className="text-brand-text font-medium">{mitre.technique_name}</p>
                <p className="text-gray-500 text-[10px]">{mitre.tactic}</p>
              </div>
              <span className="badge bg-gray-100 text-gray-600 border border-gray-200 font-mono flex-shrink-0">
                {mitre.technique_id}
              </span>
            </div>
          </div>
        )}

        {/* IOC Panel */}
        {iocs.length > 0 && (
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-2.5">
            <p className="text-[10px] font-semibold text-amber-700 uppercase tracking-wider mb-2 flex items-center gap-1">
              <AlertTriangle size={9} /> IOCs Detected ({iocs.length})
            </p>
            <div className="space-y-1">
              {iocs.map((ioc, i) => (
                <div key={i} className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <span className="text-[10px] text-gray-500 flex-shrink-0 w-16">{ioc.type}</span>
                    <span className={`font-mono text-[10px] truncate ${ioc.color}`}>{ioc.value}</span>
                  </div>
                  <button
                    onClick={() => pivot(iocSearchQuery(ioc))}
                    className="flex-shrink-0 p-1 rounded hover:bg-amber-100 text-amber-500 hover:text-amber-700 transition-colors"
                    title="Find all events with this IOC"
                  >
                    <Search size={10} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Tags */}
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
            <Tag size={9} /> Tags
          </p>
          <div className="flex flex-wrap gap-1 mb-1.5">
            {(event.tags || []).map(t => (
              <span
                key={t}
                className="badge bg-brand-accentlight text-brand-accent border border-brand-accent/20 cursor-pointer hover:bg-brand-accent/10 transition-colors"
                onClick={() => removeTag(t)}
              >
                {t} ×
              </span>
            ))}
          </div>
          <form onSubmit={addTag} className="flex gap-1">
            <input
              value={tagInput}
              onChange={e => setTagInput(e.target.value)}
              placeholder="Add tag…"
              className="input flex-1 py-1 text-xs"
            />
            <button type="submit" className="btn-ghost px-2 text-xs" aria-label="Add"><Plus size={12} /></button>
          </form>
        </div>

        {/* Analyst Note */}
        <div>
          <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
            Analyst Note
          </p>
          <textarea
            value={note}
            onChange={e => setNote(e.target.value)}
            className="input w-full h-20 resize-none text-xs"
            placeholder="Investigation notes…"
          />
          <button onClick={saveNote} disabled={saving} className={`text-xs mt-1.5 btn ${noteSaved ? 'btn-success' : 'btn-primary'}`}>
            {noteSaved ? <Check size={11} /> : <Save size={11} />}
            {saving ? 'Saving…' : noteSaved ? 'Saved' : 'Save Note'}
          </button>
          {actionError ? (
            <div role="alert" className="text-xs mt-1.5 text-red-600">{actionError}</div>
          ) : null}
        </div>

        {/* Full message */}
        {event.message && (
          <div>
            <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">Message</p>
            <pre className="bg-gray-50 border border-gray-200 rounded-lg p-2.5 text-[11px] font-mono text-gray-800 whitespace-pre-wrap break-words leading-relaxed">
              <Highlight text={event.message} query={findText} />
            </pre>
          </div>
        )}

        {/* Base event info */}
        <FieldGroup
          title="Event"
          fields={{
            Timestamp:   ts,
            Type:        event.artifact_type,
            Description: event.timestamp_desc,
            Level:       event.level || event[event.artifact_type]?.level,
            Channel:     event.channel || event[event.artifact_type]?.channel,
            Rule:        event.rule_title || event[event.artifact_type]?.rule_title,
            'Event ID':  event[event.artifact_type]?.event_id != null ? String(event[event.artifact_type].event_id) : undefined,
          }}
          filterFields={{
            Type:        'artifact_type',
            Description: 'timestamp_desc',
            Level:       'level',
            Channel:     `${event.artifact_type}.channel`,
            Rule:        `${event.artifact_type}.rule_title`,
            'Event ID':  `${event.artifact_type}.event_id`,
          }}
          onFilterIn={onFilterIn}
          onFilterOut={onFilterOut}
          findText={findText}
        />

        {/* Host */}
        <FieldGroup
          title="Host"
          fields={{
            Hostname: event.host?.hostname,
            FQDN:     event.host?.fqdn,
            IP:       event.host?.ip,
            OS:       event.host?.os,
            Domain:   event.host?.domain,
          }}
          pivotFields={['Hostname', 'FQDN', 'IP']}
          filterFields={{
            Hostname: 'host.hostname',
            FQDN:     'host.fqdn',
            IP:       'host.ip',
            OS:       'host.os',
            Domain:   'host.domain',
          }}
          onPivot={pivot}
          onFilterIn={onFilterIn}
          onFilterOut={onFilterOut}
          findText={findText}
        />

        {/* User */}
        <FieldGroup
          title="User"
          fields={{
            Name:   event.user?.name,
            Domain: event.user?.domain,
            SID:    event.user?.sid,
            Type:   event.user?.type,
          }}
          pivotFields={['Name']}
          filterFields={{
            Name:   'user.name',
            Domain: 'user.domain',
            SID:    'user.sid',
            Type:   'user.type',
          }}
          onPivot={pivot}
          onFilterIn={onFilterIn}
          onFilterOut={onFilterOut}
          findText={findText}
        />

        {/* Process */}
        <FieldGroup
          title="Process"
          fields={{
            Name:          event.process?.name,
            Path:          event.process?.path,
            'Command Line':event.process?.command_line,
            PID:           event.process?.pid,
            'Parent Name': event.process?.parent_name,
            'Parent PID':  event.process?.parent_pid,
          }}
          pivotFields={['Name', 'Command Line']}
          filterFields={{
            Name:          'process.name',
            Path:          'process.path',
            'Command Line':'process.command_line',
            PID:           'process.pid',
            'Parent Name': 'process.parent_name',
            'Parent PID':  'process.parent_pid',
          }}
          onPivot={pivot}
          onFilterIn={onFilterIn}
          onFilterOut={onFilterOut}
          findText={findText}
        />

        {/* Network */}
        <FieldGroup
          title="Network"
          fields={{
            'Src IP':   event.network?.src_ip,
            'Src Port': event.network?.src_port != null ? String(event.network.src_port) : undefined,
            'Dst IP':   event.network?.dst_ip,
            'Dst Port': event.network?.dst_port != null ? String(event.network.dst_port) : undefined,
            Protocol:   event.network?.protocol,
            Action:     event.network?.action,
            Bytes:      event.network?.bytes != null ? String(event.network.bytes) : undefined,
          }}
          pivotFields={['Src IP', 'Dst IP']}
          filterFields={{
            'Src IP':   'network.src_ip',
            'Src Port': 'network.src_port',
            'Dst IP':   'network.dst_ip',
            'Dst Port': 'network.dst_port',
            Protocol:   'network.protocol',
            Action:     'network.action',
          }}
          onPivot={pivot}
          onFilterIn={onFilterIn}
          onFilterOut={onFilterOut}
          findText={findText}
        />

        {/* HTTP */}
        <FieldGroup
          title="HTTP"
          fields={{
            Method:     event.http?.method,
            Path:       event.http?.request_path,
            Status:     event.http?.status_code != null ? String(event.http.status_code) : undefined,
            'User Agent':event.http?.user_agent,
            Referer:    event.http?.referer,
            'Resp Size': event.http?.response_size != null ? String(event.http.response_size) : undefined,
          }}
          filterFields={{
            Method:      'http.method',
            Path:        'http.request_path',
            Status:      'http.status_code',
            'User Agent':'http.user_agent',
            Referer:     'http.referer',
          }}
          onFilterIn={onFilterIn}
          onFilterOut={onFilterOut}
          findText={findText}
        />

        {/* Artifact-specific rendering */}
        {(event.artifact_type === 'strings' || event.artifact_type === 'file') ? (
          // Binary/text files — show filename + extracted content
          <div className="space-y-2">
            {/* Filename banner */}
            {artifactData.filename && (
              <div className="flex items-center gap-2 px-2.5 py-2 bg-gray-100 rounded-lg border border-gray-200">
                <FileText size={12} className="text-gray-500 flex-shrink-0" />
                <span className="font-mono text-xs text-brand-text font-semibold truncate flex-1" title={artifactData.filename}>
                  {artifactData.filename}
                </span>
                {event.ingest_job_id && (
                  <button
                    onClick={downloadFile}
                    disabled={downloading}
                    className="btn-ghost text-[10px] flex items-center gap-1 flex-shrink-0 px-1.5 py-0.5"
                    title="Download original file"
                  >
                    {downloading ? <Loader2 size={10} className="animate-spin" /> : <Download size={10} />}
                    {downloading ? '' : 'Download'}
                  </button>
                )}
              </div>
            )}
            {/* Extracted content */}
            <div>
              <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 flex items-center gap-1">
                <FileText size={9} />
                {event.artifact_type === 'strings' ? 'Extracted Strings' : 'File Content'}
                {artifactData.count != null && (
                  <span className="normal-case font-normal text-gray-500 ml-1">
                    ({Number(artifactData.count).toLocaleString()} strings)
                  </span>
                )}
              </p>
              <pre className="bg-gray-50 border border-gray-200 rounded-lg p-2 text-[10px] font-mono text-gray-700 overflow-auto max-h-56 leading-relaxed whitespace-pre-wrap break-all">
                <Highlight text={artifactData.content || '—'} query={findText} />
              </pre>
            </div>
          </div>
        ) : Object.keys(artifactData).length > 0 && (
          // Generic artifact fields for all other types
          <FieldGroup
            title={event.artifact_type?.toUpperCase()}
            fields={Object.fromEntries(
              Object.entries(artifactData)
                .filter(([, v]) => v !== null && v !== undefined && v !== '')
                .map(([k, v]) => [k, typeof v === 'object' ? JSON.stringify(v, null, 2) : v])
            )}
            filterFields={artifactFilterFields}
            onFilterIn={onFilterIn}
            onFilterOut={onFilterOut}
            findText={findText}
          />
        )}

        {/* Metadata */}
        <FieldGroup
          title="Metadata"
          fields={{
            'Ingest Job': event.ingest_job_id,
            'Source file': sourceFileName(event.source_file) || undefined,
            'Source path': event.source_file,
            Ingested:     event.ingested_at,
          }}
          findText={findText}
        />

        {/* Raw event */}
        <RawEvent event={event} caseId={caseId} findText={findText} />
      </div>
    </div>
  )
}

function _rawFromObj(r) {
  if (!r || typeof r !== 'object') return null
  if (r.line)    return r.line
  if (r.xml)     return r.xml
  if (r.content) return String(r.content)
  if (Object.keys(r).length > 0) return JSON.stringify(r, null, 2)
  return null
}

function RawEvent({ event, caseId, findText = '' }) {
  const [open, setOpen]       = useState(true)
  const [copied, setCopied]   = useState(false)
  const [loading, setLoading] = useState(false)
  const [fetchedText, setFetchedText] = useState(undefined)
  const fetchedRef = useRef(false)

  // raw.line (syslog/access_log) or raw.xml if already in search results
  const immediateText = _rawFromObj(event.raw)

  // Fallback: artifact sub-object as pretty JSON (evtx, hayabusa, plaso, mft…)
  const _sub = event.artifact_type ? event[event.artifact_type] : null
  const fallbackText = (_sub && typeof _sub === 'object' && Object.keys(_sub).length > 0)
    ? JSON.stringify(_sub, null, 2) : null

  // Lazy-fetch raw.xml only for evtx (excluded from search results for size)
  const needsFetch = !immediateText && event.artifact_type === 'evtx' && !fetchedRef.current

  async function fetchRaw() {
    if (fetchedRef.current) return
    fetchedRef.current = true
    setLoading(true)
    try {
      const full = await api.search.getEvent(caseId, event.fo_id)
      setFetchedText(_rawFromObj(full?.raw) || null)
    } catch (err) {
      console.error('[RawEvent] fetch failed for fo_id', event.fo_id, err)
      setFetchedText(null)
    } finally {
      setLoading(false)
    }
  }

  // Raw panel is open by default — kick off the fetch on mount/event change.
  useEffect(() => {
    if (open && needsFetch) fetchRaw()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [event.fo_id])

  function toggle() {
    const next = !open
    setOpen(next)
    if (next && needsFetch) fetchRaw()
  }

  // Priority: raw.line/xml > fetched XML (evtx) > artifact sub-object JSON
  let displayText
  if (immediateText) {
    displayText = immediateText
  } else if (loading) {
    displayText = null
  } else if (fetchedText !== undefined) {
    displayText = fetchedText || fallbackText
  } else {
    displayText = needsFetch ? null : fallbackText
  }

  function copyRaw() {
    if (!displayText) return
    navigator.clipboard.writeText(displayText).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <div>
      <button
        onClick={toggle}
        className="flex items-center gap-1.5 text-[10px] font-semibold text-gray-400 uppercase tracking-widest hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
      >
        <Code2 size={10} />
        Raw
        {open ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
      </button>
      {open && (
        <div className="mt-1.5 relative group/raw">
          {loading ? (
            <div className="flex items-center gap-2 py-3 text-[10px] text-gray-400">
              <Loader2 size={10} className="animate-spin" />
              Loading…
            </div>
          ) : displayText ? (
            <>
              <button
                onClick={copyRaw}
                className="absolute top-2 right-2 opacity-0 group-hover/raw:opacity-100 transition-opacity btn-ghost text-[10px] px-1.5 py-0.5 flex items-center gap-1"
                title="Copy raw"
              >
                {copied ? <Check size={10} /> : <Copy size={10} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
              <pre className="bg-gray-50 dark:bg-white/5 border border-gray-200 dark:border-white/10 rounded-lg p-3 text-[10px] font-mono text-gray-700 dark:text-gray-300 leading-relaxed whitespace-pre-wrap break-words">
                <Highlight text={displayText} query={findText} />
              </pre>
            </>
          ) : (
            <p className="text-[10px] text-gray-400 italic py-2">No raw data for this event type.</p>
          )}
        </div>
      )}
    </div>
  )
}

function FieldGroup({ title, fields, pivotFields = [], filterFields = {}, onPivot, onFilterIn, onFilterOut, findText = '' }) {
  const entries = Object.entries(fields).filter(([, v]) => v !== null && v !== undefined && v !== '')
  if (!entries.length) return null

  const canFilter = onFilterIn && onFilterOut

  return (
    <div>
      <p className="text-[10px] font-semibold text-gray-500 uppercase tracking-widest mb-1.5">{title}</p>
      <div className="space-y-1">
        {entries.map(([k, v]) => {
          const esField = filterFields[k]
          const isFilterable = canFilter && esField && (typeof v === 'number' || (typeof v === 'string' && !v.includes('\n')))
          const str = String(v)
          return (
            <div key={k} className="flex gap-2 items-start group">
              <span
                className="text-gray-500 flex-shrink-0 w-24 text-[10px] pt-0.5 cursor-default"
                title={esField ? `ES field: ${esField}` : undefined}
              >{k}</span>
              <span className="text-gray-700 break-all font-mono text-[10px] flex-1">
                {typeof v === 'string' && v.includes('\n')
                  ? <pre className="whitespace-pre-wrap"><Highlight text={v} query={findText} /></pre>
                  : <Highlight text={str} query={findText} />}
              </span>
              {/* Filter in / out buttons — visible on group row hover */}
              {isFilterable && (
                <span className="inline-flex gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                  <button
                    type="button"
                    onClick={() => onFilterIn(esField, String(v))}
                    className="w-3.5 h-3.5 rounded flex items-center justify-center bg-green-100 text-green-700 hover:bg-green-200 transition-colors"
                    title={`Filter: ${esField}:"${v}"`}
                  >
                    <Plus size={8} />
                  </button>
                  <button
                    type="button"
                    onClick={() => onFilterOut(esField, String(v))}
                    className="w-3.5 h-3.5 rounded flex items-center justify-center bg-red-100 text-red-600 hover:bg-red-200 transition-colors"
                    title={`Exclude: NOT ${esField}:"${v}"`}
                  >
                    <Minus size={8} />
                  </button>
                </span>
              )}
              {/* Pivot / search button */}
              {pivotFields.includes(k) && onPivot && v && (
                <button
                  onClick={() => onPivot(`"${v}"`)}
                  className="flex-shrink-0 p-0.5 rounded hover:bg-gray-100 text-gray-500 hover:text-brand-accent transition-colors"
                  title={`Search all events for: ${v}`}
                >
                  <Search size={10} />
                </button>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
