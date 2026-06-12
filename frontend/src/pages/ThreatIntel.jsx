import { useState, useEffect, useRef } from 'react'
import { Shield, Plus, Trash2, RefreshCw, Download, Upload, Search, Globe, Hash, AtSign, Link2, FileText, Loader2, Check, X, AlertTriangle, CheckCircle, ExternalLink, Play, ChevronRight } from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'

// ── Helpers ──────────────────────────────────────────────────────────────────

const FEED_TYPES = [
  { value: 'taxii',    label: 'TAXII 2.1 Server' },
  { value: 'stix_url', label: 'STIX Bundle URL' },
  { value: 'manual',   label: 'Manual Import' },
  { value: 'misp',     label: 'MISP Instance' },
  { value: 'yeti',     label: 'YETI Instance' },
]

const IOC_TYPES = [
  { value: '',         label: 'All types' },
  { value: 'hash',     label: 'Hash' },
  { value: 'ip',       label: 'IP' },
  { value: 'domain',   label: 'Domain' },
  { value: 'url',      label: 'URL' },
  { value: 'email',    label: 'Email' },
  { value: 'filename', label: 'Filename' },
]

const TYPE_BADGE_COLORS = {
  taxii:    'bg-purple-100 text-purple-700 border border-purple-200',
  stix_url: 'bg-blue-100 text-blue-700 border border-blue-200',
  manual:   'bg-gray-100 text-gray-600 border border-gray-200',
  misp:     'bg-orange-100 text-orange-700 border border-orange-200',
  yeti:     'bg-teal-100 text-teal-700 border border-teal-200',
}

const IOC_BADGE_COLORS = {
  hash:     'bg-amber-100 text-amber-700 border border-amber-200',
  ip:       'bg-red-100 text-red-700 border border-red-200',
  domain:   'bg-green-100 text-green-700 border border-green-200',
  url:      'bg-blue-100 text-blue-700 border border-blue-200',
  email:    'bg-purple-100 text-purple-700 border border-purple-200',
  filename: 'bg-gray-100 text-gray-600 border border-gray-200',
}

const IOC_ICONS = {
  hash:     Hash,
  ip:       Globe,
  domain:   Globe,
  url:      Link2,
  email:    AtSign,
  filename: FileText,
}

function fmtDate(d) {
  if (!d) return 'Never'
  return new Date(d).toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

// ── IOC Stat Card ────────────────────────────────────────────────────────────

function StatBox({ icon: Icon, label, value, color }) {
  return (
    <div className="card px-3 py-2.5 flex items-center gap-2.5 min-w-0">
      <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 ${color}`}>
        <Icon size={13} />
      </div>
      <div className="min-w-0">
        <p className="text-lg font-bold text-brand-text leading-tight">{(value ?? 0).toLocaleString()}</p>
        <p className="text-[10px] text-gray-500 uppercase tracking-wider font-semibold">{label}</p>
      </div>
    </div>
  )
}

// ── Add / Edit Feed Modal ────────────────────────────────────────────────────

const POLL_UNITS = [
  { value: 'minutes', label: 'Minutes' },
  { value: 'hours',   label: 'Hours'   },
  { value: 'days',    label: 'Days'    },
]

function FeedModal({ feed, onClose, onSaved }) {
  const [form, setForm] = useState({
    name:                 feed?.name || '',
    type:                 feed?.type || 'taxii',
    url:                  feed?.url || '',
    api_key:              '',
    collection:           feed?.collection || '',
    poll_interval_value:  feed?.poll_interval_value ?? 24,
    poll_interval_unit:   feed?.poll_interval_unit  ?? 'hours',
    auto_pull:            feed?.auto_pull !== false,
    enabled:              feed?.enabled   !== false,
  })
  const [saving, setSaving] = useState(false)

  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  async function save(e) {
    e.preventDefault()
    if (!form.name.trim()) return
    setSaving(true)
    try {
      const payload = { ...form }
      if (!payload.api_key) delete payload.api_key
      const result = feed
        ? await api.cti.updateFeed(feed.id, payload)
        : await api.cti.addFeed(payload)
      onSaved(result)
    } catch (err) {
      alert('Save failed: ' + err.message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal-box max-w-lg">
        <div className="modal-header">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-brand-accent" />
            <span className="text-sm font-semibold text-brand-text">
              {feed ? 'Edit Feed' : 'Add CTI Feed'}
            </span>
          </div>
          <button onClick={onClose} className="icon-btn"><X size={14} /></button>
        </div>
        <form onSubmit={save} className="p-5 space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Name *</label>
            <input value={form.name} onChange={e => set('name', e.target.value)}
              placeholder="AlienVault OTX" className="input text-xs" required />
          </div>

          {/* Type */}
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Type</label>
            <select value={form.type} onChange={e => set('type', e.target.value)}
              className="input text-xs">
              {FEED_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
          </div>

          {/* URL — required for TAXII/STIX/MISP/YETI, optional for manual */}
          {form.type !== 'manual' ? (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">URL *</label>
              <input value={form.url} onChange={e => set('url', e.target.value)}
                placeholder={
                  form.type === 'taxii'    ? 'https://taxii.example.com/taxii2/' :
                  form.type === 'misp'     ? 'https://misp.example.com' :
                  form.type === 'yeti'     ? 'https://yeti.example.com' :
                  'https://example.com/stix-bundle.json'
                }
                className="input text-xs font-mono" required />
            </div>
          ) : (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Re-import URL <span className="text-gray-500 font-normal">(optional — enables periodic auto-pull)</span>
              </label>
              <input value={form.url} onChange={e => set('url', e.target.value)}
                placeholder="https://example.com/stix-bundle.json"
                className="input text-xs font-mono" />
              {form.url && (
                <p className="text-[10px] text-blue-600 mt-1">
                  ↻ This feed will be periodically re-fetched from the URL above.
                </p>
              )}
            </div>
          )}

          {/* API Key (for TAXII, MISP, YETI) */}
          {(form.type === 'taxii' || form.type === 'misp' || form.type === 'yeti') && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                API Key <span className="text-gray-500 font-normal">
                  {form.type === 'misp' ? '(required)' : '(optional)'}
                </span>
              </label>
              <input value={form.api_key} onChange={e => set('api_key', e.target.value)}
                placeholder={form.type === 'misp' ? 'MISP API key' : form.type === 'yeti' ? 'YETI API key' : 'Bearer token or API key'}
                className="input text-xs" />
            </div>
          )}

          {/* Collection (TAXII) / Tag filter (MISP) */}
          {(form.type === 'taxii' || form.type === 'misp') && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                {form.type === 'misp' ? 'Tag filter' : 'Collection'}{' '}
                <span className="text-gray-500 font-normal">(optional)</span>
              </label>
              <input value={form.collection} onChange={e => set('collection', e.target.value)}
                placeholder={form.type === 'misp' ? 'e.g. tlp:white' : 'Collection ID or name'}
                className="input text-xs font-mono" />
            </div>
          )}

          {/* Auto-pull schedule (shown for all feeds that have a URL to pull from) */}
          {(form.type !== 'manual' || form.url?.trim()) && (
            <div className="space-y-2 p-3 border border-gray-200 rounded-lg bg-gray-50">
              <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer select-none">
                <input type="checkbox" checked={form.auto_pull} onChange={e => set('auto_pull', e.target.checked)}
                  className="rounded border-gray-300 accent-brand-accent" />
                <span className="font-medium">Auto-pull on schedule</span>
              </label>
              {form.auto_pull && (
                <div className="flex items-center gap-2 pl-5">
                  <span className="text-xs text-gray-500 whitespace-nowrap">Every</span>
                  <input
                    type="number" min="1" max="9999"
                    value={form.poll_interval_value}
                    onChange={e => set('poll_interval_value', parseInt(e.target.value) || 1)}
                    className="input text-xs w-20 py-1"
                  />
                  <select
                    value={form.poll_interval_unit}
                    onChange={e => set('poll_interval_unit', e.target.value)}
                    className="input text-xs py-1"
                  >
                    {POLL_UNITS.map(u => (
                      <option key={u.value} value={u.value}>{u.label}</option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          )}

          {/* Enabled */}
          <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer select-none">
            <input type="checkbox" checked={form.enabled} onChange={e => set('enabled', e.target.checked)}
              className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent" />
            Enabled
          </label>

          {/* Actions */}
          <div className="flex gap-2 pt-1">
            <button type="submit" disabled={saving} className="btn-primary text-xs">
              {saving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
              {feed ? 'Update Feed' : 'Add Feed'}
            </button>
            <button type="button" onClick={onClose} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function ThreatIntel() {
  // Feeds
  const [feeds, setFeeds]           = useState([])
  const [feedsLoading, setFeedsLoading] = useState(true)
  const [editFeed, setEditFeed]     = useState(null)   // null = closed, {} = new, feed = edit
  const [pullingId, setPullingId]   = useState(null)

  // IOC stats
  const [stats, setStats]           = useState(null)

  // IOC browser
  const [iocs, setIocs]             = useState([])
  const [iocTotal, setIocTotal]     = useState(0)
  const [iocPage, setIocPage]       = useState(1)
  const [iocType, setIocType]       = useState('')
  const [iocSearch, setIocSearch]   = useState('')
  const [iocLoading, setIocLoading] = useState(false)

  // Import
  const [bundleText, setBundleText] = useState('')
  const [importing, setImporting]   = useState(false)
  const [importMsg, setImportMsg]   = useState(null) // { ok, text }
  const fileRef = useRef()

  // Case matching
  const [cases, setCases]           = useState([])
  const [matchCaseId, setMatchCaseId] = useState('')
  const [matching, setMatching]     = useState(false)
  const [matchResult, setMatchResult] = useState(null)
  const [matchTypes, setMatchTypes] = useState([])      // [] = all types
  const [showOwn, setShowOwn]       = useState(false)   // show own/private indicators
  const [drill, setDrill]           = useState({})      // indicator key -> {loading, events, total}
  const [autoRun, setAutoRun]       = useState(null)    // per-case auto-run stage flags

  // Clear IOCs
  const [clearing, setClearing]     = useState(false)

  // Own networks (operator's public IPs — excluded from IOC matches/enrichment)
  const [ownNets, setOwnNets]       = useState('')
  const [ownSaving, setOwnSaving]   = useState(false)
  const [ownMsg, setOwnMsg]         = useState(null)

  // Allowlist (known-good values suppressed from matches)
  const [allowlist, setAllowlist]   = useState('')
  const [allowSaving, setAllowSaving] = useState(false)
  const [allowMsg, setAllowMsg]     = useState(null)

  // ── Load data ──────────────────────────────────────────────────────────────

  useEffect(() => { loadFeeds(); loadStats(); loadCases(); loadOwnNets(); loadAllowlist() }, [])

  function loadAllowlist() {
    api.cti.getAllowlist()
      .then(r => setAllowlist(Object.values(r.allowlist || {}).flat().join('\n')))
      .catch(() => {})
  }

  async function saveAllowlist() {
    setAllowSaving(true); setAllowMsg(null)
    const values = allowlist.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
    try {
      const r = await api.cti.setAllowlist(values)
      setAllowlist(Object.values(r.allowlist || {}).flat().join('\n'))
      setAllowMsg({ ok: true, text: `Saved ${r.count ?? 0} known-good value(s).` })
    } catch (err) {
      setAllowMsg({ ok: false, text: err.message })
    } finally { setAllowSaving(false) }
  }

  function loadOwnNets() {
    api.cti.getOwnNetworks()
      .then(r => setOwnNets((r.cidrs || []).join('\n')))
      .catch(() => {})
  }

  async function saveOwnNets() {
    setOwnSaving(true); setOwnMsg(null)
    const cidrs = ownNets.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)
    try {
      const r = await api.cti.setOwnNetworks(cidrs)
      setOwnNets((r.cidrs || []).join('\n'))
      setOwnMsg({ ok: true, text: `Saved ${r.cidrs?.length ?? 0} network(s); re-flagged ${r.reflagged ?? 0} IOC(s).` })
    } catch (err) {
      setOwnMsg({ ok: false, text: err.message })
    } finally { setOwnSaving(false) }
  }
  useEffect(() => { loadIOCs() }, [iocPage, iocType, iocSearch])

  function loadFeeds() {
    setFeedsLoading(true)
    api.cti.listFeeds()
      .then(r => setFeeds(r.feeds || r || []))
      .catch(() => {})
      .finally(() => setFeedsLoading(false))
  }

  function loadStats() {
    api.cti.iocStats()
      .then(r => setStats(r))
      .catch(() => {})
  }

  function loadIOCs() {
    setIocLoading(true)
    const params = { page: iocPage, size: 25 }
    if (iocType) params.type = iocType
    if (iocSearch.trim()) params.q = iocSearch.trim()
    api.cti.listIOCs(params)
      .then(r => {
        setIocs(r.iocs || [])
        setIocTotal(r.total || 0)
      })
      .catch(() => {})
      .finally(() => setIocLoading(false))
  }

  function loadCases() {
    api.cases.list()
      .then(r => setCases(r.cases || []))
      .catch(() => {})
  }

  // ── Feed actions ───────────────────────────────────────────────────────────

  async function pullFeed(id) {
    setPullingId(id)
    try {
      await api.cti.pullFeed(id)
      loadFeeds()
      loadStats()
    } catch (err) {
      alert('Pull failed: ' + err.message)
    } finally {
      setPullingId(null)
    }
  }

  async function deleteFeed(id) {
    if (!confirm('Delete this feed?')) return
    try {
      await api.cti.deleteFeed(id)
      setFeeds(prev => prev.filter(f => f.id !== id))
    } catch (err) {
      alert('Delete failed: ' + err.message)
    }
  }

  function handleFeedSaved(result) {
    setEditFeed(null)
    loadFeeds()
  }

  // ── Import STIX bundle ────────────────────────────────────────────────────

  function handleFileUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setBundleText(reader.result)
    reader.readAsText(file)
  }

  async function importBundle() {
    if (!bundleText.trim()) return
    setImporting(true)
    setImportMsg(null)
    try {
      let parsed
      try { parsed = JSON.parse(bundleText) } catch { throw new Error('Invalid JSON') }
      const r = await api.cti.importBundle(parsed)
      setImportMsg({ ok: true, text: `Imported ${r.imported ?? r.indicators ?? 0} indicator(s)` })
      setBundleText('')
      loadStats()
      loadIOCs()
    } catch (err) {
      setImportMsg({ ok: false, text: err.message })
    } finally {
      setImporting(false)
    }
  }

  // ── Clear IOCs ─────────────────────────────────────────────────────────────

  async function clearIOCs() {
    if (!confirm('Delete ALL IOCs? This cannot be undone.')) return
    setClearing(true)
    try {
      await api.cti.clearIOCs()
      loadStats()
      loadIOCs()
    } catch (err) {
      alert('Clear failed: ' + err.message)
    } finally {
      setClearing(false)
    }
  }

  // ── Case matching ─────────────────────────────────────────────────────────

  async function runMatch() {
    if (!matchCaseId) return
    setMatching(true)
    setMatchResult(null)
    setDrill({})
    try {
      const r = await api.cti.matchCase(matchCaseId, matchTypes.length ? matchTypes.join(',') : undefined)
      setMatchResult(r)
    } catch (err) {
      alert('Match failed: ' + err.message)
    } finally {
      setMatching(false)
    }
  }

  function toggleMatchType(t) {
    setMatchTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])
  }

  useEffect(() => {
    if (!matchCaseId) { setAutoRun(null); return }
    api.cases.getAutoRun(matchCaseId).then(setAutoRun).catch(() => setAutoRun(null))
  }, [matchCaseId])

  async function toggleAuto(k) {
    const next = { ...autoRun, [k]: !autoRun[k] }
    setAutoRun(next)
    try { await api.cases.setAutoRun(matchCaseId, { [k]: next[k] }) } catch { /* ignore */ }
  }

  async function toggleDrill(ind) {
    const key = `${ind.ioc_type}:${ind.ioc_value}`
    if (drill[key]) { setDrill(d => { const n = { ...d }; delete n[key]; return n }) ; return }
    setDrill(d => ({ ...d, [key]: { loading: true, events: [] } }))
    try {
      const r = await api.cti.indicatorEvents(matchCaseId, ind.ioc_type, ind.ioc_value)
      setDrill(d => ({ ...d, [key]: { loading: false, events: r.events || [], total: r.total } }))
    } catch (err) {
      setDrill(d => ({ ...d, [key]: { loading: false, events: [], error: err.message } }))
    }
  }

  // ── Pagination ─────────────────────────────────────────────────────────────

  const totalPages = Math.ceil(iocTotal / 25) || 1

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <PageShell>
      {/* Feed modal */}
      {editFeed !== null && (
        <FeedModal
          feed={editFeed?.id ? editFeed : null}
          onClose={() => setEditFeed(null)}
          onSaved={handleFeedSaved}
        />
      )}

      {/* ── Header ───────────────────────────────────────────────────────────── */}
      <PageHeader
        title="Threat Intelligence"
        icon={Shield}
        subtitle="Manage CTI feeds, import STIX bundles, and match IOCs against case artifacts"
      />


      {/* ── IOC Stats ────────────────────────────────────────────────────────── */}
      {stats && (
        <div className="grid grid-cols-3 sm:grid-cols-4 lg:grid-cols-7 gap-2 mb-6">
          <StatBox icon={Shield}   label="Total"    value={stats.total}    color="bg-brand-accentlight text-brand-accent" />
          <StatBox icon={Hash}     label="Hashes"   value={stats.hash}     color="bg-gray-100 text-gray-500" />
          <StatBox icon={Globe}    label="IPs"       value={stats.ip}       color="bg-gray-100 text-gray-500" />
          <StatBox icon={Globe}    label="Domains"  value={stats.domain}   color="bg-gray-100 text-gray-500" />
          <StatBox icon={Link2}    label="URLs"      value={stats.url}      color="bg-gray-100 text-gray-500" />
          <StatBox icon={AtSign}   label="Emails"   value={stats.email}    color="bg-gray-100 text-gray-500" />
          <StatBox icon={FileText} label="Files"    value={stats.filename} color="bg-gray-100 text-gray-500" />
        </div>
      )}

      {/* ── CTI Feeds ────────────────────────────────────────────────────────── */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-brand-text">CTI Feeds</h2>
          <button onClick={() => setEditFeed({})} className="btn-primary text-xs">
            <Plus size={13} /> Add Feed
          </button>
        </div>

        {feedsLoading ? (
          <div className="space-y-2">
            {[1, 2].map(i => <div key={i} className="skeleton h-20 w-full" />)}
          </div>
        ) : feeds.length === 0 ? (
          <div className="card px-4 py-6 text-sm text-gray-400">No feeds configured — add one above.</div>
        ) : (
          <div className="space-y-2">
            {feeds.map(feed => (
              <div key={feed.id} className="card p-4">
                <div className="flex items-start gap-3">
                  {/* Icon */}
                  <div className="w-8 h-8 rounded-lg bg-brand-accentlight border border-brand-accent/20 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Shield size={14} className="text-brand-accent" />
                  </div>

                  {/* Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-0.5">
                      <span className="text-sm font-semibold text-brand-text">{feed.name}</span>
                      <span className={`badge text-[10px] ${TYPE_BADGE_COLORS[feed.type] || TYPE_BADGE_COLORS.manual}`}>
                        {feed.type === 'taxii' ? 'TAXII' : feed.type === 'stix_url' ? 'URL' : feed.type === 'misp' ? 'MISP' : feed.type === 'yeti' ? 'YETI' : 'Manual'}
                      </span>
                      {feed.enabled ? (
                        <span className="badge bg-green-50 text-green-700 border border-green-200 text-[10px]">
                          <CheckCircle size={9} className="mr-0.5" /> enabled
                        </span>
                      ) : (
                        <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[10px]">
                          disabled
                        </span>
                      )}
                    </div>
                    {feed.url && (
                      <p className="text-[11px] text-gray-500 font-mono truncate mb-0.5">{feed.url}</p>
                    )}
                    <div className="flex items-center gap-3 text-[10px] text-gray-500 flex-wrap">
                      {pullingId === feed.id ? (
                        <span className="flex items-center gap-1 text-brand-accent font-semibold">
                          <Loader2 size={9} className="animate-spin" /> Downloading…
                        </span>
                      ) : (
                        <span>Last pull: {fmtDate(feed.last_pull)}</span>
                      )}
                      <span>{(feed.ioc_count ?? 0).toLocaleString()} IOCs</span>
                      {feed.type !== 'manual' && feed.auto_pull !== false && (
                        <span className="flex items-center gap-1 text-green-600">
                          <RefreshCw size={9} />
                          Every {feed.poll_interval_value ?? feed.poll_interval_hours ?? 24} {feed.poll_interval_unit ?? 'hours'}
                        </span>
                      )}
                      {feed.type !== 'manual' && feed.auto_pull === false && (
                        <span className="text-gray-500">Manual pull only</span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <button
                      onClick={() => pullFeed(feed.id)}
                      disabled={pullingId === feed.id}
                      className="btn-ghost text-xs p-1.5"
                      title="Pull Now"
                    >
                      {pullingId === feed.id
                        ? <Loader2 size={13} className="animate-spin" />
                        : <Download size={13} />}
                    </button>
                    <button onClick={() => setEditFeed(feed)} className="btn-ghost text-xs p-1.5" title="Edit">
                      <RefreshCw size={13} />
                    </button>
                    <button onClick={() => deleteFeed(feed.id)} className="btn-ghost text-xs p-1.5 text-gray-500 hover:text-red-500" title="Delete">
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Your Networks (own public IPs) ───────────────────────────────────── */}
      <div className="mb-8">
        <h2 className="text-sm font-semibold text-brand-text mb-3">Your Networks</h2>
        <div className="card p-4 space-y-3">
          <p className="text-xs text-gray-500">
            Your organisation's own public IP ranges (CIDR, one per line). IPs in these
            ranges are flagged <code className="text-brand-accent">own</code>. They still
            <strong> match</strong> on the case timeline, but as <strong>low-severity
            "info"</strong> hits labelled <em>CTI Match (own)</em> — separated from real
            threats (high severity). Filter them out on the timeline with the severity
            filter. Private IPs (RFC1918) get the same treatment automatically.
          </p>
          <textarea
            value={ownNets}
            onChange={e => setOwnNets(e.target.value)}
            placeholder={"203.0.113.0/24\n198.51.100.5\n2001:db8::/32"}
            rows={4}
            className="input text-xs font-mono resize-y"
          />
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={saveOwnNets} disabled={ownSaving} className="btn-primary text-xs">
              {ownSaving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
              Save Networks
            </button>
            {ownMsg && (
              <span className={`text-xs flex items-center gap-1 ${ownMsg.ok ? 'text-green-600' : 'text-red-600'}`}>
                {ownMsg.ok ? <CheckCircle size={12} /> : <AlertTriangle size={12} />} {ownMsg.text}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── Allowlist (known-good values) ────────────────────────────────────── */}
      <div className="mb-8">
        <h2 className="text-sm font-semibold text-brand-text mb-3">Allowlist (Known-Good)</h2>
        <div className="card p-4 space-y-3">
          <p className="text-xs text-gray-500">
            Known-good values to suppress from IOC matches — one per line. IPs, domains,
            URLs, hashes, emails, filenames or process names (auto-classified). Matches on
            these are kept but downgraded to <strong>"info"</strong> (like own/private), so
            real threats stand out. Use it to mute baseline noise (your own infra,
            monitoring agents, common false positives).
          </p>
          <textarea
            value={allowlist}
            onChange={e => setAllowlist(e.target.value)}
            placeholder={"8.8.8.8\nmonitoring.example.com\nd41d8cd98f00b204e9800998ecf8427e\nMsMpEng.exe"}
            rows={4}
            className="input text-xs font-mono resize-y"
          />
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={saveAllowlist} disabled={allowSaving} className="btn-primary text-xs">
              {allowSaving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
              Save Allowlist
            </button>
            {allowMsg && (
              <span className={`text-xs flex items-center gap-1 ${allowMsg.ok ? 'text-green-600' : 'text-red-600'}`}>
                {allowMsg.ok ? <CheckCircle size={12} /> : <AlertTriangle size={12} />} {allowMsg.text}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ── IOC Browser ──────────────────────────────────────────────────────── */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-brand-text">IOC Browser</h2>
          <button onClick={clearIOCs} disabled={clearing || iocTotal === 0} className="btn-danger text-xs">
            {clearing ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
            Clear All IOCs
          </button>
        </div>

        {/* Filters */}
        <div className="card p-3 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={iocType}
              onChange={e => { setIocType(e.target.value); setIocPage(1) }}
              className="input text-xs w-auto max-w-[140px]"
            >
              {IOC_TYPES.map(t => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <div className="relative flex-1 min-w-[180px]">
              <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
              <input
                value={iocSearch}
                onChange={e => { setIocSearch(e.target.value); setIocPage(1) }}
                placeholder="Search IOC values..."
                className="input text-xs pl-8"
              />
            </div>
            <span className="text-[10px] text-gray-500 flex-shrink-0">
              {iocTotal.toLocaleString()} result{iocTotal !== 1 ? 's' : ''}
            </span>
          </div>
        </div>

        {/* Table */}
        <div className="card overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-gray-50 border-b border-gray-200">
                <th className="text-left px-4 py-2.5 section-title">Type</th>
                <th className="text-left px-4 py-2.5 section-title">Value</th>
                <th className="text-left px-4 py-2.5 section-title">Source</th>
                <th className="text-left px-4 py-2.5 section-title">Date</th>
              </tr>
            </thead>
            <tbody>
              {iocLoading ? (
                <tr><td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                  <Loader2 size={16} className="animate-spin inline mr-2" />Loading...
                </td></tr>
              ) : iocs.length === 0 ? (
                <tr><td colSpan={4} className="px-4 py-8 text-center text-gray-500">
                  No IOCs found
                </td></tr>
              ) : iocs.map((ioc, i) => {
                const IocIcon = IOC_ICONS[ioc.type] || Shield
                return (
                  <tr key={ioc.indicator_id || i} className="border-b border-gray-100 hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-2">
                      <span className={`badge text-[10px] ${IOC_BADGE_COLORS[ioc.type] || 'bg-gray-100 text-gray-600 border border-gray-200'}`}>
                        <IocIcon size={9} className="mr-0.5" />
                        {ioc.type}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-[11px] text-brand-text truncate max-w-[300px]" title={ioc.value}>
                      {ioc.value}
                    </td>
                    <td className="px-4 py-2 text-gray-500 truncate max-w-[150px]" title={ioc.source}>
                      {ioc.source || '—'}
                    </td>
                    <td className="px-4 py-2 text-gray-500 whitespace-nowrap">
                      {fmtDate(ioc.created_at)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-2.5 border-t border-gray-100 bg-gray-50">
              <button
                onClick={() => setIocPage(p => Math.max(1, p - 1))}
                disabled={iocPage <= 1}
                className="btn-ghost text-xs"
              >
                Previous
              </button>
              <span className="text-[10px] text-gray-500">
                Page {iocPage} of {totalPages}
              </span>
              <button
                onClick={() => setIocPage(p => Math.min(totalPages, p + 1))}
                disabled={iocPage >= totalPages}
                className="btn-ghost text-xs"
              >
                Next
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── Case Matching ────────────────────────────────────────────────────── */}
      <div className="mb-8">
        <h2 className="text-sm font-semibold text-brand-text mb-3">Case IOC Matching</h2>
        <div className="card p-4 space-y-3">
          <p className="text-xs text-gray-500">
            Match a case against the IOC database. Uses Elasticsearch aggregations — returns the
            distinct indicators present (with event counts + feed context), not millions of rows.
          </p>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={matchCaseId}
              onChange={e => { setMatchCaseId(e.target.value); setMatchResult(null); setDrill({}) }}
              className="input text-xs w-auto max-w-[280px]"
            >
              <option value="">Select a case...</option>
              {cases.map(c => (
                <option key={c.case_id} value={c.case_id}>{c.name}</option>
              ))}
            </select>
            <button onClick={runMatch} disabled={matching || !matchCaseId} className="btn-primary text-xs">
              {matching ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
              Run IOC Match
            </button>
          </div>

          {/* Per-case auto-run: which post-ingestion stages run automatically */}
          {autoRun && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[10px] uppercase tracking-wide text-gray-400 mr-1">Auto-run on ingest</span>
              {[['auto_detections', 'Detections'], ['auto_ioc_match', 'IOC match'], ['auto_ai', 'AI risk']].map(([k, lbl]) => (
                <button key={k} onClick={() => toggleAuto(k)}
                  className={`badge text-[10px] border ${autoRun[k]
                    ? 'bg-green-50 text-green-700 border-green-200'
                    : 'bg-gray-100 text-gray-400 border-gray-200'}`}
                  title="Toggle whether this stage runs automatically after each ingest for this case">
                  {autoRun[k] ? '✓ ' : '✕ '}{lbl}
                </button>
              ))}
            </div>
          )}

          {/* Type filter — narrow which IOC types to check (faster) */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[10px] uppercase tracking-wide text-gray-400 mr-1">Types</span>
            {['ip', 'domain', 'url', 'hash', 'email', 'filename'].map(t => {
              const on = matchTypes.length === 0 || matchTypes.includes(t)
              return (
                <button key={t} onClick={() => toggleMatchType(t)}
                  className={`badge text-[10px] border ${on
                    ? 'bg-brand-accentlight text-brand-text border-brand-accent/40'
                    : 'bg-gray-100 text-gray-400 border-gray-200'}`}>
                  {t}
                </button>
              )
            })}
            {matchTypes.length > 0 && (
              <button onClick={() => setMatchTypes([])} className="text-[10px] text-gray-400 hover:text-brand-text">all</button>
            )}
          </div>

          {/* Match results — distinct indicators */}
          {matchResult && (() => {
            const inds = matchResult.indicators || []
            if (inds.length === 0) {
              return (
                <div className="flex items-center gap-2 text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2">
                  <CheckCircle size={13} /> No IOC matches found in this case.
                </div>
              )
            }
            const shown = showOwn ? inds : inds.filter(i => i.severity === 'high')
            return (
              <div className="space-y-2 pt-1">
                <div className="flex items-center gap-3 flex-wrap text-xs">
                  <span className="flex items-center gap-1.5 text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-1.5">
                    <AlertTriangle size={13} />
                    {matchResult.real_count} external indicator{matchResult.real_count !== 1 ? 's' : ''}
                  </span>
                  <span className="text-gray-500">{matchResult.total_event_hits?.toLocaleString()} event hits</span>
                  {matchResult.own_or_private_count > 0 && (
                    <label className="flex items-center gap-1.5 text-gray-500 cursor-pointer ml-auto">
                      <input type="checkbox" checked={showOwn} onChange={e => setShowOwn(e.target.checked)} />
                      show {matchResult.own_or_private_count} own/private
                    </label>
                  )}
                </div>
                {matchResult.truncated_fields?.length > 0 && (
                  <p className="text-[10px] text-amber-600">
                    Note: very high-cardinality fields were sampled (top {(20000).toLocaleString()} values): {matchResult.truncated_fields.join(', ')}.
                  </p>
                )}
                <div className="space-y-1">
                  {shown.map((m) => {
                    const key = `${m.ioc_type}:${m.ioc_value}`
                    const MIcon = IOC_ICONS[m.ioc_type] || Shield
                    const d = drill[key]
                    const sevCls = m.severity === 'high'
                      ? 'border-l-2 border-red-400' : 'border-l-2 border-gray-300'
                    return (
                      <div key={key} className={`bg-gray-50 rounded-lg ${sevCls}`}>
                        <button onClick={() => toggleDrill(m)}
                          className="w-full flex items-center gap-2 px-3 py-2 text-xs text-left hover:bg-gray-100 rounded-lg">
                          <span className={`badge text-[10px] ${IOC_BADGE_COLORS[m.ioc_type] || 'bg-gray-100 text-gray-600 border border-gray-200'}`}>
                            <MIcon size={9} className="mr-0.5" />{m.ioc_type}
                          </span>
                          <span className="font-mono text-brand-text truncate" title={m.ioc_value}>{m.ioc_value}</span>
                          {m.is_own && <span className="badge text-[9px] bg-blue-50 text-blue-600 border border-blue-200">own</span>}
                          {m.is_private && <span className="badge text-[9px] bg-gray-100 text-gray-500 border border-gray-200">private</span>}
                          {m.threat_type && <span className="text-[10px] text-gray-400">{m.threat_type}</span>}
                          {m.feed_name && <span className="text-[10px] text-gray-400 hidden sm:inline">· {m.feed_name}</span>}
                          <span className="text-gray-500 ml-auto flex-shrink-0 tabular-nums">
                            {m.event_count?.toLocaleString()} event{m.event_count !== 1 ? 's' : ''}
                          </span>
                          <ChevronRight size={12} className={`text-gray-400 transition-transform ${d ? 'rotate-90' : ''}`} />
                        </button>
                        {d && (
                          <div className="px-3 pb-2 space-y-1">
                            {d.loading && <p className="text-[11px] text-gray-400 flex items-center gap-1"><Loader2 size={11} className="animate-spin" /> loading events…</p>}
                            {d.error && <p className="text-[11px] text-red-500">{d.error}</p>}
                            {!d.loading && d.events?.length === 0 && <p className="text-[11px] text-gray-400">no events</p>}
                            {(d.events || []).map((ev, i) => (
                              <a key={i} href={`/cases/${matchCaseId}?event=${ev.fo_id}`}
                                className="flex items-center gap-2 text-[11px] text-gray-600 hover:text-brand-accent px-2 py-1 rounded hover:bg-white">
                                <span className="text-gray-400 tabular-nums flex-shrink-0">{(ev.timestamp || '').slice(0, 19).replace('T', ' ')}</span>
                                <span className="truncate">{ev.message || ev.artifact_type}</span>
                                <ExternalLink size={9} className="ml-auto flex-shrink-0" />
                              </a>
                            ))}
                            {d.total > (d.events?.length || 0) && (
                              <p className="text-[10px] text-gray-400">showing {d.events.length} of {d.total.toLocaleString()} — refine in the case timeline</p>
                            )}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })()}
        </div>
      </div>

      {/* ── Import STIX Bundle ───────────────────────────────────────────────── */}
      <div className="mb-8">
        <h2 className="text-sm font-semibold text-brand-text mb-3">Import STIX Bundle</h2>
        <div className="card p-4 space-y-3">
          <p className="text-xs text-gray-500">
            Paste a STIX 2.1 JSON bundle or upload a <code className="text-brand-accent">.json</code> file to import indicators.
          </p>
          <textarea
            value={bundleText}
            onChange={e => setBundleText(e.target.value)}
            placeholder='{"type": "bundle", "id": "bundle--...", "objects": [...]}'
            rows={5}
            className="input text-xs font-mono resize-y"
          />
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={importBundle} disabled={importing || !bundleText.trim()} className="btn-primary text-xs">
              {importing ? <Loader2 size={12} className="animate-spin" /> : <Upload size={12} />}
              Import
            </button>
            <button onClick={() => fileRef.current?.click()} className="btn-outline text-xs">
              <FileText size={12} /> Upload .json
            </button>
            <input ref={fileRef} type="file" accept=".json" className="hidden"
              onChange={handleFileUpload} />
          </div>
          {importMsg && (
            <div className={`flex items-center gap-2 text-xs rounded-lg px-3 py-2 ${
              importMsg.ok
                ? 'text-green-700 bg-green-50 border border-green-200'
                : 'text-red-600 bg-red-50 border border-red-200'
            }`}>
              {importMsg.ok ? <CheckCircle size={13} /> : <AlertTriangle size={13} />}
              {importMsg.text}
            </div>
          )}
        </div>
      </div>

    </PageShell>
  )
}
