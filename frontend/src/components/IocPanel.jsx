import { useState, useEffect } from 'react'
import { Loader2, Search, Copy, ChevronDown, ChevronRight, Download, Globe, X, Play, AlertTriangle, CheckCircle, ShieldCheck } from 'lucide-react'
import { api } from '../api/client'

// ── Threat-intel matching (aggregation-based; moved here from the CTI page) ───
// Matches the case against the IOC database via ES aggregations → distinct
// enriched indicators (value, event count, feed, severity). Clicking an
// indicator pivots the timeline to that value via onSearch (reliable nav).
function ThreatMatch({ caseId, onSearch }) {
  const [matching, setMatching] = useState(false)
  const [result, setResult]     = useState(null)
  const [types, setTypes]       = useState([])
  const [showOwn, setShowOwn]   = useState(false)
  const [autoRun, setAutoRun]   = useState(null)
  const [open, setOpen]         = useState(true)

  useEffect(() => {
    api.cases.getAutoRun(caseId).then(setAutoRun).catch(() => setAutoRun(null))
  }, [caseId])

  const toggleType = t => setTypes(p => p.includes(t) ? p.filter(x => x !== t) : [...p, t])
  async function toggleAuto(k) {
    const next = { ...autoRun, [k]: !autoRun[k] }; setAutoRun(next)
    try { await api.cases.setAutoRun(caseId, { [k]: next[k] }) } catch { /* ignore */ }
  }

  async function run() {
    setMatching(true); setResult(null)
    try {
      const r = await api.cti.matchCase(caseId, types.length ? types.join(',') : undefined)
      setResult(r)
    } catch (e) { setResult({ error: e.message }) }
    finally { setMatching(false) }
  }

  const inds = result?.indicators || []
  const shown = showOwn ? inds : inds.filter(i => i.severity === 'high')

  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <button onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 hover:bg-gray-100 text-xs">
        <span className="font-semibold text-fuchsia-600 flex items-center gap-1.5"><ShieldCheck size={11} /> Threat Intel Matches</span>
        {open ? <ChevronDown size={11} className="text-gray-400" /> : <ChevronRight size={11} className="text-gray-400" />}
      </button>
      {open && (
        <div className="p-3 space-y-2">
          <div className="flex items-center gap-1.5 flex-wrap">
            {['ip', 'domain', 'url', 'hash', 'email', 'filename'].map(t => {
              const on = types.length === 0 || types.includes(t)
              return (
                <button key={t} onClick={() => toggleType(t)}
                  className={`badge text-[10px] border ${on ? 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200' : 'bg-gray-100 text-gray-400 border-gray-200'}`}>{t}</button>
              )
            })}
            <button onClick={run} disabled={matching} className="btn-primary text-[11px] py-0.5 ml-auto">
              {matching ? <Loader2 size={11} className="animate-spin" /> : <Play size={11} />} Match
            </button>
          </div>

          {autoRun && (
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[9px] uppercase tracking-wide text-gray-400">Auto-run</span>
              {[['auto_detections', 'Detections'], ['auto_ioc_match', 'IOC'], ['auto_ai', 'AI']].map(([k, lbl]) => (
                <button key={k} onClick={() => toggleAuto(k)}
                  className={`badge text-[9px] border ${autoRun[k] ? 'bg-green-50 text-green-700 border-green-200' : 'bg-gray-100 text-gray-400 border-gray-200'}`}>
                  {autoRun[k] ? '✓' : '✕'} {lbl}
                </button>
              ))}
            </div>
          )}

          {result?.error && <p className="text-[11px] text-red-500">{result.error}</p>}
          {result && !result.error && inds.length === 0 && (
            <p className="text-[11px] text-green-700 flex items-center gap-1"><CheckCircle size={11} /> No IOC matches.</p>
          )}
          {result && shown.length > 0 && (
            <>
              <div className="flex items-center gap-2 text-[11px]">
                <span className="text-amber-700 flex items-center gap-1"><AlertTriangle size={11} />{result.real_count} external</span>
                <span className="text-gray-400">{result.total_event_hits?.toLocaleString()} hits</span>
                {result.own_or_private_count > 0 && (
                  <label className="flex items-center gap-1 text-gray-500 ml-auto cursor-pointer">
                    <input type="checkbox" checked={showOwn} onChange={e => setShowOwn(e.target.checked)} />
                    +{result.own_or_private_count} own/private
                  </label>
                )}
              </div>
              <div className="space-y-0.5 max-h-72 overflow-y-auto">
                {shown.map(m => (
                  <button key={`${m.ioc_type}:${m.ioc_value}`} onClick={() => onSearch(`"${m.ioc_value}"`)}
                    title="Pivot the timeline to this indicator"
                    className={`w-full flex items-center gap-1.5 px-2 py-1 text-[11px] text-left rounded hover:bg-fuchsia-50 ${m.severity === 'high' ? 'border-l-2 border-red-400' : 'border-l-2 border-gray-200'}`}>
                    <span className="badge text-[9px] bg-gray-100 text-gray-500 border border-gray-200">{m.ioc_type}</span>
                    <span className="font-mono text-gray-800 truncate" title={m.ioc_value}>{m.ioc_value}</span>
                    {m.threat_type && <span className="text-[9px] text-gray-400">{m.threat_type}</span>}
                    <span className="ml-auto text-gray-500 tabular-nums flex-shrink-0">×{m.event_count?.toLocaleString()}</span>
                    <Search size={9} className="text-gray-400 flex-shrink-0" />
                  </button>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

const CATEGORIES = [
  { key: 'src_ips',       label: 'Source IPs',      searchField: 'network.src_ip',      color: 'text-red-600',    isIp: true  },
  { key: 'dst_ips',       label: 'Dest IPs',         searchField: 'network.dst_ip',      color: 'text-orange-600', isIp: true  },
  { key: 'hostnames',     label: 'Hostnames',        searchField: 'host.hostname',       color: 'text-sky-600',    isIp: false },
  { key: 'usernames',     label: 'Users',            searchField: 'user.name',           color: 'text-violet-600', isIp: false },
  { key: 'processes',     label: 'Processes',        searchField: 'process.name',        color: 'text-emerald-600',isIp: false },
  { key: 'domains',       label: 'Domains',          searchField: 'network.dst_domain',  color: 'text-teal-600',   isIp: false },
  { key: 'urls',          label: 'URLs / Paths',     searchField: 'http.request_path',   color: 'text-blue-600',   isIp: false },
  { key: 'cmdlines',      label: 'Command Lines',    searchField: 'process.command_line.keyword', color: 'text-amber-600',  isIp: false },
  { key: 'hashes_md5',    label: 'MD5 Hashes',       searchField: 'process.hash_md5',    color: 'text-pink-600',   isIp: false },
  { key: 'hashes_sha256', label: 'SHA256 Hashes',    searchField: 'process.hash_sha256', color: 'text-pink-700',   isIp: false },
  { key: 'reg_keys',      label: 'Registry Keys',    searchField: 'registry.key',        color: 'text-indigo-600', isIp: false },
  { key: 'user_agents',   label: 'User Agents',      searchField: 'http.user_agent',     color: 'text-gray-600',   isIp: false },
]

// ── WHOIS popover ─────────────────────────────────────────────────────────────
function WhoisPopover({ ip, onClose }) {
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState('')

  useEffect(() => {
    setLoading(true)
    setError('')
    api.search.whois(ip)
      .then(setData)
      .catch(err => setError(err.message || 'Lookup failed'))
      .finally(() => setLoading(false))
  }, [ip])

  return (
    <div className="mt-1 mx-1 mb-1 rounded-lg border border-gray-200 bg-white shadow-lg p-3 text-xs">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5">
          <Globe size={11} className="text-sky-500" />
          <span className="font-semibold text-gray-700 font-mono">{ip}</span>
        </div>
        <button onClick={onClose} className="text-gray-500 hover:text-gray-600 p-0.5 rounded hover:bg-gray-100">
          <X size={10} />
        </button>
      </div>

      {loading ? (
        <div className="flex items-center gap-1.5 text-gray-500 py-1">
          <Loader2 size={11} className="animate-spin" />
          <span className="text-[11px]">Looking up…</span>
        </div>
      ) : error ? (
        <p className="text-red-500 text-[11px]">{error}</p>
      ) : data ? (
        <div className="space-y-1">
          {[
            { label: 'Org',      value: data.org         },
            { label: 'Country',  value: data.country     },
            { label: 'CIDR',     value: data.cidr        },
            { label: 'Handle',   value: data.handle      },
            { label: 'Notes',    value: data.description },
          ].filter(r => r.value && r.value !== '—').map(row => (
            <div key={row.label} className="flex items-baseline gap-2">
              <span className="text-[10px] text-gray-500 w-12 flex-shrink-0">{row.label}</span>
              <span className="font-mono text-[11px] text-gray-800 break-all">{row.value}</span>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  )
}

// ── Category accordion ────────────────────────────────────────────────────────
function IocCategory({ cat, items, onSearch }) {
  const [open, setOpen]           = useState(items.length > 0 && items.length <= 10)
  const [whoisIp, setWhoisIp]     = useState(null)

  if (!items.length) return null

  return (
    <div className="border border-gray-100 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(v => !v)}
        className="w-full flex items-center justify-between px-3 py-2 bg-gray-50 hover:bg-gray-100 transition-colors text-xs"
      >
        <span className={`font-semibold ${cat.color}`}>{cat.label}</span>
        <div className="flex items-center gap-2 text-gray-500">
          <span className="badge bg-gray-100 text-gray-500 border border-gray-200 text-[9px]">{items.length}</span>
          {open ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
        </div>
      </button>

      {open && (
        <div className="divide-y divide-gray-50 max-h-72 overflow-y-auto">
          {items.map((item, i) => (
            <div key={item.value ?? i}>
              <div className="flex items-center gap-2 px-3 py-1.5 group hover:bg-blue-50 transition-colors">
                <span className="flex-1 text-[11px] font-mono text-gray-800 truncate" title={item.value}>
                  {item.value}
                </span>
                <span className="text-[9px] text-gray-500 flex-shrink-0 tabular-nums">
                  ×{item.count.toLocaleString()}
                </span>
                <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0">
                  <button
                    onClick={() => navigator.clipboard.writeText(item.value)}
                    className="p-0.5 rounded hover:bg-gray-200 text-gray-500 hover:text-gray-600 transition-colors"
                    title="Copy"
                  >
                    <Copy size={9} />
                  </button>
                  {cat.isIp && (
                    <button
                      onClick={() => setWhoisIp(whoisIp === item.value ? null : item.value)}
                      className={`p-0.5 rounded transition-colors ${whoisIp === item.value ? 'bg-sky-100 text-sky-600' : 'hover:bg-sky-100 text-gray-500 hover:text-sky-600'}`}
                      title="WHOIS / RDAP lookup"
                    >
                      <Globe size={9} />
                    </button>
                  )}
                  <button
                    onClick={() => onSearch(`${cat.searchField}:"${item.value}"`)}
                    className="p-0.5 rounded hover:bg-blue-100 text-gray-500 hover:text-blue-600 transition-colors"
                    title="Search this value in timeline"
                  >
                    <Search size={9} />
                  </button>
                </div>
              </div>
              {whoisIp === item.value && (
                <WhoisPopover ip={item.value} onClose={() => setWhoisIp(null)} />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Export helpers ────────────────────────────────────────────────────────────
function exportCsv(iocs) {
  const rows = ['Type,Value,Count']
  CATEGORIES.forEach(cat => {
    ;(iocs[cat.key] || []).forEach(item => {
      rows.push(`${cat.label},${JSON.stringify(item.value)},${item.count}`)
    })
  })
  _download(rows.join('\n'), 'text/csv', `iocs-${Date.now()}.csv`)
}

function exportJson(iocs) {
  const out = {}
  CATEGORIES.forEach(cat => {
    const items = iocs[cat.key] || []
    if (items.length) out[cat.label] = items
  })
  _download(JSON.stringify(out, null, 2), 'application/json', `iocs-${Date.now()}.json`)
}

function _download(content, mime, filename) {
  const blob = new Blob([content], { type: mime })
  const url  = URL.createObjectURL(blob)
  const a    = document.createElement('a')
  a.href     = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// ── Main panel ────────────────────────────────────────────────────────────────
export default function IocPanel({ caseId, onSearch }) {
  const [iocs, setIocs]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [filter, setFilter]   = useState('')
  const [showExport, setShowExport] = useState(false)

  useEffect(() => {
    setLoading(true)
    api.search.iocs(caseId)
      .then(setIocs)
      .catch(() => setIocs({}))
      .finally(() => setLoading(false))
  }, [caseId])

  const totalIocs = iocs
    ? Object.values(iocs).reduce((s, arr) => s + arr.length, 0)
    : 0

  const filteredCats = CATEGORIES.map(cat => {
    if (!iocs) return { ...cat, items: [] }
    const items = filter
      ? (iocs[cat.key] || []).filter(i => i.value.toLowerCase().includes(filter.toLowerCase()))
      : (iocs[cat.key] || [])
    return { ...cat, items }
  }).filter(c => c.items.length > 0)

  return (
    <div className="flex flex-col h-full p-4 space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-semibold text-brand-text">Observed Indicators</p>
          <p className="text-[10px] text-gray-500 mt-0.5">
            {loading ? 'Loading…' : `${totalIocs} unique values across ${filteredCats.length} categories`}
          </p>
        </div>

        {/* Export dropdown */}
        {!loading && totalIocs > 0 && (
          <div className="relative">
            <button
              onClick={() => setShowExport(v => !v)}
              className={`btn-ghost text-xs flex items-center gap-1 ${showExport ? 'text-brand-accent' : 'text-gray-500'}`}
              title="Export IOCs"
            >
              <Download size={12} />
              Export
            </button>
            {showExport && (
              <div
                className="absolute right-0 top-full mt-1 bg-white border border-gray-200 rounded-lg shadow-lg z-20 w-36 py-1"
                onMouseLeave={() => setShowExport(false)}
              >
                <button
                  onClick={() => { exportCsv(iocs); setShowExport(false) }}
                  className="w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Export as CSV
                </button>
                <button
                  onClick={() => { exportJson(iocs); setShowExport(false) }}
                  className="w-full text-left px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-50 transition-colors"
                >
                  Export as JSON
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Search filter */}
      <div className="relative">
        <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter indicators…"
          className="input w-full pl-7 text-xs"
        />
      </div>

      {/* Threat-intel matching against the IOC database */}
      <ThreatMatch caseId={caseId} onSearch={onSearch} />

      {/* Body */}
      {loading ? (
        <div className="flex items-center justify-center py-12 text-gray-500">
          <Loader2 size={16} className="animate-spin mr-2" />
          <span className="text-xs">Aggregating case data…</span>
        </div>
      ) : totalIocs === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-center text-gray-500">
          <p className="text-xs">No indicators found for this case.</p>
          <p className="text-[10px] mt-1">Ingest data to populate this panel.</p>
        </div>
      ) : filteredCats.length === 0 ? (
        <p className="text-xs text-gray-500 text-center py-6">No results for "{filter}"</p>
      ) : (
        <div className="space-y-2 overflow-y-auto flex-1">
          {filteredCats.map(cat => (
            <IocCategory key={cat.key} cat={cat} items={cat.items} onSearch={onSearch} />
          ))}
        </div>
      )}
    </div>
  )
}
