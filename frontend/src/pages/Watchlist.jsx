import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Plus, X, Eye, Loader2, AlertTriangle, ExternalLink, ListChecks,
  Info, Globe, Hash, Terminal, Code, Network, ShieldAlert, Check, ShieldCheck,
} from 'lucide-react'
import { api } from '../api/client'
import { PageShell, PageHeader } from '../components/shared/PageShell'

// ── IOC kind catalogue ──────────────────────────────────────────────────────
// Each entry: id, label, icon, hint (what it matches), example (placeholder),
// and a tiny `preview(value)` describing the Lucene clause the backend builds
// so the analyst sees exactly which fields will be searched.
const KINDS = [
  {
    id: 'ip',
    label: 'IP address',
    icon: Network,
    hint: 'Matches network.src_ip / network.dst_ip / host.ip',
    example: '203.0.113.42',
    preview: v => `network.src_ip:"${v}" OR network.dst_ip:"${v}" OR host.ip:"${v}"`,
  },
  {
    id: 'domain',
    label: 'Domain',
    icon: Globe,
    hint: 'Matches network.dst_domain, http.host, and browser URLs (substring)',
    example: 'evil.example.com',
    preview: v => `network.dst_domain:"${v}" OR http.host:"${v}" OR browser_report.url:*${v}*`,
  },
  {
    id: 'hash',
    label: 'File hash',
    icon: Hash,
    hint: 'MD5, SHA1, or SHA256 — matches across all three process.hash_* fields',
    example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    preview: v => `process.hash_md5:"${v}" OR process.hash_sha1:"${v}" OR process.hash_sha256:"${v}"`,
  },
  {
    id: 'cmdline',
    label: 'Command line',
    icon: Terminal,
    hint: 'Exact match on process.command_line. Use wildcards for partial matches.',
    example: 'powershell -enc *',
    preview: v => `process.command_line:"${v}"`,
  },
  {
    id: 'regex',
    label: 'Regex on message',
    icon: Code,
    hint: 'Regex against the event `message` field. Slow on huge cases — prefer cmdline / hash when possible.',
    example: 'rundll32\\.exe.*shell32',
    preview: v => `message:/${v}/`,
  },
  {
    id: 'custom',
    label: 'Raw Lucene',
    icon: ShieldAlert,
    hint: 'Full Lucene query_string syntax. No transformation — full power, no safety net.',
    example: 'process.name:powershell.exe AND user.name:admin',
    preview: v => v,
  },
]

export default function Watchlist() {
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(true)
  const [draftKindId, setDraftKindId] = useState('ip')
  const [draftValue, setDraftValue]   = useState('')
  const [draftLabel, setDraftLabel]   = useState('')
  const [adding,    setAdding]   = useState(false)
  const [running,   setRunning]  = useState(false)
  const [lastSweep, setLastSweep] = useState(null)
  const [wlHosts, setWlHosts]    = useState('')
  const [wlIps, setWlIps]        = useState('')
  const [wlSaving, setWlSaving]  = useState(false)
  const [wlMsg, setWlMsg]        = useState(null)
  const navigate = useNavigate()

  const draftKind = useMemo(
    () => KINDS.find(k => k.id === draftKindId) || KINDS[0],
    [draftKindId],
  )

  async function load() {
    setLoading(true)
    try {
      const r = await api.watchlist.list()
      setEntries(r.entries || [])
    } catch { setEntries([]) }
    finally { setLoading(false) }
  }
  useEffect(() => { load(); loadWhitelist() }, [])

  function loadWhitelist() {
    api.watchlist.getWhitelist()
      .then(w => { setWlHosts((w.hostnames || []).join('\n')); setWlIps((w.ips || []).join('\n')) })
      .catch(() => {})
  }
  async function saveWhitelist() {
    setWlSaving(true); setWlMsg(null)
    const split = s => s.split(/[\s,]+/).map(x => x.trim()).filter(Boolean)
    try {
      const w = await api.watchlist.setWhitelist(split(wlHosts), split(wlIps))
      setWlHosts((w.hostnames || []).join('\n')); setWlIps((w.ips || []).join('\n'))
      setWlMsg({ ok: true, text: `Saved ${(w.hostnames?.length || 0) + (w.ips?.length || 0)} asset(s).` })
    } catch (e) { setWlMsg({ ok: false, text: e.message }) }
    finally { setWlSaving(false) }
  }

  async function add(e) {
    e.preventDefault()
    if (!draftValue.trim()) return
    setAdding(true)
    try {
      await api.watchlist.add({ kind: draftKindId, value: draftValue.trim(), label: draftLabel.trim() })
      setDraftValue('')
      setDraftLabel('')
      // Auto-sweep — analyst gets hit counts without a second click.
      await sweep()
    } catch (err) {
      alert(err.message)
    } finally {
      setAdding(false)
    }
  }

  async function remove(id) {
    if (!confirm('Delete this watchlist entry? It will stop being evaluated against future cases.')) return
    await api.watchlist.delete(id)
    load()
  }

  async function sweep() {
    setRunning(true)
    try {
      const r = await api.watchlist.evaluate()
      setEntries(r.entries || [])
      setLastSweep(new Date())
    } catch (err) {
      alert(err.message)
    } finally {
      setRunning(false)
    }
  }

  // Group entries by kind for scannability — IPs together, hashes together, …
  const grouped = useMemo(() => {
    const g = {}
    for (const e of entries) {
      const k = e.kind || 'custom'
      ;(g[k] = g[k] || []).push(e)
    }
    return KINDS
      .map(k => ({ kind: k, items: g[k.id] || [] }))
      .filter(g => g.items.length > 0)
  }, [entries])

  const hotCount = entries.filter(e => (e.total_hits || 0) > 0).length

  return (
    <PageShell>
      <PageHeader
        title="IOC watchlist"
        icon={ListChecks}
        subtitle="Persistent IOCs evaluated against every case you can access. Add an indicator once; sweep all cases with one click after any ingest."
        actions={
          <button
            onClick={sweep}
            disabled={running || entries.length === 0}
            className="btn-primary text-xs flex items-center gap-1.5"
          >
            {running ? <Loader2 size={12} className="animate-spin" /> : <Eye size={12} />}
            {running ? 'Sweeping…' : 'Sweep all cases'}
          </button>
        }
      />

      {/* ── Add form ───────────────────────────────────────────────────────── */}
      <form onSubmit={add} className="card p-4 space-y-3">
        {/* Kind selector — visual chips, not a hidden <select> */}
        <div>
          <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
            Indicator type
          </label>
          <div className="flex flex-wrap gap-1.5">
            {KINDS.map(k => {
              const Icon = k.icon
              const active = k.id === draftKindId
              return (
                <button
                  key={k.id}
                  type="button"
                  onClick={() => setDraftKindId(k.id)}
                  className={`flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-lg border transition-colors ${
                    active
                      ? 'bg-brand-accent text-white border-brand-accent'
                      : 'bg-white text-gray-700 border-gray-200 hover:border-brand-accent hover:text-brand-accent'
                  }`}
                >
                  <Icon size={11} />
                  {k.label}
                </button>
              )
            })}
          </div>
          <div className="flex items-start gap-1.5 mt-1.5 text-[11px] text-gray-500">
            <Info size={11} className="flex-shrink-0 mt-0.5" />
            <span>{draftKind.hint}</span>
          </div>
        </div>

        {/* Value + Label */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-2">
          <div className="md:col-span-6">
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">Value</label>
            <input
              value={draftValue}
              onChange={e => setDraftValue(e.target.value)}
              placeholder={draftKind.example}
              className="input text-xs h-9 font-mono w-full"
            />
          </div>
          <div className="md:col-span-4">
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
              Label <span className="text-gray-400 font-normal normal-case">(optional)</span>
            </label>
            <input
              value={draftLabel}
              onChange={e => setDraftLabel(e.target.value)}
              placeholder="e.g. APT29 — Cozy Bear C2"
              className="input text-xs h-9 w-full"
            />
          </div>
          <div className="md:col-span-2 flex items-end">
            <button
              type="submit"
              disabled={!draftValue.trim() || adding}
              className="btn-primary text-xs h-9 w-full flex items-center justify-center gap-1.5"
            >
              {adding ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />}
              Add &amp; sweep
            </button>
          </div>
        </div>

        {/* Live query preview — analyst sees exactly what will run */}
        {draftValue.trim() && (
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">
              Generated Lucene query
            </label>
            <code className="block bg-gray-50 border border-gray-200 rounded px-2 py-1.5 text-[11px] font-mono text-gray-700 whitespace-pre-wrap break-all">
              {draftKind.preview(draftValue.trim())}
            </code>
          </div>
        )}
      </form>

      {/* ── Company asset whitelist ───────────────────────────────────────── */}
      <div className="card p-4 space-y-3">
        <div className="flex items-center gap-2">
          <ShieldCheck size={15} className="text-brand-accent" />
          <h2 className="font-semibold text-brand-text text-sm">Company Asset Whitelist</h2>
        </div>
        <p className="text-xs text-gray-500">
          Your organisation's own hostnames and IP addresses. Watchlist sweeps exclude events
          on these assets, so your own infrastructure never generates watchlist noise.
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">Hostnames</label>
            <textarea value={wlHosts} onChange={e => setWlHosts(e.target.value)}
              placeholder={"DC01\nWEB-PROD-01\nfileserver.corp.local"} rows={4}
              className="input text-xs font-mono resize-y w-full" />
          </div>
          <div>
            <label className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1 block">IP addresses</label>
            <textarea value={wlIps} onChange={e => setWlIps(e.target.value)}
              placeholder={"10.0.0.5\n192.168.1.10\n203.0.113.7"} rows={4}
              className="input text-xs font-mono resize-y w-full" />
          </div>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={saveWhitelist} disabled={wlSaving} className="btn-primary text-xs">
            {wlSaving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save Whitelist
          </button>
          {wlMsg && (
            <span className={`text-xs flex items-center gap-1 ${wlMsg.ok ? 'text-green-600' : 'text-red-600'}`}>
              {wlMsg.ok ? <Check size={12} /> : <AlertTriangle size={12} />} {wlMsg.text}
            </span>
          )}
        </div>
      </div>

      {/* ── Sweep status banner ───────────────────────────────────────────── */}
      {hotCount > 0 && (
        <div className="card border-amber-200 bg-amber-50 p-3 flex items-start gap-2.5 text-xs">
          <AlertTriangle size={14} className="text-amber-600 flex-shrink-0 mt-0.5" />
          <span className="text-amber-800">
            <strong>{hotCount}</strong> IOC{hotCount === 1 ? '' : 's'} matched at least one case in the last sweep.
            {lastSweep && (
              <span className="text-amber-700/80"> · Last sweep: {lastSweep.toLocaleTimeString()}</span>
            )}
          </span>
        </div>
      )}

      {/* ── Entries — grouped by kind ─────────────────────────────────────── */}
      {loading ? (
        <div className="card p-6 text-center text-sm text-gray-500">
          <Loader2 size={14} className="inline-block animate-spin mr-1" /> Loading…
        </div>
      ) : entries.length === 0 ? (
        <div className="card p-8 text-center space-y-3">
          <ListChecks size={28} className="text-gray-400 mx-auto" />
          <div>
            <p className="text-sm font-medium text-gray-700">Watchlist is empty</p>
            <p className="text-xs text-gray-500 mt-1 max-w-md mx-auto">
              Add a known-bad IP, domain, file hash, or command line above.
              The watchlist sweeps every case you can access after each ingest
              so you don't miss a re-occurrence across investigations.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {grouped.map(({ kind, items }) => {
            const KindIcon = kind.icon
            return (
              <div key={kind.id}>
                <div className="flex items-center gap-2 mb-2">
                  <KindIcon size={13} className="text-gray-600" />
                  <h3 className="text-xs font-semibold text-gray-700 uppercase tracking-wider">
                    {kind.label}
                  </h3>
                  <span className="text-[10px] text-gray-500 tabular-nums">
                    {items.length} entr{items.length === 1 ? 'y' : 'ies'}
                  </span>
                </div>
                <div className="space-y-2">
                  {items.map(e => {
                    const hot = (e.total_hits || 0) > 0
                    return (
                      <div
                        key={e.id}
                        className={`card p-3 ${hot ? 'border-amber-300 bg-amber-50/30' : ''}`}
                      >
                        <div className="flex items-center gap-3 flex-wrap mb-1.5">
                          <span className="font-semibold text-brand-text text-sm">
                            {e.label || e.value}
                          </span>
                          {e.label && (
                            <span className="font-mono text-[11px] text-gray-500">{e.value}</span>
                          )}
                          <span className="ml-auto flex items-center gap-2">
                            {e.total_hits != null && (
                              <span className={`badge text-[10px] ${
                                hot
                                  ? 'bg-amber-100 text-amber-800 font-semibold'
                                  : 'bg-gray-100 text-gray-500'
                              }`}>
                                {e.total_hits.toLocaleString()} hits
                              </span>
                            )}
                            <button
                              onClick={() => remove(e.id)}
                              className="icon-btn h-7 w-7 text-gray-400 hover:text-red-600"
                              title="Delete"
                            >
                              <X size={13} />
                            </button>
                          </span>
                        </div>
                        <code className="block bg-gray-50 border border-gray-100 rounded px-2 py-1 text-[11px] font-mono text-gray-700 break-all">
                          {e.query}
                        </code>
                        {(e.matched_cases || []).length > 0 && (
                          <div className="mt-2 space-y-0.5">
                            {e.matched_cases.map(m => (
                              <button
                                key={m.case_id}
                                onClick={() => navigate(`/cases/${m.case_id}`, { state: { pivotQuery: e.query } })}
                                className="w-full flex items-center gap-2 text-[11px] hover:bg-brand-accentlight/40 rounded px-2 py-1 transition-colors group"
                                title={`Open ${m.case_name} with this IOC pivoted in`}
                              >
                                <span className="text-gray-700 truncate flex-1 text-left">{m.case_name}</span>
                                <span className="badge text-[10px] bg-amber-50 text-amber-700">{m.hits.toLocaleString()}</span>
                                <ExternalLink size={11} className="text-gray-400 opacity-0 group-hover:opacity-100 transition-opacity" />
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </PageShell>
  )
}
