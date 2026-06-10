import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Loader2, ExternalLink, Database, Globe, FolderOpen } from 'lucide-react'
import { api } from '../api/client'

const PRESETS = [
  { label: 'PowerShell launched as admin',     q: 'process.executable_name:powershell.exe AND process.integrity_level:High' },
  { label: 'Failed logons',                    q: 'evtx.event_id:4625' },
  { label: 'New service installed',            q: 'evtx.event_id:7045' },
  { label: 'Log cleared',                      q: 'evtx.event_id:1102' },
  { label: 'Hayabusa critical/high',           q: 'artifact_type:hayabusa AND hayabusa.level:(critical OR high)' },
  { label: 'Outbound connect from Office',     q: 'process.parent_executable:(WINWORD.EXE OR EXCEL.EXE OR OUTLOOK.EXE) AND _exists_:network.dst_ip' },
]

export default function CrossCaseSearch() {
  const [query, setQuery]     = useState('')
  const [result, setResult]   = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState('')
  const navigate = useNavigate()

  async function run(q) {
    const text = (q ?? query).trim()
    if (!text) return
    setQuery(text); setLoading(true); setError(''); setResult(null)
    try {
      const r = await api.search.crossCase(text, 3)
      setResult(r)
    } catch (e) {
      setError(e?.message || 'Search failed')
    } finally {
      setLoading(false)
    }
  }

  const totalHits = (result?.results || []).reduce((s, r) => s + (r.hits || 0), 0)

  return (
    <div className="px-4 sm:px-6 lg:px-8 py-6 lg:py-8 space-y-6 fade-in">
      <div>
        <h1 className="text-[28px] sm:text-[32px] font-bold text-brand-text tracking-tight leading-none">
          Cross-case search
        </h1>
        <p className="text-sm text-gray-500 mt-2">
          Run a single Lucene query across every accessible case. Find repeat IOCs, lateral movement signals
          shared between investigations, or campaign-wide hunting.
        </p>
      </div>

      {/* Search box */}
      <form onSubmit={e => { e.preventDefault(); run() }} className="card p-4 space-y-3">
        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 pointer-events-none" />
            <input
              autoFocus
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Lucene: process.executable_name:powershell.exe   OR   1.2.3.4   OR   message:/cmd\.exe/"
              className="input-lg pl-9 w-full font-mono text-xs"
            />
          </div>
          <button type="submit" disabled={!query.trim() || loading} className="btn-primary text-xs px-4">
            {loading ? <Loader2 size={12} className="animate-spin" /> : 'Search'}
          </button>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mt-1.5">Presets</span>
          {PRESETS.map(p => (
            <button
              key={p.label}
              type="button"
              onClick={() => run(p.q)}
              className="text-[11px] font-mono px-2 py-1 rounded border border-gray-200 text-gray-600 hover:bg-brand-accentlight hover:text-brand-text transition-colors"
            >
              {p.label}
            </button>
          ))}
        </div>
      </form>

      {error && (
        <div className="card border-red-200 bg-red-50 p-3 text-xs text-red-700">{error}</div>
      )}

      {/* Summary */}
      {result && (
        <div className="grid grid-cols-3 gap-4">
          <Stat icon={Globe}     label="Cases searched"  value={result.total_cases} />
          <Stat icon={FolderOpen} label="Matching cases"  value={result.matching_cases} />
          <Stat icon={Database}  label="Total hits"      value={totalHits.toLocaleString()} />
        </div>
      )}

      {/* Results */}
      {result?.results?.length > 0 && (
        <div className="space-y-2">
          {result.results.map(r => (
            <div key={r.case_id} className="card p-4">
              <div className="flex items-center gap-3 mb-2">
                <h3 className="text-sm font-semibold text-brand-text">{r.case_name}</h3>
                {r.company && <span className="badge badge-generic">{r.company}</span>}
                {r.status && <span className="badge badge-generic">{r.status}</span>}
                <span className="ml-auto badge bg-brand-accentlight text-brand-text font-semibold">{r.hits.toLocaleString()} hits</span>
                <button
                  onClick={() => navigate(`/cases/${r.case_id}`, { state: { pivotQuery: result.query } })}
                  className="btn-ghost text-xs gap-1"
                  title="Open case with this query"
                >
                  Open <ExternalLink size={11} />
                </button>
              </div>
              {r.samples?.length > 0 && (
                <div className="divide-y divide-gray-100 border border-gray-100 rounded-md">
                  {r.samples.map((s, i) => (
                    <div key={i} className="px-3 py-2 text-[12px] flex items-center gap-3">
                      <span className="text-gray-500 font-mono text-[10px] whitespace-nowrap">
                        {s.timestamp ? s.timestamp.slice(0, 19).replace('T', ' ') : '—'}
                      </span>
                      <span className="badge badge-generic">{s.artifact_type}</span>
                      <span className="text-gray-700 truncate flex-1" title={s.message}>
                        {s.message || '(no message)'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {result && result.results?.length === 0 && !loading && (
        <div className="card p-6 text-center text-sm text-gray-500">
          No matches across {result.total_cases} cases.
        </div>
      )}
    </div>
  )
}

function Stat({ icon: Icon, label, value }) {
  return (
    <div className="card p-5">
      <div className="flex items-center justify-between mb-3">
        <p className="text-[11px] text-gray-500 font-semibold uppercase tracking-wider">{label}</p>
        <Icon size={14} className="text-gray-400" />
      </div>
      <p className="text-[30px] font-bold tabular-nums text-brand-text leading-none tracking-tight">{value}</p>
    </div>
  )
}
