import { useEffect, useRef, useState } from 'react'
import { BarChart3 } from 'lucide-react'
import { api } from '../../api/client'

/**
 * Click-triggered stats popover.
 *
 *   <StatsPopover caseId={id} type={artifactType} />
 *
 * Renders a tiny chart icon button. Click → fetches top 3 hostnames / users /
 * processes for the artifact_type. Click outside or press Esc → closes.
 * Result is cached per (caseId, type) for the session.
 *
 * Previously this was a hover wrapper around the badge itself, which fired
 * randomly when the cursor brushed past. Now intentional — analyst clicks
 * the icon to ask.
 */
const _CACHE = new Map()

export default function StatsPopover({ caseId, type }) {
  const [open, setOpen]   = useState(false)
  const [data, setData]   = useState(_CACHE.get(`${caseId}|${type}`) || null)
  const [pos,  setPos]    = useState({ x: 0, y: 0, above: true })
  const btnRef  = useRef(null)
  const popRef  = useRef(null)

  async function fetchStats() {
    if (data || !caseId || !type) return
    const cacheKey = `${caseId}|${type}`
    const q = `artifact_type:${type}`
    const fetchTerms = (field) =>
      api.search.aggregate(caseId, { field, agg: 'terms', q, size: 3 }).catch(() => null)
    const [hosts, users, procs, totalRes] = await Promise.all([
      fetchTerms('host.hostname'),
      fetchTerms('user.name'),
      fetchTerms('process.name'),
      api.search.aggregate(caseId, { field: 'artifact_type', agg: 'cardinality', q, size: 1 }).catch(() => null),
    ])
    // ES "missing" bucket label is "__missing__" (server-side default). Strip
    // it out everywhere — empty-host / empty-user buckets aren't useful in the
    // top-3 list and analysts read the label as garbage.
    const stripMissing = (buckets) =>
      (buckets || []).filter(b => b.value !== '__missing__' && b.value !== '' && b.value != null)
    const payload = {
      total: totalRes?.total ?? 0,
      hosts: stripMissing(hosts?.buckets),
      users: stripMissing(users?.buckets),
      procs: stripMissing(procs?.buckets),
    }
    _CACHE.set(cacheKey, payload)
    setData(payload)
  }

  function toggle(e) {
    e.stopPropagation()
    if (!open) {
      const rect = btnRef.current?.getBoundingClientRect()
      if (rect) {
        const above = rect.top > 240   // flip below if too close to top
        setPos({
          x: rect.left,
          y: above ? rect.top : rect.bottom,
          above,
        })
      }
      setOpen(true)
      fetchStats()
    } else {
      setOpen(false)
    }
  }

  // Close on outside click / Esc
  useEffect(() => {
    if (!open) return
    const onDoc = (e) => {
      if (popRef.current?.contains(e.target)) return
      if (btnRef.current?.contains(e.target)) return
      setOpen(false)
    }
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown',   onKey)
    return () => {
      document.removeEventListener('mousedown', onDoc)
      document.removeEventListener('keydown',   onKey)
    }
  }, [open])

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={toggle}
        title="Quick stats for this artifact type"
        className={`inline-flex items-center justify-center w-5 h-5 rounded transition-colors ${
          open ? 'bg-brand-accentlight text-brand-accent'
               : 'text-gray-300 hover:text-brand-accent hover:bg-brand-accentlight/60'
        }`}
      >
        <BarChart3 size={11} />
      </button>

      {open && (
        <div
          ref={popRef}
          className="fixed z-[60] bg-white border border-gray-200 rounded-lg shadow-card-md p-3 w-64 fade-in"
          style={{
            left: Math.min(pos.x, window.innerWidth - 280),
            top:  pos.above ? Math.max(8, pos.y - 8 - 220) : pos.y + 8,
          }}
        >
          <div className="flex items-center gap-2 mb-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-gray-500">{type}</span>
            {data && <span className="ml-auto text-[10px] text-gray-400">{data.total.toLocaleString()} events</span>}
          </div>
          {!data ? (
            <div className="text-[11px] text-gray-500 italic">Loading…</div>
          ) : (
            <div className="space-y-1.5">
              <MiniRow label="Top hosts"     items={data.hosts} />
              <MiniRow label="Top users"     items={data.users} />
              <MiniRow label="Top processes" items={data.procs} />
              {(data.hosts.length === 0 && data.users.length === 0 && data.procs.length === 0) && (
                <p className="text-[11px] text-gray-500 italic">No host/user/process metadata.</p>
              )}
            </div>
          )}
        </div>
      )}
    </>
  )
}

function MiniRow({ label, items }) {
  if (!items?.length) return null
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">{label}</div>
      <div className="space-y-0.5">
        {items.slice(0, 3).map((b, i) => (
          <div key={i} className="flex items-center gap-2 text-[11px]">
            <span className="truncate flex-1 font-mono text-gray-700" title={String(b.value)}>{String(b.value)}</span>
            <span className="tabular-nums text-gray-500">{b.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
