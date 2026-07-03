import { useEffect, useState, useMemo } from 'react'
import { Network, RefreshCw } from 'lucide-react'
import { api } from '../../api/client'
import PanelShell from './PanelShell'

/**
 * Right-side drawer: entity graph / lateral-movement view.
 *
 *   GET /cases/{id}/graph?focus=&limit=
 *   GET /cases/{id}/graph/entities?limit=
 *
 * Renders a simple, robust 3-column layered SVG layout (host | user | ip) —
 * no physics sim, no extra npm deps. Clicking a node pivots to the timeline.
 */

const TYPE_COLOR = {
  host: '#2563eb', // blue-600
  user: '#7c3aed', // violet-600
  ip:   '#d97706', // amber-600
}
const TYPE_FILL = {
  host: '#dbeafe', // blue-100
  user: '#ede9fe', // violet-100
  ip:   '#fef3c7', // amber-100
}
const COLUMN_OF = { host: 0, user: 1, ip: 2 }
const MAX_NODES = 40

export function pivotQuery(node) {
  const value = String(node.label).replace(/"/g, '\\"')
  switch (node.type) {
    case 'host': return `(host.hostname:"${value}" OR host.ip:"${value}")`
    case 'user': return `user.name:"${value}"`
    // An IP can appear under any of the normalised network fields — OR them all
    // (matches the backend's IOC match-field list) so the pivot never misses.
    case 'ip':   return `(network.src_ip:"${value}" OR network.dst_ip:"${value}" OR network.dest_ip:"${value}" OR source.ip:"${value}" OR destination.ip:"${value}" OR host.ip:"${value}")`
    default:     return ''
  }
}

export default function EntityGraphPanel({ caseId, onClose, onPivot }) {
  const [graph, setGraph]     = useState({ nodes: [], edges: [] })
  const [entities, setEnt]    = useState({ hosts: [], users: [] })
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [focus, setFocus]     = useState('')
  const [limit, setLimit]     = useState(50)
  const [hovered, setHovered] = useState(null)  // node id under the cursor

  async function refresh() {
    setLoading(true); setError(null)
    try {
      const r = await api.graph.get(caseId, { focus: focus || undefined, limit })
      setGraph({ nodes: r?.nodes || [], edges: r?.edges || [] })
    } catch (e) {
      setError(e.message || 'Failed to load entity graph.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { refresh() }, [caseId, focus, limit])

  useEffect(() => {
    let alive = true
    api.graph.entities(caseId, 50)
      .then(r => { if (alive) setEnt({ hosts: r?.hosts || [], users: r?.users || [] }) })
      .catch(() => { /* focus picker is optional — ignore */ })
    return () => { alive = false }
  }, [caseId])

  // Cap to top-N nodes by count, keep only edges whose endpoints survive.
  const { nodes, edges, capped, totalNodes } = useMemo(() => {
    const all = graph.nodes || []
    const ranked = [...all].sort((a, b) => (b.count || 0) - (a.count || 0))
    const kept = ranked.slice(0, MAX_NODES)
    const keptIds = new Set(kept.map(n => n.id))
    const e = (graph.edges || []).filter(x => keptIds.has(x.source) && keptIds.has(x.target))
    return { nodes: kept, edges: e, capped: all.length > kept.length, totalNodes: all.length }
  }, [graph])

  // Layout: 3 columns, evenly spaced vertically within a fixed-height SVG.
  const layout = useMemo(() => {
    const W = 820
    const colX = [110, W / 2, W - 110]
    const cols = { host: [], user: [], ip: [] }
    for (const n of nodes) (cols[n.type] || cols.host).push(n)

    const counts = nodes.map(n => n.count || 0)
    const maxCount = Math.max(1, ...counts)
    const rOf = (c) => 8 + Math.round(10 * Math.sqrt((c || 0) / maxCount))

    const rowH = 46
    const pos = {}
    let maxRows = 0
    for (const t of ['host', 'user', 'ip']) {
      cols[t].forEach((n, i) => {
        pos[n.id] = { x: colX[COLUMN_OF[t]], y: 50 + i * rowH, r: rOf(n.count), node: n }
      })
      maxRows = Math.max(maxRows, cols[t].length)
    }
    const H = Math.max(220, 50 + maxRows * rowH + 30)
    return { W, H, pos }
  }, [nodes])

  const counts = useMemo(() => {
    const c = { host: 0, user: 0, ip: 0 }
    for (const n of nodes) c[n.type] = (c[n.type] || 0) + 1
    return c
  }, [nodes])

  function handleNode(node) {
    const q = pivotQuery(node)
    if (q) onPivot?.(q)
  }

  const actions = (
    <>
      <select
        value={focus}
        onChange={e => setFocus(e.target.value)}
        className="input h-8 text-xs w-44"
        title="Scope the graph to a single entity's neighborhood"
      >
        <option value="">All entities</option>
        {entities.hosts.length > 0 && (
          <optgroup label="Hosts">
            {entities.hosts.map(h => (
              <option key={`h:${h.value}`} value={h.value}>{h.value} ({h.count})</option>
            ))}
          </optgroup>
        )}
        {entities.users.length > 0 && (
          <optgroup label="Users">
            {entities.users.map(u => (
              <option key={`u:${u.value}`} value={u.value}>{u.value} ({u.count})</option>
            ))}
          </optgroup>
        )}
      </select>
      <select
        value={limit}
        onChange={e => setLimit(+e.target.value || 50)}
        className="input h-8 text-xs w-20"
        title="Max relationships to fetch"
      >
        <option value={25}>25</option>
        <option value={50}>50</option>
        <option value={100}>100</option>
      </select>
      <button onClick={refresh} disabled={loading} className="btn-secondary text-xs flex items-center gap-1.5">
        <RefreshCw size={12} className={loading ? 'animate-spin' : ''} />
        Refresh
      </button>
    </>
  )

  return (
    <PanelShell
      icon={Network}
      title="Entity graph"
      onClose={onClose}
      loading={loading}
      error={error}
      empty={!loading && !error && nodes.length === 0}
      emptyText={`No host/user/IP relationships found${focus ? ` for "${focus}"` : ''}. Ingest events with host / user / ip fields, or widen the focus.`}
      actions={actions}
      help={{
        use: 'Draws host ↔ user ↔ IP relationships straight from the events so lateral movement is visible at a glance.',
        when: 'When you suspect an account or host pivoted to others and want to see the blast radius.',
        data: ['Events carrying host.hostname and user.name', 'network.dst_ip for the host/user → IP edges'],
        tip: "Set a focus host or user to scope the graph to that entity's neighborhood.",
      }}
      width="md:w-[900px]"
    >
      <p className="text-[11px] text-gray-500">
        Host ↔ user ↔ ip relationships for spotting lateral movement. Click any node to pivot
        the timeline to that entity's events.
      </p>

      {/* Legend + stats */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="flex items-center gap-3 text-[11px]">
          <Legend color={TYPE_COLOR.host} label="host" />
          <Legend color={TYPE_COLOR.user} label="user" />
          <Legend color={TYPE_COLOR.ip}   label="ip" />
        </div>
        <div className="text-[11px] text-gray-500 tabular-nums">
          {counts.host} hosts, {counts.user} users, {counts.ip} ips, {edges.length} links
          {capped && <span className="ml-1 text-amber-600">· showing top {nodes.length} of {totalNodes}</span>}
        </div>
      </div>

      <div className="card p-2 overflow-hidden">
        <svg
          viewBox={`0 0 ${layout.W} ${layout.H}`}
          width="100%"
          height={layout.H}
          preserveAspectRatio="xMidYMin meet"
          role="img"
          aria-label="Entity relationship graph"
        >
          {/* Column captions */}
          <text x={110} y={28} textAnchor="middle" className="fill-gray-400" style={{ fontSize: 10, fontWeight: 600, letterSpacing: 1 }}>HOSTS</text>
          <text x={layout.W / 2} y={28} textAnchor="middle" className="fill-gray-400" style={{ fontSize: 10, fontWeight: 600, letterSpacing: 1 }}>USERS</text>
          <text x={layout.W - 110} y={28} textAnchor="middle" className="fill-gray-400" style={{ fontSize: 10, fontWeight: 600, letterSpacing: 1 }}>IPS</text>

          {/* Hover highlight: the hovered node + its direct neighbours stay
              vivid; everything else dims — makes one entity's blast radius pop. */}
          {/* Edges */}
          {edges.map((e, i) => {
            const a = layout.pos[e.source]
            const b = layout.pos[e.target]
            if (!a || !b) return null
            const w = Math.min(4, 0.5 + Math.log2((e.count || 1) + 1))
            const touches = !hovered || e.source === hovered || e.target === hovered
            return (
              <line
                key={`e${i}`}
                x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={touches && hovered ? '#6366F1' : '#cbd5e1'}
                strokeWidth={w}
                strokeOpacity={touches ? 0.8 : 0.12}
              />
            )
          })}

          {/* Nodes */}
          {Object.values(layout.pos).map(({ x, y, r, node }) => {
            const onLeft  = COLUMN_OF[node.type] === 2 // ip column → label to the left
            const labelX  = onLeft ? x - r - 6 : x + r + 6
            const anchor  = onLeft ? 'end' : 'start'
            const near = !hovered || node.id === hovered ||
              edges.some(e => (e.source === hovered && e.target === node.id) ||
                              (e.target === hovered && e.source === node.id))
            return (
              <g
                key={node.id}
                onClick={() => handleNode(node)}
                onMouseEnter={() => setHovered(node.id)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'pointer', opacity: near ? 1 : 0.25, transition: 'opacity 120ms' }}
              >
                <title>{`${node.type}: ${node.label} (${node.count ?? 0})`}</title>
                <circle
                  cx={x} cy={y} r={r}
                  fill={TYPE_FILL[node.type] || '#f1f5f9'}
                  stroke={node.id === hovered ? '#6366F1' : (TYPE_COLOR[node.type] || '#64748b')}
                  strokeWidth={node.id === hovered ? 3 : 2}
                />
                <text
                  x={labelX} y={y + 3}
                  textAnchor={anchor}
                  fill="currentColor"
                  className="text-brand-text"
                  style={{ fontSize: 11 }}
                >
                  {node.label}
                </text>
              </g>
            )
          })}
        </svg>
        {/* Legend */}
        <div className="flex items-center gap-3 px-2 pt-1.5 text-[10px] text-gray-500">
          {[['host', 'Host'], ['user', 'User'], ['ip', 'IP']].map(([t, lbl]) => (
            <span key={t} className="inline-flex items-center gap-1">
              <span className="inline-block w-2.5 h-2.5 rounded-full"
                style={{ background: TYPE_FILL[t], border: `1.5px solid ${TYPE_COLOR[t]}` }} />
              {lbl}
            </span>
          ))}
          <span className="ml-auto italic">Hover a node to trace its links · click to pivot the timeline</span>
        </div>
      </div>
    </PanelShell>
  )
}

function Legend({ color, label }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-gray-600">
      <span className="inline-block w-3 h-3 rounded-full border-2" style={{ borderColor: color, background: `${color}22` }} />
      {label}
    </span>
  )
}
