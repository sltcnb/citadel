import { useEffect, useMemo, useState } from 'react'
import { Cpu, Loader2, ChevronRight, ChevronDown, ExternalLink, X } from 'lucide-react'
import { api } from '../../api/client'
import PanelHelp from './PanelHelp'

/**
 * Right-side drawer version of the old Process Tree page.
 *
 *   GET /cases/{id}/process-tree?host=<hostname>
 *
 * Wider than other panels (1024px) because cmdlines are long and the tree
 * indents far at depth >5.
 */
export default function ProcessTreePanel({ caseId, onClose, onPivot }) {
  const [host, setHost]     = useState('')
  const [data, setData]     = useState(null)
  const [loading, setLoad]  = useState(true)
  const [filter, setFilter] = useState('')

  useEffect(() => {
    setLoad(true)
    api.search.processTree(caseId, host)
      .then(d => { setData(d); if (!host && d?.selected_host) setHost(d.selected_host) })
      .catch(() => setData(null))
      .finally(() => setLoad(false))
  }, [caseId, host])

  const nodesByPid = useMemo(() => {
    const map = {}
    for (const n of data?.nodes || []) map[n.pid] = n
    return map
  }, [data])

  const filterLower = filter.trim().toLowerCase()
  function nodeMatches(n) {
    if (!filterLower) return true
    return (n.name || '').toLowerCase().includes(filterLower)
        || (n.cmdline || '').toLowerCase().includes(filterLower)
        || (n.user || '').toLowerCase().includes(filterLower)
        || String(n.pid).includes(filterLower)
  }
  // Lift ancestors of any match so the path remains visible after filtering
  const visiblePids = useMemo(() => {
    if (!filterLower) return null
    const out = new Set()
    function lift(pid) {
      while (pid != null && nodesByPid[pid]) {
        out.add(pid)
        pid = nodesByPid[pid].ppid
      }
    }
    for (const n of data?.nodes || []) {
      if (nodeMatches(n)) lift(n.pid)
    }
    return out
  }, [filterLower, data, nodesByPid])

  return (
    <div className="panel-backdrop" onClick={onClose}>
      <div
        className="panel-drawer md:w-[1024px]"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-200 flex-shrink-0">
          <div className="flex items-center gap-2">
            <Cpu size={16} className="text-brand-accent" />
            <span className="font-semibold text-brand-text">Process tree</span>
          </div>
          <div className="flex items-center gap-2">
            {data?.hosts?.length > 1 && (
              <select
                value={host}
                onChange={e => setHost(e.target.value)}
                className="input h-8 text-xs"
              >
                {data.hosts.map(h => <option key={h} value={h}>{h}</option>)}
              </select>
            )}
            <button onClick={onClose} className="btn-ghost p-1.5 rounded-lg">
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          <PanelHelp title="Process tree"
            use="Reconstructs parent → child process chains from process-creation events."
            when="To trace what spawned a suspicious process, or what a process went on to launch."
            data={['Process-creation events with pid/ppid — Windows EVTX 4688, Sysmon 1, or Linux auditd']}
            tip="Pivot from a process name in the timeline, then walk its ancestry here." />
          <p className="text-[11px] text-gray-500">
            Reconstructed from Windows EVTX 4688, Sysmon (Windows + Linux), and auditd execve.
            Click any process → pivot to timeline filtered by that PID.
          </p>

          {loading && (
            <div className="card p-6 flex items-center justify-center gap-2 text-gray-500 text-sm">
              <Loader2 size={14} className="animate-spin" /> Loading process events…
            </div>
          )}

          {!loading && (!data || (data.nodes || []).length === 0) && (
            <div className="card p-6 text-center text-xs text-gray-500">
              No process-creation events found. Ingest one of:
              <div className="mt-2 space-y-0.5">
                <div>· Windows EVTX with Security <code>4688</code> (Process Creation)</div>
                <div>· Sysmon-Operational event ID <code>1</code> (Windows or Linux port)</div>
                <div>· Linux auditd logs with <code>execve</code> / <code>execveat</code> syscalls</div>
              </div>
            </div>
          )}

          {!loading && (data?.nodes || []).length > 0 && (
            <div className="card p-3 space-y-2">
              <div className="flex items-center gap-2 mb-1">
                <input
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                  placeholder="Filter by name / cmdline / user / pid"
                  className="input h-8 text-xs w-72"
                />
                <span className="text-[11px] text-gray-500 ml-auto">
                  {data.nodes.length.toLocaleString()} processes · {data.roots.length.toLocaleString()} roots
                </span>
              </div>

              <div className="font-mono text-[11px] max-h-[calc(100vh-260px)] overflow-y-auto overflow-x-auto">
                {data.roots.map(pid => (
                  <TreeNode
                    key={pid}
                    pid={pid}
                    nodesByPid={nodesByPid}
                    visiblePids={visiblePids}
                    depth={0}
                    onPivot={(p) => onPivot?.(`process.pid:${p.pid} AND host.hostname:"${data.selected_host}"`)}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function TreeNode({ pid, nodesByPid, visiblePids, depth, onPivot }) {
  const node = nodesByPid[pid]
  if (!node) return null
  const [open, setOpen] = useState(depth < 2)

  if (visiblePids && !visiblePids.has(pid)) return null
  const visibleChildren = (node.children || []).filter(c => !visiblePids || visiblePids.has(c))
  const hasChildren = visibleChildren.length > 0

  return (
    <div>
      <div
        className={`flex items-start gap-2 px-2 py-1 rounded hover:bg-brand-accentlight/40 group transition-colors ${depth > 0 ? 'border-l border-gray-100' : ''}`}
        style={{ marginLeft: `${depth * 14}px` }}
      >
        <button
          type="button"
          onClick={() => hasChildren && setOpen(v => !v)}
          className={`w-4 flex-shrink-0 ${hasChildren ? 'text-gray-500 hover:text-brand-text cursor-pointer' : 'text-transparent cursor-default'}`}
        >
          {hasChildren ? (open ? <ChevronDown size={11}/> : <ChevronRight size={11}/>) : '·'}
        </button>
        <span className="text-gray-400 w-12 text-right flex-shrink-0">{node.pid}</span>
        <span className="font-semibold text-brand-text">{node.name || '<unknown>'}</span>
        {node.source && (
          <span className={`text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wide font-medium flex-shrink-0 ${
            node.source === 'auditd'    ? 'bg-emerald-50 text-emerald-700' :
            node.source === 'sysmon'    ? 'bg-blue-50    text-blue-700' :
            node.source === 'evtx-4688' ? 'bg-indigo-50  text-indigo-700' :
                                          'bg-gray-100   text-gray-600'
          }`} title={`Event source: ${node.source}`}>
            {node.source}
          </span>
        )}
        {node.user && <span className="text-purple-600">{node.user}</span>}
        <span className="text-gray-600 truncate flex-1 min-w-0" title={node.cmdline}>{node.cmdline || node.path}</span>
        <button
          onClick={() => onPivot(node)}
          className="opacity-0 group-hover:opacity-100 text-[10px] text-brand-accent hover:text-brand-accenthover px-1.5 py-0.5 rounded transition-opacity flex-shrink-0"
          title="Open this PID in the timeline"
        >
          <ExternalLink size={10} />
        </button>
      </div>
      {open && hasChildren && (
        <div>
          {visibleChildren.map(cpid => (
            <TreeNode
              key={cpid}
              pid={cpid}
              nodesByPid={nodesByPid}
              visiblePids={visiblePids}
              depth={depth + 1}
              onPivot={onPivot}
            />
          ))}
        </div>
      )}
    </div>
  )
}
