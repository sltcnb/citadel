import { useEffect, useRef, useState } from 'react'
import { Loader2, CheckCircle2, UploadCloud, Cpu, Sparkles } from 'lucide-react'
import { api } from '../../api/client'

/**
 * CaseActivityBar — a live strip under the case header showing what's happening
 * in the case: ingestion (uploads can be long), module runs, and AI autorun.
 * Polls GET /cases/:id/activity — fast while work is in flight, slow when idle.
 */
function Phase({ icon: Icon, label, c, title }) {
  const idle = !c || c.total === 0
  return (
    <span
      className="flex items-center gap-1 text-gray-500 whitespace-nowrap"
      title={title}
    >
      <Icon size={12} className="text-gray-400 flex-shrink-0" />
      <span className="font-medium">{label}</span>
      {idle ? (
        <span className="text-gray-300">—</span>
      ) : (
        <>
          {c.running > 0 && <span className="text-brand-accent font-semibold">{c.running}▶</span>}
          {c.pending > 0 && <span className="text-amber-500">{c.pending}⏳</span>}
          {c.completed > 0 && <span className="text-green-600">{c.completed}✓</span>}
          {c.failed > 0 && <span className="text-red-500">{c.failed}⚠</span>}
        </>
      )}
    </span>
  )
}

export default function CaseActivityBar({ caseId }) {
  const [act, setAct] = useState(null)
  const timer = useRef(null)

  useEffect(() => {
    let alive = true
    async function poll() {
      let busy = false
      try {
        const a = await api.cases.activity(caseId)
        if (!alive) return
        setAct(a)
        busy = !!a?.busy
      } catch {
        /* best-effort — keep the last snapshot, retry on the slow cadence */
      }
      if (alive) timer.current = setTimeout(poll, busy ? 3000 : 15000)
    }
    poll()
    return () => {
      alive = false
      if (timer.current) clearTimeout(timer.current)
    }
  }, [caseId])

  if (!act) return null
  const ing = act.ingestion || {}
  const mod = act.modules || {}
  const ai = act.ai || {}
  const done = (ing.completed || 0) + (mod.completed || 0)
  const total = (ing.total || 0) + (mod.total || 0)
  const pct = total ? Math.round((done * 100) / total) : (ai.active ? 100 : 0)
  const busy = !!act.busy

  // Nothing has ever happened and nothing is running — don't add a blank strip.
  if (total === 0 && !ai.active) return null

  return (
    <div className="bg-white border-b border-gray-200 px-4 sm:px-6 py-1.5 flex items-center gap-3 sm:gap-4 flex-shrink-0 text-[11px] overflow-x-auto">
      <span className="flex items-center gap-1.5 flex-shrink-0">
        {busy
          ? <Loader2 size={12} className="animate-spin text-brand-accent" />
          : <CheckCircle2 size={12} className="text-green-500" />}
        <span className="text-gray-600 font-medium">{busy ? 'Working' : 'Idle'}</span>
      </span>

      <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden w-24 sm:w-40 flex-shrink-0" title={`${done}/${total} tasks complete`}>
        <div
          className={`h-full transition-all duration-500 ${busy ? 'bg-brand-accent' : 'bg-green-500'}`}
          style={{ width: `${pct}%` }}
        />
      </div>

      <Phase
        icon={UploadCloud}
        label="Ingest"
        c={ing}
        title={`Ingestion — ${ing.running || 0} running, ${ing.pending || 0} pending, ${ing.completed || 0} done, ${ing.failed || 0} failed`}
      />
      <Phase
        icon={Cpu}
        label="Modules"
        c={mod}
        title={`Modules — ${mod.running || 0} running, ${mod.pending || 0} pending, ${mod.completed || 0} done, ${mod.failed || 0} failed`}
      />
      <span className="flex items-center gap-1 whitespace-nowrap" title="AI autorun (Pilot)">
        <Sparkles size={12} className={ai.active ? 'text-purple-500' : 'text-gray-400'} />
        <span className="font-medium text-gray-500">AI</span>
        {ai.active ? (
          <span className="text-purple-600 font-semibold flex items-center gap-1">
            <Loader2 size={10} className="animate-spin" />
            {ai.max_steps ? `${ai.step_count || 0}/${ai.max_steps}` : 'running'}
          </span>
        ) : (
          <span className="text-gray-300">—</span>
        )}
      </span>
    </div>
  )
}
