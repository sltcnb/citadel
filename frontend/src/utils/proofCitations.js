// Groups a Pilot conclusion's claims by the events (fo_ids) they cite.
// Structured fields carry fo_ids arrays; free-text evidence (hypotheses,
// pre-v2 runs) only counts ids the run actually surfaced, so words that
// merely look like ids are never fetched.
const str = v => (v == null ? '' : String(v))

function idsIn(text, seen) {
  return [...new Set(str(text).split(/[^\w-]+/).filter(t => seen.has(t)))]
}

export function proofGroups(c, seen = new Set()) {
  const groups = []
  const add = (label, ids, tone = 'claim') => {
    const clean = [...new Set((ids || []).map(str).filter(Boolean))]
    if (clean.length) groups.push({ label, ids: clean, tone })
  }
  for (const cl of c.claims || []) {
    if (cl && typeof cl === 'object') add(`[${cl.provenance || '?'}] ${str(cl.text)}`, cl.fo_ids)
  }
  for (const e of c.entities || []) {
    if (e && typeof e === 'object') add(`${e.kind || 'entity'} ${str(e.value)} — ${e.status || '?'}`, e.fo_ids, 'entity')
  }
  for (const d of c.discrepancies || []) {
    if (d && typeof d === 'object') add(`${d.field || 'field'}: alert says ${str(d.alert_value)}, evidence shows ${str(d.evidence_value)}`, d.fo_ids, 'discrepancy')
  }
  for (const h of c.hypotheses || []) {
    for (const ev of h?.for_evidence || []) add(`${h.id || 'H'} FOR: ${str(ev)}`, idsIn(ev, seen), 'for')
    for (const ev of h?.against_evidence || []) add(`${h.id || 'H'} AGAINST: ${str(ev)}`, idsIn(ev, seen), 'against')
  }
  if (!(c.claims || []).length) {
    for (const ev of c.evidence || []) add(str(ev), idsIn(ev, seen))
  }
  return groups
}

// Ids surfaced by tool results during the run (what the harness counts as "seen").
export function surfacedIds(steps) {
  const ids = new Set()
  for (const s of steps || []) {
    for (const id of s.sample_ids || []) if (id) ids.add(String(id))
    if (s.action === 'inspect' && s.fo_id) ids.add(String(s.fo_id))
  }
  return ids
}
