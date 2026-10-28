import { describe, it, expect } from 'vitest'
import { proofGroups, surfacedIds } from '../proofCitations'

describe('proofGroups', () => {
  const seen = surfacedIds([
    { action: 'search', sample_ids: ['evt-aa1', 'evt-bb2'] },
    { action: 'inspect', fo_id: 'evt-cc3' },
  ])

  it('takes structured fo_ids from claims, entities and discrepancies', () => {
    const g = proofGroups({
      claims: [{ text: 'logon from X', provenance: 'collected', fo_ids: ['evt-aa1', 'evt-aa1'] }, { text: 'no ids' }],
      entities: [{ kind: 'account', value: 'svc', status: 'confirmed', fo_ids: ['evt-bb2'] }],
      discrepancies: [{ field: 'host', alert_value: 'A', evidence_value: 'B', fo_ids: ['evt-cc3'] }],
    }, seen)
    expect(g.map(x => x.ids)).toEqual([['evt-aa1'], ['evt-bb2'], ['evt-cc3']])
    expect(g[0].label).toBe('[collected] logon from X')
  })

  it('only parses ids from free text when the run surfaced them', () => {
    const g = proofGroups({
      hypotheses: [{ id: 'H1', for_evidence: ['4624 at 08:04 (evt-aa1) and not-an-id'], against_evidence: ['legit-123'] }],
    }, seen)
    expect(g).toEqual([{ label: 'H1 FOR: 4624 at 08:04 (evt-aa1) and not-an-id', ids: ['evt-aa1'], tone: 'for' }])
  })

  it('falls back to v1 evidence strings when there are no claims', () => {
    expect(proofGroups({ evidence: ['x (fo_id evt-cc3, evt-zz9)'] }, seen)[0].ids).toEqual(['evt-cc3'])
  })
})
