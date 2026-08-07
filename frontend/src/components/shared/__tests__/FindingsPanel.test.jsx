import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'

const navigateMock = vi.fn()

vi.mock('react-router', () => ({
  useNavigate: () => navigateMock,
}))

// Mock the two API layers the panel talks to.
vi.mock('../../../api/client', () => ({
  api: {
    findings: {
      remove: vi.fn(() => Promise.resolve({ deleted: 1 })),
      promote: vi.fn(() => Promise.resolve({ count: 1, filename: 'f.jsonl' })),
      csvUrl: vi.fn(() => '/api/v1/cases/c1/export/csv?q=artifact_type:finding'),
    },
  },
}))

const listTriageMock = vi.fn()
const setTriageMock = vi.fn(() => Promise.resolve({ updated: 1, status: 'reviewed' }))
vi.mock('../../../api/findingsTriage', () => ({
  listTriage: (...a) => listTriageMock(...a),
  setTriage: (...a) => setTriageMock(...a),
}))

import FindingsPanel, { evidencePivotQuery } from '../FindingsPanel.jsx'

const FINDINGS = [
  {
    finding_id: 'f1', title: 'Suspicious PowerShell', severity: 'high', kind: 'ioc',
    source_feature: 'ioc-extract', timestamp: '2026-01-02T00:00:00Z',
    evidence: ['ev1', 'ev2'],
  },
  {
    finding_id: 'f2', title: 'Rare hash', severity: 'low', kind: 'baseline',
    source_feature: 'baseline-scan', timestamp: '2026-01-01T00:00:00Z',
    triage_status: 'reviewed', evidence: [],
  },
]

const RESPONSE = {
  findings: FINDINGS,
  total: 2,
  size: 500,
  counts: {
    by_status: { open: 5, reviewed: 2, false_positive: 1 },
    by_status_severity: { open: { high: 3, medium: 2 }, reviewed: {}, false_positive: {} },
    by_kind: { ioc: 4, baseline: 4 },
    by_source: { 'ioc-extract': 4, 'baseline-scan': 4 },
  },
}

function renderPanel() {
  listTriageMock.mockResolvedValue(structuredClone(RESPONSE))
  return render(<FindingsPanel caseId="c1" onClose={vi.fn()} />)
}

beforeEach(() => {
  vi.clearAllMocks()
  localStorage.clear()
})

describe('FindingsPanel triage hub', () => {
  it('loads the triage queue and renders header counts', async () => {
    renderPanel()
    expect(await screen.findByText('Suspicious PowerShell')).toBeInTheDocument()
    expect(screen.getByText('Open · 5')).toBeInTheDocument()
    expect(screen.getByText('Reviewed · 2')).toBeInTheDocument()
    expect(screen.getByText('False positive · 1')).toBeInTheDocument()
    // Severity breakdown of the open bucket.
    expect(screen.getByText('high · 3')).toBeInTheDocument()
    // Findings without a stored status count as open → per-finding buttons.
    expect(screen.getByTitle('Mark reviewed')).toBeInTheDocument()
    // Reviewed finding offers Reopen instead.
    expect(screen.getByTitle('Send back to the open queue')).toBeInTheDocument()
  })

  it('passes the status filter to the API when a tab is clicked', async () => {
    renderPanel()
    fireEvent.click(await screen.findByText('False positive · 1'))
    await waitFor(() =>
      expect(listTriageMock).toHaveBeenLastCalledWith('c1', expect.objectContaining({ status: 'false_positive' })),
    )
  })

  it('bulk-marks the selection reviewed', async () => {
    renderPanel()
    fireEvent.click(await screen.findByLabelText('Select finding Suspicious PowerShell'))
    fireEvent.click(screen.getByLabelText('Select finding Rare hash'))
    fireEvent.click(screen.getByRole('button', { name: /mark reviewed/i }))
    await waitFor(() =>
      expect(setTriageMock).toHaveBeenCalledWith('c1', expect.arrayContaining(['f1', 'f2']), 'reviewed'),
    )
  })

  it('per-finding false positive button sets only that finding', async () => {
    renderPanel()
    fireEvent.click(await screen.findByTitle('Mark false positive'))
    await waitFor(() =>
      expect(setTriageMock).toHaveBeenCalledWith('c1', ['f1'], 'false_positive'),
    )
  })

  it('pivots to the timeline with the evidence fo_id query', async () => {
    const onClose = vi.fn()
    listTriageMock.mockResolvedValue(structuredClone(RESPONSE))
    render(<FindingsPanel caseId="c1" onClose={onClose} />)
    fireEvent.click(await screen.findByTitle(/pivot the timeline/i))
    expect(onClose).toHaveBeenCalled()
    expect(navigateMock).toHaveBeenCalledWith('/cases/c1', {
      state: { pivotQuery: '(fo_id:"ev1" OR fo_id:"ev2")' },
    })
  })
})

describe('evidencePivotQuery', () => {
  it('builds a single fo_id query', () => {
    expect(evidencePivotQuery({ evidence: ['abc'] })).toBe('fo_id:"abc"')
  })
  it('ORs multiple evidence ids', () => {
    expect(evidencePivotQuery({ evidence: ['a', 'b'] })).toBe('(fo_id:"a" OR fo_id:"b")')
  })
  it('escapes embedded quotes', () => {
    expect(evidencePivotQuery({ evidence: ['a"b'] })).toBe('fo_id:"a\\"b"')
  })
  it('returns empty without evidence', () => {
    expect(evidencePivotQuery({ evidence: [] })).toBe('')
    expect(evidencePivotQuery({})).toBe('')
  })
})
