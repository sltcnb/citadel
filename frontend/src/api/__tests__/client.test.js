import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { api } from '../client.js'

// Helper to build a fake fetch Response-like object
function fakeResponse({ status = 200, ok, json, text } = {}) {
  return {
    status,
    ok: ok !== undefined ? ok : status >= 200 && status < 300,
    statusText: `Status ${status}`,
    json: json ?? (async () => ({})),
  }
}

describe('api client request()', () => {
  let originalLocation

  beforeEach(() => {
    // Fresh fetch mock per test
    global.fetch = vi.fn()
    localStorage.clear()

    // Make window.location.href assignable & observable
    originalLocation = window.location
    delete window.location
    window.location = { href: '' }
  })

  afterEach(() => {
    window.location = originalLocation
    vi.restoreAllMocks()
  })

  it('flattens a Pydantic-array detail into a single message and throws', async () => {
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 422,
      ok: false,
      json: async () => ({
        detail: [
          { msg: 'field required', loc: ['body', 'name'] },
          { msg: 'value is not a valid integer', loc: ['body', 'age'] },
        ],
      }),
    }))

    await expect(api.cases.list()).rejects.toThrow(
      'field required; value is not a valid integer'
    )
  })

  it('throws with a string detail when detail is a plain string', async () => {
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 400,
      ok: false,
      json: async () => ({ detail: 'Bad request, something went wrong' }),
    }))

    await expect(api.cases.list()).rejects.toThrow(
      'Bad request, something went wrong'
    )
  })

  it('returns null on 204 No Content', async () => {
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 204,
      ok: true,
      // json() should never be called for 204; make it throw if it is
      json: async () => { throw new Error('json() should not be called on 204') },
    }))

    const result = await api.cases.delete('case-123')
    expect(result).toBeNull()
  })

  it('returns parsed JSON on a successful 200', async () => {
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 200,
      ok: true,
      json: async () => ([{ id: '1', name: 'Case One' }]),
    }))

    const result = await api.cases.list()
    expect(result).toEqual([{ id: '1', name: 'Case One' }])
  })

  it('on 401 clears the token and redirects to /login (never resolves)', async () => {
    localStorage.setItem('fo_token', 'stale-token')
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 401,
      ok: false,
      json: async () => ({ detail: 'Not authenticated' }),
    }))

    // request() returns a never-resolving promise on 401, so we race it.
    const pending = api.cases.list()
    const settled = await Promise.race([
      pending.then(() => 'resolved', () => 'rejected'),
      new Promise(r => setTimeout(() => r('pending'), 30)),
    ])

    expect(settled).toBe('pending')                       // never resolves/rejects
    expect(localStorage.getItem('fo_token')).toBeNull()   // token cleared
    expect(window.location.href).toBe('/login')           // redirected
  })

  it('attaches the Bearer token when one is stored', async () => {
    localStorage.setItem('fo_token', 'my-jwt')
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 200, ok: true, json: async () => ({}),
    }))

    await api.cases.list()

    const [, opts] = global.fetch.mock.calls[0]
    expect(opts.headers['Authorization']).toBe('Bearer my-jwt')
  })

  it('watchlist.autoRun GETs the case auto-run endpoint', async () => {
    const payload = { ran_at: '2026-08-01T00:00:00Z', checked: 3, hits: [{ id: 'w1', hits: 7 }] }
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 200, ok: true, json: async () => payload,
    }))

    const result = await api.watchlist.autoRun('case-1')

    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/cases/case-1/watchlist/auto-run')
    expect(opts.method).toBe('GET')
    expect(result).toEqual(payload)
  })
})

describe('api client — newly wired bindings', () => {
  beforeEach(() => {
    global.fetch = vi.fn()
    localStorage.clear()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  function mockOk(payload = {}) {
    global.fetch.mockResolvedValueOnce(fakeResponse({
      status: 200, ok: true, json: async () => payload,
    }))
  }

  it('audit.log GETs /audit/log with query params', async () => {
    mockOk({ items: [], count: 0, limit: 50, offset: 0 })
    await api.audit.log({ limit: 50, actor: 'alice' })
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/audit/log?limit=50&actor=alice')
    expect(opts.method).toBe('GET')
  })

  it('audit.verify GETs /audit/verify with a limit', async () => {
    mockOk({ ok: true, broken_at: null, checked: 42 })
    const result = await api.audit.verify(500)
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/audit/verify?limit=500')
    expect(opts.method).toBe('GET')
    expect(result).toEqual({ ok: true, broken_at: null, checked: 42 })
  })

  it('deadLetter.list GETs /admin/dead-letter', async () => {
    mockOk({ count: 0, total: 0, entries: [] })
    await api.deadLetter.list(100)
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/admin/dead-letter?limit=100')
    expect(opts.method).toBe('GET')
  })

  it('deadLetter.replay POSTs to the entry replay endpoint', async () => {
    mockOk({ status: 'requeued', task: 'ingest', task_id: 't1', job_id: 'j1', queue: 'q' })
    const result = await api.deadLetter.replay(3)
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/admin/dead-letter/3/replay')
    expect(opts.method).toBe('POST')
    expect(result.status).toBe('requeued')
  })

  it('deadLetter.replayAll POSTs to replay-all', async () => {
    mockOk({ replayed: 2, skipped_already_processed: 1, results: [] })
    await api.deadLetter.replayAll()
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/admin/dead-letter/replay-all')
    expect(opts.method).toBe('POST')
  })

  it('sigmaSync.status GETs /sigma/status', async () => {
    mockOk({ last_sync: null, sigma_rules_count: 12, sigma_available: true })
    await api.sigmaSync.status()
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/sigma/status')
    expect(opts.method).toBe('GET')
  })

  it('sigmaSync.sync POSTs level filters to /sigma/sync', async () => {
    mockOk({ imported: 5, skipped: 2, errors: 0, total_rules: 7 })
    await api.sigmaSync.sync({ levels: ['high', 'critical'] })
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/sigma/sync')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ levels: ['high', 'critical'] })
  })

  it('sigmaSync.clear DELETEs /sigma/clear', async () => {
    mockOk({ cleared: 9 })
    const result = await api.sigmaSync.clear()
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/sigma/clear')
    expect(opts.method).toBe('DELETE')
    expect(result.cleared).toBe(9)
  })

  it('sigmaSync.setSettings PUTs the enabled flag', async () => {
    mockOk({ sigma_enabled: false })
    await api.sigmaSync.setSettings(false)
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/sigma/settings')
    expect(opts.method).toBe('PUT')
    expect(JSON.parse(opts.body)).toEqual({ enabled: false })
  })

  it('export.chainOfCustody GETs the case chain-of-custody endpoint', async () => {
    mockOk({ document_type: 'chain_of_custody', artifact_count: 0, artifacts: [] })
    await api.export.chainOfCustody('case-9')
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/cases/case-9/chain-of-custody')
    expect(opts.method).toBe('GET')
  })

  it('export.archiveUrl builds a download URL with the token as a query param', () => {
    localStorage.setItem('fo_token', 'tok 123')
    expect(api.export.archiveUrl('case-9')).toBe(
      '/api/v1/cases/case-9/export/archive?_token=tok%20123'
    )
  })

  it('export.archiveUrl omits the token when logged out', () => {
    expect(api.export.archiveUrl('case-9')).toBe('/api/v1/cases/case-9/export/archive')
  })

  it('studio.queryTest POSTs case_id + query', async () => {
    mockOk({ hits: [] })
    await api.studio.queryTest('case-1', 'process.name:cmd.exe')
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/studio/query-test')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ case_id: 'case-1', query: 'process.name:cmd.exe' })
  })

  it('studio.yaraTest POSTs case_id + job_id + rules', async () => {
    mockOk({ matches: [], scanned_bytes: 128 })
    await api.studio.yaraTest('case-1', 'job-7', 'rule r { condition: true }')
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/studio/yara-test')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({
      case_id: 'case-1', job_id: 'job-7', rules: 'rule r { condition: true }',
    })
  })

  it('findings.remove DELETEs with a finding_ids body', async () => {
    mockOk({ deleted: 1 })
    await api.findings.remove('case-1', { findingIds: ['f1'] })
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/cases/case-1/findings')
    expect(opts.method).toBe('DELETE')
    expect(JSON.parse(opts.body)).toEqual({ finding_ids: ['f1'], kind: null })
  })

  it('findings.promote POSTs a subset re-ingest', async () => {
    mockOk({ job_id: 'j1', filename: 'findings-selection-abc.jsonl', count: 1, status: 'PENDING' })
    await api.findings.promote('case-1', { findingIds: ['f1'] })
    const [url, opts] = global.fetch.mock.calls[0]
    expect(url).toBe('/api/v1/cases/case-1/findings/promote')
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body)).toEqual({ finding_ids: ['f1'], kind: null, filename: null })
  })
})
