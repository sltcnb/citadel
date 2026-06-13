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
})
