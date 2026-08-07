/**
 * Findings triage API — the review-queue endpoints.
 *
 * Lives outside client.js's `api` object because that file is owned by another
 * work stream; this module reuses its token handling and mirrors its request
 * semantics (Bearer auth, 401 → re-login redirect, Error(message) on failure).
 *
 *   GET  /cases/{id}/findings/triage?status=&severity=&kind=&source=
 *   POST /cases/{id}/findings/triage   { finding_ids, status }
 */
import { getToken } from './client'

const BASE = '/api/v1'

export const TRIAGE_STATUSES = ['open', 'reviewed', 'false_positive']

async function request(method, path, body) {
  const headers = { 'Content-Type': 'application/json' }
  const token = getToken()
  if (token) headers['Authorization'] = `Bearer ${token}`

  let res
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new Error('Cannot reach the API — check that the server is running')
  }

  if (res.status === 401) {
    // Same contract as client.js: drop the session and bounce to /login.
    localStorage.removeItem('fo_token')
    window.location.href = '/login'
    return new Promise(() => {})
  }
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    const detail = err.detail
    const msg = Array.isArray(detail)
      ? detail.map(d => d.msg || JSON.stringify(d)).join('; ')
      : (typeof detail === 'string' ? detail : `HTTP ${res.status}`)
    throw new Error(msg || `HTTP ${res.status}`)
  }
  return res.json()
}

/**
 * Filtered triage listing + review-queue counts.
 * `params` may carry status / severity / kind / source; empty values dropped.
 * Returns { findings, total, size, counts: { by_status, by_status_severity,
 * by_kind, by_source } }.
 */
export function listTriage(caseId, params = {}) {
  const q = new URLSearchParams(
    Object.entries(params).filter(([, v]) => v !== '' && v != null),
  ).toString()
  return request('GET', `/cases/${caseId}/findings/triage${q ? `?${q}` : ''}`)
}

/** Bulk-set the triage status ('open' | 'reviewed' | 'false_positive'). */
export function setTriage(caseId, findingIds, status) {
  return request('POST', `/cases/${caseId}/findings/triage`, {
    finding_ids: findingIds,
    status,
  })
}
