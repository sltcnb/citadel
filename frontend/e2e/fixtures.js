// Shared API-mocking fixture for the Citadel e2e smoke suite.
//
// A single route handler intercepts every /api/v1/** request so the app runs
// against deterministic, in-memory responses — no backend, ES, Redis or MinIO.
// Tests override individual endpoints by mutating the `state` object or by
// registering more-specific page.route() handlers *before* installApiMocks.

import { test as base, expect } from '@playwright/test'

export const DEFAULT_CASE = {
  case_id: 'case-smoke01',
  name: 'Operation Smoke',
  company: '',
  status: 'active',
  analyst: 'nbuiss',
  created_at: '2026-07-11T00:00:00Z',
  event_count: 0,
  artifact_types: [],
}

// Deterministic responses keyed by "METHOD /path" (path without the /api/v1
// prefix, without query string). Anything unmatched falls through to a
// permissive default so lazy case-view panels never crash the page.
function defaultRoutes(state) {
  return {
    'GET /auth/sso/providers': { providers: [] },
    'GET /auth/me': { username: 'nbuiss', role: 'admin' },
    'POST /auth/login': { access_token: 'tok-e2e', username: 'nbuiss', role: 'admin' },
    'POST /auth/logout': {},
    'GET /license': { valid: true, tier: 'community', features: [] },
    'GET /license/info': { valid: true, tier: 'community', features: [] },
    'GET /companies': { companies: [] },
    'GET /metrics/dashboard': {},
    'GET /admin/llm-usage': { total_calls: 0, total_tokens: 0 },
    'GET /alert-rules/library': { rules: [] },
    'GET /cases': { cases: state.cases },
    'POST /cases': state.createdCase,
    [`GET /cases/${DEFAULT_CASE.case_id}`]: DEFAULT_CASE,
  }
}

export async function installApiMocks(page, state) {
  await page.route('**/api/v1/**', async (route) => {
    const req = route.request()
    const url = new URL(req.url())
    const key = `${req.method()} ${url.pathname.replace(/^\/api\/v1/, '')}`
    const routes = defaultRoutes(state)

    if (state.overrides && key in state.overrides) {
      const o = state.overrides[key]
      return route.fulfill({
        status: o.status ?? 200,
        contentType: 'application/json',
        body: JSON.stringify(o.body ?? {}),
      })
    }
    if (key in routes) {
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(routes[key]),
      })
    }
    // Permissive fallback: empty-but-valid JSON for any other GET/POST so the
    // heavy case-view panels resolve to empty states instead of throwing.
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({}),
    })
  })
}

// Test fixture that pre-installs the mocks and exposes a mutable `state`.
export const test = base.extend({
  apiState: async ({ page }, use) => {
    const state = {
      cases: [],
      createdCase: { ...DEFAULT_CASE },
      overrides: {},
    }
    await installApiMocks(page, state)
    await use(state)
  },
})

export { expect }
