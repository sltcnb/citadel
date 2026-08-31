/**
 * Browser-side error reporting.
 *
 * A React crash, a rejected promise or a 500 is visible to the user and
 * invisible to us — the server log records that it returned 500, not that the
 * timeline page then rendered blank. This ships those to POST /telemetry/ui,
 * where they land in the same Elasticsearch telemetry index as the backend's
 * events and show up in GET /admin/telemetry/summary.
 *
 * Three rules, all of them about not making a bad situation worse:
 *   1. Fire and forget. Never await, never throw, never retry.
 *   2. Never report a failure of the reporting endpoint itself.
 *   3. Deduplicate. A render loop can fire the same error hundreds of times a
 *      second, and the useful information is "this happened", not "this
 *      happened 400 times".
 */

const ENDPOINT = '/api/v1/telemetry/ui'
const TOKEN_KEY = 'fo_token'

// Signatures already sent, with the time they were sent. A repeat within the
// window is dropped; after it, one more is allowed so an error that is still
// happening an hour later doesn't go silent.
const _seen = new Map()
const DEDUPE_MS = 5 * 60 * 1000
const MAX_PER_SESSION = 50
let _sent = 0

function _signature({ event, message, component, route }) {
  return [event, component, route, (message || '').slice(0, 200)].join('|')
}

function _shouldSend(sig) {
  if (_sent >= MAX_PER_SESSION) return false
  const now = Date.now()
  const last = _seen.get(sig)
  if (last && now - last < DEDUPE_MS) return false
  _seen.set(sig, now)
  return true
}

/**
 * Report one browser-side problem.
 *
 * @param {object} report
 * @param {string} report.event      short kind, e.g. 'render_crash'
 * @param {string} report.message    the error message
 * @param {string} [report.stack]    stack trace, if there is one
 * @param {string} [report.component] React component / page it came from
 * @param {string} [report.source]   what noticed it: boundary | window | api
 */
export function reportUIError({ event, message, stack = '', component = '', source = '' }) {
  try {
    const route = window.location?.pathname || ''
    const sig = _signature({ event, message, component, route })
    if (!_shouldSend(sig)) return
    _sent += 1

    const token = (() => {
      try { return localStorage.getItem(TOKEN_KEY) } catch { return null }
    })()

    fetch(ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify({
        event: String(event || 'ui_error').slice(0, 64),
        message: String(message || '').slice(0, 2000),
        stack: String(stack || '').slice(0, 8000),
        route: route.slice(0, 300),
        component: String(component || '').slice(0, 120),
        source: String(source || '').slice(0, 64),
        app_version: (typeof __APP_VERSION__ !== 'undefined' ? __APP_VERSION__ : '') || '',
      }),
      // The report must survive the navigation or reload that often follows
      // the error it describes.
      keepalive: true,
    }).catch(() => { /* rule 1: reporting never surfaces its own failure */ })
  } catch {
    /* rule 1 again — a bug in the reporter must not replace the bug it reports */
  }
}

/** True when a URL belongs to the reporter itself (rule 2). */
export function isTelemetryEndpoint(url) {
  return typeof url === 'string' && url.includes(ENDPOINT)
}

/**
 * Install the global handlers. Called once from main.jsx, outside React, so it
 * also catches errors thrown before or outside the component tree.
 */
export function installGlobalErrorReporting() {
  window.addEventListener('error', (e) => {
    // Resource load failures (an <img> 404) surface here too with no `error`
    // object; they aren't worth a telemetry document.
    if (!e?.error && !e?.message) return
    reportUIError({
      event: 'window_error',
      message: e?.error?.message || e.message || 'unknown error',
      stack: e?.error?.stack || '',
      source: 'window',
    })
  })

  window.addEventListener('unhandledrejection', (e) => {
    const reason = e?.reason
    reportUIError({
      event: 'unhandled_rejection',
      message: reason?.message || String(reason || 'unknown rejection'),
      stack: reason?.stack || '',
      source: 'window',
    })
  })
}
