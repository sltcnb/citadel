import { useEffect, useRef, useState } from 'react'
import { getToken } from '../api/client'

/**
 * Subscribes to /cases/{caseId}/collab/stream (SSE). Returns:
 *   { events, presence, publish }
 * - events: rolling buffer (last 50)
 * - presence: { username -> { lastSeen, ts } } — last 60s active users
 * - publish: function (type, payload) to broadcast
 *
 * Auto-sends a 'presence' ping every 15s so other clients see you.
 */
export function useCollab(caseId, currentUser) {
  const [events,   setEvents]   = useState([])
  const [presence, setPresence] = useState({})
  const esRef = useRef(null)

  // Publish helper — fetch POST with bearer token
  async function publish(type, payload = {}) {
    if (!caseId) return
    try {
      const token = getToken()
      await fetch(`/api/v1/cases/${caseId}/collab/event`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json',
                   ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body:    JSON.stringify({ type, payload }),
      })
    } catch { /* silent */ }
  }

  useEffect(() => {
    if (!caseId) return
    const token = getToken()
    // EventSource doesn't accept headers — pass token as query param; api router
    // accepts both (Authorization header OR ?_token=)
    const url = `/api/v1/cases/${caseId}/collab/stream${token ? `?_token=${encodeURIComponent(token)}` : ''}`
    const es = new EventSource(url)
    esRef.current = es

    es.onmessage = e => {
      try {
        const ev = JSON.parse(e.data)
        setEvents(prev => [...prev.slice(-49), ev])
        if (ev.user) {
          setPresence(prev => ({ ...prev, [ev.user]: { lastSeen: Date.now(), ts: ev.ts } }))
        }
      } catch { /* ignore malformed */ }
    }

    return () => { try { es.close() } catch {} }
  }, [caseId])

  // Heartbeat presence
  useEffect(() => {
    if (!caseId || !currentUser) return
    publish('presence', {})
    const id = setInterval(() => publish('presence', {}), 15_000)
    return () => clearInterval(id)
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId, currentUser])

  // Garbage-collect presence after 60s
  useEffect(() => {
    const id = setInterval(() => {
      setPresence(prev => {
        const now = Date.now()
        const next = {}
        for (const [u, info] of Object.entries(prev)) {
          if (now - info.lastSeen < 60_000) next[u] = info
        }
        return next
      })
    }, 5_000)
    return () => clearInterval(id)
  }, [])

  return { events, presence, publish }
}
