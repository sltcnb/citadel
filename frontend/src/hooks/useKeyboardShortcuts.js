import { useEffect, useRef } from 'react'

/**
 * Register keyboard shortcuts.
 * @param {Array<{key: string, handler: function, description?: string, skipInputs?: boolean}>} shortcuts
 *
 * key formats:
 *   'escape'      - single key (case-insensitive)
 *   'cmd+k'       - Cmd/Ctrl modifier combo
 *   'shift+/'     - Shift modifier combo
 *   'g d'         - sequential: press G then D within 1 second
 *
 * skipInputs defaults to true (shortcut ignored when focus is in input/textarea/select)
 */
export function useKeyboardShortcuts(shortcuts) {
  const pendingRef = useRef(null)  // for sequential shortcuts
  const timerRef = useRef(null)

  useEffect(() => {
    if (!shortcuts?.length) return

    function handler(e) {
      const inInput = e.target.tagName === 'INPUT' ||
                      e.target.tagName === 'TEXTAREA' ||
                      e.target.tagName === 'SELECT' ||
                      e.target.isContentEditable

      const mod = e.metaKey || e.ctrlKey
      const shift = e.shiftKey
      const key = e.key.toLowerCase()

      for (const sc of shortcuts) {
        const skipInputs = sc.skipInputs !== false
        if (skipInputs && inInput) continue

        const parts = sc.key.toLowerCase().split(' ')

        if (parts.length === 2) {
          // Sequential shortcut like 'g d'
          if (key === parts[0] && !mod) {
            if (!pendingRef.current) {
              pendingRef.current = parts[0]
              clearTimeout(timerRef.current)
              timerRef.current = setTimeout(() => { pendingRef.current = null }, 1000)
            }
            e.preventDefault()
          } else if (pendingRef.current === parts[0] && key === parts[1] && !mod) {
            pendingRef.current = null
            clearTimeout(timerRef.current)
            e.preventDefault()
            sc.handler(e)
          }
          continue
        }

        // Single/modifier shortcut
        const wantsCmd = parts[0].includes('cmd+') || parts[0].includes('ctrl+')
        const wantsShift = parts[0].includes('shift+')
        const bare = parts[0].replace('cmd+', '').replace('ctrl+', '').replace('shift+', '')

        if (
          key === bare &&
          mod === wantsCmd &&
          shift === wantsShift
        ) {
          e.preventDefault()
          sc.handler(e)
          break
        }
      }
    }

    window.addEventListener('keydown', handler)
    return () => {
      window.removeEventListener('keydown', handler)
      clearTimeout(timerRef.current)
    }
  }, [shortcuts])
}
