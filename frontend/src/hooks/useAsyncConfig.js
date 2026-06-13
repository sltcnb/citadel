import { useState, useEffect, useCallback, useRef } from 'react'

/**
 * Encapsulates the load → form → save state machine repeated across Settings
 * config sections.
 *
 * @param {object}   opts
 * @param {Function} opts.load        async () => config   (fetch current config)
 * @param {Function} opts.save        async (form) => updatedConfig   (persist)
 * @param {object}   opts.initialForm starting form values
 * @param {Function} [opts.toForm]    (config) => formPatch   maps a loaded/saved
 *                                     config back onto the form. Returning a
 *                                     falsy value leaves the form untouched.
 * @param {number}   [opts.savedTimeout=3000]  ms before `saved` auto-resets
 *
 * @returns {{
 *   config, setConfig,
 *   form, setForm, setField,
 *   loading, saving, saved, error, setError,
 *   save, reload
 * }}
 */
export function useAsyncConfig({ load, save: saveFn, initialForm, toForm, savedTimeout = 3000 }) {
  const [config, setConfig]   = useState(null)
  const [form, setForm]       = useState(initialForm)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [saved, setSaved]     = useState(false)
  const [error, setError]     = useState('')

  const savedTimer = useRef(null)
  // Keep latest callbacks without forcing reload/effect churn.
  const loadRef  = useRef(load)
  const toFormRef = useRef(toForm)
  loadRef.current  = load
  toFormRef.current = toForm

  const reload = useCallback(async () => {
    setLoading(true)
    try {
      const cfg = await loadRef.current()
      setConfig(cfg)
      const patch = toFormRef.current ? toFormRef.current(cfg) : null
      if (patch) setForm(f => ({ ...f, ...patch }))
    } catch {
      // Swallow load errors (matches existing .catch(() => {}) behaviour).
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    reload()
    return () => { if (savedTimer.current) clearTimeout(savedTimer.current) }
  }, [reload])

  const setField = useCallback((k, v) => setForm(f => ({ ...f, [k]: v })), [])

  const save = useCallback(async (e) => {
    if (e && e.preventDefault) e.preventDefault()
    setSaving(true); setError(''); setSaved(false)
    try {
      const updated = await saveFn(form)
      if (updated) {
        setConfig(updated)
        const patch = toFormRef.current ? toFormRef.current(updated) : null
        if (patch) setForm(f => ({ ...f, ...patch }))
      }
      setSaved(true)
      savedTimer.current = setTimeout(() => setSaved(false), savedTimeout)
      return updated
    } catch (err) {
      setError(err.message)
      throw err
    } finally {
      setSaving(false)
    }
  }, [form, saveFn, savedTimeout])

  return { config, setConfig, form, setForm, setField, loading, saving, saved, error, setError, save, reload }
}

export default useAsyncConfig
