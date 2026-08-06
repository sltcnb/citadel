import { useCallback, useState } from 'react'
import ConfirmDialog from './ConfirmDialog'

/**
 * useConfirm — promise-based replacement for the native confirm(), rendered
 * through the shared ConfirmDialog (Escape / focus-trap / aria-modal included
 * via Modal).
 *
 *   const [confirmEl, askConfirm] = useConfirm()
 *   async function onDelete() {
 *     if (!await askConfirm('Delete this feed?')) return
 *     …
 *   }
 *   return (<> … {confirmEl} </>)
 *
 * opts: { title, confirmLabel, confirmClass } — see ConfirmDialog props.
 */
export function useConfirm() {
  const [req, setReq] = useState(null) // { message, title, confirmLabel, confirmClass, resolve }

  const askConfirm = useCallback((message, opts = {}) => new Promise(resolve => {
    setReq({
      message,
      title: opts.title || 'Please confirm',
      confirmLabel: opts.confirmLabel || 'Confirm',
      confirmClass: opts.confirmClass,
      resolve,
    })
  }), [])

  const settle = useCallback((answer) => {
    setReq(cur => { cur?.resolve(answer); return null })
  }, [])

  const el = req ? (
    <ConfirmDialog
      title={req.title}
      message={req.message}
      confirmLabel={req.confirmLabel}
      confirmClass={req.confirmClass || 'btn-outline'}
      onConfirm={() => settle(true)}
      onCancel={() => settle(false)}
    />
  ) : null

  return [el, askConfirm]
}
