import { useState, useEffect } from 'react'
import { UserCircle, KeyRound, Check, AlertCircle, Loader2, Shield } from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'

/*
 * Personal account settings for the signed-in user — profile + own-password
 * change. Platform/admin configuration lives under Admin → Platform Settings.
 */
export default function Account() {
  const [me, setMe] = useState(null)
  const [pw, setPw] = useState({ old_password: '', new_password: '', confirm: '' })
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState(null)

  useEffect(() => {
    api.auth.me().then(setMe).catch(() => {
      try { setMe(JSON.parse(localStorage.getItem('fo_user') || 'null')) } catch { /* ignore */ }
    })
  }, [])

  async function changePw(e) {
    e.preventDefault()
    setMsg(null)
    if (pw.new_password !== pw.confirm) {
      setMsg({ ok: false, text: 'New password and confirmation do not match.' })
      return
    }
    if (pw.new_password.length < 8) {
      setMsg({ ok: false, text: 'New password must be at least 8 characters.' })
      return
    }
    setSaving(true)
    try {
      await api.auth.changePassword({ old_password: pw.old_password, new_password: pw.new_password })
      setPw({ old_password: '', new_password: '', confirm: '' })
      setMsg({ ok: true, text: 'Password changed.' })
    } catch (err) {
      setMsg({ ok: false, text: err.message })
    } finally {
      setSaving(false)
    }
  }

  const field = (k, v) => setPw(p => ({ ...p, [k]: v }))

  return (
    <PageShell>
      <PageHeader title="Account" icon={UserCircle} subtitle="Your profile and password" />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 max-w-3xl">
        {/* Profile */}
        <section className="card p-5 space-y-3">
          <div className="flex items-center gap-2">
            <UserCircle size={15} className="text-brand-accent" />
            <h2 className="font-semibold text-brand-text">Profile</h2>
          </div>
          <Row label="Username" value={me?.username} />
          <Row label="Role" value={me?.role} icon={<Shield size={11} className="text-gray-400" />} />
          {me?.company && <Row label="Company" value={me.company} />}
          <p className="text-[11px] text-gray-400 pt-1">
            Account provisioning and roles are managed by an administrator.
          </p>
        </section>

        {/* Change password */}
        <section className="card p-5 space-y-3">
          <div className="flex items-center gap-2">
            <KeyRound size={15} className="text-brand-accent" />
            <h2 className="font-semibold text-brand-text">Change Password</h2>
          </div>
          <form onSubmit={changePw} className="space-y-3">
            <Input label="Current password" type="password" value={pw.old_password}
              onChange={v => field('old_password', v)} autoComplete="current-password" required />
            <Input label="New password" type="password" value={pw.new_password}
              onChange={v => field('new_password', v)} autoComplete="new-password" required
              help="At least 8 characters." />
            <Input label="Confirm new password" type="password" value={pw.confirm}
              onChange={v => field('confirm', v)} autoComplete="new-password" required />

            {msg && (
              <p className={`text-xs flex items-center gap-1.5 ${msg.ok ? 'text-green-600' : 'text-red-600'}`}>
                {msg.ok ? <Check size={12} /> : <AlertCircle size={12} />} {msg.text}
              </p>
            )}

            <button type="submit" disabled={saving} className="btn-primary text-xs inline-flex items-center gap-1.5">
              {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />} Update password
            </button>
          </form>
        </section>
      </div>
    </PageShell>
  )
}

function Row({ label, value, icon }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-gray-100 last:border-0">
      <span className="text-xs text-gray-500">{label}</span>
      <span className="text-sm font-medium text-brand-text inline-flex items-center gap-1 capitalize">
        {icon}{value || '—'}
      </span>
    </div>
  )
}

function Input({ label, type = 'text', value, onChange, help, ...rest }) {
  return (
    <div>
      <label className="block text-xs font-medium text-gray-600 mb-1">{label}</label>
      <input type={type} className="input text-sm w-full" value={value}
        onChange={e => onChange(e.target.value)} {...rest} />
      {help && <p className="text-[10px] text-gray-400 mt-1">{help}</p>}
    </div>
  )
}
