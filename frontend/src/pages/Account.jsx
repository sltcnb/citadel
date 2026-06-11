import { useState, useEffect } from 'react'
import {
  UserCircle, KeyRound, Check, AlertCircle, Loader2, Shield,
  ShieldCheck, Smartphone, Copy, Lock,
} from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'

/*
 * Personal account settings for the signed-in user — profile, own-password
 * change, and two-factor authentication. Platform/admin configuration lives
 * under Admin → Platform Settings.
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
      <PageHeader title="Account" icon={UserCircle} subtitle="Your profile, password and security" />

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

      <div className="max-w-3xl mt-4">
        <MfaSection />
      </div>
    </PageShell>
  )
}

// ── Two-factor authentication ────────────────────────────────────────────────

function MfaSection() {
  const [status, setStatus] = useState(null)   // { enabled, backup_codes_remaining }
  const [phase, setPhase]   = useState('idle')  // idle | enrolling | showBackup | disabling
  const [enroll, setEnroll] = useState(null)    // { secret, otpauth_uri, qr }
  const [code, setCode]     = useState('')
  const [backup, setBackup] = useState([])
  const [disablePw, setDisablePw] = useState('')
  const [busy, setBusy]     = useState(false)
  const [err, setErr]       = useState('')

  const refresh = () => api.auth.totpStatus().then(setStatus).catch(() => setStatus({ enabled: false }))
  useEffect(() => { refresh() }, [])

  async function beginEnroll() {
    setErr(''); setBusy(true)
    try {
      const data = await api.auth.totpSetup()
      setEnroll(data); setCode(''); setPhase('enrolling')
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  async function activate(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      const res = await api.auth.totpEnable(code.trim())
      setBackup(res.backup_codes || []); setPhase('showBackup'); refresh()
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  async function disable(e) {
    e.preventDefault(); setErr(''); setBusy(true)
    try {
      await api.auth.totpDisable(disablePw)
      setDisablePw(''); setPhase('idle'); refresh()
    } catch (e) { setErr(e.message) } finally { setBusy(false) }
  }

  const enabled = status?.enabled

  return (
    <section className="card p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck size={15} className="text-brand-accent" />
          <h2 className="font-semibold text-brand-text">Two-Factor Authentication</h2>
        </div>
        {status && (
          <span className={`text-[11px] font-medium px-2 py-0.5 rounded-full ${
            enabled ? 'bg-green-50 text-green-700 border border-green-200'
                    : 'bg-gray-100 text-gray-500'}`}>
            {enabled ? 'Enabled' : 'Disabled'}
          </span>
        )}
      </div>

      {err && (
        <p className="text-xs text-red-600 flex items-center gap-1.5"><AlertCircle size={12} /> {err}</p>
      )}

      {!status && <Loader2 size={14} className="animate-spin text-gray-400" />}

      {/* Enabled, idle */}
      {status && enabled && phase !== 'disabling' && phase !== 'showBackup' && (
        <div className="space-y-3">
          <p className="text-xs text-gray-500">
            Your account is protected with an authenticator app.
            {typeof status.backup_codes_remaining === 'number' &&
              ` ${status.backup_codes_remaining} backup code(s) remaining.`}
          </p>
          <button onClick={() => { setErr(''); setPhase('disabling') }}
            className="btn-outline text-xs inline-flex items-center gap-1.5">
            <Lock size={13} /> Disable two-factor
          </button>
        </div>
      )}

      {/* Disabled, idle */}
      {status && !enabled && phase === 'idle' && (
        <div className="space-y-3">
          <p className="text-xs text-gray-500">
            Add a second step at sign-in using an authenticator app (Google Authenticator,
            1Password, Authy…). Strongly recommended.
          </p>
          <button onClick={beginEnroll} disabled={busy}
            className="btn-primary text-xs inline-flex items-center gap-1.5">
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Smartphone size={13} />} Enable two-factor
          </button>
        </div>
      )}

      {/* Enrolling — show QR + secret + confirm code */}
      {phase === 'enrolling' && enroll && (
        <form onSubmit={activate} className="space-y-3">
          <p className="text-xs text-gray-500">
            1. Scan this QR code with your authenticator app.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 items-start">
            <img src={enroll.qr} alt="TOTP QR code"
              className="w-40 h-40 rounded-lg border border-gray-200 bg-white p-1" />
            <div className="space-y-2 min-w-0">
              <p className="text-[11px] text-gray-500">Or enter this key manually:</p>
              <code className="block text-xs bg-gray-50 border border-gray-200 rounded px-2 py-1.5 break-all font-mono">
                {enroll.secret}
              </code>
              <button type="button" onClick={() => navigator.clipboard?.writeText(enroll.secret)}
                className="text-[11px] text-brand-accent inline-flex items-center gap-1 hover:underline">
                <Copy size={11} /> Copy key
              </button>
            </div>
          </div>
          <Input label="2. Enter the 6-digit code to confirm" value={code}
            onChange={setCode} inputMode="numeric" autoComplete="one-time-code"
            placeholder="123456" required />
          <div className="flex gap-2">
            <button type="submit" disabled={busy || !code.trim()}
              className="btn-primary text-xs inline-flex items-center gap-1.5">
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />} Activate
            </button>
            <button type="button" onClick={() => { setPhase('idle'); setErr('') }}
              className="btn-outline text-xs">Cancel</button>
          </div>
        </form>
      )}

      {/* Show backup codes once */}
      {phase === 'showBackup' && (
        <div className="space-y-3">
          <p className="text-xs text-green-700 flex items-center gap-1.5">
            <Check size={12} /> Two-factor is now enabled.
          </p>
          <p className="text-xs text-gray-500">
            Save these one-time backup codes somewhere safe — each works once if you lose your
            authenticator. They will not be shown again.
          </p>
          <div className="grid grid-cols-2 gap-1.5 bg-gray-50 border border-gray-200 rounded-lg p-3 font-mono text-xs">
            {backup.map(c => <span key={c}>{c}</span>)}
          </div>
          <div className="flex gap-2">
            <button onClick={() => navigator.clipboard?.writeText(backup.join('\n'))}
              className="btn-outline text-xs inline-flex items-center gap-1.5">
              <Copy size={13} /> Copy codes
            </button>
            <button onClick={() => { setBackup([]); setPhase('idle') }}
              className="btn-primary text-xs">Done</button>
          </div>
        </div>
      )}

      {/* Disabling — confirm password */}
      {phase === 'disabling' && (
        <form onSubmit={disable} className="space-y-3">
          <p className="text-xs text-gray-500">Confirm your password to disable two-factor authentication.</p>
          <Input label="Password" type="password" value={disablePw}
            onChange={setDisablePw} autoComplete="current-password" required />
          <div className="flex gap-2">
            <button type="submit" disabled={busy || !disablePw}
              className="btn-danger text-xs inline-flex items-center gap-1.5">
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Lock size={13} />} Disable
            </button>
            <button type="button" onClick={() => { setPhase('idle'); setErr(''); setDisablePw('') }}
              className="btn-outline text-xs">Cancel</button>
          </div>
        </form>
      )}
    </section>
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
