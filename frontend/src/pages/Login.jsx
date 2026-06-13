import { useState, useRef, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Loader2, Eye, EyeOff, ShieldCheck, ArrowLeft, KeyRound, Lock } from 'lucide-react'

// Robust FastAPI error extraction (detail may be a string or a 422 array).
async function readError(res) {
  let data = {}
  try { data = await res.json() } catch {
    if (res.status >= 500) return `Server error (HTTP ${res.status})`
    return `Unexpected response (HTTP ${res.status})`
  }
  const detail = data?.detail
  if (Array.isArray(detail)) return detail.map(d => d.msg ?? JSON.stringify(d)).join('; ')
  return typeof detail === 'string' ? detail : `HTTP ${res.status}`
}

async function postJSON(path, body) {
  let res
  try {
    res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
  } catch {
    throw new Error('Cannot reach the API — check that the server is running')
  }
  if (!res.ok) throw new Error(await readError(res))
  return res.json()
}

export default function Login({ onLogin }) {
  const navigate = useNavigate()
  const location = useLocation()

  const [step, setStep]         = useState('credentials')   // 'credentials' | 'mfa' | 'change_password'
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [mfaToken, setMfaToken] = useState('')
  const [code, setCode]         = useState('')
  const [pwToken, setPwToken]   = useState('')
  const [newPass, setNewPass]   = useState('')
  const [confirmPass, setConfirmPass] = useState('')
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const codeRef = useRef(null)

  useEffect(() => { if (step === 'mfa') codeRef.current?.focus() }, [step])

  function finish(data) {
    onLogin(data.access_token, { username: data.username, role: data.role })
    const from = location.state?.from?.pathname || '/'
    navigate(from, { replace: true })
  }

  async function submitCredentials(e) {
    e.preventDefault()
    if (!username.trim() || !password) return
    setLoading(true); setError('')
    try {
      const data = await postJSON('/api/v1/auth/login', { username: username.trim(), password })
      if (data.password_change_required) {
        setPwToken(data.pw_token)
        setNewPass(''); setConfirmPass('')
        setStep('change_password')
      } else if (data.mfa_required) {
        setMfaToken(data.mfa_token)
        setCode('')
        setStep('mfa')
      } else {
        finish(data)
      }
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  async function submitChangePassword(e) {
    e.preventDefault()
    if (newPass.length < 8) { setError('Password must be at least 8 characters'); return }
    if (newPass !== confirmPass) { setError('Passwords do not match'); return }
    setLoading(true); setError('')
    try {
      const data = await postJSON('/api/v1/auth/login/change-password', {
        pw_token: pwToken, new_password: newPass,
      })
      finish(data)
    } catch (err) {
      setError(err.message || 'Could not set new password')
    } finally {
      setLoading(false)
    }
  }

  async function submitMfa(e) {
    e.preventDefault()
    if (!code.trim()) return
    setLoading(true); setError('')
    try {
      const data = await postJSON('/api/v1/auth/login/totp', { mfa_token: mfaToken, code: code.trim() })
      finish(data)
    } catch (err) {
      setError(err.message || 'Verification failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen grid lg:grid-cols-2 bg-white">
      {/* ── Brand panel (hidden on small screens) ──────────────────────────── */}
      <div className="hidden lg:flex relative flex-col justify-between overflow-hidden bg-gray-950 text-white p-12">
        <div className="absolute inset-0 opacity-[0.35] bg-[radial-gradient(60rem_40rem_at_top_left,theme(colors.brand-accent/40),transparent)]" />
        <div className="absolute inset-0 opacity-20 bg-[radial-gradient(40rem_30rem_at_bottom_right,theme(colors.indigo.500/40),transparent)]" />
        <div className="relative flex items-center gap-3">
          <img src="/favicon.svg" alt="" className="w-10 h-10 rounded-xl shadow-lg" />
          <span className="text-lg font-semibold tracking-tight">Citadel</span>
        </div>
        <div className="relative space-y-6 max-w-md">
          <h1 className="text-3xl font-semibold leading-tight tracking-tight">
            Digital forensics &amp; incident response, end&nbsp;to&nbsp;end.
          </h1>
          <p className="text-sm text-gray-300 leading-relaxed">
            Collect, parse, correlate and report — one decoupled suite. Sign in to
            pick up your investigations.
          </p>
          <ul className="space-y-2.5 text-sm text-gray-300">
            {['Tool-agnostic ingestion & timelines',
              'Detection rules, YARA & threat intel',
              'AI-assisted risk analysis'].map(t => (
              <li key={t} className="flex items-center gap-2.5">
                <ShieldCheck size={15} className="text-brand-accent shrink-0" /> {t}
              </li>
            ))}
          </ul>
        </div>
        <p className="relative text-[11px] text-gray-500">© Citadel — authorized use only.</p>
      </div>

      {/* ── Form panel ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          {/* mobile brand */}
          <div className="lg:hidden flex flex-col items-center mb-8">
            <img src="/favicon.svg" alt="Citadel" className="w-14 h-14 mb-3 rounded-2xl shadow-card-md" />
            <img src="/logo.svg" alt="Citadel" className="h-8 object-contain" />
          </div>

          {step === 'credentials' ? (
            <>
              <div className="mb-6">
                <h2 className="text-xl font-semibold text-brand-text tracking-tight">Sign in</h2>
                <p className="text-sm text-gray-500 mt-1">Welcome back. Enter your credentials.</p>
              </div>

              <form onSubmit={submitCredentials} className="space-y-4">
                {error && <ErrorBox msg={error} />}

                <Field label="Username">
                  <input
                    type="text" value={username} onChange={e => setUsername(e.target.value)}
                    autoFocus autoComplete="username" placeholder="Enter your username"
                    className="input w-full" disabled={loading}
                  />
                </Field>

                <Field label="Password">
                  <div className="relative">
                    <input
                      type={showPass ? 'text' : 'password'} value={password}
                      onChange={e => setPassword(e.target.value)} autoComplete="current-password"
                      placeholder="Enter your password" className="input w-full pr-10" disabled={loading}
                    />
                    <button type="button" onClick={() => setShowPass(v => !v)} tabIndex={-1}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                      {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </Field>

                <button type="submit" disabled={loading || !username.trim() || !password}
                  className="btn-primary w-full justify-center py-2.5">
                  {loading ? <><Loader2 size={14} className="animate-spin" /> Signing in…</>
                           : <><Lock size={14} /> Sign in</>}
                </button>
              </form>
            </>
          ) : step === 'mfa' ? (
            <>
              <button onClick={() => { setStep('credentials'); setError(''); setCode('') }}
                className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-brand-text mb-5">
                <ArrowLeft size={13} /> Back
              </button>
              <div className="mb-6">
                <div className="w-11 h-11 rounded-xl bg-brand-accent/10 flex items-center justify-center mb-3">
                  <KeyRound size={20} className="text-brand-accent" />
                </div>
                <h2 className="text-xl font-semibold text-brand-text tracking-tight">Two-factor authentication</h2>
                <p className="text-sm text-gray-500 mt-1">
                  Enter the 6-digit code from your authenticator app, or a backup code.
                </p>
              </div>

              <form onSubmit={submitMfa} className="space-y-4">
                {error && <ErrorBox msg={error} />}
                <Field label="Authentication code">
                  <input
                    ref={codeRef} type="text" inputMode="numeric" value={code}
                    onChange={e => setCode(e.target.value)} autoComplete="one-time-code"
                    placeholder="123456"
                    className="input w-full text-center text-lg tracking-[0.4em] font-mono"
                    disabled={loading}
                  />
                </Field>
                <button type="submit" disabled={loading || !code.trim()}
                  className="btn-primary w-full justify-center py-2.5">
                  {loading ? <><Loader2 size={14} className="animate-spin" /> Verifying…</>
                           : <><ShieldCheck size={14} /> Verify &amp; sign in</>}
                </button>
              </form>
            </>
          ) : (
            <>
              <button onClick={() => { setStep('credentials'); setError(''); setNewPass(''); setConfirmPass('') }}
                className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-brand-text mb-5">
                <ArrowLeft size={13} /> Back
              </button>
              <div className="mb-6">
                <div className="w-11 h-11 rounded-xl bg-brand-accent/10 flex items-center justify-center mb-3">
                  <KeyRound size={20} className="text-brand-accent" />
                </div>
                <h2 className="text-xl font-semibold text-brand-text tracking-tight">Set a new password</h2>
                <p className="text-sm text-gray-500 mt-1">
                  This account still uses the default password. Choose a new one to continue.
                </p>
              </div>

              <form onSubmit={submitChangePassword} className="space-y-4">
                {error && <ErrorBox msg={error} />}
                <Field label="New password">
                  <div className="relative">
                    <input
                      type={showPass ? 'text' : 'password'} value={newPass}
                      onChange={e => setNewPass(e.target.value)} autoComplete="new-password"
                      placeholder="At least 8 characters" className="input w-full pr-10"
                      autoFocus disabled={loading}
                    />
                    <button type="button" onClick={() => setShowPass(v => !v)} tabIndex={-1}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                      {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
                    </button>
                  </div>
                </Field>
                <Field label="Confirm new password">
                  <input
                    type={showPass ? 'text' : 'password'} value={confirmPass}
                    onChange={e => setConfirmPass(e.target.value)} autoComplete="new-password"
                    placeholder="Re-enter the new password" className="input w-full" disabled={loading}
                  />
                </Field>
                <button type="submit" disabled={loading || newPass.length < 8 || !confirmPass}
                  className="btn-primary w-full justify-center py-2.5">
                  {loading ? <><Loader2 size={14} className="animate-spin" /> Saving…</>
                           : <><KeyRound size={14} /> Set password &amp; sign in</>}
                </button>
              </form>
            </>
          )}

          <p className="text-center text-xs text-gray-400 mt-8">
            Account provisioning is managed by an administrator.
          </p>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }) {
  return (
    <div>
      <label className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
        {label}
      </label>
      {children}
    </div>
  )
}

function ErrorBox({ msg }) {
  return (
    <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
      {msg}
    </div>
  )
}
