import { useState } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { Loader2, Eye, EyeOff } from 'lucide-react'

export default function Login({ onLogin }) {
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername]     = useState('')
  const [password, setPassword]     = useState('')
  const [showPass, setShowPass]     = useState(false)
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState('')

  async function handleSubmit(e) {
    e.preventDefault()
    if (!username.trim() || !password) return
    setLoading(true)
    setError('')
    try {
      // Network-level failure (DNS, refused connection, offline…)
      let res
      try {
        res = await fetch('/api/v1/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: username.trim(), password }),
        })
      } catch {
        throw new Error('Cannot reach the API — check that the server is running')
      }

      // The API should always return JSON; if not, show the HTTP status so the
      // user (or admin) knows where to look.
      let data = {}
      try {
        data = await res.json()
      } catch {
        if (res.status >= 500) {
          throw new Error(`Server error (HTTP ${res.status}) — check the API logs: python3 deploy.py --logs api`)
        }
        throw new Error(`Unexpected response (HTTP ${res.status})`)
      }

      if (!res.ok) {
        // FastAPI detail can be a plain string (HTTPException) or an array of
        // objects (Pydantic v2 validation errors — 422).
        const detail = data?.detail
        const msg = Array.isArray(detail)
          ? detail.map(d => d.msg ?? JSON.stringify(d)).join('; ')
          : (typeof detail === 'string' ? detail : `HTTP ${res.status}`)
        throw new Error(msg)
      }

      onLogin(data.access_token, { username: data.username, role: data.role })
      const from = location.state?.from?.pathname || '/'
      navigate(from, { replace: true })
    } catch (err) {
      setError(err.message || 'Login failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <div className="w-full max-w-sm">

        {/* Logo / brand */}
        <div className="flex flex-col items-center mb-8">
          <img src="/favicon.svg" alt="Citadel" className="w-16 h-16 mb-4 shadow-card-md rounded-2xl select-none" />
          <img src="/logo.svg" alt="Citadel" className="h-9 object-contain" />
          <p className="text-sm text-gray-500 mt-1">Sign in to your account</p>
        </div>

        {/* Card */}
        <form onSubmit={handleSubmit} className="card p-6 space-y-4">

          {error && (
            <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <div>
            <label className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
              Username
            </label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              autoFocus
              autoComplete="username"
              placeholder="Enter username"
              className="input w-full"
              disabled={loading}
            />
          </div>

          <div>
            <label className="text-[11px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5 block">
              Password
            </label>
            <div className="relative">
              <input
                type={showPass ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="Enter password"
                className="input w-full pr-10"
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPass(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
                tabIndex={-1}
              >
                {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading || !username.trim() || !password}
            className="btn-primary w-full justify-center py-2.5"
          >
            {loading
              ? <><Loader2 size={14} className="animate-spin" /> Signing in…</>
              : 'Sign in'}
          </button>
        </form>

        <p className="text-center text-xs text-gray-500 mt-5">
          Account provisioning is managed by an administrator.
        </p>
      </div>
    </div>
  )
}
