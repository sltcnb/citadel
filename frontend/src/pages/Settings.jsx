import { useState, useEffect } from 'react'
import { useOutletContext } from 'react-router-dom'
import {
  Settings2, Sparkles, Check, X, Loader2, Trash2, Eye, EyeOff,
  AlertCircle, Wifi, FlaskConical, Cpu, Info,
  Shield, Lock, Archive, Database, Upload, Server,
  Activity, Plus, Pencil, HardDrive, ChevronDown, ChevronRight,
  KeyRound, RefreshCw, Award, Webhook, Send, SlidersHorizontal,
} from 'lucide-react'
import { api } from '../api/client'
import LicenseGate from '../components/LicenseGate'
import { useLicense } from '../contexts/LicenseContext'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { useAsyncConfig } from '../hooks/useAsyncConfig'

/* ── Constants ────────────────────────────────────────────────────────────── */

const PROVIDERS = [
  {
    id: 'openai',
    name: 'OpenAI',
    placeholder_model: 'gpt-4o',
    needs_key: true,
    default_url: '',
    hint: 'gpt-4o, gpt-4-turbo, gpt-4o-mini, gpt-3.5-turbo',
  },
  {
    id: 'anthropic',
    name: 'Anthropic',
    placeholder_model: 'claude-3-5-sonnet-20241022',
    needs_key: true,
    default_url: '',
    hint: 'claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001',
  },
  {
    id: 'ollama',
    name: 'Ollama (local)',
    placeholder_model: 'llama3',
    needs_key: false,
    default_url: 'http://localhost:11434',
    hint: 'llama3, mistral, gemma2, codellama — any model pulled in Ollama',
  },
  {
    id: 'custom',
    name: 'Custom (OpenAI-compatible)',
    placeholder_model: 'local-model',
    needs_key: true,
    key_optional: true,
    default_url: 'http://localhost:8000/v1',
    hint: 'LiteLLM, vLLM, LM Studio, LocalAI, Jan — any /chat/completions endpoint',
  },
]

const S3_VENDORS = [
  { id: 'aws',      name: 'AWS S3' },
  { id: 'scaleway', name: 'Scaleway' },
  { id: 'minio',    name: 'MinIO' },
  { id: 'wasabi',   name: 'Wasabi' },
  { id: 'gcs',      name: 'GCS' },
  { id: 'other',    name: 'Other' },
]

const SCALEWAY_REGIONS = [
  { region: 'nl-ams', endpoint: 's3.nl-ams.scw.cloud', label: 'Amsterdam (nl-ams)' },
  { region: 'fr-par', endpoint: 's3.fr-par.scw.cloud', label: 'Paris (fr-par)' },
  { region: 'pl-waw', endpoint: 's3.pl-waw.scw.cloud', label: 'Warsaw (pl-waw)' },
]

// `tool` = the suite tool(s) that own each settings group (shown as a sub-label
// so config reads tool-wise without restructuring the forms).
const TABS = [
  { id: 'ai',           label: 'AI Analysis',  icon: Sparkles,  tool: 'Pilot' },
  { id: 'talon',        label: 'Collector',    icon: Upload,    tool: 'Talon' },
  { id: 'sluice',       label: 'Import',       icon: HardDrive, tool: 'Sluice' },
  { id: 'scribe',       label: 'Archive',      icon: Archive,   tool: 'Scribe' },
  { id: 'integrations', label: 'Integrations', icon: Shield,    tool: 'Augur · sandboxes' },
  { id: 'system',       label: 'System',       icon: Server,    tool: 'Platform' },
  { id: 'license',      label: 'License',      icon: Award,     tool: 'Platform' },
]

/* ── Pilot (autonomous DFIR agent) capabilities ──────────────────────────────── */

function PilotSettingsSection() {
  const [cfg, setCfg]         = useState(null)
  const [form, setForm]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [saved, setSaved]     = useState(false)
  const [error, setError]     = useState('')
  const [showKey, setShowKey] = useState(false)

  function hydrate(c) {
    setCfg(c)
    setForm({
      disabled_tools:         c.disabled_tools || [],
      allow_module_launch:    c.allow_module_launch !== false,
      module_launch_cap:      c.module_launch_cap ?? 3,
      web_search_enabled:     !!c.web_search_enabled,
      web_search_provider:    c.web_search_provider || 'tavily',
      web_search_api_key:     '',  // never echoed; blank = keep stored
      web_search_max_results: c.web_search_max_results ?? 5,
    })
  }

  useEffect(() => {
    api.pilotConfig.getConfig()
      .then(hydrate)
      .catch(err => setError(err.message || 'Failed to load Pilot settings'))
      .finally(() => setLoading(false))
  }, [])

  function setF(k, v) { setForm(f => ({ ...f, [k]: v })); setSaved(false) }

  function toggleTool(t) {
    setForm(f => {
      const off = f.disabled_tools.includes(t)
      return { ...f, disabled_tools: off ? f.disabled_tools.filter(x => x !== t) : [...f.disabled_tools, t] }
    })
    setSaved(false)
  }

  async function save(e) {
    e?.preventDefault?.()
    setSaving(true); setSaved(false); setError('')
    try { hydrate(await api.pilotConfig.setConfig(form)); setSaved(true) }
    catch (err) { setError(err.message || 'Failed to save') }
    finally { setSaving(false) }
  }

  // Tools the admin can toggle on/off (web_search has its own block below).
  const toolList = (cfg?.known_tools || []).filter(t => t !== 'web_search')
  const providers = cfg?.web_search_providers || ['tavily', 'brave']

  return (
    <section className="card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <Sparkles size={15} className="text-fuchsia-500" />
        <h2 className="font-semibold text-brand-text">Pilot · Agent Capabilities</h2>
      </div>
      <p className="text-xs text-gray-500">
        Control what the autonomous investigation agent (Pilot) is allowed to do.
        Tools are enabled by default. Web search is the only capability that
        reaches off the appliance — it stays off until you enable it and supply a
        provider key.
      </p>

      {loading ? (
        <div className="flex items-center gap-2 text-gray-500 py-2">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : form && (
        <form onSubmit={save} className="space-y-5">
          {/* Tool enable/disable */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-gray-700">Enabled tools</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
              {toolList.map(t => {
                const enabled = !form.disabled_tools.includes(t)
                return (
                  <label key={t} className="flex items-center gap-2 text-xs cursor-pointer select-none">
                    <input type="checkbox" checked={enabled} onChange={() => toggleTool(t)} className="h-3.5 w-3.5" />
                    <span className={enabled ? 'text-gray-700' : 'text-gray-400 line-through'}>{t}</span>
                  </label>
                )
              })}
            </div>
          </div>

          {/* Module launching */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-gray-700">Module launching</h3>
            <label className="flex items-center gap-2 text-xs cursor-pointer select-none">
              <input type="checkbox" checked={form.allow_module_launch}
                onChange={e => setF('allow_module_launch', e.target.checked)} className="h-3.5 w-3.5" />
              <span className="text-gray-700">Allow the Pilot to launch modules</span>
            </label>
            {form.allow_module_launch && (
              <label className="flex items-center gap-2 text-xs text-gray-600">
                Max launches per case / 10 min
                <input type="number" min={1} max={50} value={form.module_launch_cap}
                  onChange={e => setF('module_launch_cap', parseInt(e.target.value || '1', 10))}
                  className="w-16 border border-gray-200 rounded px-2 py-1 text-xs" />
              </label>
            )}
          </div>

          {/* Web search */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-gray-700">Web search (external)</h3>
            <label className="flex items-center gap-2 text-xs cursor-pointer select-none">
              <input type="checkbox" checked={form.web_search_enabled}
                onChange={e => setF('web_search_enabled', e.target.checked)} className="h-3.5 w-3.5" />
              <span className="text-gray-700">Let the Pilot search the public web</span>
            </label>
            {form.web_search_enabled && (
              <div className="space-y-2 pl-1">
                <div className="flex items-center gap-2">
                  <label className="text-xs text-gray-600 w-20">Provider</label>
                  <select value={form.web_search_provider} onChange={e => setF('web_search_provider', e.target.value)}
                    className="text-xs border border-gray-200 rounded px-2 py-1">
                    {providers.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <label className="text-xs text-gray-600 ml-2">Max results</label>
                  <input type="number" min={1} max={20} value={form.web_search_max_results}
                    onChange={e => setF('web_search_max_results', parseInt(e.target.value || '5', 10))}
                    className="w-14 border border-gray-200 rounded px-2 py-1 text-xs" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">
                    API key {cfg?.web_search_api_key_set && <span className="text-gray-400">(set — leave blank to keep)</span>}
                  </label>
                  <div className="relative">
                    <input type={showKey ? 'text' : 'password'} value={form.web_search_api_key}
                      onChange={e => setF('web_search_api_key', e.target.value)}
                      placeholder={cfg?.web_search_api_key_set ? '••••••••' : 'provider API key'}
                      className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 pr-9" />
                    <button type="button" onClick={() => setShowKey(s => !s)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600">
                      {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          <div className="flex items-center gap-3">
            <button type="submit" disabled={saving} className="btn-primary text-xs flex items-center gap-1.5">
              {saving ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />} Save
            </button>
            {saved && <span className="text-xs text-green-600 flex items-center gap-1"><Check size={12} /> Saved</span>}
          </div>
        </form>
      )}
      {error && (
        <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertCircle size={12} /> {error}
        </p>
      )}
    </section>
  )
}

/* ── SSO / Single Sign-On (Google + Microsoft OIDC) ──────────────────────────── */

const SSO_ROLES = ['admin', 'analyst', 'developer', 'guest']

function SSOSettingsSection() {
  const [cfg, setCfg]       = useState(null)   // server view (with *_set flags)
  const [form, setForm]     = useState(null)   // editable form
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [saved, setSaved]   = useState(false)
  const [error, setError]   = useState('')
  const [showG, setShowG]   = useState(false)
  const [showM, setShowM]   = useState(false)

  function hydrate(c) {
    setCfg(c)
    setForm({
      google_client_id:        c.google_client_id || '',
      google_client_secret:    '',  // never echoed back; blank = keep
      microsoft_client_id:     c.microsoft_client_id || '',
      microsoft_client_secret: '',
      microsoft_tenant:        c.microsoft_tenant || 'common',
      redirect_base:           c.redirect_base || '',
      allowed_domains:         (c.allowed_domains || []).join(', '),
      default_role:            c.default_role || 'analyst',
      auto_provision:          c.auto_provision !== false,
    })
  }

  useEffect(() => {
    api.sso.getConfig()
      .then(hydrate)
      .catch(err => setError(err.message || 'Failed to load SSO settings'))
      .finally(() => setLoading(false))
  }, [])

  function setF(k, v) { setForm(f => ({ ...f, [k]: v })); setSaved(false) }

  async function save(e) {
    e?.preventDefault?.()
    setSaving(true); setSaved(false); setError('')
    try {
      const payload = {
        ...form,
        allowed_domains: form.allowed_domains
          .split(',').map(d => d.trim()).filter(Boolean),
      }
      const res = await api.sso.setConfig(payload)
      hydrate(res)
      setSaved(true)
      setShowG(false); setShowM(false)
    } catch (err) {
      setError(err.message || 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <KeyRound size={15} className="text-amber-500" />
        <h2 className="font-semibold text-brand-text">SSO · Single Sign-On</h2>
      </div>
      <p className="text-xs text-gray-500">
        Configure Google and Microsoft OIDC sign-in. These override the
        corresponding environment variables; leave a field blank to fall back to
        the env default. A provider's login button only appears once both its
        client ID and secret are set. Register the callback URL shown below with
        each provider.
      </p>

      {loading ? (
        <div className="flex items-center gap-2 text-gray-500 py-2">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : form && (
        <form onSubmit={save} className="space-y-4">
          {/* Google */}
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-gray-700">Google</h3>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Client ID</label>
              <input
                type="text"
                value={form.google_client_id}
                onChange={e => setF('google_client_id', e.target.value)}
                placeholder="xxxxx.apps.googleusercontent.com"
                className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Client Secret</label>
              <div className="relative">
                <input
                  type={showG ? 'text' : 'password'}
                  value={form.google_client_secret}
                  onChange={e => setF('google_client_secret', e.target.value)}
                  placeholder={cfg?.google_secret_set ? '•••• set (leave blank to keep)' : 'not set'}
                  className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 pr-9"
                />
                <button type="button" onClick={() => setShowG(s => !s)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400">
                  {showG ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>
            {cfg?.callback_base?.google && (
              <p className="text-[10px] text-gray-500">
                Authorized redirect URI: <code className="bg-gray-100 px-1 rounded">{cfg.callback_base.google}</code>
              </p>
            )}
          </div>

          {/* Microsoft */}
          <div className="space-y-2 border-t border-gray-100 pt-3">
            <h3 className="text-xs font-semibold text-gray-700">Microsoft</h3>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Client ID</label>
              <input
                type="text"
                value={form.microsoft_client_id}
                onChange={e => setF('microsoft_client_id', e.target.value)}
                placeholder="application (client) ID"
                className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Client Secret</label>
              <div className="relative">
                <input
                  type={showM ? 'text' : 'password'}
                  value={form.microsoft_client_secret}
                  onChange={e => setF('microsoft_client_secret', e.target.value)}
                  placeholder={cfg?.microsoft_secret_set ? '•••• set (leave blank to keep)' : 'not set'}
                  className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 pr-9"
                />
                <button type="button" onClick={() => setShowM(s => !s)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400">
                  {showM ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Tenant</label>
              <input
                type="text"
                value={form.microsoft_tenant}
                onChange={e => setF('microsoft_tenant', e.target.value)}
                placeholder="common | organizations | <tenant-guid>"
                className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
              />
            </div>
            {cfg?.callback_base?.microsoft && (
              <p className="text-[10px] text-gray-500">
                Authorized redirect URI: <code className="bg-gray-100 px-1 rounded">{cfg.callback_base.microsoft}</code>
              </p>
            )}
          </div>

          {/* Common policy */}
          <div className="space-y-3 border-t border-gray-100 pt-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Redirect base URL</label>
              <input
                type="text"
                value={form.redirect_base}
                onChange={e => setF('redirect_base', e.target.value)}
                placeholder="https://citadel.example.com"
                className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
              />
              <p className="text-[10px] text-gray-500 mt-1">Public base URL of Citadel; used to build the callback URIs above.</p>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Allowed email domains</label>
              <input
                type="text"
                value={form.allowed_domains}
                onChange={e => setF('allowed_domains', e.target.value)}
                placeholder="acme.com, partner.io  (blank = allow all)"
                className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
              />
            </div>
            <div className="flex gap-4">
              <div className="flex-1">
                <label className="block text-xs font-medium text-gray-600 mb-1">Default role</label>
                <select
                  value={form.default_role}
                  onChange={e => setF('default_role', e.target.value)}
                  className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white"
                >
                  {SSO_ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <label className="flex items-center gap-2 cursor-pointer select-none mt-5">
                <input
                  type="checkbox"
                  checked={!!form.auto_provision}
                  onChange={e => setF('auto_provision', e.target.checked)}
                  className="h-4 w-4"
                />
                <span className="text-sm text-gray-700">Auto-provision new users</span>
              </label>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-1">
            <button type="submit" disabled={saving}
              className="btn-primary text-sm px-4 py-2 flex items-center gap-2">
              {saving && <Loader2 size={13} className="animate-spin" />}
              Save SSO settings
            </button>
            {saved && <span className="text-xs text-green-600 flex items-center gap-1"><Check size={13} /> Saved</span>}
          </div>
        </form>
      )}

      {error && (
        <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertCircle size={12} /> {error}
        </p>
      )}
    </section>
  )
}

/* ── Platform runtime settings (admin-tunable knobs) ─────────────────────────── */

const PLATFORM_LANGUAGES = [
  { code: 'en', label: 'English' },
  { code: 'fr', label: 'Français' },
  { code: 'es', label: 'Español' },
  { code: 'de', label: 'Deutsch' },
  { code: 'it', label: 'Italiano' },
  { code: 'pt', label: 'Português' },
  { code: 'nl', label: 'Nederlands' },
  { code: 'ja', label: '日本語' },
  { code: 'zh', label: '中文' },
]

const PLATFORM_NUMERIC_FIELDS = [
  {
    key: 'jwt_expire_hours', label: 'JWT expiry (hours)', min: 1,
    help: 'How long an access token stays valid after login. Takes effect for newly issued tokens.',
  },
  {
    key: 'login_rate_limit', label: 'Login attempts per window', min: 1,
    help: 'Max failed/total login attempts allowed from one IP within the window below before a 429.',
  },
  {
    key: 'login_rate_window_seconds', label: 'Login rate window (seconds)', min: 1,
    help: 'Length of the rolling window for the login attempt limit above.',
  },
  {
    key: 'agent_max_steps', label: 'Pilot agent max steps', min: 1,
    help: 'Per-run ceiling on autonomous Pilot agent steps (bounds cost). Capped by the server hard limit (50).',
  },
  {
    key: 'max_upload_gib', label: 'Max upload size (GiB)', min: 1,
    help: 'Upload cap for standalone malware/ingest files. Enforced per request.',
  },
  {
    key: 'session_idle_minutes', label: 'Session idle timeout (minutes)', min: 0,
    help: 'Advisory idle timeout. 0 disables it.',
  },
]

function PlatformSettingsSection() {
  const [form, setForm]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving]   = useState(false)
  const [saved, setSaved]     = useState(false)
  const [error, setError]     = useState('')

  useEffect(() => {
    api.platform.getConfig()
      .then(setForm)
      .catch(err => setError(err.message || 'Failed to load platform settings'))
      .finally(() => setLoading(false))
  }, [])

  function setF(k, v) { setForm(f => ({ ...f, [k]: v })); setSaved(false) }

  async function save(e) {
    e?.preventDefault?.()
    setSaving(true); setSaved(false); setError('')
    try {
      const payload = {
        jwt_expire_hours:          Number(form.jwt_expire_hours),
        login_rate_limit:          Number(form.login_rate_limit),
        login_rate_window_seconds: Number(form.login_rate_window_seconds),
        agent_max_steps:           Number(form.agent_max_steps),
        default_report_language:   form.default_report_language,
        max_upload_gib:            Number(form.max_upload_gib),
        session_idle_minutes:      Number(form.session_idle_minutes),
      }
      const res = await api.platform.setConfig(payload)
      setForm(res)
      setSaved(true)
    } catch (err) {
      setError(err.message || 'Failed to save')
    } finally {
      setSaving(false)
    }
  }

  return (
    <section className="card p-5 space-y-4">
      <div className="flex items-center gap-2">
        <SlidersHorizontal size={15} className="text-sky-500" />
        <h2 className="font-semibold text-brand-text">Platform</h2>
      </div>
      <p className="text-xs text-gray-500">
        Runtime-configurable platform limits. These override the corresponding
        environment defaults and take effect without a restart. Each setting falls
        back to its env/const default if the store is unavailable.
      </p>

      {loading ? (
        <div className="flex items-center gap-2 text-gray-500 py-2">
          <Loader2 size={14} className="animate-spin" /> Loading…
        </div>
      ) : form && (
        <form onSubmit={save} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {PLATFORM_NUMERIC_FIELDS.map(f => (
              <div key={f.key}>
                <label className="block text-xs font-medium text-gray-600 mb-1">{f.label}</label>
                <input
                  type="number"
                  min={f.min}
                  value={form[f.key] ?? ''}
                  onChange={e => setF(f.key, e.target.value)}
                  className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2"
                />
                <p className="text-[10px] text-gray-500 mt-1">{f.help}</p>
              </div>
            ))}
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Default report language</label>
              <select
                value={form.default_report_language || 'en'}
                onChange={e => setF('default_report_language', e.target.value)}
                className="w-full text-sm border border-gray-200 rounded-lg px-3 py-2 bg-white"
              >
                {PLATFORM_LANGUAGES.map(l => (
                  <option key={l.code} value={l.code}>{l.label}</option>
                ))}
              </select>
              <p className="text-[10px] text-gray-500 mt-1">Default language for generated case reports.</p>
            </div>
          </div>

          <div className="flex items-center gap-3 pt-1">
            <button type="submit" disabled={saving}
              className="btn-primary text-sm px-4 py-2 flex items-center gap-2">
              {saving && <Loader2 size={13} className="animate-spin" />}
              Save platform settings
            </button>
            {saved && <span className="text-xs text-green-600 flex items-center gap-1"><Check size={13} /> Saved</span>}
          </div>
        </form>
      )}

      {error && (
        <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
          <AlertCircle size={12} /> {error}
        </p>
      )}
    </section>
  )
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function endpointPlaceholder(vendor) {
  if (vendor === 'aws')      return 's3.amazonaws.com'
  if (vendor === 'scaleway') return 's3.nl-ams.scw.cloud'
  if (vendor === 'wasabi')   return 's3.wasabisys.com'
  if (vendor === 'gcs')      return 'storage.googleapis.com'
  return 'minio.example.com:9000'
}

function emptyS3Form(vendor = 'aws') {
  return { vendor, endpoint: '', access_key: '', secret_key: '', bucket: '', region: '', use_ssl: true }
}

/* ── Reusable S3 form component ───────────────────────────────────────────── */

function S3Form({ form, setF, showKey, setShowKey, secretKeySet, label = 'S3 Storage' }) {
  return (
    <div className="space-y-3">
      {/* Vendor selector */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Vendor</label>
        <div className="flex flex-wrap gap-2">
          {S3_VENDORS.map(v => (
            <button
              key={v.id}
              type="button"
              onClick={() => {
                setF('vendor', v.id)
                if (v.id === 'scaleway') {
                  setF('endpoint', SCALEWAY_REGIONS[0].endpoint)
                  setF('region', SCALEWAY_REGIONS[0].region)
                } else {
                  setF('endpoint', '')
                }
              }}
              className={`text-xs py-1.5 px-3 rounded-lg border transition-colors font-medium ${
                form.vendor === v.id
                  ? 'bg-brand-accent text-white border-brand-accent'
                  : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
              }`}
            >
              {v.name}
            </button>
          ))}
        </div>
      </div>

      {/* Scaleway region buttons */}
      {form.vendor === 'scaleway' && (
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Region</label>
          <div className="flex flex-wrap gap-2">
            {SCALEWAY_REGIONS.map(r => (
              <button
                key={r.region}
                type="button"
                onClick={() => { setF('region', r.region); setF('endpoint', r.endpoint) }}
                className={`text-xs py-1.5 px-3 rounded-lg border transition-colors font-medium ${
                  form.region === r.region
                    ? 'bg-blue-600 text-white border-blue-600'
                    : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                }`}
              >
                {r.label}
              </button>
            ))}
          </div>
          <p className="text-[10px] text-gray-500 mt-1">Selecting a region auto-fills the endpoint below.</p>
        </div>
      )}

      {/* Endpoint */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Endpoint URL</label>
        <input
          className="input text-xs font-mono"
          placeholder={endpointPlaceholder(form.vendor)}
          value={form.endpoint}
          onChange={e => setF('endpoint', e.target.value)}
          required
        />
      </div>

      {/* Access key */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">Access Key</label>
        <input
          className="input text-xs font-mono"
          placeholder="AKIAIOSFODNN7EXAMPLE"
          value={form.access_key}
          onChange={e => setF('access_key', e.target.value)}
          required
        />
      </div>

      {/* Secret key */}
      <div>
        <label className="block text-xs font-medium text-gray-600 mb-1">
          Secret Key
          {secretKeySet && <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>}
        </label>
        <div className="relative">
          <input
            type={showKey ? 'text' : 'password'}
            className="input text-xs pr-8 font-mono"
            placeholder={secretKeySet ? '••••••••••••••••' : 'wJalrXUtnFEMI/K7MDENG/bPxR...'}
            value={form.secret_key}
            onChange={e => setF('secret_key', e.target.value)}
          />
          <button
            type="button"
            onClick={() => setShowKey(v => !v)}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
          >
            {showKey ? <EyeOff size={13} /> : <Eye size={13} />}
          </button>
        </div>
      </div>

      {/* Bucket + region grid */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Bucket Name</label>
          <input
            className="input text-xs font-mono"
            placeholder="my-bucket"
            value={form.bucket}
            onChange={e => setF('bucket', e.target.value)}
            required
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">
            Region{' '}
            <span className="text-gray-500 font-normal">
              {form.vendor === 'scaleway' ? '(set above)' : '(optional)'}
            </span>
          </label>
          <input
            className="input text-xs font-mono"
            placeholder={form.vendor === 'scaleway' ? 'nl-ams' : 'us-east-1'}
            value={form.region}
            onChange={e => setF('region', e.target.value)}
            readOnly={form.vendor === 'scaleway'}
          />
        </div>
      </div>

      {/* SSL */}
      <label className="flex items-center gap-2 text-xs text-gray-600 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={form.use_ssl}
          onChange={e => setF('use_ssl', e.target.checked)}
          className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
        />
        Use SSL / HTTPS
      </label>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════ */

export default function Settings() {
  const { user } = useOutletContext() || {}
  const isAdmin = user?.role === 'admin'
  const license = useLicense()
  const visibleTabs = isAdmin ? TABS : []
  const [tab, setTab] = useState('ai')

  /* ── AI state ─────────────────────────────────────────────────────────── */
  const [config, setConfig]       = useState(null)
  const [loading, setLoading]     = useState(true)
  const [saving, setSaving]       = useState(false)
  const [saved, setSaved]         = useState(false)
  const [error, setError]         = useState('')
  const [showKey, setShowKey]     = useState(false)
  const [testing, setTesting]     = useState(false)
  const [testResult, setTestResult] = useState(null)

  const [form, setForm] = useState({
    provider: 'openai',
    model: '',
    api_key: '',
    base_url: '',
    enabled: true,
  })
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  /* ── Import Sources state ─────────────────────────────────────────────── */
  const [importSources, setImportSources]     = useState([])
  const [sourcesLoading, setSourcesLoading]   = useState(true)
  const [showAddSource, setShowAddSource]     = useState(false)
  const [editingSource, setEditingSource]     = useState(null)
  const [sourceForm, setSourceForm]           = useState({ name: '', ...emptyS3Form('aws') })
  const [sourceShowKey, setSourceShowKey]     = useState(false)
  const [sourceTestResults, setSourceTestResults] = useState({}) // id -> {ok, message/error}
  const [sourceTestingId, setSourceTestingId] = useState(null)
  const [sourceSaving, setSourceSaving]       = useState(false)
  const [sourceError, setSourceError]         = useState('')
  const setSourceF = (k, v) => setSourceForm(f => ({ ...f, [k]: v }))

  /* ── Triage dropzone state ────────────────────────────────────────────── */
  const [s3TriageConfig, setS3TriageConfig]       = useState(null)
  const [s3TriageLoading, setS3TriageLoading]     = useState(true)
  const [s3TriageSaving, setS3TriageSaving]       = useState(false)
  const [s3TriageSaved, setS3TriageSaved]         = useState(false)
  const [s3TriageError, setS3TriageError]         = useState('')
  const [s3TriageShowKey, setS3TriageShowKey]     = useState(false)
  const [s3TriageTesting, setS3TriageTesting]     = useState(false)
  const [s3TriageTestResult, setS3TriageTestResult] = useState(null)
  const [s3TriageForm, setS3TriageForm]           = useState(emptyS3Form('scaleway'))
  const setS3Triage = (k, v) => setS3TriageForm(f => ({ ...f, [k]: v }))

  /* ── Archive state ────────────────────────────────────────────────────── */
  const [showArchiveKey, setShowArchiveKey]       = useState(false)
  const [archiveSecretSet, setArchiveSecretSet]   = useState(false)
  const [archiveTesting, setArchiveTesting]       = useState(false)
  const [archiveTestResult, setArchiveTestResult] = useState(null)
  const {
    form: archiveForm, setForm: setArchiveForm, setField: setArchive,
    loading: archiveLoading, saving: archiveSaving, saved: archiveSaved,
    error: archiveError, save: saveArchive,
  } = useAsyncConfig({
    load: () => api.admin.getArchiveSettings(),
    save: (form) => api.admin.updateArchiveSettings(form),
    initialForm: {
      auto_archive_enabled: false,
      auto_archive_days:    14,
      auto_export_enabled:  false,
      s3_vendor:     '',
      s3_endpoint:   '',
      s3_access_key: '',
      s3_secret_key: '',
      s3_bucket:     '',
      s3_region:     '',
      s3_use_ssl:    true,
    },
    // Runs on load and after save: keep the "secret is set" flag in sync and
    // always re-blank the secret field ("leave blank to keep" semantics).
    toForm: (cfg) => {
      setArchiveSecretSet(!!cfg.s3_secret_key_set)
      return {
        auto_archive_enabled: cfg.auto_archive_enabled ?? false,
        auto_archive_days:    cfg.auto_archive_days    ?? 14,
        auto_export_enabled:  cfg.auto_export_enabled  ?? false,
        s3_vendor:     cfg.s3_vendor     || '',
        s3_endpoint:   cfg.s3_endpoint   || '',
        s3_access_key: cfg.s3_access_key || '',
        s3_secret_key: '',
        s3_bucket:     cfg.s3_bucket     || '',
        s3_region:     cfg.s3_region     || '',
        s3_use_ssl:    cfg.s3_use_ssl    !== false,
      }
    },
  })

  /* ── Cuckoo state ─────────────────────────────────────────────────────── */
  const [showCuckooToken, setShowCuckooToken] = useState(false)
  const {
    config: cuckooConfig, setConfig: setCuckooConfig,
    form: cuckooForm, setForm: setCuckooForm, setField: setCuckoo,
    loading: cuckooLoading, saving: cuckooSaving, saved: cuckooSaved,
    error: cuckooError, setError: setCuckooError, save: saveCuckoo,
  } = useAsyncConfig({
    load: () => api.cuckooConfig.get(),
    save: (form) => api.cuckooConfig.set(form),
    initialForm: { api_url: '', api_token: '' },
    // Only restore the URL on load; keep the secret token field blank.
    toForm: (cfg) => (cfg?.api_url ? { api_url: cfg.api_url } : null),
  })

  /* ── VirusTotal state ─────────────────────────────────────────────────── */
  const [showVtKey, setShowVtKey] = useState(false)
  const {
    config: vtConfig, setConfig: setVtConfig,
    form: vtForm, setForm: setVtForm, setField: setVt,
    loading: vtLoading, saving: vtSaving, saved: vtSaved,
    error: vtError, setError: setVtError, save: saveVt,
  } = useAsyncConfig({
    load: () => api.mwoConfig.get(),
    save: (form) => api.mwoConfig.set(form),
    initialForm: { vt_api_key: '' },
  })

  /* ── Webhooks state ───────────────────────────────────────────────────── */
  const [webhooksList, setWebhooksList]   = useState([])
  const [whLoading, setWhLoading]         = useState(true)
  const [whSaving, setWhSaving]           = useState(false)
  const [whError, setWhError]             = useState('')
  const [whForm, setWhForm]               = useState({ name: '', url: '', alert_rules: true, module_completed: false })
  const [whTesting, setWhTesting]         = useState(null)
  const [whTestResult, setWhTestResult]   = useState(null)

  /* ── Report template state ────────────────────────────────────────────── */
  const RT_SECTION_LABELS = {
    exec_summary: 'Executive summary', ai_report: 'AI Autopilot', pinned: 'Pinned events',
    flagged: 'Flagged events', mitre: 'MITRE ATT&CK', detections: 'Detection rules',
    watchlist: 'Watchlist hits', notes: 'Analyst notes',
  }
  const [rtForm, setRtForm]       = useState(null)   // null until loaded
  const [rtSaving, setRtSaving]   = useState(false)
  const [rtSaved, setRtSaved]     = useState(false)
  const [rtError, setRtError]     = useState('')

  async function saveReportTemplate(e) {
    e.preventDefault()
    setRtSaving(true); setRtError(''); setRtSaved(false)
    try {
      const saved = await api.admin.setReportTemplate(rtForm)
      setRtForm(saved)
      setRtSaved(true)
      setTimeout(() => setRtSaved(false), 2500)
    } catch (err) {
      setRtError(err.message)
    } finally { setRtSaving(false) }
  }

  async function resetReportTemplate() {
    if (!confirm('Reset the report template to defaults?')) return
    try {
      const tpl = await api.admin.resetReportTemplate()
      setRtForm(tpl)
    } catch (err) { setRtError(err.message) }
  }

  /* ── System state ─────────────────────────────────────────────────────── */
  const [workerMetrics, setWorkerMetrics]   = useState(null)
  const [purging, setPurging]               = useState(false)
  const [purgeResult, setPurgeResult]       = useState(null)
  const [wipeInput, setWipeInput]           = useState('')
  const [wiping, setWiping]                 = useState(false)
  const [wipeResult, setWipeResult]         = useState(null)

  /* ── Load all data ────────────────────────────────────────────────────── */
  useEffect(() => {
    api.llm.getConfig()
      .then(cfg => {
        setConfig(cfg)
        if (cfg.provider) {
          setForm({ provider: cfg.provider, model: cfg.model || '', api_key: '', base_url: cfg.base_url || '', enabled: cfg.enabled })
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false))

    api.s3Multi.list()
      .then(list => setImportSources(list || []))
      .catch(() => {})
      .finally(() => setSourcesLoading(false))

    api.s3Triage.getConfig()
      .then(cfg => {
        setS3TriageConfig(cfg)
        if (cfg.endpoint) {
          setS3TriageForm({
            vendor:     cfg.vendor || 'scaleway',
            endpoint:   cfg.endpoint || '',
            access_key: cfg.access_key || '',
            secret_key: '',
            bucket:     cfg.bucket || '',
            region:     cfg.region || 'nl-ams',
            use_ssl:    cfg.use_ssl !== false,
          })
        }
      })
      .catch(() => {})
      .finally(() => setS3TriageLoading(false))

    api.webhooks.list()
      .then(r => setWebhooksList(r.webhooks || []))
      .catch(() => {})
      .finally(() => setWhLoading(false))

    api.admin.getReportTemplate()
      .then(tpl => setRtForm(tpl))
      .catch(() => {})

    api.metrics.dashboard()
      .then(m => setWorkerMetrics(m))
      .catch(() => {})
  }, [])

  /* ── AI handlers ──────────────────────────────────────────────────────── */
  async function saveAI(e) {
    e.preventDefault()
    setSaving(true); setError(''); setSaved(false)
    try {
      const updated = await api.llm.updateConfig({ ...form, enabled: true })
      setConfig(updated)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (err) { setError(err.message) }
    finally { setSaving(false) }
  }

  async function clearAI() {
    if (!confirm('Remove LLM configuration?')) return
    try {
      await api.llm.clearConfig()
      setConfig({ provider: '', model: '', api_key_set: false, base_url: '', enabled: false })
      setForm({ provider: 'openai', model: '', api_key: '', base_url: '', enabled: true })
    } catch (err) { setError(err.message) }
  }

  async function testAI() {
    setTesting(true); setTestResult(null)
    try {
      const res = await api.llm.testConfig()
      setTestResult({ ok: true, response: res.response })
    } catch (err) { setTestResult({ ok: false, error: err.message }) }
    finally { setTesting(false) }
  }

  /* ── Import Sources handlers ──────────────────────────────────────────── */
  function openAddSource() {
    setEditingSource(null)
    setSourceForm({ name: '', ...emptyS3Form('aws') })
    setSourceShowKey(false)
    setSourceError('')
    setShowAddSource(true)
  }

  function openEditSource(src) {
    setEditingSource(src)
    setSourceForm({
      name:       src.name       || '',
      vendor:     src.vendor     || 'aws',
      endpoint:   src.endpoint   || '',
      access_key: src.access_key || '',
      secret_key: '',
      bucket:     src.bucket     || '',
      region:     src.region     || '',
      use_ssl:    src.use_ssl    !== false,
    })
    setSourceShowKey(false)
    setSourceError('')
    setShowAddSource(true)
  }

  async function saveSource(e) {
    e.preventDefault()
    setSourceSaving(true); setSourceError('')
    try {
      if (editingSource) {
        const updated = await api.s3Multi.update(editingSource.id, sourceForm)
        setImportSources(prev => prev.map(s => s.id === editingSource.id ? updated : s))
      } else {
        const created = await api.s3Multi.add(sourceForm)
        setImportSources(prev => [...prev, created])
      }
      setShowAddSource(false)
      setEditingSource(null)
    } catch (err) { setSourceError(err.message) }
    finally { setSourceSaving(false) }
  }

  async function deleteSource(id) {
    if (!confirm('Remove this import source?')) return
    try {
      await api.s3Multi.delete(id)
      setImportSources(prev => prev.filter(s => s.id !== id))
    } catch (err) { setSourceError(err.message) }
  }

  async function testSource(id) {
    setSourceTestingId(id)
    try {
      const res = await api.s3Multi.test(id)
      setSourceTestResults(prev => ({ ...prev, [id]: { ok: true, message: res.message } }))
    } catch (err) {
      setSourceTestResults(prev => ({ ...prev, [id]: { ok: false, error: err.message } }))
    } finally { setSourceTestingId(null) }
  }

  /* ── Triage dropzone handlers ─────────────────────────────────────────── */
  async function saveS3Triage(e) {
    e.preventDefault()
    setS3TriageSaving(true); setS3TriageError(''); setS3TriageSaved(false)
    try {
      const updated = await api.s3Triage.setConfig(s3TriageForm)
      setS3TriageConfig(updated)
      setS3TriageSaved(true)
      setTimeout(() => setS3TriageSaved(false), 3000)
    } catch (err) { setS3TriageError(err.message) }
    finally { setS3TriageSaving(false) }
  }

  async function clearS3Triage() {
    if (!confirm('Remove Collector Dropzone configuration?')) return
    try {
      await api.s3Triage.clearConfig()
      setS3TriageConfig({ endpoint: '', access_key: '', secret_key_set: false, bucket: '', region: '', vendor: 'scaleway', use_ssl: true })
      setS3TriageForm(emptyS3Form('scaleway'))
      setS3TriageTestResult(null)
    } catch (err) { setS3TriageError(err.message) }
  }

  async function testS3Triage() {
    setS3TriageTesting(true); setS3TriageTestResult(null)
    try {
      const res = await api.s3Triage.testConfig()
      setS3TriageTestResult({ ok: true, message: res.message })
    } catch (err) { setS3TriageTestResult({ ok: false, error: err.message }) }
    finally { setS3TriageTesting(false) }
  }

  /* ── Archive handlers ─────────────────────────────────────────────────── */
  async function testArchive() {
    setArchiveTesting(true); setArchiveTestResult(null)
    try {
      const res = await api.export.testArchiveS3()
      setArchiveTestResult({ ok: true, message: res.message })
    } catch (err) { setArchiveTestResult({ ok: false, error: err.message }) }
    finally { setArchiveTesting(false) }
  }

  /* ── Cuckoo handlers ──────────────────────────────────────────────────── */
  async function clearCuckoo() {
    if (!confirm('Remove Cuckoo Sandbox configuration?')) return
    try {
      await api.cuckooConfig.clear()
      setCuckooConfig({ api_url: '', api_token_set: false, configured: false })
      setCuckooForm({ api_url: '', api_token: '' })
    } catch (err) { setCuckooError(err.message) }
  }

  /* ── VirusTotal handlers ──────────────────────────────────────────────── */
  async function saveWebhook(e) {
    e.preventDefault()
    setWhSaving(true); setWhError('')
    const events = [
      ...(whForm.alert_rules ? ['alert_rules'] : []),
      ...(whForm.module_completed ? ['module_completed'] : []),
    ]
    if (events.length === 0) { setWhError('Pick at least one event'); setWhSaving(false); return }
    try {
      await api.webhooks.create({ name: whForm.name, url: whForm.url, enabled: true, events })
      setWhForm({ name: '', url: '', alert_rules: true, module_completed: false })
      const r = await api.webhooks.list()
      setWebhooksList(r.webhooks || [])
    } catch (err) {
      setWhError(err.message)
    } finally { setWhSaving(false) }
  }

  async function deleteWebhook(id) {
    if (!confirm('Delete this webhook?')) return
    try {
      await api.webhooks.remove(id)
      setWebhooksList(list => list.filter(h => h.id !== id))
    } catch (err) { setWhError(err.message) }
  }

  async function testWebhook(id) {
    setWhTesting(id); setWhTestResult(null)
    try {
      const r = await api.webhooks.test(id)
      setWhTestResult({ id, ...r })
    } catch (err) {
      setWhTestResult({ id, delivered: false, error: err.message })
    } finally { setWhTesting(null) }
  }

  async function clearVt() {
    if (!confirm('Remove VirusTotal API key?')) return
    try {
      await api.mwoConfig.clear()
      setVtConfig({ vt_api_key_set: false, configured: false })
      setVtForm({ vt_api_key: '' })
    } catch (err) { setVtError(err.message) }
  }

  /* ── System handlers ──────────────────────────────────────────────────── */
  async function runPurge() {
    if (!confirm('Purge all orphaned case data? This deletes MinIO objects, ES indices, and all Redis keys (jobs, collab lists, dedup sets, alert runs, case records) for cases no longer in the database. Active cases are untouched.')) return
    setPurging(true); setPurgeResult(null)
    try {
      const res = await api.admin.purgeOrphaned()
      setPurgeResult({ ok: true, data: res })
    } catch (err) { setPurgeResult({ ok: false, error: err.message }) }
    finally { setPurging(false) }
  }

  async function runWipeAll() {
    setWiping(true); setWipeResult(null)
    try {
      const res = await api.admin.wipeAll()
      setWipeResult({ ok: true, data: res })
      setWipeInput('')
    } catch (err) { setWipeResult({ ok: false, error: err.message }) }
    finally { setWiping(false) }
  }

  const provider = PROVIDERS.find(p => p.id === form.provider) || PROVIDERS[0]

  /* ── Tab content renderers ────────────────────────────────────────────── */

  function renderAI() {
    return (
      <LicenseGate feature="ai_assist">
      <section className="card p-5 space-y-4">
        <div className="flex items-center gap-2">
          <Sparkles size={15} className="text-purple-500" />
          <h2 className="font-semibold text-brand-text">AI Analysis</h2>
          {!loading && config?.provider && (
            <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
              <Check size={10} /> Configured
            </span>
          )}
        </div>

        <p className="text-xs text-gray-500">
          Connect an LLM to enable the <strong className="text-brand-text">"Analyze with AI"</strong> button
          on module run results. The AI reads your detections and produces a structured forensic report
          (severity, timeline, IOCs, MITRE techniques, recommendations).
        </p>

        {loading ? (
          <div className="flex items-center gap-2 text-gray-500 py-4">
            <Loader2 size={14} className="animate-spin" /> Loading…
          </div>
        ) : (
          <form onSubmit={saveAI} className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Provider</label>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                {PROVIDERS.map(p => (
                  <button
                    key={p.id}
                    type="button"
                    onClick={() => { set('provider', p.id); set('base_url', p.default_url || '') }}
                    className={`relative text-xs py-2 px-3 rounded-lg border transition-colors text-left font-medium ${
                      form.provider === p.id
                        ? 'bg-brand-accent text-white border-brand-accent'
                        : 'bg-white text-gray-600 border-gray-200 hover:border-gray-400'
                    }`}
                  >
                    {p.name}
                    {config?.provider === p.id && (
                      <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-green-400 border-2 border-white" title="Currently saved" />
                    )}
                  </button>
                ))}
              </div>
              {provider.hint && <p className="text-[10px] text-gray-500 mt-1">{provider.hint}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Model</label>
              <input
                className="input text-xs"
                placeholder={provider.placeholder_model}
                value={form.model}
                onChange={e => set('model', e.target.value)}
                required
              />
            </div>

            {provider.needs_key && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  API Key
                  {provider.key_optional && <span className="ml-1 text-gray-500 font-normal">(optional — for authenticated endpoints)</span>}
                  {!provider.key_optional && config?.api_key_set && (
                    <span className="ml-1 text-green-600 font-normal">(key already set — leave blank to keep)</span>
                  )}
                  {provider.key_optional && config?.api_key_set && (
                    <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>
                  )}
                </label>
                <div className="relative">
                  <input
                    type={showKey ? 'text' : 'password'}
                    className="input text-xs pr-8"
                    placeholder={config?.api_key_set ? '••••••••••••••••' : 'sk-…'}
                    value={form.api_key}
                    onChange={e => set('api_key', e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
                  >
                    {showKey ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
              </div>
            )}

            {(provider.id === 'ollama' || provider.id === 'custom') && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Base URL</label>
                <input
                  className="input text-xs font-mono"
                  placeholder={provider.default_url}
                  value={form.base_url}
                  onChange={e => set('base_url', e.target.value)}
                  required
                />
              </div>
            )}
            {(provider.id === 'openai' || provider.id === 'anthropic') && form.base_url && (
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Base URL
                  <span className="text-gray-500 font-normal ml-1">(optional — override default endpoint)</span>
                </label>
                <input
                  className="input text-xs font-mono"
                  placeholder="https://api.openai.com/v1"
                  value={form.base_url}
                  onChange={e => set('base_url', e.target.value)}
                />
              </div>
            )}

            {error && (
              <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                <AlertCircle size={12} /> {error}
              </p>
            )}

            <div className="flex items-center gap-2 flex-wrap">
              <button type="submit" disabled={saving} className="btn-primary text-xs">
                {saving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                Save
              </button>
              {config?.provider && (
                <button type="button" onClick={testAI} disabled={testing} className="btn-outline text-xs">
                  {testing ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
                  Test Connection
                </button>
              )}
              {saved && <span className="text-xs text-green-600 flex items-center gap-1"><Check size={11} /> Saved</span>}
              {config?.provider && (
                <button type="button" onClick={clearAI} className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto">
                  <Trash2 size={12} /> Remove
                </button>
              )}
            </div>

            {testResult && (
              testResult.ok ? (
                <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <Check size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Connected.</strong> Model replied: <em className="font-mono">{testResult.response}</em></span>
                </div>
              ) : (
                <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                  <X size={12} className="mt-0.5 flex-shrink-0" />
                  <span><strong>Failed:</strong> {testResult.error}</span>
                </div>
              )
            )}
          </form>
        )}
      </section>

      {/* Pilot agent capabilities — tools, module launching, web search */}
      <PilotSettingsSection />
      </LicenseGate>
    )
  }

  // Storage is split per owning tool: Sluice (import sources), Talon (collector
  // dropzone), Scribe (case archive) — one tab each.
  function renderSluiceStorage() {
    return (
      <div className="space-y-6">
        {/* Evidence Import Sources — Sluice */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <HardDrive size={15} className="text-blue-500" />
              <h2 className="font-semibold text-brand-text">Evidence Import Sources</h2>
            </div>
            <button onClick={openAddSource} className="btn-primary text-xs">
              <Plus size={13} /> Add Source
            </button>
          </div>

          <p className="text-xs text-gray-500">
            External S3-compatible buckets you browse and pull forensic artifacts FROM into cases.
            Multiple sources let you access different clients' evidence buckets simultaneously.
          </p>

          {sourcesLoading ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : importSources.length === 0 && !showAddSource ? (
            <p className="text-xs text-gray-500 italic py-2">No import sources configured yet.</p>
          ) : (
            <div className="space-y-2">
              {importSources.map(src => {
                const testRes = sourceTestResults[src.id]
                return (
                  <div key={src.id} className="rounded-lg border border-gray-100 bg-gray-50/50 dark:bg-transparent dark:border-white/10 px-4 py-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <span className="font-medium text-sm text-brand-text truncate">{src.name}</span>
                        <span className="text-[10px] bg-white dark:bg-white/10 border border-gray-200 dark:border-white/15 rounded px-1.5 py-0.5 text-gray-500 uppercase tracking-wide flex-shrink-0">
                          {src.vendor || 'other'}
                        </span>
                        <span className="text-xs text-gray-500 font-mono truncate hidden sm:block">{src.bucket}</span>
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        {src.endpoint ? (
                          <span className="text-[10px] text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5">Connected</span>
                        ) : (
                          <span className="text-[10px] text-gray-500">—</span>
                        )}
                        <button
                          type="button"
                          onClick={() => testSource(src.id)}
                          disabled={sourceTestingId === src.id}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Test connection"
                        >
                          {sourceTestingId === src.id ? <Loader2 size={12} className="animate-spin" /> : <Wifi size={12} />}
                        </button>
                        <button
                          type="button"
                          onClick={() => openEditSource(src)}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Edit"
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          type="button"
                          onClick={() => deleteSource(src.id)}
                          className="btn-ghost text-xs py-1 px-2 text-red-500 hover:text-red-700"
                          title="Delete"
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </div>
                    {testRes && (
                      <p className={`text-[10px] mt-1.5 flex items-center gap-1 ${testRes.ok ? 'text-green-600' : 'text-red-500'}`}>
                        {testRes.ok ? <Check size={10} /> : <X size={10} />}
                        {testRes.ok ? testRes.message : testRes.error}
                      </p>
                    )}
                  </div>
                )
              })}
            </div>
          )}

          {/* Add/Edit source form */}
          {showAddSource && (
            <form onSubmit={saveSource} className="border border-brand-accent/30 rounded-xl p-4 space-y-4 bg-brand-accentlight/30">
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs font-semibold text-brand-text">
                  {editingSource ? `Edit: ${editingSource.name}` : 'New Import Source'}
                </p>
                <button type="button" onClick={() => { setShowAddSource(false); setEditingSource(null) }} className="text-gray-500 hover:text-gray-600">
                  <X size={14} />
                </button>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Source Name</label>
                <input
                  className="input text-xs"
                  placeholder="e.g. Client A — AWS Evidence"
                  value={sourceForm.name}
                  onChange={e => setSourceF('name', e.target.value)}
                  required
                  autoFocus
                />
              </div>

              <S3Form
                form={sourceForm}
                setF={setSourceF}
                showKey={sourceShowKey}
                setShowKey={setSourceShowKey}
                secretKeySet={editingSource?.secret_key_set}
                label="Source S3 Config"
              />

              {sourceError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {sourceError}
                </p>
              )}

              <div className="flex items-center gap-2">
                <button type="submit" disabled={sourceSaving} className="btn-primary text-xs">
                  {sourceSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  {editingSource ? 'Update' : 'Add Source'}
                </button>
                <button type="button" onClick={() => { setShowAddSource(false); setEditingSource(null) }} className="btn-ghost text-xs">
                  Cancel
                </button>
              </div>
            </form>
          )}
        </section>
      </div>
    )
  }

  function renderTalonStorage() {
    return (
      <div className="space-y-6">
        {/* Collector Dropzone — Talon */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Upload size={15} className="text-orange-500" />
            <h2 className="font-semibold text-brand-text">Collector Dropzone</h2>
            {!s3TriageLoading && s3TriageConfig?.endpoint && (
              <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
                <Check size={10} /> Configured
              </span>
            )}
          </div>

          <p className="text-xs text-gray-500">
            S3 bucket where automated collection scripts deposit evidence packages.
            Field agents push triage ZIPs, memory dumps and disk images here; analysts browse
            this bucket from the Collector page and pull files into cases.
          </p>

          {s3TriageLoading ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <form onSubmit={saveS3Triage} className="space-y-4">
              <S3Form
                form={s3TriageForm}
                setF={setS3Triage}
                showKey={s3TriageShowKey}
                setShowKey={setS3TriageShowKey}
                secretKeySet={s3TriageConfig?.secret_key_set}
                label="Dropzone S3"
              />

              {s3TriageError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {s3TriageError}
                </p>
              )}

              <div className="flex items-center gap-2 flex-wrap">
                <button type="submit" disabled={s3TriageSaving} className="btn-primary text-xs">
                  {s3TriageSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  Save
                </button>
                {s3TriageConfig?.endpoint && (
                  <button type="button" onClick={testS3Triage} disabled={s3TriageTesting} className="btn-outline text-xs">
                    {s3TriageTesting ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
                    Test Connection
                  </button>
                )}
                {s3TriageSaved && <span className="text-xs text-green-600 flex items-center gap-1"><Check size={11} /> Saved</span>}
                {s3TriageConfig?.endpoint && (
                  <button type="button" onClick={clearS3Triage} className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto">
                    <Trash2 size={12} /> Remove
                  </button>
                )}
              </div>

              {s3TriageTestResult && (
                s3TriageTestResult.ok ? (
                  <div className="text-xs text-green-700 bg-green-50 border border-green-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                    <Check size={12} className="mt-0.5 flex-shrink-0" />
                    <span><strong>Connected.</strong> {s3TriageTestResult.message}</span>
                  </div>
                ) : (
                  <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                    <X size={12} className="mt-0.5 flex-shrink-0" />
                    <span><strong>Failed:</strong> {s3TriageTestResult.error}</span>
                  </div>
                )
              )}
            </form>
          )}
        </section>
      </div>
    )
  }

  function renderScribeStorage() {
    const archiveS3 = {
      vendor:     archiveForm.s3_vendor,
      endpoint:   archiveForm.s3_endpoint,
      access_key: archiveForm.s3_access_key,
      secret_key: archiveForm.s3_secret_key,
      bucket:     archiveForm.s3_bucket,
      region:     archiveForm.s3_region,
      use_ssl:    archiveForm.s3_use_ssl,
    }
    const setArchiveS3 = (k, v) => setArchive(`s3_${k}`, v)
    return (
      <div className="space-y-6">
        {/* Case Archive — Scribe */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Archive size={15} className="text-indigo-500" />
            <h2 className="font-semibold text-brand-text">Case Archive</h2>
          </div>

          <p className="text-xs text-gray-500">
            Long-term storage for completed cases. When a case is purge-archived, its full data bundle
            (.citadel) is uploaded here and local Elasticsearch + MinIO data is freed.
            Archives can be restored at any time.
          </p>

          {archiveLoading ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <form onSubmit={saveArchive} className="space-y-4">
              <label className="flex items-center gap-2 text-xs text-gray-700 cursor-pointer select-none font-medium">
                <input
                  type="checkbox"
                  checked={archiveForm.auto_archive_enabled}
                  onChange={e => setArchive('auto_archive_enabled', e.target.checked)}
                  className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
                />
                Auto-archive inactive cases
              </label>

              {archiveForm.auto_archive_enabled && (
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Archive after days of inactivity</label>
                  <input
                    type="number"
                    min={1}
                    className="input text-xs w-28"
                    value={archiveForm.auto_archive_days}
                    onChange={e => setArchive('auto_archive_days', parseInt(e.target.value, 10) || 14)}
                  />
                </div>
              )}

              <label className="flex items-center gap-2 text-xs text-gray-700 cursor-pointer select-none font-medium">
                <input
                  type="checkbox"
                  checked={archiveForm.auto_export_enabled}
                  onChange={e => setArchive('auto_export_enabled', e.target.checked)}
                  className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
                />
                Export to S3 and purge local data when archiving
              </label>

              <div className="border border-gray-100 dark:border-white/10 rounded-lg p-4 space-y-4 bg-gray-50/50 dark:bg-transparent">
                <p className="text-xs font-medium text-gray-600">S3 Archive Storage</p>
                <p className="text-xs text-gray-500">
                  Required for manual purge-archive and auto-export. Works with AWS S3, MinIO, Wasabi, and any S3-compatible service.
                </p>
                <S3Form
                  form={archiveS3}
                  setF={setArchiveS3}
                  showKey={showArchiveKey}
                  setShowKey={setShowArchiveKey}
                  secretKeySet={archiveSecretSet}
                  label="Archive S3"
                />
              </div>

              {archiveError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {archiveError}
                </p>
              )}

              {archiveTestResult && (
                <p className={`text-xs flex items-center gap-1.5 ${archiveTestResult.ok ? 'text-green-600' : 'text-red-500'}`}>
                  {archiveTestResult.ok ? <Check size={11} /> : <AlertCircle size={11} />}
                  {archiveTestResult.ok ? archiveTestResult.message : archiveTestResult.error}
                </p>
              )}

              <div className="flex items-center gap-2 flex-wrap">
                <button type="submit" disabled={archiveSaving} className="btn-primary text-xs">
                  {archiveSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  Save
                </button>
                <button
                  type="button"
                  onClick={testArchive}
                  disabled={archiveTesting}
                  className="btn-outline text-xs flex items-center gap-1.5"
                >
                  {archiveTesting ? <Loader2 size={13} className="animate-spin" /> : <Wifi size={13} />}
                  Test Connection
                </button>
                {archiveSaved && <span className="text-xs text-green-600 flex items-center gap-1"><Check size={11} /> Saved</span>}
              </div>
            </form>
          )}
        </section>
      </div>
    )
  }

  function renderIntegrations() {
    return (
      <div className="space-y-6">
        {/* Cuckoo Sandbox */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <FlaskConical size={15} className="text-orange-500" />
            <h2 className="font-semibold text-brand-text">Cuckoo Sandbox</h2>
            {!cuckooLoading && cuckooConfig?.configured && (
              <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
                <Check size={10} /> Configured
              </span>
            )}
            {!cuckooLoading && cuckooConfig?.source === 'env' && (
              <span className="text-xs text-blue-600 bg-blue-50 border border-blue-200 rounded-full px-2 py-0.5 flex items-center gap-1">
                <Info size={10} /> Via env var
              </span>
            )}
          </div>

          <div className="rounded-lg bg-orange-50 border border-orange-200 p-3 space-y-2">
            <p className="text-xs font-semibold text-orange-800 flex items-center gap-1.5">
              <Shield size={12} /> Isolation model
            </p>
            <p className="text-xs text-orange-700 leading-relaxed">
              Files submitted to Cuckoo <strong>never execute on this server</strong>. Our processor
              sends the file bytes to Cuckoo's REST API via HTTP, then polls for the report.
              Cuckoo runs the sample inside a <strong>fresh VM snapshot</strong> (KVM/VirtualBox guest)
              that is reset to a clean state after each task — the malware is fully contained within
              Cuckoo's infrastructure.
            </p>
            <p className="text-xs text-orange-600 leading-relaxed">
              One VM task is created per submitted file. The VM monitors API calls, network connections,
              file writes, and registry changes, then generates a behavioral report with a severity score.
            </p>
          </div>

          <p className="text-xs text-gray-500">
            Enter the URL of your Cuckoo Sandbox API. Settings saved here are stored securely in Redis
            and take effect immediately — no pod restart needed.
            If you also set <code className="bg-gray-100 px-1 rounded font-mono">CUCKOO_API_URL</code> as
            an environment variable, the UI config takes priority.
          </p>

          {cuckooLoading ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <form onSubmit={saveCuckoo} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Cuckoo API URL</label>
                <input
                  className="input text-xs font-mono"
                  placeholder="http://cuckoo.internal:8090"
                  value={cuckooForm.api_url}
                  onChange={e => setCuckoo('api_url', e.target.value)}
                  required
                />
                <p className="text-[10px] text-gray-500 mt-1">
                  Default Cuckoo API port is 8090. Include the scheme and host.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  API Token
                  <span className="ml-1 text-gray-500 font-normal">(optional — only if auth is enabled on Cuckoo)</span>
                  {cuckooConfig?.api_token_set && (
                    <span className="ml-1 text-green-600 font-normal">(token set — leave blank to keep)</span>
                  )}
                </label>
                <div className="relative">
                  <input
                    type={showCuckooToken ? 'text' : 'password'}
                    className="input text-xs pr-8 font-mono"
                    placeholder={cuckooConfig?.api_token_set ? '••••••••••••••••' : '(leave blank if no auth)'}
                    value={cuckooForm.api_token}
                    onChange={e => setCuckoo('api_token', e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowCuckooToken(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
                  >
                    {showCuckooToken ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
              </div>

              {cuckooError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {cuckooError}
                </p>
              )}

              <div className="flex items-center gap-2 flex-wrap">
                <button type="submit" disabled={cuckooSaving} className="btn-primary text-xs">
                  {cuckooSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  Save
                </button>
                {cuckooSaved && (
                  <span className="text-xs text-green-600 flex items-center gap-1">
                    <Check size={11} /> Saved — takes effect immediately
                  </span>
                )}
                {cuckooConfig?.configured && (
                  <button type="button" onClick={clearCuckoo} className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto">
                    <Trash2 size={12} /> Remove
                  </button>
                )}
              </div>
            </form>
          )}
        </section>

        {/* VirusTotal */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Shield size={15} className="text-purple-500" />
            <h2 className="font-semibold text-brand-text">VirusTotal</h2>
            {!vtLoading && vtConfig?.vt_api_key_set && (
              <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
                <Check size={10} /> Configured
              </span>
            )}
            {!vtLoading && vtConfig?.source === 'env' && (
              <span className="text-xs text-blue-600 bg-blue-50 border border-blue-200 rounded-full px-2 py-0.5 flex items-center gap-1">
                <Info size={10} /> Via env var
              </span>
            )}
          </div>

          <p className="text-xs text-gray-500">
            Required by the <strong className="text-brand-text">Malwoverview</strong> module for file hash
            lookups against the VirusTotal v3 API. Enter a public (free) or private key. Stored securely
            in Redis — takes effect immediately without a restart. You can also set{' '}
            <code className="bg-gray-100 px-1 rounded font-mono">VT_API_KEY</code> as an environment variable.
          </p>

          {vtLoading ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <form onSubmit={saveVt} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  VirusTotal API Key
                  {vtConfig?.vt_api_key_set && (
                    <span className="ml-1 text-green-600 font-normal">(key set — leave blank to keep)</span>
                  )}
                </label>
                <div className="relative">
                  <input
                    type={showVtKey ? 'text' : 'password'}
                    className="input text-xs pr-8 font-mono"
                    placeholder={vtConfig?.vt_api_key_set ? '••••••••••••••••••••••••••••••••' : 'Enter your VirusTotal API key'}
                    value={vtForm.vt_api_key}
                    onChange={e => setVt('vt_api_key', e.target.value)}
                  />
                  <button
                    type="button"
                    onClick={() => setShowVtKey(v => !v)}
                    className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-600"
                  >
                    {showVtKey ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
                <p className="text-[10px] text-gray-500 mt-1">
                  Get your key at{' '}
                  <a
                    href="https://www.virustotal.com/gui/my-apikey"
                    target="_blank"
                    rel="noreferrer"
                    className="text-brand-accent hover:underline"
                  >
                    virustotal.com/gui/my-apikey
                  </a>
                </p>
              </div>

              {vtError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {vtError}
                </p>
              )}

              <div className="flex items-center gap-2 flex-wrap">
                <button type="submit" disabled={vtSaving} className="btn-primary text-xs">
                  {vtSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  Save
                </button>
                {vtSaved && (
                  <span className="text-xs text-green-600 flex items-center gap-1">
                    <Check size={11} /> Saved — takes effect immediately
                  </span>
                )}
                {vtConfig?.vt_api_key_set && (
                  <button type="button" onClick={clearVt} className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto">
                    <Trash2 size={12} /> Remove
                  </button>
                )}
              </div>
            </form>
          )}
        </section>

        {/* Outbound Webhooks */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Webhook size={15} className="text-teal-500" />
            <h2 className="font-semibold text-brand-text">Alert Webhooks</h2>
            {webhooksList.length > 0 && (
              <span className="text-xs text-green-600 bg-green-50 border border-green-200 rounded-full px-2 py-0.5 flex items-center gap-1">
                <Check size={10} /> {webhooksList.length} configured
              </span>
            )}
          </div>

          <p className="text-xs text-gray-500">
            POST a JSON summary to external systems whenever detection rules fire on a case
            (auto-run after ingest completes). The payload includes a Slack/Teams-compatible{' '}
            <code className="bg-gray-100 px-1 rounded font-mono">text</code> field plus structured
            match data for SOAR platforms. Webhook URLs often embed secrets — they're stored in
            Redis and redacted in this list.
          </p>

          {whLoading ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <>
              {webhooksList.length > 0 && (
                <div className="space-y-1.5">
                  {webhooksList.map(hook => (
                    <div key={hook.id} className="flex items-center gap-2 bg-gray-50 border border-gray-200 rounded-lg px-3 py-2">
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-brand-text flex items-center gap-1.5">
                          {hook.name}
                          {(hook.events || []).map(ev => (
                            <span key={ev} className="px-1.5 py-px rounded text-[9px] font-medium bg-teal-50 text-teal-600 border border-teal-200">
                              {ev === 'alert_rules' ? 'detections' : 'module hits'}
                            </span>
                          ))}
                        </p>
                        <p className="text-[10px] text-gray-500 font-mono truncate">{hook.url}</p>
                      </div>
                      {whTestResult?.id === hook.id && (
                        <span className={`text-[10px] ${whTestResult.delivered ? 'text-green-600' : 'text-red-500'}`}>
                          {whTestResult.delivered ? `delivered (${whTestResult.status_code})` : (whTestResult.error || 'failed')}
                        </span>
                      )}
                      <button
                        onClick={() => testWebhook(hook.id)}
                        disabled={whTesting === hook.id}
                        className="btn-ghost text-xs px-1.5 py-0.5 text-brand-accent flex items-center gap-1"
                        title="Send a test payload"
                      >
                        {whTesting === hook.id ? <Loader2 size={11} className="animate-spin" /> : <Send size={11} />}
                        Test
                      </button>
                      <button
                        onClick={() => deleteWebhook(hook.id)}
                        className="btn-ghost text-xs px-1.5 py-0.5 text-red-500 hover:text-red-700"
                        title="Delete webhook"
                      >
                        <Trash2 size={11} />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              <form onSubmit={saveWebhook} className="flex items-end gap-2 flex-wrap">
                <div className="flex-1 min-w-[140px]">
                  <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
                  <input
                    className="input text-xs"
                    placeholder="SOC Slack channel"
                    value={whForm.name}
                    onChange={e => setWhForm(f => ({ ...f, name: e.target.value }))}
                    required
                  />
                </div>
                <div className="flex-[2] min-w-[220px]">
                  <label className="block text-xs font-medium text-gray-600 mb-1">URL</label>
                  <input
                    className="input text-xs font-mono"
                    placeholder="https://hooks.slack.com/services/…"
                    value={whForm.url}
                    onChange={e => setWhForm(f => ({ ...f, url: e.target.value }))}
                    required
                  />
                </div>
                <div className="flex items-center gap-3 pb-1.5">
                  <label className="flex items-center gap-1 text-[11px] text-gray-600">
                    <input
                      type="checkbox"
                      checked={whForm.alert_rules}
                      onChange={e => setWhForm(f => ({ ...f, alert_rules: e.target.checked }))}
                    />
                    Detections
                  </label>
                  <label className="flex items-center gap-1 text-[11px] text-gray-600">
                    <input
                      type="checkbox"
                      checked={whForm.module_completed}
                      onChange={e => setWhForm(f => ({ ...f, module_completed: e.target.checked }))}
                    />
                    Module hits
                  </label>
                </div>
                <button type="submit" disabled={whSaving} className="btn-primary text-xs">
                  {whSaving ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
                  Add
                </button>
              </form>

              {whError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {whError}
                </p>
              )}
            </>
          )}
        </section>
      </div>
    )
  }

  function renderSystem() {
    return (
      <div className="space-y-6">
        {/* Platform runtime knobs (admin-tunable) */}
        <PlatformSettingsSection />

        {/* SSO / Single Sign-On (Google + Microsoft OIDC) */}
        <SSOSettingsSection />

        {/* Report template */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Pencil size={15} className="text-indigo-500" />
            <h2 className="font-semibold text-brand-text">Report Template</h2>
          </div>
          <p className="text-xs text-gray-500">
            Org-wide customization of generated case reports (Markdown + HTML downloads).
            Add a branding header, change the footer, and toggle sections off entirely.
          </p>
          {!rtForm ? (
            <div className="flex items-center gap-2 text-gray-500 py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : (
            <form onSubmit={saveReportTemplate} className="space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Title prefix</label>
                  <input
                    className="input text-xs"
                    value={rtForm.title_prefix}
                    onChange={e => setRtForm(f => ({ ...f, title_prefix: e.target.value }))}
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-600 mb-1">Max flagged events</label>
                  <input
                    type="number" min={1} max={500}
                    className="input text-xs"
                    value={rtForm.max_flagged}
                    onChange={e => setRtForm(f => ({ ...f, max_flagged: parseInt(e.target.value || '50', 10) }))}
                  />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">
                  Header (Markdown) <span className="text-gray-500 font-normal">— rendered under the title; org branding, classification banner…</span>
                </label>
                <textarea
                  rows={3}
                  className="input text-xs font-mono resize-y"
                  placeholder={'**ACME CSIRT** — TLP:AMBER\\n_Confidential — distribution restricted_'}
                  value={rtForm.header_md}
                  onChange={e => setRtForm(f => ({ ...f, header_md: e.target.value }))}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1">Footer (Markdown)</label>
                <input
                  className="input text-xs font-mono"
                  value={rtForm.footer_md}
                  onChange={e => setRtForm(f => ({ ...f, footer_md: e.target.value }))}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-600 mb-1.5">Sections</label>
                <div className="flex flex-wrap gap-x-4 gap-y-1.5">
                  {Object.entries(RT_SECTION_LABELS).map(([key, label]) => (
                    <label key={key} className="flex items-center gap-1.5 text-[11px] text-gray-600">
                      <input
                        type="checkbox"
                        checked={rtForm.sections?.[key] !== false}
                        onChange={e => setRtForm(f => ({
                          ...f, sections: { ...f.sections, [key]: e.target.checked },
                        }))}
                      />
                      {label}
                    </label>
                  ))}
                </div>
              </div>
              {rtError && (
                <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
                  <AlertCircle size={12} /> {rtError}
                </p>
              )}
              <div className="flex items-center gap-2">
                <button type="submit" disabled={rtSaving} className="btn-primary text-xs">
                  {rtSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
                  Save
                </button>
                {rtSaved && (
                  <span className="text-xs text-green-600 flex items-center gap-1">
                    <Check size={11} /> Saved
                  </span>
                )}
                <button type="button" onClick={resetReportTemplate} className="btn-ghost text-xs text-red-500 hover:text-red-700 ml-auto">
                  <RefreshCw size={12} /> Reset to defaults
                </button>
              </div>
            </form>
          )}
        </section>

        {/* Worker Performance */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Cpu size={15} className="text-brand-accent" />
            <h2 className="font-semibold text-brand-text">Worker Performance</h2>
          </div>

          {workerMetrics && (
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: 'Active Workers', value: workerMetrics.celery?.registered_workers ?? '—' },
                { label: 'Running Tasks',  value: workerMetrics.celery?.active_tasks ?? '—' },
                { label: 'Queued Tasks',   value: (
                  (workerMetrics.celery?.queue_lengths?.ingest || 0) +
                  (workerMetrics.celery?.queue_lengths?.modules || 0)
                )},
              ].map(({ label, value }) => (
                <div key={label} className="bg-gray-50 rounded-lg p-3 text-center border border-gray-200">
                  <p className="text-lg font-bold text-brand-text">{value}</p>
                  <p className="text-[10px] text-gray-500 mt-0.5">{label}</p>
                </div>
              ))}
            </div>
          )}

          <div className="rounded-lg bg-brand-accentlight border border-brand-accent/20 p-3 space-y-2">
            <p className="text-xs font-semibold text-brand-accent flex items-center gap-1.5">
              <Lock size={12} /> Sandbox isolation for custom modules
            </p>
            <p className="text-xs text-gray-600 leading-relaxed">
              Python modules you write in <strong>Studio</strong> run in a double-sandboxed child process:
              Linux resource limits (CPU time, RAM, file size, max processes), a stripped environment
              (no MinIO or Redis credentials visible), and a wall-clock kill timer.
              Built-in analysis tools (Hayabusa, YARA, ExifTool, de4dot) run as trusted binaries with
              no access to server secrets in their subprocess environment.
            </p>
          </div>

          <div className="space-y-3 text-xs">
            <p className="text-gray-500 font-medium">How to increase compute capacity</p>
            <div className="space-y-2">
              {[
                {
                  label: 'CELERY_CONCURRENCY',
                  desc: 'Number of parallel task processes per pod. Set to the number of vCPUs you allocate. Changing this + redeploying is all you need — no image rebuild.',
                  default_: '4',
                },
                {
                  label: 'SANDBOX_CPU_SECONDS',
                  desc: 'Max CPU time (seconds) a custom Python module can use. Default 3600 (1 h). Raise for very large memory image analysis.',
                  default_: '3600',
                },
                {
                  label: 'SANDBOX_MEMORY_BYTES',
                  desc: 'Max RSS memory a custom Python module can allocate. Default 2 GB. Match this to the pod memory limit.',
                  default_: '2147483648',
                },
                {
                  label: 'SANDBOX_TIMEOUT_SEC',
                  desc: 'Wall-clock timeout for a custom module subprocess. Default 30 min. Volatility3 on large images may need 45–60 min.',
                  default_: '1800',
                },
              ].map(({ label, desc, default_ }) => (
                <div key={label} className="flex gap-3 items-start">
                  <code className="text-[10px] font-mono text-brand-accent bg-brand-accentlight px-1.5 py-0.5 rounded flex-shrink-0 mt-0.5">
                    {label}
                  </code>
                  <div>
                    <p className="text-gray-600">{desc}</p>
                    <p className="text-gray-500 text-[10px]">Default: {default_}</p>
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-lg bg-gray-50 border border-gray-200 p-3">
              <p className="text-gray-500 font-medium mb-1.5">Set in your K8s deployment</p>
              <pre className="text-[10px] font-mono text-gray-600 whitespace-pre-wrap leading-relaxed">{`# k8s/processor/deployment.yaml
env:
  - name: CELERY_CONCURRENCY
    value: "8"          # match to CPU limit
  - name: SANDBOX_MEMORY_BYTES
    value: "4294967296" # 4 GB for Volatility3
resources:
  limits:
    cpu: "8"
    memory: "12Gi"`}</pre>
            </div>
          </div>
        </section>

        {/* System Maintenance */}
        <section className="card p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Trash2 size={15} className="text-red-500" />
            <h2 className="font-semibold text-brand-text">System Maintenance</h2>
          </div>

          <p className="text-xs text-gray-500">
            Purge orphaned data left by cases that were deleted or expired — MinIO artifact files,
            Elasticsearch indices, and Redis job records — without touching any active case.
          </p>

          <div className="flex items-center gap-3 flex-wrap">
            <button
              type="button"
              onClick={runPurge}
              disabled={purging}
              className="btn-outline text-xs px-4 py-1.5 flex items-center gap-1.5 text-red-500 border-red-200 hover:border-red-400 disabled:opacity-50"
            >
              {purging ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
              {purging ? 'Purging…' : 'Purge Orphaned Case Data'}
            </button>
          </div>

          {purgeResult && (
            purgeResult.ok ? (
              <div className="text-xs bg-gray-50 border border-gray-200 rounded-lg px-3 py-2 space-y-1">
                <p className="font-medium text-brand-text flex items-center gap-1"><Check size={12} className="text-green-600" /> Purge complete</p>
                <p className="text-gray-500">MinIO cases purged: <strong>{purgeResult.data.minio_cases_purged.length}</strong> ({purgeResult.data.minio_cases_purged.map(c => c.case_id).join(', ') || 'none'})</p>
                <p className="text-gray-500">ES cases purged: <strong>{purgeResult.data.es_cases_purged.length}</strong> ({purgeResult.data.es_cases_purged.join(', ') || 'none'})</p>
                <p className="text-gray-500">Redis job keys deleted: <strong>{purgeResult.data.redis_job_keys_deleted.toLocaleString()}</strong></p>
                <p className="text-gray-500">Redis case keys deleted: <strong>{(purgeResult.data.redis_case_keys_deleted ?? 0).toLocaleString()}</strong></p>
              </div>
            ) : (
              <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                <AlertCircle size={12} className="mt-0.5 flex-shrink-0" />
                <span>{purgeResult.error}</span>
              </div>
            )
          )}
        </section>

        {/* Wipe All Data */}
        <section className="card p-5 space-y-4 border-red-300">
          <div className="flex items-center gap-2">
            <Trash2 size={15} className="text-red-600" />
            <h2 className="font-semibold text-red-600">Danger Zone — Wipe All Data</h2>
          </div>
          <p className="text-xs text-gray-500">
            Permanently deletes <strong>all case data</strong>: every Elasticsearch index, every MinIO artifact, and all
            Redis case/job keys. This affects <em>all active cases</em> and cannot be undone.
          </p>
          <div className="flex items-center gap-3 flex-wrap">
            <input
              type="text"
              value={wipeInput}
              onChange={e => setWipeInput(e.target.value)}
              placeholder="Type WIPE to confirm"
              className="input text-xs w-48 font-mono"
            />
            <button
              type="button"
              onClick={runWipeAll}
              disabled={wiping || wipeInput !== 'WIPE'}
              className="btn text-xs px-4 py-1.5 bg-red-600 hover:bg-red-700 text-white border-0 disabled:opacity-40"
            >
              {wiping ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />}
              {wiping ? 'Wiping…' : 'Wipe All Data'}
            </button>
          </div>
          {wipeResult && (
            wipeResult.ok ? (
              <div className="text-xs bg-gray-50 border border-gray-200 rounded-lg px-3 py-2 space-y-1">
                <p className="font-medium text-brand-text flex items-center gap-1"><Check size={12} className="text-green-600" /> Wipe complete</p>
                <p className="text-gray-500">ES indices deleted: <strong>{wipeResult.data.es_indices_deleted.length}</strong></p>
                <p className="text-gray-500">MinIO objects deleted: <strong>{wipeResult.data.minio_objects_deleted.toLocaleString()}</strong></p>
                <p className="text-gray-500">Redis keys deleted: <strong>{wipeResult.data.redis_keys_deleted.toLocaleString()}</strong></p>
              </div>
            ) : (
              <div className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-start gap-1.5">
                <AlertCircle size={12} className="mt-0.5 flex-shrink-0" />
                <span>{wipeResult.error}</span>
              </div>
            )
          )}
        </section>
      </div>
    )
  }

  /* ── Main render ──────────────────────────────────────────────────────── */
  return (
    <PageShell>
      <PageHeader
        title="Platform Settings"
        icon={Settings2}
        subtitle={isAdmin ? 'Platform configuration for administrators. Your account & password are under Account.' : 'Administrators only — your account & password are under Account.'}
        actions={(
          <span className={`text-[10px] font-semibold px-2.5 py-1 rounded-full border ${
            license.plan === 'enterprise' ? 'bg-indigo-50 text-indigo-700 border-indigo-200' :
            license.plan === 'pro'        ? 'bg-blue-50 text-blue-700 border-blue-200' :
            'bg-gray-100 text-gray-500 border-gray-200'
          }`}>
            {license.plan_label}
            {license.org_name && license.org_name !== 'Community' ? ` · ${license.org_name}` : ''}
          </span>
        )}
      />

      {/* Tab nav */}
      <div className="flex gap-1 border-b border-gray-200 mb-6 overflow-x-auto">
        {visibleTabs.map(t => {
          const Icon = t.icon
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              title={t.tool ? `${t.label} — ${t.tool}` : t.label}
              className={`flex items-center gap-1.5 px-4 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-colors -mb-px ${
                tab === t.id
                  ? 'border-brand-accent text-brand-accent'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
            >
              <Icon size={13} />
              <span className="flex flex-col items-start leading-tight">
                {t.label}
                {t.tool && <span className="text-[9px] text-gray-400 font-normal">{t.tool}</span>}
              </span>
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {!isAdmin && (
        <div className="card p-6 text-sm text-gray-600">
          Settings are restricted to administrators. Contact an admin to change platform configuration.
        </div>
      )}
      {tab === 'ai'           && renderAI()}
      {tab === 'talon'        && renderTalonStorage()}
      {tab === 'sluice'       && renderSluiceStorage()}
      {tab === 'scribe'       && renderScribeStorage()}
      {tab === 'integrations' && renderIntegrations()}
      {tab === 'system'       && renderSystem()}
      {tab === 'license'      && <LicensePanel />}
    </PageShell>
  )
}

/* ── License panel ──────────────────────────────────────────────────────────
   Admin-only. Shows the active license + lets the operator paste a JWT
   (and optionally a new HS256 signing key) at runtime. Validation happens
   server-side before the override is persisted to the shared PVC. */

function LicensePanel() {
  const license = useLicense()
  const [key, setKey]               = useState('')
  const [signingKey, setSigningKey] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [busy, setBusy]             = useState(false)
  const [error, setError]           = useState(null)
  const [okMessage, setOkMessage]   = useState(null)

  const planBadge =
    license.plan === 'community'  ? 'bg-gray-100 text-gray-700' :
    license.plan === 'pro'        ? 'bg-blue-50 text-blue-700' :
    license.plan === 'enterprise' ? 'bg-indigo-50 text-indigo-700' :
    license.plan === 'mssp'       ? 'bg-amber-50 text-amber-700' :
                                    'bg-gray-100 text-gray-700'

  async function handleInstall() {
    setBusy(true); setError(null); setOkMessage(null)
    try {
      await api.license.install(key.trim(), signingKey.trim() || undefined)
      await license.refresh()
      setKey(''); setSigningKey('')
      setOkMessage('License installed.')
    } catch (e) {
      setError(e.message || 'Install failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleClear() {
    if (!confirm('Remove the runtime license override and revert to the env / community license?')) return
    setBusy(true); setError(null); setOkMessage(null)
    try {
      await api.license.uninstall()
      await license.refresh()
      setOkMessage('License override cleared.')
    } catch (e) {
      setError(e.message || 'Clear failed.')
    } finally {
      setBusy(false)
    }
  }

  async function handleRefresh() {
    setBusy(true); setError(null); setOkMessage(null)
    try {
      await api.license.refresh()
      await license.refresh()
      setOkMessage('License re-validated.')
    } catch (e) {
      setError(e.message || 'Refresh failed.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Current license */}
      <div className="card p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-indigo-50">
              <Award size={20} className="text-indigo-600" />
            </div>
            <div>
              <div className="text-sm font-semibold text-gray-900 flex items-center gap-2">
                {license.plan_label || license.plan}
                <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${planBadge}`}>
                  {license.plan}
                </span>
              </div>
              <div className="text-xs text-gray-500">{license.org_name}</div>
            </div>
          </div>
          <button
            onClick={handleRefresh}
            disabled={busy}
            className="btn-secondary text-xs flex items-center gap-1.5"
            title="Re-validate the current key"
          >
            <RefreshCw size={13} className={busy ? 'animate-spin' : ''} />
            Re-validate
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 text-xs">
          <Field label="Source" value={
            license.source === 'file'    ? 'Installed via UI' :
            license.source === 'env'     ? 'Env (CITADEL_LICENSE_KEY)' :
            license.source === 'default' ? 'Default (no key)' : '—'
          } />
          <Field label="Seats" value={license.seats || '—'} />
          <Field label="Expires" value={license.valid_until || 'Never'} />
          <Field label="Key configured" value={license.key_present ? 'Yes' : 'No'} />
        </div>

        {license.message && (
          <div className="mt-3 text-xs text-gray-500 italic">{license.message}</div>
        )}
      </div>

      {/* Install / replace */}
      <div className="card p-5">
        <div className="flex items-center gap-2 mb-1">
          <KeyRound size={16} className="text-gray-700" />
          <h3 className="text-sm font-semibold text-gray-900">Install a license key</h3>
        </div>
        <p className="text-xs text-gray-500 mb-4">
          Paste a signed JWT minted by the operator-side <code>generate_license.py</code>.
          Validation is server-side — a bad key never replaces the running one.
          The override persists on the API pod's shared volume (survives restarts).
        </p>

        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">License JWT</label>
            <textarea
              value={key}
              onChange={e => setKey(e.target.value)}
              placeholder="eyJhbGciOiJIUzI1NiIs…"
              rows={3}
              className="input w-full font-mono text-xs"
              spellCheck={false}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Signing key (HS256 secret) <span className="text-gray-400">— optional, reuses current if blank</span>
            </label>
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                value={signingKey}
                onChange={e => setSigningKey(e.target.value)}
                placeholder="The same secret you passed to --signing-key when minting"
                className="input w-full font-mono text-xs pr-9"
                spellCheck={false}
              />
              <button
                type="button"
                onClick={() => setShowSecret(s => !s)}
                className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-700"
                title={showSecret ? 'Hide' : 'Show'}
              >
                {showSecret ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="flex items-start gap-2 p-2.5 rounded-md bg-red-50 border border-red-200 text-xs text-red-700">
              <AlertCircle size={14} className="mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
          {okMessage && (
            <div className="flex items-start gap-2 p-2.5 rounded-md bg-emerald-50 border border-emerald-200 text-xs text-emerald-700">
              <Check size={14} className="mt-0.5 flex-shrink-0" />
              <span>{okMessage}</span>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={handleInstall}
              disabled={busy || !key.trim()}
              className="btn-primary text-xs flex items-center gap-1.5"
            >
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
              Install + validate
            </button>
            {license.source === 'file' && (
              <button
                onClick={handleClear}
                disabled={busy}
                className="btn-secondary text-xs flex items-center gap-1.5 text-red-700"
              >
                <Trash2 size={13} />
                Remove override
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function Field({ label, value }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wide text-gray-400 font-medium">{label}</div>
      <div className="text-xs text-gray-900 mt-0.5">{value}</div>
    </div>
  )
}
