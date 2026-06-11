import { Outlet, NavLink, useNavigate, useLocation, useParams } from 'react-router-dom'
import { useState, useEffect, useRef } from 'react'
import {
  LayoutDashboard, FolderOpen, Bell, FileCode, Shield, FlaskConical,
  Cpu, Code2, PackageOpen, Puzzle, BookOpen, Activity, Users, Settings2,
  LogOut, UserCircle, Sun, Moon, ChevronDown, Loader2,
  X, Menu, Plus, Search, ListChecks, ScrollText, Boxes,
} from 'lucide-react'
import { api } from '../../api/client'
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts'
import KeyboardShortcutsModal from '../KeyboardShortcutsModal'
import CommandPalette from '../CommandPalette'
import { useUpload } from '../../contexts/UploadContext'

const THEMES = ['light', 'dark']
function useTheme() {
  const [theme, setTheme] = useState(() => {
    if (typeof window === 'undefined') return 'light'
    const saved = localStorage.getItem('fo-theme')
    if (saved && THEMES.includes(saved)) return saved
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  })
  useEffect(() => {
    const root = document.documentElement
    THEMES.forEach(t => root.classList.remove(t))
    if (theme !== 'light') root.classList.add(theme)
    localStorage.setItem('fo-theme', theme)
  }, [theme])
  return [theme, () => setTheme(t => THEMES[(THEMES.indexOf(t) + 1) % THEMES.length])]
}

const HOME_ITEM = { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true }

const DROPDOWN_GROUPS = [
  {
    label: 'Analyze',
    items: [
      { to: '/cross-search', icon: Search,      label: 'Cross-Case Search' },
      { to: '/malware',      icon: FlaskConical, label: 'Malware' },
      { to: '/modules',      icon: Cpu,          label: 'Modules' },
      { to: '/collector',    icon: PackageOpen,  label: 'Collector' },
    ],
  },
  {
    label: 'Knowledge',
    items: [
      { to: '/alert-rules', icon: Bell,       label: 'Alert Rules' },
      { to: '/yara-rules',  icon: FileCode,   label: 'YARA Rules' },
      { to: '/cti',         icon: Shield,     label: 'Threat Intel' },
      { to: '/watchlist',   icon: ListChecks, label: 'IOC Watchlist' },
    ],
  },
  {
    label: 'Platform',
    adminOnly: true,
    items: [
      { to: '/suite',         icon: Boxes,     label: 'Suite' },
      { to: '/capabilities',  icon: Boxes,     label: 'Capabilities' },
      { to: '/studio',    icon: Code2,    label: 'Studio' },
      { to: '/ingesters', icon: Puzzle,   label: 'Ingesters' },
      { to: '/docs',      icon: BookOpen, label: 'Docs' },
    ],
  },
  {
    label: 'Admin',
    adminOnly: true,
    items: [
      { to: '/settings',    icon: Settings2,   label: 'Platform Settings' },
      { to: '/performance', icon: Activity,    label: 'Performance' },
      { to: '/logs',        icon: ScrollText,  label: 'Tool Logs' },
      { to: '/users',       icon: Users,       label: 'Users' },
    ],
  },
]

function Dropdown({ group, location }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  const isActive = group.items.some(i => location.pathname.startsWith(i.to))

  useEffect(() => {
    function handler(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className={`flex items-center gap-1 px-2.5 py-1 rounded-md text-[13px] transition-colors ${
          isActive
            ? 'text-brand-text font-semibold bg-gray-100'
            : 'text-gray-600 hover:text-brand-text hover:bg-gray-100 font-medium'
        }`}
      >
        {group.label}
        <ChevronDown size={11} className={`transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute top-full left-0 mt-2 w-48 bg-white border border-gray-200 rounded-xl shadow-card-md py-1.5 z-50 fade-in">
          {group.items.map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 text-[13px] transition-colors mx-1 rounded-md ${
                  isActive ? 'text-brand-text bg-gray-100 font-semibold' : 'text-gray-600 hover:text-brand-text hover:bg-gray-50 font-medium'
                }`
              }
            >
              <item.icon size={13} className="flex-shrink-0 text-gray-400" />
              {item.label}
            </NavLink>
          ))}
        </div>
      )}
    </div>
  )
}


const isAdmin = (user) => user?.role === 'admin'

export default function ModernLayout({ user, onLogout }) {
  const [theme, cycleTheme]           = useTheme()
  const [showShortcuts, setShowShortcuts] = useState(false)
  const [mobileOpen, setMobileOpen]   = useState(false)
  const navigate  = useNavigate()
  const location  = useLocation()
  const { caseId } = useParams()
  const { uploads } = useUpload()

  const [lastCaseId, setLastCaseId] = useState(() => localStorage.getItem('fo-last-case') || null)
  useEffect(() => {
    if (caseId) {
      localStorage.setItem('fo-last-case', caseId)
      setLastCaseId(caseId)
    }
  }, [caseId])
  const uploadCount = Object.keys(uploads).length
  const avgPct = uploadCount > 0
    ? Math.round(Object.values(uploads).reduce((s, u) => s + (u.pct || 0), 0) / uploadCount)
    : 0

  const [showNewCase, setShowNewCase] = useState(false)
  const [newCaseName, setNewCaseName] = useState('')
  const [newCaseCompany, setNewCaseCompany] = useState('')
  const [creating, setCreating] = useState(false)
  const [availableCompanies, setAvailableCompanies] = useState([])
  const newCaseRef = useRef(null)

  useEffect(() => {
    api.companies.list().then(d => setAvailableCompanies(d.companies || [])).catch(() => {})
  }, [])

  useEffect(() => {
    if (showNewCase) setTimeout(() => newCaseRef.current?.focus(), 50)
  }, [showNewCase])

  async function handleCreateCase(e) {
    e.preventDefault()
    if (!newCaseName.trim() || creating) return
    setCreating(true)
    try {
      const c = await api.cases.create({ name: newCaseName.trim(), company: newCaseCompany })
      setNewCaseName('')
      setNewCaseCompany('')
      setShowNewCase(false)
      localStorage.setItem('fo-last-case', c.case_id)
      setLastCaseId(c.case_id)
      navigate(`/cases/${c.case_id}`)
    } catch { /* ignore */ }
    finally { setCreating(false) }
  }

  useKeyboardShortcuts([
    { key: 'g d', handler: () => navigate('/') },
    { key: 'g c', handler: () => navigate('/cases') },
    { key: 'g s', handler: () => navigate('/studio') },
    { key: 'g a', handler: () => navigate('/alert-rules') },
    { key: 'g t', handler: () => navigate('/cti') },
    { key: 'g m', handler: () => navigate('/modules') },
    { key: 'g n', handler: () => setShowNewCase(true) },
    { key: 'shift+/', handler: () => setShowShortcuts(v => !v) },
    { key: 'escape', handler: () => setShowShortcuts(false) },
  ])

  const refreshCases = () => {}

  useEffect(() => { setMobileOpen(false) }, [location.pathname])

  const logoFilter = theme === 'dark' ? 'invert(1) brightness(2)' : 'none'

  return (
    <div className="flex flex-col h-screen bg-gray-50">

      {/* ── Top bar ──────────────────────────────────────────────────────────── */}
      <header className="bg-white/85 backdrop-blur-md border-b border-gray-200 h-14 flex items-center gap-2 px-3 sm:px-4 md:px-6 flex-shrink-0 z-40 relative">

        <NavLink to="/" className="flex items-center mr-2 md:mr-4 flex-shrink-0">
          <img src="/logo.svg" alt="Citadel" style={{ height: '34px', filter: logoFilter }} className="object-contain" />
        </NavLink>

        {/* ── Desktop nav ────────────────────────────────────────────────── */}
        <nav className="hidden md:flex items-center gap-1 flex-1">
          <NavLink
            to={HOME_ITEM.to}
            end={HOME_ITEM.end}
            className={({ isActive }) =>
              `flex items-center px-2.5 py-1 rounded-md text-[13px] transition-colors ${
                isActive
                  ? 'text-brand-text font-semibold bg-gray-100'
                  : 'text-gray-600 hover:text-brand-text hover:bg-gray-100 font-medium'
              }`
            }
          >
            {HOME_ITEM.label}
          </NavLink>

          {lastCaseId && (
            <NavLink
              to={`/cases/${lastCaseId}`}
              className={({ isActive }) =>
                `flex items-center px-2.5 py-1 rounded-md text-[13px] transition-colors ${
                  isActive
                    ? 'text-brand-text font-semibold bg-gray-100'
                    : 'text-gray-600 hover:text-brand-text hover:bg-gray-100 font-medium'
                }`
              }
              title="Active case"
            >
              Case
            </NavLink>
          )}

          {DROPDOWN_GROUPS.filter(g => !g.adminOnly || isAdmin(user)).map((group, gi) => (
            <Dropdown key={gi} group={group} location={location} />
          ))}
        </nav>

        {/* ── Right side ─────────────────────────────────────────────────── */}
        <div className="flex items-center gap-0.5 ml-auto flex-shrink-0">

          {/* New case */}
          {showNewCase ? (
            <form onSubmit={handleCreateCase} className="flex items-center gap-1.5 mr-1">
              <input
                ref={newCaseRef}
                value={newCaseName}
                onChange={e => setNewCaseName(e.target.value)}
                onKeyDown={e => e.key === 'Escape' && setShowNewCase(false)}
                placeholder="Case name…"
                className="h-8 px-2.5 text-[13px] border border-gray-200 rounded-md focus:outline-none focus:border-gray-400 focus:ring-2 focus:ring-gray-200 w-40 transition-all"
              />
              {availableCompanies.length > 0 ? (
                <select
                  value={newCaseCompany}
                  onChange={e => setNewCaseCompany(e.target.value)}
                  className="h-8 px-2 text-[13px] border border-gray-200 rounded-md focus:outline-none focus:border-gray-400 bg-white w-32"
                >
                  <option value="">No company</option>
                  {availableCompanies.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              ) : null}
              <button type="submit" disabled={creating}
                className="h-8 px-3 text-[13px] font-medium bg-brand-accent text-white rounded-md hover:bg-brand-accenthover transition-colors disabled:opacity-50"
              >
                {creating ? <Loader2 size={12} className="animate-spin" /> : 'Create'}
              </button>
              <button type="button" onClick={() => setShowNewCase(false)}
                className="h-8 w-8 flex items-center justify-center rounded-md text-gray-500 hover:text-brand-text hover:bg-gray-100"
              >
                <X size={14} />
              </button>
            </form>
          ) : (
            <button onClick={() => setShowNewCase(true)}
              className="hidden md:flex items-center gap-1.5 h-8 px-3 text-[13px] font-medium text-gray-600 hover:text-brand-text hover:bg-gray-100 rounded-md transition-colors mr-1"
              title="New case (g n)"
            >
              <Plus size={13} /> New case
            </button>
          )}

          {/* Cmd-K palette hint — clicking dispatches the same shortcut event */}
          <button
            type="button"
            onClick={() => window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true }))}
            className="hidden md:inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border border-gray-200 text-[12px] text-gray-500 hover:text-brand-text hover:border-gray-300 hover:bg-gray-50 transition-colors"
            title="Search and navigate (⌘K)"
          >
            <Search size={12} />
            <span className="hidden lg:inline">Search</span>
            <kbd className="kbd ml-1">⌘K</kbd>
          </button>

          {uploadCount > 0 && (
            <div className="hidden md:flex items-center gap-1.5 px-2.5 h-7 rounded-full bg-gray-100">
              <Loader2 size={11} className="animate-spin text-brand-text" />
              <span className="text-[11px] text-gray-600 font-medium tabular-nums">{avgPct}%</span>
            </div>
          )}

          <div className="hidden md:block w-px h-5 bg-gray-200 mx-1.5" />

          <NavLink to="/account"
            className={({ isActive }) =>
              `w-8 h-8 flex items-center justify-center rounded-md transition-colors ${
                isActive ? 'text-brand-text bg-gray-100' : 'text-gray-500 hover:text-brand-text hover:bg-gray-100'
              }`
            }
            title="Account"
          >
            <UserCircle size={15} />
          </NavLink>

          <button onClick={cycleTheme}
            className="w-8 h-8 flex items-center justify-center rounded-md text-gray-500 hover:text-brand-text hover:bg-gray-100 transition-colors"
            title={theme === 'light' ? 'Dark mode' : 'Light mode'}
          >
            {theme === 'light' ? <Moon size={15} /> : <Sun size={15} />}
          </button>

          <button onClick={() => setShowShortcuts(v => !v)}
            className="hidden md:flex w-8 h-8 items-center justify-center rounded-md text-gray-500 hover:text-brand-text hover:bg-gray-100 transition-colors"
            title="Keyboard shortcuts (?)"
          >
            <span className="text-[12px] font-mono font-semibold">?</span>
          </button>

          {user && (
            <>
              <div className="hidden md:block w-px h-5 bg-gray-200 mx-1.5" />
              <div className="hidden md:flex items-center gap-2 px-2 py-1 rounded-md">
                <div className="w-6 h-6 rounded-full bg-gray-900 text-white flex items-center justify-center text-[10px] font-semibold uppercase">
                  {(user.username || '?').slice(0, 2)}
                </div>
                <span className="text-[12px] text-gray-700 font-medium max-w-[90px] truncate">{user.username}</span>
              </div>
              <button onClick={onLogout} title="Sign out"
                className="w-8 h-8 flex items-center justify-center rounded-md text-gray-500 hover:text-brand-text hover:bg-gray-100 transition-colors"
              >
                <LogOut size={14} />
              </button>
            </>
          )}

          <button onClick={() => setMobileOpen(v => !v)}
            className="md:hidden w-8 h-8 flex items-center justify-center rounded-md text-gray-500 hover:text-brand-text"
          >
            {mobileOpen ? <X size={16} /> : <Menu size={16} />}
          </button>
        </div>
      </header>

      {/* ── Mobile nav drawer ────────────────────────────────────────────────── */}
      {mobileOpen && (
        <div className="md:hidden fixed inset-0 top-12 z-30 bg-white overflow-y-auto py-3 px-2 border-t border-gray-200">
          {[
            HOME_ITEM,
            ...(lastCaseId ? [{ to: `/cases/${lastCaseId}`, icon: FolderOpen, label: 'Case' }] : []),
            ...DROPDOWN_GROUPS.filter(g => !g.adminOnly || isAdmin(user)).flatMap(g => g.items),
            { to: '/account', icon: UserCircle, label: 'Account' },
          ].map(item => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive ? 'text-gray-900 bg-gray-100' : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50'
                }`
              }
            >
              <item.icon size={14} />
              {item.label}
            </NavLink>
          ))}
        </div>
      )}

      {/* ── Body ─────────────────────────────────────────────────────────────── */}
      <div className="flex flex-1 min-h-0">
        <main className="flex-1 overflow-y-auto min-w-0">
          <div className="w-full h-full fade-in">
            <Outlet context={{ refreshCases, user }} />
          </div>
        </main>
      </div>

      {showShortcuts && <KeyboardShortcutsModal onClose={() => setShowShortcuts(false)} />}
      <CommandPalette />
    </div>
  )
}
