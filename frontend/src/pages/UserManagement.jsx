import { useState, useEffect } from 'react'
import { Users, Plus, Trash2, Pencil, Key, Shield, ShieldCheck, Loader2, Check, X, UserCircle, AlertTriangle, Building2, Code2, Eye, UsersRound, KeySquare, Layers, Wand2 } from 'lucide-react'
import { PageShell, PageHeader } from '../components/shared/PageShell'
import { api } from '../api/client'
import { formatDate } from '../utils/format'
import SharedModal from '../components/shared/Modal'

/* ── Shared company hooks ─────────────────────────────────────────────────── */

// Module-level cache: all components share a single request per page load.
let _companiesPromise = null

export function useCompanies() {
  const [companies, setCompanies] = useState([])
  useEffect(() => {
    if (!_companiesPromise) {
      _companiesPromise = api.companies.list().catch(() => ({ companies: [] }))
    }
    _companiesPromise.then(d => setCompanies(d.companies || []))
  }, [])
  return companies
}

/* ── Helpers ──────────────────────────────────────────────────────────────── */

function cachedUser() {
  try { return JSON.parse(localStorage.getItem('fo_user')) } catch { return null }
}

const fmtDate = iso => formatDate(iso, 'date', '-')

/* ── Modal shell ──────────────────────────────────────────────────────────── */

function Modal({ open, onClose, title, children, wide = false }) {
  if (!open) return null
  return (
    <SharedModal
      onClose={onClose}
      overlayClassName="fixed inset-0 z-50 flex items-center justify-center bg-black/30"
      className={`card p-5 w-full ${wide ? 'max-w-2xl' : 'max-w-md'} mx-4 space-y-4 max-h-[90vh] overflow-y-auto`}
      ariaLabel={title}
    >
      <>
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-brand-text">{title}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-600"><X size={16} /></button>
        </div>
        {children}
      </>
    </SharedModal>
  )
}

/* ── Role badge ───────────────────────────────────────────────────────────── */

const ROLE_META = {
  admin:     { color: 'bg-purple-100 text-purple-700', icon: ShieldCheck },
  analyst:   { color: 'bg-blue-100 text-blue-700',     icon: Shield },
  developer: { color: 'bg-amber-100 text-amber-700',   icon: Code2 },
  guest:     { color: 'bg-gray-100 text-gray-500',     icon: Eye },
}

function RoleBadge({ role }) {
  const meta = ROLE_META[role] || ROLE_META.analyst
  const Icon = meta.icon
  return (
    <span className={`badge ${meta.color} gap-1`}>
      <Icon size={11} /> {role}
    </span>
  )
}

/* ── Stats card ───────────────────────────────────────────────────────────── */

function StatCard({ label, value, color = 'text-brand-text' }) {
  return (
    <div className="card p-3 text-center">
      <p className={`text-xl font-bold ${color}`}>{value}</p>
      <p className="text-[11px] text-gray-500 mt-0.5">{label}</p>
    </div>
  )
}

/* ── RBAC reusable bits ───────────────────────────────────────────────────── */

// Checkbox list bound to an array of selected string ids.
function CheckboxList({ options, selected, onChange, getId = o => o, getLabel = o => o, getDesc, maxHeight = 'max-h-36', empty }) {
  if (!options || options.length === 0) {
    return <p className="text-xs text-gray-500 italic">{empty || 'Nothing available.'}</p>
  }
  return (
    <div className={`space-y-1 ${maxHeight} overflow-y-auto border border-gray-200 rounded-lg px-3 py-2`}>
      {options.map(o => {
        const id = getId(o)
        const checked = selected.includes(id)
        return (
          <label key={id} className="flex items-start gap-2 text-xs text-gray-700 cursor-pointer hover:bg-gray-50 rounded px-1 py-0.5">
            <input
              type="checkbox"
              checked={checked}
              onChange={e => onChange(e.target.checked ? [...selected, id] : selected.filter(x => x !== id))}
              className="mt-0.5 rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
            />
            <span>
              <span className="font-medium">{getLabel(o)}</span>
              {getDesc && getDesc(o) && <span className="text-gray-400 ml-1">— {getDesc(o)}</span>}
            </span>
          </label>
        )
      })}
    </div>
  )
}

// Comma/tag style input backed by a string array.
function TagInput({ value, onChange, placeholder }) {
  const [draft, setDraft] = useState('')
  function commit() {
    const v = draft.trim()
    if (v && !value.includes(v)) onChange([...value, v])
    setDraft('')
  }
  return (
    <div className="border border-gray-200 rounded-lg px-2 py-1.5 flex flex-wrap gap-1 items-center">
      {value.map(t => (
        <span key={t} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px] gap-1">
          {t}
          <button type="button" onClick={() => onChange(value.filter(x => x !== t))} className="text-cyan-400 hover:text-red-500"><X size={10} /></button>
        </span>
      ))}
      <input
        className="flex-1 min-w-[100px] text-xs outline-none bg-transparent py-0.5"
        placeholder={placeholder || 'Type and press Enter…'}
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onKeyDown={e => {
          if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); commit() }
          else if (e.key === 'Backspace' && !draft && value.length) onChange(value.slice(0, -1))
        }}
        onBlur={commit}
      />
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════ */

export default function UserManagement() {
  const [me, setMe] = useState(cachedUser)  // seed from cache, verified via API below

  /* ── State ── */
  const [tab, setTab]           = useState('users')   // 'users' | 'groups'
  const [users, setUsers]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState('')

  // RBAC: permission catalog + groups
  const [catalog, setCatalog]   = useState({ permissions: [], roles: [], role_presets: {} })
  const [groups, setGroups]     = useState([])
  const [groupsLoading, setGroupsLoading] = useState(false)
  const [groupsError, setGroupsError]     = useState('')

  // Group editor (create or edit). null = closed.
  const [groupTarget, setGroupTarget] = useState(null) // null | {} (new) | existing group
  const [groupForm, setGroupForm]     = useState({ name: '', description: '', roles: [], permissions: [], companies: [], members: [] })
  const [groupSaving, setGroupSaving] = useState(false)
  const [groupErr, setGroupErr]       = useState('')

  // Companies registry
  const [companyList, setCompanyList]   = useState([])
  const [newCompany, setNewCompany]     = useState('')
  const [addingCo, setAddingCo]         = useState(false)
  const [coError, setCoError]           = useState('')

  // Create user
  const [showCreate, setShowCreate]   = useState(false)
  const [createForm, setCreateForm]   = useState({ username: '', password: '', role: 'analyst', companiesInput: '', groups: [], extra_permissions: [] })
  const [creating, setCreating]       = useState(false)
  const [createErr, setCreateErr]     = useState('')

  // Unified user editor (role + groups + extra permissions + effective access)
  const [userTarget, setUserTarget]   = useState(null) // existing user object | null
  const [userForm, setUserForm]       = useState({ role: 'analyst', groups: [], extra_permissions: [] })
  const [userSaving, setUserSaving]   = useState(false)
  const [userErr, setUserErr]         = useState('')
  const [effective, setEffective]     = useState(null)   // userEffective() result
  const [effLoading, setEffLoading]   = useState(false)

  // Edit role
  const [editTarget, setEditTarget]     = useState(null) // { username, role }
  const [editRole, setEditRole]         = useState('analyst')
  const [editingSave, setEditingSave]   = useState(false)
  const [editErr, setEditErr]           = useState('')

  // Edit companies
  const [companiesTarget, setCompaniesTarget]   = useState(null) // { username, companies }
  const [companiesInput, setCompaniesInput]     = useState('') // comma-separated string
  const [companiesSaving, setCompaniesSaving]   = useState(false)
  const [companiesErr, setCompaniesErr]         = useState('')
  const [editCoSearch, setEditCoSearch]         = useState('')

  // Company search in create modal
  const [createCoSearch, setCreateCoSearch]     = useState('')

  // Reset password
  const [resetTarget, setResetTarget]     = useState(null) // username
  const [resetPw, setResetPw]             = useState('')
  const [resetting, setResetting]         = useState(false)
  const [resetErr, setResetErr]           = useState('')

  // Change own password
  const [ownPw, setOwnPw]         = useState({ old_password: '', new_password: '', confirm: '' })
  const [changingPw, setChangingPw] = useState(false)
  const [pwMsg, setPwMsg]           = useState({ ok: false, text: '' })

  /* ── Load users + companies ── */
  useEffect(() => {
    api.companies.list().then(d => setCompanyList(d.companies || [])).catch(() => {})
    // Always verify role from server — localStorage may be stale
    api.auth.me()
      .then(user => {
        setMe(user)
        localStorage.setItem('fo_user', JSON.stringify(user))
        if (user?.role === 'admin') { loadUsers(); loadRbac() }
        else setLoading(false)
      })
      .catch(() => {
        // Fall back to cached value
        if (me?.role === 'admin') { loadUsers(); loadRbac() }
        else setLoading(false)
      })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  async function loadRbac() {
    try {
      const cat = await api.auth.permissionCatalog()
      setCatalog({
        permissions: cat.permissions || [],
        roles: cat.roles || [],
        role_presets: cat.role_presets || {},
      })
    } catch {}
    loadGroups()
  }

  async function loadGroups() {
    setGroupsLoading(true)
    setGroupsError('')
    try {
      const d = await api.auth.listGroups()
      setGroups(d.groups || [])
    } catch (err) {
      setGroupsError(err.message)
    } finally {
      setGroupsLoading(false)
    }
  }

  async function loadCompanies() {
    try {
      const d = await api.companies.list()
      setCompanyList(d.companies || [])
    } catch {}
  }

  async function handleAddCompany(e) {
    e.preventDefault()
    if (!newCompany.trim()) return
    setAddingCo(true)
    setCoError('')
    try {
      const d = await api.companies.add(newCompany.trim())
      setCompanyList(d.companies || [])
      setNewCompany('')
    } catch (err) {
      setCoError(err.message)
    } finally {
      setAddingCo(false)
    }
  }

  async function handleDeleteCompany(name) {
    if (!confirm(`Remove company "${name}"? Users restricted to this company will lose their restriction.`)) return
    try {
      const d = await api.companies.remove(name)
      setCompanyList(d.companies || [])
    } catch (err) {
      setCoError(err.message)
    }
  }

  async function loadUsers() {
    setLoading(true)
    setError('')
    try {
      const data = await api.auth.listUsers()
      setUsers(data.users || [])
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  /* ── Create user ── */
  async function handleCreate(e) {
    e.preventDefault()
    setCreating(true)
    setCreateErr('')
    try {
      const companies = createForm.companiesInput
        ? createForm.companiesInput.split(',').map(s => s.trim()).filter(Boolean)
        : []
      await api.auth.createUser({
        username: createForm.username,
        password: createForm.password,
        role: createForm.role,
        companies,
        groups: createForm.groups,
        extra_permissions: createForm.extra_permissions,
      })
      setShowCreate(false)
      setCreateForm({ username: '', password: '', role: 'analyst', companiesInput: '', groups: [], extra_permissions: [] })
      setCreateCoSearch('')
      await loadUsers()
    } catch (err) {
      setCreateErr(err.message)
    } finally {
      setCreating(false)
    }
  }

  /* ── Edit role ── */
  function openEditRole(u) {
    setEditTarget(u)
    setEditRole(u.role)
    setEditErr('')
  }

  async function handleEditRole(e) {
    e.preventDefault()
    setEditingSave(true)
    setEditErr('')
    try {
      await api.auth.updateUser(editTarget.username, { role: editRole })
      setEditTarget(null)
      await loadUsers()
    } catch (err) {
      setEditErr(err.message)
    } finally {
      setEditingSave(false)
    }
  }

  /* ── Unified user editor (role + groups + extra permissions) ── */
  function openUserEditor(u) {
    setUserTarget(u)
    setUserForm({
      role: u.role,
      groups: (u.groups || []).slice(),
      extra_permissions: (u.extra_permissions || []).slice(),
    })
    setUserErr('')
    setEffective(null)
    // Load resolved effective access
    setEffLoading(true)
    api.auth.userEffective(u.username)
      .then(setEffective)
      .catch(() => {})
      .finally(() => setEffLoading(false))
  }

  async function handleSaveUser(e) {
    e.preventDefault()
    setUserSaving(true)
    setUserErr('')
    try {
      await api.auth.updateUser(userTarget.username, {
        role: userForm.role,
        groups: userForm.groups,
        extra_permissions: userForm.extra_permissions,
      })
      setUserTarget(null)
      await loadUsers()
    } catch (err) {
      setUserErr(err.message)
    } finally {
      setUserSaving(false)
    }
  }

  /* ── Group editor ── */
  function openGroupEditor(g) {
    setGroupTarget(g || {})
    setGroupForm(g ? {
      name: g.name || '',
      description: g.description || '',
      roles: (g.roles || []).slice(),
      permissions: (g.permissions || []).slice(),
      companies: (g.companies || []).slice(),
      members: (g.members || []).slice(),
    } : { name: '', description: '', roles: [], permissions: [], companies: [], members: [] })
    setGroupErr('')
  }

  async function handleSaveGroup(e) {
    e.preventDefault()
    setGroupSaving(true)
    setGroupErr('')
    try {
      const payload = {
        name: groupForm.name.trim(),
        description: groupForm.description,
        roles: groupForm.roles,
        permissions: groupForm.permissions,
        companies: groupForm.companies,
        members: groupForm.members,
      }
      if (groupTarget?.id) await api.auth.updateGroup(groupTarget.id, payload)
      else await api.auth.createGroup(payload)
      setGroupTarget(null)
      await loadGroups()
      await loadUsers()  // group membership may have changed
    } catch (err) {
      setGroupErr(err.message)
    } finally {
      setGroupSaving(false)
    }
  }

  async function handleDeleteGroup(g) {
    if (!confirm(`Delete group "${g.name}"? Members will lose the access it grants.`)) return
    try {
      await api.auth.deleteGroup(g.id)
      await loadGroups()
      await loadUsers()
    } catch (err) {
      setGroupsError(err.message)
    }
  }

  // Fill the group permission set from a role's preset (union, no removals).
  function fillFromPreset(role) {
    const preset = catalog.role_presets?.[role] || []
    setGroupForm(f => ({ ...f, permissions: Array.from(new Set([...f.permissions, ...preset])) }))
  }

  /* ── Edit companies ── */
  function openEditCompanies(u) {
    setCompaniesTarget(u)
    setCompaniesInput((u.companies || []).join(', '))
    setCompaniesErr('')
    setEditCoSearch('')
  }

  async function handleEditCompanies(e) {
    e.preventDefault()
    setCompaniesSaving(true)
    setCompaniesErr('')
    try {
      const companies = companiesInput
        ? companiesInput.split(',').map(s => s.trim()).filter(Boolean)
        : []
      await api.auth.setUserCompanies(companiesTarget.username, companies)
      setCompaniesTarget(null)
      await loadUsers()
    } catch (err) {
      setCompaniesErr(err.message)
    } finally {
      setCompaniesSaving(false)
    }
  }

  /* ── Reset password ── */
  async function handleResetPw(e) {
    e.preventDefault()
    setResetting(true)
    setResetErr('')
    try {
      await api.auth.updateUser(resetTarget, { password: resetPw })
      setResetTarget(null)
      setResetPw('')
    } catch (err) {
      setResetErr(err.message)
    } finally {
      setResetting(false)
    }
  }

  /* ── Delete user ── */
  async function handleDelete(username) {
    if (!confirm(`Delete user "${username}"? This cannot be undone.`)) return
    try {
      await api.auth.deleteUser(username)
      await loadUsers()
    } catch (err) {
      setError(err.message)
    }
  }

  /* ── Change own password ── */
  async function handleChangePw(e) {
    e.preventDefault()
    if (ownPw.new_password !== ownPw.confirm) {
      setPwMsg({ ok: false, text: 'New passwords do not match.' })
      return
    }
    setChangingPw(true)
    setPwMsg({ ok: false, text: '' })
    try {
      await api.auth.changePassword({
        old_password: ownPw.old_password,
        new_password: ownPw.new_password,
      })
      setOwnPw({ old_password: '', new_password: '', confirm: '' })
      setPwMsg({ ok: true, text: 'Password changed successfully.' })
      setTimeout(() => setPwMsg({ ok: false, text: '' }), 4000)
    } catch (err) {
      setPwMsg({ ok: false, text: err.message })
    } finally {
      setChangingPw(false)
    }
  }

  const isAdmin = me?.role === 'admin'

  /* ── Render helpers ── */
  function renderChangePasswordForm() {
    return (
      <form onSubmit={handleChangePw} className="space-y-3">
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Current Password</label>
          <input
            type="password"
            className="input text-xs"
            placeholder="Enter current password"
            value={ownPw.old_password}
            onChange={e => setOwnPw(f => ({ ...f, old_password: e.target.value }))}
            required
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">
            New Password <span className="text-gray-500 font-normal">(min. 8 characters)</span>
          </label>
          <input
            type="password"
            className="input text-xs"
            placeholder="Enter new password (min. 8 characters)"
            value={ownPw.new_password}
            onChange={e => setOwnPw(f => ({ ...f, new_password: e.target.value }))}
            minLength={8}
            required
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-600 mb-1">Confirm New Password</label>
          <input
            type="password"
            className="input text-xs"
            placeholder="Confirm new password"
            value={ownPw.confirm}
            onChange={e => setOwnPw(f => ({ ...f, confirm: e.target.value }))}
            required
          />
        </div>

        {pwMsg.text && (
          <p className={`text-xs rounded-lg px-3 py-2 flex items-center gap-1.5 ${
            pwMsg.ok
              ? 'text-green-700 bg-green-50 border border-green-200'
              : 'text-red-600 bg-red-50 border border-red-200'
          }`}>
            {pwMsg.ok ? <Check size={12} /> : <X size={12} />} {pwMsg.text}
          </p>
        )}

        <button type="submit" disabled={changingPw} className="btn-primary text-xs">
          {changingPw ? <Loader2 size={13} className="animate-spin" /> : <Key size={13} />}
          Change Password
        </button>
      </form>
    )
  }

  /* ── Derived stats ── */
  const roleCounts = Object.fromEntries(
    Object.keys(ROLE_META).map(r => [r, users.filter(u => u.role === r).length])
  )

  /* ── Main render ── */
  return (
    <PageShell>

      {/* Header */}
      <PageHeader
        title="Users"
        icon={Users}
        subtitle={isAdmin ? 'Create, edit, and remove platform users.' : 'View platform users and manage your account.'}
      />

      {/* Stats bar — admin only */}
      {isAdmin && !loading && users.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
          <StatCard label="Total Users" value={users.length} color="text-brand-accent" />
          <StatCard label="Admins"      value={roleCounts.admin}     color="text-purple-600" />
          <StatCard label="Analysts"    value={roleCounts.analyst}   color="text-blue-600" />
          <StatCard label="Developers"  value={roleCounts.developer} color="text-amber-600" />
          <StatCard label="Companies"   value={companyList.length}   color="text-cyan-500" />
        </div>
      )}

      {/* User list — admin only */}
      {!isAdmin && (
        <div className="card p-5 mb-6 flex items-start gap-3 bg-amber-50 border border-amber-200">
          <AlertTriangle size={16} className="text-amber-500 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-amber-700">
            Logged in as <strong>{me?.username}</strong> ({me?.role}). Admin access required to manage users.
          </p>
        </div>
      )}

      {/* Tabs — admin only */}
      {isAdmin && (
        <div className="flex items-center gap-1 mb-4 border-b border-gray-200">
          {[
            { id: 'users',  label: 'Users',  icon: Users },
            { id: 'groups', label: 'Groups', icon: UsersRound },
          ].map(t => {
            const Icon = t.icon
            const active = tab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setTab(t.id)}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                  active ? 'border-brand-accent text-brand-accent' : 'border-transparent text-gray-500 hover:text-brand-text'
                }`}
              >
                <Icon size={14} /> {t.label}
                {t.id === 'groups' && groups.length > 0 && (
                  <span className="text-[10px] bg-gray-100 text-gray-500 rounded-full px-1.5">{groups.length}</span>
                )}
              </button>
            )
          })}
        </div>
      )}

      {isAdmin && tab === 'users' && <section className="card">
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-100">
          <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Users</span>
          <button onClick={() => { setShowCreate(true); setCreateErr('') }} className="btn-primary text-xs">
            <Plus size={13} /> New User
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 text-gray-500 py-12">
            <Loader2 size={14} className="animate-spin" /> Loading users...
          </div>
        ) : error ? (
          <div className="text-xs text-red-600 bg-red-50 border-t border-red-100 px-5 py-4 flex items-center gap-1.5">
            <AlertTriangle size={12} /> {error}
          </div>
        ) : users.length === 0 ? (
          <div className="text-sm text-gray-500 text-center py-12">No users found.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-5 py-2.5 font-medium">Username</th>
                  <th className="px-5 py-2.5 font-medium">Role</th>
                  <th className="px-5 py-2.5 font-medium">Groups</th>
                  <th className="px-5 py-2.5 font-medium">Companies</th>
                  <th className="px-5 py-2.5 font-medium">Created</th>
                  <th className="px-5 py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {users.map(u => (
                  <tr key={u.username} className="hover:bg-gray-50/50 transition-colors">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <UserCircle size={16} className="text-gray-500" />
                        <span className="font-medium text-brand-text">{u.username}</span>
                        {u.username === me?.username && (
                          <span className="text-[10px] text-gray-500 bg-gray-100 rounded-full px-1.5 py-0.5">you</span>
                        )}
                      </div>
                    </td>
                    <td className="px-5 py-3"><RoleBadge role={u.role} /></td>
                    <td className="px-5 py-3">
                      {(u.groups || []).length === 0 ? (
                        <span className="text-xs text-gray-400 italic">—</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {(u.groups || []).map(g => {
                            const grp = groups.find(x => x.id === g || x.name === g)
                            return (
                              <span key={g} className="badge bg-indigo-50 text-indigo-700 border border-indigo-200 text-[10px]">
                                {grp?.name || g}
                              </span>
                            )
                          })}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-3">
                      {u.role === 'admin' ? (
                        <span className="text-xs text-gray-500 italic">all (admin)</span>
                      ) : u.role === 'guest' ? (
                        <span className="text-xs text-gray-500 italic">read-only</span>
                      ) : (u.companies || []).length === 0 ? (
                        <span className="text-xs text-gray-500 italic">all</span>
                      ) : (
                        <div className="flex flex-wrap gap-1">
                          {(u.companies || []).map(c => (
                            <span key={c} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px]">{c}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-3 text-gray-500 text-xs">{fmtDate(u.created_at)}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openUserEditor(u)}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Edit role, groups & permissions"
                        >
                          <Pencil size={12} />
                        </button>
                        <button
                          onClick={() => openEditCompanies(u)}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Edit company access"
                          disabled={u.role === 'admin' || u.role === 'guest'}
                        >
                          <Building2 size={12} />
                        </button>
                        <button
                          onClick={() => { setResetTarget(u.username); setResetPw(''); setResetErr('') }}
                          className="btn-ghost text-xs py-1 px-2"
                          title="Reset password"
                        >
                          <Key size={12} />
                        </button>
                        <button
                          onClick={() => handleDelete(u.username)}
                          disabled={u.username === me?.username}
                          className="btn-ghost text-xs py-1 px-2 text-red-500 hover:text-red-700 disabled:opacity-30"
                          title={u.username === me?.username ? 'Cannot delete yourself' : 'Delete user'}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>}

      {/* ── Groups tab ── */}
      {isAdmin && tab === 'groups' && <section className="card">
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-100">
          <span className="text-xs font-medium text-gray-500 uppercase tracking-wider">Groups</span>
          <button onClick={() => openGroupEditor(null)} className="btn-primary text-xs">
            <Plus size={13} /> New Group
          </button>
        </div>

        {groupsLoading ? (
          <div className="flex items-center justify-center gap-2 text-gray-500 py-12">
            <Loader2 size={14} className="animate-spin" /> Loading groups...
          </div>
        ) : groupsError ? (
          <div className="text-xs text-red-600 bg-red-50 border-t border-red-100 px-5 py-4 flex items-center gap-1.5">
            <AlertTriangle size={12} /> {groupsError}
          </div>
        ) : groups.length === 0 ? (
          <div className="text-sm text-gray-500 text-center py-12">No groups defined yet.</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <th className="px-5 py-2.5 font-medium">Name</th>
                  <th className="px-5 py-2.5 font-medium">Roles</th>
                  <th className="px-5 py-2.5 font-medium">Permissions</th>
                  <th className="px-5 py-2.5 font-medium">Companies</th>
                  <th className="px-5 py-2.5 font-medium">Members</th>
                  <th className="px-5 py-2.5 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {groups.map(g => (
                  <tr key={g.id} className="hover:bg-gray-50/50 transition-colors">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <Layers size={15} className="text-indigo-500" />
                        <div>
                          <div className="font-medium text-brand-text">{g.name}</div>
                          {g.description && <div className="text-[11px] text-gray-400">{g.description}</div>}
                        </div>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      {(g.roles || []).length === 0 ? <span className="text-xs text-gray-400 italic">—</span> : (
                        <div className="flex flex-wrap gap-1">{(g.roles || []).map(r => <RoleBadge key={r} role={r} />)}</div>
                      )}
                    </td>
                    <td className="px-5 py-3 text-gray-500 text-xs">
                      <span className="badge bg-gray-100 text-gray-600">{(g.permissions || []).length} perms</span>
                    </td>
                    <td className="px-5 py-3">
                      {(g.companies || []).length === 0 ? <span className="text-xs text-gray-400 italic">all</span> : (
                        <div className="flex flex-wrap gap-1">
                          {(g.companies || []).map(c => <span key={c} className="badge bg-cyan-50 text-cyan-700 border border-cyan-200 text-[10px]">{c}</span>)}
                        </div>
                      )}
                    </td>
                    <td className="px-5 py-3 text-gray-500 text-xs">{(g.members || []).length}</td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button onClick={() => openGroupEditor(g)} className="btn-ghost text-xs py-1 px-2" title="Edit group">
                          <Pencil size={12} />
                        </button>
                        <button onClick={() => handleDeleteGroup(g)} className="btn-ghost text-xs py-1 px-2 text-red-500 hover:text-red-700" title="Delete group">
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>}

      {/* Companies registry — visible to all, editable by admin */}
      <section className="card mt-6">
        <div className="flex items-center justify-between px-5 py-3 border-b border-gray-100">
          <div className="flex items-center gap-2">
            <Building2 size={15} className="text-cyan-500" />
            <span className="font-semibold text-brand-text text-sm">Companies</span>
          </div>
          <span className="text-xs text-gray-500">Used for case assignment and analyst access scoping</span>
        </div>
        <div className="px-5 py-4 space-y-3">
          {companyList.length === 0 ? (
            <p className="text-xs text-gray-500 italic">No companies defined yet.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {companyList.map(c => (
                <div key={c} className="flex items-center gap-1 badge bg-cyan-50 text-cyan-700 border border-cyan-200">
                  <span className="text-xs">{c}</span>
                  {isAdmin && (
                    <button
                      onClick={() => handleDeleteCompany(c)}
                      className="text-cyan-400 hover:text-red-500 transition-colors ml-0.5"
                      title={`Remove ${c}`}
                    >
                      <X size={10} />
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
          {isAdmin && (
            <form onSubmit={handleAddCompany} className="flex items-center gap-2">
              <input
                className="input text-xs flex-1"
                placeholder="New company name…"
                value={newCompany}
                onChange={e => setNewCompany(e.target.value)}
              />
              <button type="submit" disabled={addingCo || !newCompany.trim()} className="btn-primary text-xs">
                {addingCo ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />}
                Add
              </button>
            </form>
          )}
          {coError && (
            <p className="text-xs text-red-600 flex items-center gap-1"><AlertTriangle size={11} /> {coError}</p>
          )}
        </div>
      </section>

      {/* Change own password */}
      <section className="card p-5 space-y-4 mt-6">
        <div className="flex items-center gap-2">
          <Key size={15} className="text-amber-500" />
          <h2 className="font-semibold text-brand-text">Change My Password</h2>
        </div>
        <p className="text-xs text-gray-500">Update your own account password.</p>
        {renderChangePasswordForm()}
      </section>

      {/* ── Create User Modal ── */}
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create User">
        <form onSubmit={handleCreate} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Username</label>
            <input
              className="input text-xs"
              placeholder="e.g. jdoe"
              value={createForm.username}
              onChange={e => setCreateForm(f => ({ ...f, username: e.target.value }))}
              required
              autoFocus
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Password</label>
            <input
              type="password"
              className="input text-xs"
              placeholder="Temporary password"
              value={createForm.password}
              onChange={e => setCreateForm(f => ({ ...f, password: e.target.value }))}
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
            <select
              className="input text-xs"
              value={createForm.role}
              onChange={e => setCreateForm(f => ({ ...f, role: e.target.value }))}
            >
              <option value="analyst">Analyst — full access, no Studio</option>
              <option value="developer">Developer — Analyst + Studio</option>
              <option value="guest">Guest — read-only</option>
              <option value="admin">Admin — full access</option>
            </select>
          </div>
          {(createForm.role === 'analyst' || createForm.role === 'developer' || createForm.role === 'guest') && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">
                Company Access <span className="text-gray-500 font-normal">(none = unrestricted)</span>
              </label>
              {companyList.length === 0 ? (
                <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-3 py-2">
                  No companies defined. Add them in the Companies section first.
                </p>
              ) : (
                <>
                  {companyList.length > 6 && (
                    <input
                      className="input text-xs mb-1"
                      placeholder="Filter companies…"
                      value={createCoSearch}
                      onChange={e => setCreateCoSearch(e.target.value)}
                    />
                  )}
                  <div className="space-y-1.5 max-h-36 overflow-y-auto border border-gray-200 rounded-lg px-3 py-2">
                    {companyList
                      .filter(c => c.toLowerCase().includes(createCoSearch.toLowerCase()))
                      .map(c => {
                        const selected = createForm.companiesInput.split(',').map(s => s.trim()).filter(Boolean).includes(c)
                        return (
                          <label key={c} className="flex items-center gap-2 text-xs text-gray-700 cursor-pointer hover:bg-gray-50 rounded px-1 py-0.5">
                            <input
                              type="checkbox"
                              checked={selected}
                              onChange={e => {
                                const current = createForm.companiesInput.split(',').map(s => s.trim()).filter(Boolean)
                                const next = e.target.checked ? [...current, c] : current.filter(x => x !== c)
                                setCreateForm(f => ({ ...f, companiesInput: next.join(', ') }))
                              }}
                              className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
                            />
                            {c}
                          </label>
                        )
                      })}
                  </div>
                </>
              )}
            </div>
          )}

          {groups.length > 0 && (
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5">
                <UsersRound size={12} /> Groups <span className="text-gray-400 font-normal">(optional)</span>
              </label>
              <CheckboxList
                options={groups} selected={createForm.groups}
                onChange={v => setCreateForm(f => ({ ...f, groups: v }))}
                getId={g => g.id} getLabel={g => g.name} getDesc={g => g.description}
              />
            </div>
          )}

          {createErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {createErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={creating} className="btn-primary text-xs">
              {creating ? <Loader2 size={13} className="animate-spin" /> : <Plus size={13} />}
              Create User
            </button>
            <button type="button" onClick={() => setShowCreate(false)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Edit Role Modal ── */}
      <Modal open={!!editTarget} onClose={() => setEditTarget(null)} title={`Edit Role — ${editTarget?.username}`}>
        <form onSubmit={handleEditRole} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
            <select
              className="input text-xs"
              value={editRole}
              onChange={e => setEditRole(e.target.value)}
            >
              <option value="analyst">Analyst — full access, no Studio</option>
              <option value="developer">Developer — Analyst + Studio</option>
              <option value="guest">Guest — read-only</option>
              <option value="admin">Admin — full access</option>
            </select>
          </div>

          {editErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {editErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={editingSave} className="btn-primary text-xs">
              {editingSave ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
              Save
            </button>
            <button type="button" onClick={() => setEditTarget(null)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Edit Companies Modal ── */}
      <Modal open={!!companiesTarget} onClose={() => setCompaniesTarget(null)} title={`Company Access — ${companiesTarget?.username}`}>
        <form onSubmit={handleEditCompanies} className="space-y-3">
          <p className="text-xs text-gray-500">
            Select which companies this analyst can access. Leave all unchecked for unrestricted access.
          </p>
          {companyList.length === 0 ? (
            <p className="text-xs text-amber-600 bg-amber-50 border border-amber-200 rounded px-3 py-2">
              No companies defined yet. Add companies in the Companies section first.
            </p>
          ) : (
            <>
              {companyList.length > 6 && (
                <input
                  className="input text-xs"
                  placeholder="Filter companies…"
                  value={editCoSearch}
                  onChange={e => setEditCoSearch(e.target.value)}
                />
              )}
              <div className="space-y-1.5 max-h-48 overflow-y-auto border border-gray-200 rounded-lg px-3 py-2">
                {companyList
                  .filter(c => c.toLowerCase().includes(editCoSearch.toLowerCase()))
                  .map(c => {
                    const selected = companiesInput.split(',').map(s => s.trim()).filter(Boolean).includes(c)
                    return (
                      <label key={c} className="flex items-center gap-2 text-xs text-gray-700 cursor-pointer hover:bg-gray-50 px-2 py-1 rounded">
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={e => {
                            const current = companiesInput.split(',').map(s => s.trim()).filter(Boolean)
                            const next = e.target.checked ? [...current, c] : current.filter(x => x !== c)
                            setCompaniesInput(next.join(', '))
                          }}
                          className="rounded border-gray-300 text-brand-accent focus:ring-brand-accent"
                        />
                        {c}
                      </label>
                    )
                  })}
              </div>
            </>
          )}

          {companiesErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {companiesErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={companiesSaving} className="btn-primary text-xs">
              {companiesSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />}
              Save
            </button>
            <button type="button" onClick={() => setCompaniesTarget(null)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Reset Password Modal ── */}
      <Modal open={!!resetTarget} onClose={() => setResetTarget(null)} title={`Reset Password — ${resetTarget}`}>
        <form onSubmit={handleResetPw} className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">New Password</label>
            <input
              type="password"
              className="input text-xs"
              placeholder="Enter new password"
              value={resetPw}
              onChange={e => setResetPw(e.target.value)}
              required
              autoFocus
            />
          </div>

          {resetErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {resetErr}
            </p>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={resetting} className="btn-primary text-xs">
              {resetting ? <Loader2 size={13} className="animate-spin" /> : <Key size={13} />}
              Reset Password
            </button>
            <button type="button" onClick={() => setResetTarget(null)} className="btn-ghost text-xs">
              Cancel
            </button>
          </div>
        </form>
      </Modal>

      {/* ── Unified User Editor (role + groups + extra permissions) ── */}
      <Modal open={!!userTarget} onClose={() => setUserTarget(null)} wide
        title={`Edit — ${userTarget?.username}`}>
        <form onSubmit={handleSaveUser} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Role</label>
            <select className="input text-xs" value={userForm.role}
              onChange={e => setUserForm(f => ({ ...f, role: e.target.value }))}>
              <option value="analyst">Analyst — full access, no Studio</option>
              <option value="developer">Developer — Analyst + Studio</option>
              <option value="guest">Guest — read-only</option>
              <option value="admin">Admin — full access</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5">
              <UsersRound size={12} /> Groups
            </label>
            <CheckboxList
              options={groups} selected={userForm.groups}
              onChange={v => setUserForm(f => ({ ...f, groups: v }))}
              getId={g => g.id} getLabel={g => g.name} getDesc={g => g.description}
              empty="No groups defined yet — create one in the Groups tab."
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5">
              <KeySquare size={12} /> Extra permissions (on top of role + groups)
            </label>
            <CheckboxList
              options={catalog.permissions} selected={userForm.extra_permissions}
              onChange={v => setUserForm(f => ({ ...f, extra_permissions: v }))}
              getId={p => p.id || p} getLabel={p => p.id || p} getDesc={p => p.description}
            />
          </div>

          {/* Effective (resolved) access — read-only */}
          <div className="rounded-lg bg-gray-50 border border-gray-200 px-3 py-2 text-[11px]">
            <p className="font-semibold text-gray-600 mb-1 flex items-center gap-1.5">
              <Layers size={12} /> Effective access {effLoading && <Loader2 size={10} className="animate-spin" />}
            </p>
            {effective ? (
              <>
                <p className="text-gray-600"><span className="text-gray-400">Permissions:</span> {(effective._effective_perms || effective.permissions || []).join(', ') || '—'}</p>
                <p className="text-gray-600"><span className="text-gray-400">Companies:</span> {(effective._effective_companies || effective.companies || []).join(', ') || 'all (unrestricted)'}</p>
              </>
            ) : <p className="text-gray-400">{effLoading ? 'resolving…' : 'save to refresh'}</p>}
          </div>

          {userErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {userErr}
            </p>
          )}
          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={userSaving} className="btn-primary text-xs">
              {userSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />} Save
            </button>
            <button type="button" onClick={() => setUserTarget(null)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      </Modal>

      {/* ── Group Editor (create + edit) ── */}
      <Modal open={!!groupTarget} onClose={() => setGroupTarget(null)} wide
        title={groupTarget?.id ? `Edit Group — ${groupTarget.name}` : 'New Group'}>
        <form onSubmit={handleSaveGroup} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Name</label>
              <input className="input text-xs" value={groupForm.name} autoFocus
                onChange={e => setGroupForm(f => ({ ...f, name: e.target.value }))} required />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1">Description</label>
              <input className="input text-xs" value={groupForm.description}
                onChange={e => setGroupForm(f => ({ ...f, description: e.target.value }))} />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Roles granted</label>
            <CheckboxList
              options={catalog.roles} selected={groupForm.roles}
              onChange={v => setGroupForm(f => ({ ...f, roles: v }))}
              getId={r => r.id || r} getLabel={r => r.id || r}
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="text-xs font-medium text-gray-600 flex items-center gap-1.5"><KeySquare size={12} /> Permissions</label>
              <div className="flex items-center gap-1">
                <span className="text-[10px] text-gray-400">fill from:</span>
                {(catalog.roles || []).map(r => {
                  const rid = r.id || r
                  return (
                    <button key={rid} type="button" onClick={() => fillFromPreset(rid)}
                      className="text-[10px] px-1.5 py-0.5 rounded border border-gray-200 text-gray-500 hover:border-brand-accent hover:text-brand-accent flex items-center gap-0.5">
                      <Wand2 size={9} /> {rid}
                    </button>
                  )
                })}
              </div>
            </div>
            <CheckboxList
              options={catalog.permissions} selected={groupForm.permissions}
              onChange={v => setGroupForm(f => ({ ...f, permissions: v }))}
              getId={p => p.id || p} getLabel={p => p.id || p} getDesc={p => p.description}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5"><Building2 size={12} /> Companies</label>
              <CheckboxList
                options={companyList} selected={groupForm.companies}
                onChange={v => setGroupForm(f => ({ ...f, companies: v }))}
                empty="No companies defined."
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-600 mb-1 flex items-center gap-1.5"><Users size={12} /> Members</label>
              <CheckboxList
                options={users} selected={groupForm.members}
                onChange={v => setGroupForm(f => ({ ...f, members: v }))}
                getId={u => u.username} getLabel={u => u.username} getDesc={u => u.role}
                empty="No users."
              />
            </div>
          </div>

          {groupErr && (
            <p className="text-xs text-red-600 bg-red-50 border border-red-200 rounded-lg px-3 py-2 flex items-center gap-1.5">
              <AlertTriangle size={12} /> {groupErr}
            </p>
          )}
          <div className="flex items-center gap-2 pt-1">
            <button type="submit" disabled={groupSaving} className="btn-primary text-xs">
              {groupSaving ? <Loader2 size={13} className="animate-spin" /> : <Check size={13} />} Save
            </button>
            <button type="button" onClick={() => setGroupTarget(null)} className="btn-ghost text-xs">Cancel</button>
          </div>
        </form>
      </Modal>
    </PageShell>
  )
}
