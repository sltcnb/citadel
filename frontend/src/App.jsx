import { useState } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useSearchParams } from 'react-router-dom'

import Layout         from './components/layout/ModernLayout'
import Dashboard      from './pages/Dashboard'
import CaseTimeline   from './pages/CaseTimeline'
import CaseFiles      from './pages/CaseFiles'
import CaseNotes      from './pages/CaseNotes'
import AlertLibrary   from './pages/AlertLibrary'
import YaraLibrary    from './pages/YaraLibrary'
import Ingesters      from './pages/Ingesters'
import Modules        from './pages/Modules'
import Collector      from './pages/Collector'
import Studio         from './pages/Studio'
import Docs           from './pages/Docs'
import Settings       from './pages/Settings'
import Login          from './pages/Login'
import Performance    from './pages/Performance'
import UserManagement from './pages/UserManagement'
import ThreatIntel    from './pages/ThreatIntel'
import MalwareAnalysis from './pages/MalwareAnalysis'
import CrossCaseSearch from './pages/CrossCaseSearch'
import Watchlist from './pages/Watchlist'
import { UploadProvider } from './contexts/UploadContext'
import { LicenseProvider } from './contexts/LicenseContext'

import { getToken, setToken, clearToken, isAuthenticated, api } from './api/client'

function ProtectedRoute({ children }) {
  const location = useLocation()
  if (!isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return children
}

// Redirect /cases/:id/search → /cases/:id, preserving ?q= or state.pivotQuery as state
function SearchRedirect() {
  const [searchParams] = useSearchParams()
  const location = useLocation()
  const q = location.state?.pivotQuery || searchParams.get('q') || ''
  return <Navigate to=".." replace state={q ? { pivotQuery: q } : undefined} />
}

export default function App() {
  const [user, setUser] = useState(() => {
    try {
      const raw = localStorage.getItem('fo_user')
      return raw ? JSON.parse(raw) : null
    } catch { return null }
  })

  function handleLogin(token, userInfo) {
    setToken(token)
    setUser(userInfo)
    localStorage.setItem('fo_user', JSON.stringify(userInfo))
  }

  async function handleLogout() {
    try { await api.auth.logout() } catch { /* server may be unreachable */ }
    clearToken()
    setUser(null)
    localStorage.removeItem('fo_user')
  }

  return (
    <LicenseProvider isAuthenticated={isAuthenticated()}>
    <UploadProvider>
      <BrowserRouter>
        <Routes>
          {/* ── Public ── */}
          <Route path="/login" element={<Login onLogin={handleLogin} />} />

          {/* ── Protected ── */}
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout user={user} onLogout={handleLogout} />
              </ProtectedRoute>
            }
          >
            <Route index                            element={<Dashboard />} />
            <Route path="cases"                     element={<Navigate to="/" replace />} />
            <Route path="cases/:caseId"             element={<CaseTimeline />} />
            <Route path="cases/:caseId/files"       element={<CaseFiles />} />
            <Route path="cases/:caseId/notes"       element={<CaseNotes />} />
            <Route path="cases/:caseId/mitre"        element={<Navigate to=".." replace />} />
            <Route path="cases/:caseId/process-tree" element={<Navigate to=".." replace />} />
            <Route path="cases/:caseId/anomaly"      element={<Navigate to=".." replace />} />
            <Route path="cases/:caseId/search"       element={<SearchRedirect />} />
            <Route path="alert-rules"               element={<AlertLibrary />} />
            <Route path="yara-rules"                element={<YaraLibrary />} />
            <Route path="ingesters"                 element={<Ingesters />} />
            <Route path="modules"                   element={<Modules />} />
            <Route path="collector"                 element={<Collector />} />
            <Route path="studio"                    element={<Studio />} />
            <Route path="docs"                      element={<Docs />} />
            <Route path="performance"               element={<Performance />} />
            <Route path="users"                     element={<UserManagement />} />
            <Route path="cti"                       element={<ThreatIntel />} />
            <Route path="malware"                   element={<MalwareAnalysis />} />
            <Route path="cross-search"              element={<CrossCaseSearch />} />
            <Route path="watchlist"                 element={<Watchlist />} />
            <Route path="settings"                  element={<Settings />} />
            <Route path="*"       element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </UploadProvider>
    </LicenseProvider>
  )
}
