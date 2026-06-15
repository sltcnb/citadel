import { useState, lazy, Suspense } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useSearchParams } from 'react-router-dom'

import Layout         from './components/layout/ModernLayout'
import Login          from './pages/Login'
import RouteFallback  from './components/RouteFallback'

// Heavy page components are lazy-loaded so they ship as separate chunks.
const Dashboard       = lazy(() => import('./pages/Dashboard'))
const CaseTimeline    = lazy(() => import('./pages/CaseTimeline'))
const CaseFiles       = lazy(() => import('./pages/CaseFiles'))
const CaseNotes       = lazy(() => import('./pages/CaseNotes'))
const AlertLibrary    = lazy(() => import('./pages/AlertLibrary'))
const YaraLibrary     = lazy(() => import('./pages/YaraLibrary'))
const Templates       = lazy(() => import('./pages/Templates'))
const Ingesters       = lazy(() => import('./pages/Ingesters'))
const Modules         = lazy(() => import('./pages/Modules'))
const Collector       = lazy(() => import('./pages/Collector'))
const Studio          = lazy(() => import('./pages/Studio'))
const Docs            = lazy(() => import('./pages/Docs'))
const Settings        = lazy(() => import('./pages/Settings'))
const Account         = lazy(() => import('./pages/Account'))
const Performance     = lazy(() => import('./pages/Performance'))
const Logs            = lazy(() => import('./pages/Logs'))
const Suite           = lazy(() => import('./pages/Suite'))
const UserManagement  = lazy(() => import('./pages/UserManagement'))
const ThreatIntel     = lazy(() => import('./pages/ThreatIntel'))
const MalwareAnalysis = lazy(() => import('./pages/MalwareAnalysis'))
const CrossCaseSearch = lazy(() => import('./pages/CrossCaseSearch'))
const Watchlist       = lazy(() => import('./pages/Watchlist'))

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
        <Suspense fallback={<RouteFallback />}>
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
            <Route path="templates"                 element={<Templates />} />
            <Route path="ingesters"                 element={<Ingesters />} />
            <Route path="modules"                   element={<Modules />} />
            <Route path="collector"                 element={<Collector />} />
            <Route path="studio"                    element={<Studio />} />
            <Route path="docs"                      element={<Docs />} />
            <Route path="performance"               element={<Performance />} />
            <Route path="logs"                      element={<Logs />} />
            <Route path="suite"                     element={<Suite />} />
            {/* Capabilities merged into Suite — keep the path working. */}
            <Route path="capabilities"              element={<Navigate to="/suite" replace />} />
            <Route path="users"                     element={<UserManagement />} />
            <Route path="cti"                       element={<ThreatIntel />} />
            <Route path="malware"                   element={<MalwareAnalysis />} />
            <Route path="cross-search"              element={<CrossCaseSearch />} />
            <Route path="watchlist"                 element={<Watchlist />} />
            <Route path="settings"                  element={<Settings />} />
            <Route path="account"                   element={<Account />} />
            <Route path="*"       element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
        </Suspense>
      </BrowserRouter>
    </UploadProvider>
    </LicenseProvider>
  )
}
