import { createContext, useCallback, useContext, useEffect, useState } from 'react'
import { api } from '../api/client'

const COMMUNITY_LICENSE = {
  valid:       true,
  plan:        'community',
  plan_label:  'Community',
  org_name:    'Community',
  seats:       2,
  valid_until: null,
  upgrade_to:  'pro',
  features: {
    max_cases:      3,
    max_users:      2,
    max_companies:  1,
    export:         false,
    ai_assist:      false,
    multitenancy:   false,
    s3_archive:     false,
    alert_rules:    true,
    custom_plugins: true,
    mssp_mode:      false,
  },
  message: '',
}

const LicenseContext = createContext(COMMUNITY_LICENSE)

export function LicenseProvider({ children, isAuthenticated }) {
  const [license, setLicense] = useState(COMMUNITY_LICENSE)

  const refresh = useCallback(async () => {
    if (!isAuthenticated) return
    try {
      const data = await api.license.info()
      setLicense(data)
    } catch {
      // server unreachable or 401 — stay on community defaults
    }
  }, [isAuthenticated])

  useEffect(() => {
    refresh()
  }, [refresh])

  return (
    <LicenseContext.Provider value={{ ...license, refresh }}>
      {children}
    </LicenseContext.Provider>
  )
}

export function useLicense() {
  return useContext(LicenseContext)
}

export function useFeature(feature) {
  const license = useLicense()
  return Boolean(license.features?.[feature])
}
