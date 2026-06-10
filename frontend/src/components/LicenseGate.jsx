import { Lock } from 'lucide-react'
import { useFeature, useLicense } from '../contexts/LicenseContext'

const PLAN_COLORS = {
  pro:        'bg-blue-50 border-blue-200 text-blue-700',
  enterprise: 'bg-indigo-50 border-indigo-200 text-indigo-700',
}

const PLAN_LABELS = {
  pro:        'Pro',
  enterprise: 'Enterprise',
}

export default function LicenseGate({ feature, children, blur = true }) {
  const enabled = useFeature(feature)
  const { upgrade_to } = useLicense()

  if (enabled) return children

  const requiredPlan = _required_plan(feature)
  const label = PLAN_LABELS[requiredPlan] || 'higher'
  const colors = PLAN_COLORS[requiredPlan] || PLAN_COLORS.enterprise

  return (
    <div className="relative">
      {blur && (
        <div className="pointer-events-none select-none opacity-30 blur-[2px]">
          {children}
        </div>
      )}
      <div className={`${blur ? 'absolute inset-0' : ''} flex items-center justify-center`}>
        <div className={`flex flex-col items-center gap-2 rounded-xl border px-6 py-5 shadow-sm ${colors}`}>
          <Lock size={18} />
          <p className="text-sm font-semibold">
            Requires {label} plan
          </p>
          <a
            href="https://citadel.io/pricing"
            target="_blank"
            rel="noreferrer"
            className="text-xs underline underline-offset-2 opacity-80 hover:opacity-100"
          >
            View plans →
          </a>
        </div>
      </div>
    </div>
  )
}

const FEATURE_PLAN_MAP = {
  ai_assist:    'enterprise',
  multitenancy: 'enterprise',
  export:       'pro',
  s3_archive:   'pro',
}

function _required_plan(feature) {
  return FEATURE_PLAN_MAP[feature] || 'pro'
}
