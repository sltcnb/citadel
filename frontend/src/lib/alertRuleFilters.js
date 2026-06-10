import { CATEGORY_ORDER } from '../components/RuleDrawer'

export function ruleProvenance(rule) {
  const isSigma  = rule.rule_type === 'sigma' || (!rule.rule_type && !!rule.sigma_yaml)
  const isCustom = rule.rule_type === 'custom'
  const isLegacy = !isSigma && !isCustom
  return isSigma ? 'sigma' : isCustom ? 'custom' : 'legacy'
}

export function filterAlertRules(rules, {
  search = '', provenance = 'all', category = 'all', artifact = 'all',
} = {}) {
  const q = (search || '').toLowerCase()
  return rules.filter(r => {
    const prov = ruleProvenance(r)
    if (provenance !== 'all' && prov !== provenance) return false
    if (category  !== 'all' && (r.category || 'Other') !== category)  return false
    if (artifact  !== 'all' && r.artifact_type !== artifact) return false
    if (q && !(r.name || '').toLowerCase().includes(q) &&
             !(r.description || '').toLowerCase().includes(q)) return false
    return true
  })
}

export function presentCategories(rules) {
  const cats = new Set(rules.map(r => r.category || 'Other'))
  return ['all', ...CATEGORY_ORDER.filter(c => cats.has(c))]
}

export function artifactTypes(rules) {
  return ['all', ...new Set(rules.map(r => r.artifact_type).filter(Boolean))]
}
