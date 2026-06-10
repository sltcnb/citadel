/**
 * IOC (Indicator of Compromise) extraction utilities.
 * Extracts IPs, hashes, domains, CVEs from arbitrary text.
 */

const PRIVATE_IP_RE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.0|255\.)/

const PATTERNS = [
  { key: 'ipv4',   type: 'IPv4',       color: 'text-cyan-400',   re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  { key: 'sha256', type: 'SHA256',     color: 'text-green-400',  re: /\b[0-9a-fA-F]{64}\b/g },
  { key: 'sha1',   type: 'SHA1',       color: 'text-green-400',  re: /\b[0-9a-fA-F]{40}\b/g },
  { key: 'md5',    type: 'MD5',        color: 'text-green-400',  re: /\b[0-9a-fA-F]{32}\b/g },
  { key: 'cve',    type: 'CVE',        color: 'text-red-400',    re: /CVE-\d{4}-\d{4,}/gi },
  { key: 'domain', type: 'Domain',     color: 'text-yellow-400', re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|gov|mil|edu|biz|info|co)\b/gi },
]

export function extractIocs(text) {
  if (!text || typeof text !== 'string') return []
  const iocs = [], seen = new Set()
  for (const { key, type, color, re } of PATTERNS) {
    re.lastIndex = 0
    for (const match of text.matchAll(re)) {
      const val = match[0]
      const norm = val.toLowerCase()
      if (seen.has(norm)) continue
      seen.add(norm)
      if (key === 'ipv4' && PRIVATE_IP_RE.test(val)) {
        iocs.push({ value: val, type: 'Private IP', color: 'text-slate-400', key: 'ipv4_private' })
      } else {
        iocs.push({ value: val, type, color, key })
      }
    }
  }
  return iocs
}

export function iocSearchQuery(ioc) {
  return `"${ioc.value}"`
}
