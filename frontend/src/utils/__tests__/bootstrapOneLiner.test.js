import { describe, it, expect } from 'vitest'
import { bootstrapOneLiner } from '../bootstrapOneLiner'

const SCRIPT = '#Requires -Version 5.1\nparam([switch]$Local)\nWrite-Host "── é"\nexit 3\n'
const decode = b64 => decodeURIComponent(escape(atob(b64)))

describe('bootstrapOneLiner', () => {
  it('linux pipes the decoded script to bash', () => {
    const line = bootstrapOneLiner('sh', 'echo ok')
    const b64 = line.match(/^echo "([^"]+)" \| base64 -d \| bash$/)[1]
    expect(decode(b64)).toBe('echo ok')
  })

  it('windows runs the decoded script as a file in a child powershell, then deletes it', () => {
    const line = bootstrapOneLiner('ps1', SCRIPT)
    const b64 = line.match(/FromBase64String\('([^']+)'\)/)[1]
    expect(decode(b64)).toBe(SCRIPT)                       // UTF-8 round-trip, accents included
    expect(line).toContain('New-Object Text.UTF8Encoding $true')  // BOM for Windows PowerShell 5.1
    expect(line).toContain('powershell -NoProfile -ExecutionPolicy Bypass -File $f')
    expect(line).toMatch(/finally\{Remove-Item \$f/)
    expect(line).not.toMatch(/iex|Invoke-Expression|-EncodedCommand/)
  })
})
