import { describe, it, expect } from 'vitest'
import { safeIso, safeDateLabel, sourceFileName } from '../Timeline'

describe('safeIso', () => {
  it('returns ISO for a valid date', () => {
    expect(safeIso('2026-06-09T07:12:00Z')).toBe('2026-06-09T07:12:00.000Z')
  })
  it('returns empty string for invalid / empty input (never throws)', () => {
    // The bug: new Date('garbage').toISOString() throws RangeError and crashed
    // the whole case-timeline page when a bad fromTs/toTs reached the filter.
    expect(safeIso('garbage')).toBe('')
    expect(safeIso('not-a-date')).toBe('')
    expect(safeIso('')).toBe('')
    expect(safeIso(undefined)).toBe('')
    expect(safeIso(null)).toBe('')
  })
  it('accepts an epoch-millis number', () => {
    expect(safeIso(0)).toBe('') // 0 is falsy → empty, by design
    expect(safeIso(1717916400000)).toMatch(/^20\d\d-/)
  })
})

describe('safeDateLabel', () => {
  it('returns a localized label for a valid date', () => {
    expect(safeDateLabel('2026-06-09T07:12:00Z')).not.toBe('')
  })
  it('returns empty string for invalid input', () => {
    expect(safeDateLabel('nope')).toBe('')
    expect(safeDateLabel('')).toBe('')
  })
})

describe('sourceFileName', () => {
  it('strips the cases/<case>/<job>/ prefix to the original basename', () => {
    expect(sourceFileName('cases/abc/job123/var/log/sso.log')).toBe('sso.log')
    expect(sourceFileName('cases/abc/job123/auth.log')).toBe('auth.log')
  })
  it('handles a bare path or filename', () => {
    expect(sourceFileName('/var/log/syslog')).toBe('syslog')
    expect(sourceFileName('nginx.access.log')).toBe('nginx.access.log')
  })
  it('returns empty string for missing input', () => {
    expect(sourceFileName('')).toBe('')
    expect(sourceFileName(null)).toBe('')
    expect(sourceFileName(undefined)).toBe('')
  })
})
