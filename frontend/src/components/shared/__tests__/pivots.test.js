import { describe, it, expect, beforeEach } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { pivotQuery } from '../EntityGraphPanel'
import { stepQuery } from '../KillChainPanel'
import { useResizableWidth } from '../resizableDrawer'
import { iocValueQuery, extractIocs } from '../../../utils/ioc'

describe('EntityGraph pivotQuery', () => {
  it('builds a host query', () => {
    expect(pivotQuery({ type: 'host', label: 'WIN-01' }))
      .toBe('(host.hostname:"WIN-01" OR host.ip:"WIN-01")')
  })
  it('builds a user query', () => {
    expect(pivotQuery({ type: 'user', label: 'alice' })).toBe('user.name:"alice"')
  })
  it('ORs every normalised IP field', () => {
    const q = pivotQuery({ type: 'ip', label: '10.0.0.5' })
    for (const f of ['network.src_ip', 'network.dst_ip', 'network.dest_ip', 'source.ip', 'destination.ip', 'host.ip']) {
      expect(q).toContain(`${f}:"10.0.0.5"`)
    }
  })
  it('escapes quotes in the label', () => {
    expect(pivotQuery({ type: 'user', label: 'a"b' })).toBe('user.name:"a\\"b"')
  })
  it('returns empty for unknown node types', () => {
    expect(pivotQuery({ type: 'process', label: 'x' })).toBe('')
  })
})

describe('KillChain stepQuery', () => {
  it('prefers the exact fo_id', () => {
    expect(stepQuery({ fo_id: 'abc', host: 'H', ts: '2026-01-01T00:00:00Z' })).toBe('fo_id:"abc"')
  })
  it('falls back to host + a ±2min timestamp window on the `timestamp` field', () => {
    const q = stepQuery({ host: 'WIN-01', ts: '2026-01-01T12:00:00Z' })
    expect(q).toContain('host.hostname:"WIN-01"')
    expect(q).toContain('timestamp:[2026-01-01T11:58:00.000Z TO 2026-01-01T12:02:00.000Z]')
    expect(q).not.toContain('@timestamp')
  })
  it('returns * when nothing usable', () => {
    expect(stepQuery({})).toBe('*')
  })
})

describe('iocValueQuery', () => {
  it('wraps the value as a bare quoted term (matches any field)', () => {
    expect(iocValueQuery('8.8.8.8')).toBe('"8.8.8.8"')
  })
  it('escapes embedded quotes', () => {
    expect(iocValueQuery('a"b')).toBe('"a\\"b"')
  })
})

describe('extractIocs', () => {
  it('pulls IPs, hashes and domains and dedupes', () => {
    const iocs = extractIocs('connect 1.2.3.4 to evil.com hash d41d8cd98f00b204e9800998ecf8427e 1.2.3.4')
    const values = iocs.map(i => i.value)
    expect(values).toContain('1.2.3.4')
    expect(values).toContain('evil.com')
    expect(values).toContain('d41d8cd98f00b204e9800998ecf8427e')
    expect(values.filter(v => v === '1.2.3.4')).toHaveLength(1)  // deduped
  })
})

describe('useResizableWidth', () => {
  beforeEach(() => localStorage.clear())

  it('starts at the default when nothing stored', () => {
    const { result } = renderHook(() => useResizableWidth('t1', 500))
    expect(result.current[0]).toBe(500)
  })
  it('reads a persisted width', () => {
    localStorage.setItem('fo_drawerw_t2', '640')
    const { result } = renderHook(() => useResizableWidth('t2', 500))
    expect(result.current[0]).toBe(640)
  })
  it('ignores a stored width below the minimum', () => {
    localStorage.setItem('fo_drawerw_t3', '50')
    const { result } = renderHook(() => useResizableWidth('t3', 500, { min: 360 }))
    expect(result.current[0]).toBe(500)
  })
  it('double-click resets to default and persists', () => {
    localStorage.setItem('fo_drawerw_t4', '800')
    const { result } = renderHook(() => useResizableWidth('t4', 500))
    act(() => result.current[1].onDoubleClick())
    expect(result.current[0]).toBe(500)
    expect(localStorage.getItem('fo_drawerw_t4')).toBe('500')
  })
})
