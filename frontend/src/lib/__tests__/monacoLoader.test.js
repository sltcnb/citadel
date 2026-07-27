import { describe, it, expect, vi } from 'vitest'
import pkg from '../../../package.json'

// Capture what monacoLoader hands to the real loader at import time.
const configSpy = vi.fn()
vi.mock('@monaco-editor/react', () => ({ loader: { config: configSpy } }))

describe('monaco loader pin', () => {
  it('points the loader at the pinned monaco build', async () => {
    const { MONACO_VERSION } = await import('../monacoLoader.js')

    expect(configSpy).toHaveBeenCalledWith({
      paths: { vs: `https://cdn.jsdelivr.net/npm/monaco-editor@${MONACO_VERSION}/min/vs` },
    })
  })

  it('keeps the runtime pin in step with the monaco-editor override', async () => {
    // The whole point of the pin: @monaco-editor/loader's default CDN URL is
    // independent of the resolved monaco-editor version, so a lockfile bump
    // alone would leave the browser on the old (vulnerable) build. If these two
    // drift apart, scanners read the lockfile while users run something else.
    const { MONACO_VERSION } = await import('../monacoLoader.js')

    expect(pkg.overrides['monaco-editor']).toBe(`^${MONACO_VERSION}`)
  })
})
