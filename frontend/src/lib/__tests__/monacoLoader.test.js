import { describe, it, expect, vi } from 'vitest'

// Capture what monacoLoader hands to the real loader at import time.
const configSpy = vi.fn()
vi.mock('@monaco-editor/react', () => ({ loader: { config: configSpy } }))

// Stub the heavy monaco imports — the test only verifies the wiring, not the
// editor itself.
const { fakeMonaco, FakeWorker } = vi.hoisted(() => {
  class FakeWorker {}
  return { fakeMonaco: { editor: {}, languages: {} }, FakeWorker }
})
vi.mock('monaco-editor/editor/editor.api', () => fakeMonaco)
vi.mock('monaco-editor/editor/editor.worker?worker', () => ({ default: FakeWorker }))
vi.mock('monaco-editor/languages/definitions/yaml/register.js', () => ({}))
vi.mock('monaco-editor/languages/definitions/python/register.js', () => ({}))

describe('monaco loader (bundled, no CDN)', () => {
  it('hands the locally imported monaco instance to @monaco-editor/react', async () => {
    await import('../monacoLoader.js')

    // loader.config({ monaco }) makes @monaco-editor/react skip its CDN fetch
    // entirely, so the editors work in air-gapped deployments.
    expect(configSpy).toHaveBeenCalledWith({ monaco: fakeMonaco })
  })

  it('never configures a CDN path', async () => {
    await import('../monacoLoader.js')

    for (const [cfg] of configSpy.mock.calls) {
      expect(cfg.paths).toBeUndefined()  // a `paths.vs` entry would be a CDN URL
      expect(cfg.monaco).toBeDefined()
    }
  })

  it('registers a MonacoEnvironment that spawns local editor workers', async () => {
    await import('../monacoLoader.js')

    expect(self.MonacoEnvironment).toBeDefined()
    expect(self.MonacoEnvironment.getWorker()).toBeInstanceOf(FakeWorker)
  })
})
