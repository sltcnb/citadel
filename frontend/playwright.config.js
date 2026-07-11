import { defineConfig, devices } from '@playwright/test'

/**
 * Playwright config for the Citadel frontend smoke e2e.
 *
 * The suite is fully self-contained: every /api/v1/** request is intercepted
 * in-browser (see e2e/fixtures.js) so NO live backend, Elasticsearch, Redis or
 * MinIO is required. Playwright boots the Vite dev server on a dedicated port
 * and drives it with Chromium only.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['list']] : 'list',
  use: {
    baseURL: 'http://localhost:3100',
    trace: 'on-first-retry',
    viewport: { width: 1280, height: 800 }, // wide enough for the md: top-bar nav
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  webServer: {
    command: 'npm run dev -- --port 3100 --strictPort',
    url: 'http://localhost:3100',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
