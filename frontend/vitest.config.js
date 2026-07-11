import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-setup.js'],
    // Playwright e2e specs use their own runner (@playwright/test) — keep them
    // out of the vitest unit run so they don't error on the Playwright import.
    exclude: ['node_modules/**', 'dist/**', 'e2e/**'],
  },
})
