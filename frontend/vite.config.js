import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        // When running inside Docker/K8s the API container is reachable via its
        // service name, NOT via localhost.  Override with API_TARGET env var:
        //   docker-compose:  API_TARGET=http://api:8000
        //   k3s / k8s:       API_TARGET=http://api-service:8000
        // Falls back to http://localhost:8000 for plain local dev (npm run dev).
        target: process.env.API_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        // Generous proxy timeout so slow endpoints (e.g. metrics) never cause
        // a "Failed to fetch" network error on the frontend side.
        proxyTimeout: 30000,
        timeout: 30000,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split heavy/stable deps into their own chunks so the main app bundle
        // stays small and the big libraries (Monaco especially) are cached
        // across deploys and loaded in parallel instead of as one ~1 MB blob.
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined
          // Monaco editor (the heavy editor core + the React wrapper)
          if (id.includes('@monaco-editor') || id.includes('monaco-editor')) {
            return 'vendor-monaco'
          }
          // React core + router — stable, cache across deploys
          if (
            id.includes('/react/') ||
            id.includes('/react-dom/') ||
            id.includes('/react-router') ||
            id.includes('/scheduler/')
          ) {
            return 'vendor-react'
          }
          // Icon set — large but tree-shakeable; isolate so it doesn't bloat main
          if (id.includes('lucide-react')) return 'vendor-icons'
          // Sanitiser + any other small UI libs
          if (id.includes('dompurify')) return 'vendor-ui'
          // Everything else from node_modules → a shared vendor chunk, keeping
          // the main index chunk to first-party app code only.
          return 'vendor'
        },
      },
    },
  },
})
