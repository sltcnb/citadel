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
        manualChunks: {
          'vendor-monaco': ['@monaco-editor/react'],
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-ui': ['lucide-react', 'dompurify'],
        },
      },
    },
  },
})
