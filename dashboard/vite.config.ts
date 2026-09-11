import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dashboard talks to the Go agent's HTTP API (default :9090) for
// /api/alerts and proxies /metrics for convenience during local dev.
// In production, point VITE_AGENT_URL at wherever the agent runs.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': process.env.VITE_AGENT_URL || 'http://localhost:9090',
    },
  },
})
