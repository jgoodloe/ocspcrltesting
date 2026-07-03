import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// base: './' keeps built asset URLs relative so the app works when served
// from any subpath behind a reverse proxy. The backend rewrites the
// <base href="/"> tag in index.html at serve time.
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    proxy: {
      // Dev-only proxy to the FastAPI backend. This is the ONLY place a
      // localhost URL may appear in the codebase.
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
});
