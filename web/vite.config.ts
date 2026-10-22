import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// In development, run `ven ui --port 7420 --no-browser` and `npm run dev`.
// Vite proxies /api to the Go server; Origin is rewritten so the server's
// same-origin checks still pass.
const target = "http://127.0.0.1:7420";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": "/src" } },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": {
        target,
        changeOrigin: true,
        headers: { Origin: target },
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
    // Keep every script external so the strict CSP (script-src 'self') holds.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    // Served from loopback, so one bundle is fine.
    chunkSizeWarningLimit: 800,
  },
});
