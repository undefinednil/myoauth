import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// https://vitejs.dev/config/
//
// No `.env` file is loaded: the dev proxy target comes from the plain shell
// environment variable `VITE_DEV_PROXY_TARGET`, defaulting to the local backend
// (`http://localhost:20476`). Override it per-invocation, e.g.
// `VITE_DEV_PROXY_TARGET=http://127.0.0.1:9999 npm run dev`.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../web/dist",
    emptyOutDir: false,
  },
  server: {
    proxy: {
      "/api": {
        target: (
          process.env.VITE_DEV_PROXY_TARGET || "http://localhost:20476"
        ).trim(),
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
