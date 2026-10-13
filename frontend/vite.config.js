import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // Ningún recurso se incrusta como data: en el CSS. Las tipografías salen como archivos de
  // /assets, que es lo único que permite la CSP (font-src 'self').
  build: { assetsInlineLimit: 0 },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{js,jsx}"],
  },
});
