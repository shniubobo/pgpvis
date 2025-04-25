import { fileURLToPath, URL } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import vue from "@vitejs/plugin-vue";
// @ts-expect-error No `.d.ts` available
import rust from "@wasm-tool/rollup-plugin-rust";
import { defineConfig } from "vite";
import topLevelAwait from "vite-plugin-top-level-await";
import vueDevTools from "vite-plugin-vue-devtools";

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    rust({
      extraArgs: {
        wasmBindgen: ["--remove-producers-section"],
      },
      experimental: {
        typescriptDeclarationDir: "../target/rollup-plugin-rust/",
      },
    }),
    vue(),
    vueDevTools(),
    topLevelAwait(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
      "@mocks": fileURLToPath(new URL("./__mocks__", import.meta.url)),
      "@pgpvis-core": fileURLToPath(
        new URL("../pgpvis-core/Cargo.toml", import.meta.url),
      ),
    },
  },
});
