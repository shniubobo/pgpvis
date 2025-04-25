// @ts-expect-error No `.d.ts` available
import rust from "@wasm-tool/rollup-plugin-rust";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [
    rust({
      extraArgs: {
        wasmOpt: [],
      },
      optimize: {
        release: false,
        rustc: false,
      },
      experimental: {
        typescriptDeclarationDir: "../target/rollup-plugin-rust/",
      },
    }),
  ],
  build: {
    rollupOptions: {
      input: {
        to_bootstrap: "../pgpvis-core/Cargo.toml",
      },
    },
  },
  esbuild: {
    supported: {
      "top-level-await": true,
    },
  },
});
