// @ts-expect-error No `.d.ts` available
import rust from "@wasm-tool/rollup-plugin-rust";
import { defineConfig } from "vite";

export default defineConfig({
  mode: "development",
  plugins: [
    rust({
      verbose: process.env.CI === "true",
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
    outDir: "../target/pgpvis-core-bootstrapping",
    rollupOptions: {
      input: {
        pgpvis_core_bootstrapping: "../pgpvis-core/Cargo.toml",
      },
    },
  },
  esbuild: {
    supported: {
      "top-level-await": true,
    },
  },
});
