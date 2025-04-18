import path from "node:path";
import { fileURLToPath } from "node:url";

import { configDefaults, defineConfig, mergeConfig } from "vitest/config";

import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      globals: true,
      mockReset: true,
      environment: "jsdom",
      exclude: [...configDefaults.exclude, "e2e/**"],
      root: fileURLToPath(new URL("./", import.meta.url)),
      deps: {
        // Needed for `vi.mock` to pick up `__mocks__/pgpvis-core.ts`
        moduleDirectories: ["node_modules", path.resolve("../pgpvis-core")],
      },
    },
  }),
);
