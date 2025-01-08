import type { Config } from "tailwindcss";
// @ts-expect-error https://github.com/primefaces/tailwindcss-primeui/issues/1
import tailwindcss_primeui from "tailwindcss-primeui";

export default {
  content: ["./index.html", "./src/**/*.{ts,vue}"],
  theme: {
    extend: {},
  },
  plugins: [tailwindcss_primeui],
} satisfies Config;
