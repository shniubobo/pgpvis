import type { Config } from "tailwindcss";

export default {
  content: ["./index.html", "./src/**/*.{ts,vue}"],
  theme: {
    extend: {},
  },
  plugins: [],
} satisfies Config;
