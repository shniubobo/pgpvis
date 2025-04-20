/// <reference types="vite/client" />

// https://github.com/tailwindlabs/heroicons/issues/64#issuecomment-877717508
declare module "@heroicons/vue/*" {
  import type { DefineComponent } from "vue";
  export const ArrowRightIcon: DefineComponent<{}, {}, any>;
}
