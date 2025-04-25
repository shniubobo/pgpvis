// https://github.com/wasm-tool/rollup-plugin-rust/issues/9#issuecomment-671680660
export * from "../target/rollup-plugin-rust/pgpvis_core";

type Exports = typeof import("../target/rollup-plugin-rust/pgpvis_core");
declare const exports: () => Promise<Exports>;
export default exports;
