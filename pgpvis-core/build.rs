#[cfg(all(feature = "wasm-bindgen-cli", not(target_family = "wasm")))]
fn main() {
    use std::path::Path;

    let wasm_bindgen_dir = {
        let bin_dir = std::env::var_os("CARGO_BIN_FILE_WASM_BINDGEN_CLI_wasm-bindgen").unwrap();
        Path::new(&bin_dir).to_path_buf()
    };
    let target_dir = {
        let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").unwrap();
        Path::new(&manifest_dir).parent().unwrap().join("target")
    };
    std::fs::copy(wasm_bindgen_dir, target_dir.join("wasm-bindgen")).unwrap();
}

#[cfg(any(not(feature = "wasm-bindgen-cli"), target_family = "wasm"))]
fn main() {}
