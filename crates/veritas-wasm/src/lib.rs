//! # veritas-wasm
//!
//! WebAssembly bindings for the VERITAS Protocol.
//!
//! This crate provides browser-compatible bindings:
//! - Compiled with `wasm-pack`
//! - Storage via IndexedDB (through web-sys)
//! - Randomness via `getrandom` with `js` feature
//!
//! ## WASM Constraints
//!
//! - No filesystem access
//! - No direct network access (use browser fetch)
//! - Web Crypto API integration where possible

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

use wasm_bindgen::prelude::*;

/// Initialize panic hook for better error messages in console.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Returns the library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
