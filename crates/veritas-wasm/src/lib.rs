//! # veritas-wasm
//!
//! WebAssembly bindings for VERITAS protocol.
//!
//! Provides a browser-compatible API for using VERITAS in web applications.
//!
//! ## Constraints
//!
//! - No filesystem access (use IndexedDB via web-sys)
//! - No direct network access (use browser fetch)
//! - Randomness via getrandom with `js` feature

#![deny(unsafe_code)]
#![warn(missing_docs)]

use wasm_bindgen::prelude::*;

/// Initialize the VERITAS WASM module.
#[wasm_bindgen(start)]
pub fn init() {
    // Panic hook would be set up here if console_error_panic_hook feature is enabled
}

/// Get the library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
