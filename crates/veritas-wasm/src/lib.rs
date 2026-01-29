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
//!
//! ## Example Usage
//!
//! ```javascript
//! import init, { WasmClient, WasmSafetyNumber } from './veritas_wasm.js';
//!
//! // Initialize the WASM module
//! await init();
//!
//! // Create and unlock client
//! const client = new WasmClient();
//! await client.unlock("my-password");
//!
//! // Create an identity
//! const hash = await client.createIdentity("Alice");
//! console.log("Identity:", hash);
//!
//! // List identities
//! const identities = await client.listIdentities();
//! console.log("Identities:", identities);
//!
//! // Check slots
//! const slots = await client.identitySlots();
//! console.log("Slots:", slots);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod client;
mod error;
mod identity;
mod safety;

pub use client::WasmClient;
pub use error::{WasmError, WasmResult};
pub use identity::{WasmIdentityInfo, WasmIdentitySlotInfo};
pub use safety::WasmSafetyNumber;

use wasm_bindgen::prelude::*;

/// Initialize the VERITAS WASM module.
///
/// This sets up panic hooks for better error messages in the browser console.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Get the library version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
