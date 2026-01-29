//! Error handling for WASM bindings.
//!
//! Converts internal Rust errors to JsValue for JavaScript interop.

use wasm_bindgen::JsValue;

/// Error type for WASM operations.
///
/// This wraps internal errors and converts them to JsValue for JavaScript.
#[derive(Debug)]
pub struct WasmError {
    message: String,
}

impl WasmError {
    /// Create a new error with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WasmError {}

impl From<WasmError> for JsValue {
    fn from(error: WasmError) -> JsValue {
        JsValue::from_str(&error.message)
    }
}

impl From<veritas_crypto::CryptoError> for WasmError {
    fn from(error: veritas_crypto::CryptoError) -> Self {
        Self::new(format!("Crypto error: {}", error))
    }
}

impl From<veritas_identity::IdentityError> for WasmError {
    fn from(error: veritas_identity::IdentityError) -> Self {
        Self::new(format!("Identity error: {}", error))
    }
}

impl From<String> for WasmError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

impl From<&str> for WasmError {
    fn from(message: &str) -> Self {
        Self::new(message)
    }
}

/// Result type for WASM operations.
pub type WasmResult<T> = Result<T, WasmError>;
