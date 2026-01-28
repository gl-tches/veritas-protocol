//! Error types for FFI operations.

use thiserror::Error;

/// Errors that can occur during FFI operations.
#[derive(Error, Debug)]
pub enum FfiError {
    /// Core error.
    #[error("Core error: {0}")]
    Core(#[from] veritas_core::CoreError),

    /// Null pointer provided.
    #[error("Null pointer provided")]
    NullPointer,

    /// Invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Buffer too small.
    #[error("Buffer too small: need {needed}, have {actual}")]
    BufferTooSmall {
        /// Bytes needed.
        needed: usize,
        /// Bytes available.
        actual: usize,
    },

    /// UTF-8 conversion error.
    #[error("Invalid UTF-8 string")]
    InvalidUtf8,
}

/// Result type for FFI operations.
pub type Result<T> = std::result::Result<T, FfiError>;
