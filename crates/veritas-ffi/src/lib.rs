//! # veritas-ffi
//!
//! C FFI bindings for VERITAS protocol.
//!
//! Provides a C-compatible API for using VERITAS from other languages.
//!
//! ## Safety
//!
//! All FFI functions validate inputs at the boundary before processing.
//! Error codes are used instead of exceptions/panics.
//! Memory allocated by this library must be freed using the provided `_free` functions.

#![warn(missing_docs)]

pub mod error;

pub use error::FfiError;

/// FFI error codes.
#[repr(i32)]
pub enum ErrorCode {
    /// Success.
    Success = 0,
    /// Null pointer provided.
    NullPointer = -1,
    /// Invalid argument.
    InvalidArgument = -2,
    /// Crypto error.
    CryptoError = -3,
    /// Identity error.
    IdentityError = -4,
    /// Protocol error.
    ProtocolError = -5,
    /// Network error.
    NetworkError = -6,
    /// Storage error.
    StorageError = -7,
    /// Unknown error.
    Unknown = -99,
}
