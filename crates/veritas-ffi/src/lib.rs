//! # veritas-ffi
//!
//! C FFI bindings for the VERITAS Protocol.
//!
//! This crate provides C-compatible bindings for use in:
//! - iOS (Swift/Objective-C)
//! - Android (Kotlin/Java via JNI)
//! - Desktop applications (C/C++)
//!
//! ## Safety
//!
//! All FFI functions:
//! - Validate inputs at boundary before processing
//! - Return error codes, never panic
//! - Provide `_free` functions for allocated memory
//! - Check for null pointers

#![warn(missing_docs)]
#![warn(clippy::all)]

// FFI requires unsafe code, but we minimize and audit it
#![deny(unsafe_op_in_unsafe_fn)]

/// Error codes for FFI functions.
#[repr(C)]
pub enum VeritasError {
    /// Operation succeeded.
    Ok = 0,
    /// Null pointer provided.
    NullPointer = 1,
    /// Invalid argument.
    InvalidArgument = 2,
    /// Cryptographic error.
    CryptoError = 3,
    /// Identity error.
    IdentityError = 4,
    /// Protocol error.
    ProtocolError = 5,
    /// Network error.
    NetworkError = 6,
    /// Storage error.
    StorageError = 7,
    /// Unknown error.
    Unknown = 255,
}
