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

impl From<FfiError> for crate::ErrorCode {
    fn from(err: FfiError) -> Self {
        match err {
            FfiError::NullPointer => crate::ErrorCode::NullPointer,
            FfiError::InvalidArgument(_) => crate::ErrorCode::InvalidArgument,
            FfiError::InvalidUtf8 => crate::ErrorCode::InvalidArgument,
            FfiError::BufferTooSmall { .. } => crate::ErrorCode::InvalidArgument,
            FfiError::Core(e) => match e {
                veritas_core::CoreError::Crypto(_) => crate::ErrorCode::CryptoError,
                veritas_core::CoreError::Identity(_) => crate::ErrorCode::IdentityError,
                veritas_core::CoreError::Protocol(_) => crate::ErrorCode::ProtocolError,
                veritas_core::CoreError::Net(_) => crate::ErrorCode::NetworkError,
                veritas_core::CoreError::Store(_) => crate::ErrorCode::StorageError,
                _ => crate::ErrorCode::Unknown,
            },
        }
    }
}
