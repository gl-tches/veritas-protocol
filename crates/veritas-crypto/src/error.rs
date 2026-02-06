//! Error types for cryptographic operations.

use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key generation failed.
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed (invalid ciphertext or key).
    #[error("Decryption failed: invalid ciphertext or key")]
    Decryption,

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Invalid key length.
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected key length.
        expected: usize,
        /// Actual key length.
        actual: usize,
    },

    /// Invalid nonce length.
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected nonce length.
        expected: usize,
        /// Actual nonce length.
        actual: usize,
    },

    /// Invalid hash length.
    #[error("Invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength {
        /// Expected hash length.
        expected: usize,
        /// Actual hash length.
        actual: usize,
    },

    /// Invalid hex string format (CRYPTO-FIX-5).
    #[error("Invalid hex string: {0}")]
    InvalidHexFormat(String),

    /// Key encapsulation failed.
    #[error("Key encapsulation failed: {0}")]
    Encapsulation(String),

    /// Key decapsulation failed.
    #[error("Key decapsulation failed")]
    Decapsulation,

    /// Random number generation failed.
    #[error("Random number generation failed: {0}")]
    Rng(String),
}

/// Result type for cryptographic operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
