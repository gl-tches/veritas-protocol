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

    /// Decryption failed - invalid ciphertext or wrong key.
    #[error("Decryption failed: invalid ciphertext or key")]
    Decryption,

    /// Signature creation failed.
    #[error("Signature creation failed: {0}")]
    SignatureCreation(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerification,

    /// Invalid key length.
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// Invalid nonce length.
    #[error("Invalid nonce length: expected {expected}, got {actual}")]
    InvalidNonceLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },

    /// Key encapsulation failed.
    #[error("Key encapsulation failed: {0}")]
    Encapsulation(String),

    /// Key decapsulation failed.
    #[error("Key decapsulation failed: {0}")]
    Decapsulation(String),

    /// Hash computation failed.
    #[error("Hash computation failed: {0}")]
    Hash(String),

    /// Random number generation failed.
    #[error("Random number generation failed: {0}")]
    Rng(String),
}

/// Result type for cryptographic operations.
pub type Result<T> = std::result::Result<T, CryptoError>;
