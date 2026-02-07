//! Generic wire protocol error codes.
//!
//! Error codes are intentionally generic to prevent information leakage
//! about internal state. Detailed errors are logged server-side only.

use serde::{Deserialize, Serialize};

/// Wire protocol error codes.
///
/// These codes are sent over the network and are intentionally vague
/// to prevent information leakage about internal state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum WireErrorCode {
    /// Success (no error).
    Ok = 0,

    // === 1xxx: Client errors ===
    /// Malformed request (bad encoding, missing fields).
    BadRequest = 1000,
    /// Authentication failed (invalid signature, expired key).
    Unauthorized = 1001,
    /// Insufficient reputation for this action.
    InsufficientReputation = 1002,
    /// Rate limit exceeded.
    RateLimited = 1003,
    /// Message too large (exceeds MAX_ENVELOPE_SIZE).
    PayloadTooLarge = 1004,
    /// Unknown or unsupported protocol version.
    UnsupportedVersion = 1005,
    /// Unknown or unsupported cipher suite.
    UnsupportedCipherSuite = 1006,

    // === 2xxx: Server/validator errors ===
    /// Internal validator error (details not disclosed).
    InternalError = 2000,
    /// Validator is not accepting transactions (syncing, shutting down).
    Unavailable = 2001,
    /// Transaction rejected by consensus.
    ConsensusRejected = 2002,

    // === 3xxx: Chain errors ===
    /// Block not found.
    BlockNotFound = 3000,
    /// Transaction not found.
    TransactionNotFound = 3001,
    /// Invalid block height or range.
    InvalidBlockRange = 3002,

    // === 4xxx: Identity errors ===
    /// Identity not found.
    IdentityNotFound = 4000,
    /// Identity already registered.
    IdentityExists = 4001,
    /// Username already taken.
    UsernameTaken = 4002,

    // === 5xxx: Network errors ===
    /// Peer not found.
    PeerNotFound = 5000,
    /// Connection refused.
    ConnectionRefused = 5001,
    /// Request timeout.
    Timeout = 5002,
}

impl WireErrorCode {
    /// Check if this is a success code.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Check if this is a client error (1xxx range).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        let code = *self as u16;
        (1000..2000).contains(&code)
    }

    /// Check if this is a server error (2xxx range).
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        let code = *self as u16;
        (2000..3000).contains(&code)
    }

    /// Get the numeric code.
    #[must_use]
    pub fn code(&self) -> u16 {
        *self as u16
    }

    /// Get a generic description (safe to send over wire).
    #[must_use]
    pub fn description(&self) -> &'static str {
        match self {
            Self::Ok => "success",
            Self::BadRequest => "bad request",
            Self::Unauthorized => "unauthorized",
            Self::InsufficientReputation => "insufficient reputation",
            Self::RateLimited => "rate limited",
            Self::PayloadTooLarge => "payload too large",
            Self::UnsupportedVersion => "unsupported version",
            Self::UnsupportedCipherSuite => "unsupported cipher suite",
            Self::InternalError => "internal error",
            Self::Unavailable => "unavailable",
            Self::ConsensusRejected => "consensus rejected",
            Self::BlockNotFound => "block not found",
            Self::TransactionNotFound => "transaction not found",
            Self::InvalidBlockRange => "invalid block range",
            Self::IdentityNotFound => "identity not found",
            Self::IdentityExists => "identity exists",
            Self::UsernameTaken => "username taken",
            Self::PeerNotFound => "peer not found",
            Self::ConnectionRefused => "connection refused",
            Self::Timeout => "timeout",
        }
    }
}

impl std::fmt::Display for WireErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description(), self.code())
    }
}

/// A wire error response sent over the network.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireError {
    /// The error code.
    pub code: WireErrorCode,
    /// Optional request ID for correlation.
    pub request_id: Option<u64>,
}

impl WireError {
    /// Create a new wire error.
    #[must_use]
    pub fn new(code: WireErrorCode) -> Self {
        Self {
            code,
            request_id: None,
        }
    }

    /// Create a wire error with a request ID.
    #[must_use]
    pub fn with_request_id(code: WireErrorCode, request_id: u64) -> Self {
        Self {
            code,
            request_id: Some(request_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_categories() {
        assert!(WireErrorCode::Ok.is_ok());
        assert!(WireErrorCode::BadRequest.is_client_error());
        assert!(WireErrorCode::RateLimited.is_client_error());
        assert!(WireErrorCode::InternalError.is_server_error());
        assert!(WireErrorCode::Unavailable.is_server_error());
        assert!(!WireErrorCode::Ok.is_client_error());
        assert!(!WireErrorCode::Ok.is_server_error());
    }

    #[test]
    fn test_error_code_values() {
        assert_eq!(WireErrorCode::Ok.code(), 0);
        assert_eq!(WireErrorCode::BadRequest.code(), 1000);
        assert_eq!(WireErrorCode::InternalError.code(), 2000);
        assert_eq!(WireErrorCode::BlockNotFound.code(), 3000);
        assert_eq!(WireErrorCode::IdentityNotFound.code(), 4000);
        assert_eq!(WireErrorCode::PeerNotFound.code(), 5000);
    }

    #[test]
    fn test_wire_error_display() {
        let err = WireErrorCode::RateLimited;
        let display = format!("{}", err);
        assert!(display.contains("rate limited"));
        assert!(display.contains("1003"));
    }

    #[test]
    fn test_wire_error_response() {
        let err = WireError::with_request_id(WireErrorCode::Unauthorized, 42);
        assert_eq!(err.code, WireErrorCode::Unauthorized);
        assert_eq!(err.request_id, Some(42));
    }
}
