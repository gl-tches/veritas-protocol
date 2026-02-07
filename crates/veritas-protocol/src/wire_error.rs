//! Generic wire-level error codes.
//!
//! Internal detailed errors are mapped to generic codes before transmission
//! to prevent information leakage. Detailed messages are kept for local logging.

use serde::{Deserialize, Serialize};

/// Generic wire-level error codes sent to peers.
///
/// These intentionally reveal minimal information about the failure cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WireErrorCode {
    /// Processing failed (generic catch-all).
    ProcessingFailed = 0,
    /// Invalid or malformed message.
    InvalidMessage = 1,
    /// Rate limit exceeded.
    RateLimited = 2,
    /// Unsupported protocol version.
    UnsupportedVersion = 3,
    /// Unsupported cipher suite.
    UnsupportedCipherSuite = 4,
    /// Message too large.
    MessageTooLarge = 5,
    /// Authentication failed.
    AuthenticationFailed = 6,
    /// Resource not found.
    NotFound = 7,
    /// Service temporarily unavailable.
    Unavailable = 8,
}

impl WireErrorCode {
    /// Get a generic description safe for wire transmission.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ProcessingFailed => "processing failed",
            Self::InvalidMessage => "invalid message",
            Self::RateLimited => "rate limited",
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::UnsupportedCipherSuite => "unsupported cipher suite",
            Self::MessageTooLarge => "message too large",
            Self::AuthenticationFailed => "authentication failed",
            Self::NotFound => "not found",
            Self::Unavailable => "service unavailable",
        }
    }

    /// Convert from u8.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::ProcessingFailed),
            1 => Some(Self::InvalidMessage),
            2 => Some(Self::RateLimited),
            3 => Some(Self::UnsupportedVersion),
            4 => Some(Self::UnsupportedCipherSuite),
            5 => Some(Self::MessageTooLarge),
            6 => Some(Self::AuthenticationFailed),
            7 => Some(Self::NotFound),
            8 => Some(Self::Unavailable),
            _ => None,
        }
    }
}

impl std::fmt::Display for WireErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// A wire-level error response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireError {
    /// The error code.
    pub code: WireErrorCode,
    /// Optional request ID for correlation.
    pub request_id: Option<[u8; 16]>,
}

impl WireError {
    /// Create a new wire error.
    pub fn new(code: WireErrorCode) -> Self {
        Self {
            code,
            request_id: None,
        }
    }

    /// Create a wire error with a request ID.
    pub fn with_request_id(code: WireErrorCode, request_id: [u8; 16]) -> Self {
        Self {
            code,
            request_id: Some(request_id),
        }
    }
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WireError({})", self.code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_error_code_from_u8() {
        assert_eq!(
            WireErrorCode::from_u8(0),
            Some(WireErrorCode::ProcessingFailed)
        );
        assert_eq!(
            WireErrorCode::from_u8(1),
            Some(WireErrorCode::InvalidMessage)
        );
        assert_eq!(
            WireErrorCode::from_u8(8),
            Some(WireErrorCode::Unavailable)
        );
        assert_eq!(WireErrorCode::from_u8(9), None);
        assert_eq!(WireErrorCode::from_u8(255), None);
    }

    #[test]
    fn test_wire_error_code_display() {
        assert_eq!(
            WireErrorCode::ProcessingFailed.to_string(),
            "processing failed"
        );
        assert_eq!(WireErrorCode::RateLimited.to_string(), "rate limited");
    }

    #[test]
    fn test_wire_error_new() {
        let err = WireError::new(WireErrorCode::MessageTooLarge);
        assert_eq!(err.code, WireErrorCode::MessageTooLarge);
        assert!(err.request_id.is_none());
    }

    #[test]
    fn test_wire_error_with_request_id() {
        let id = [0xAA; 16];
        let err = WireError::with_request_id(WireErrorCode::RateLimited, id);
        assert_eq!(err.code, WireErrorCode::RateLimited);
        assert_eq!(err.request_id, Some(id));
    }

    #[test]
    fn test_wire_error_serialization() {
        let err = WireError::new(WireErrorCode::AuthenticationFailed);
        let bytes = bincode::serialize(&err).unwrap();
        let restored: WireError = bincode::deserialize(&bytes).unwrap();
        assert_eq!(restored.code, WireErrorCode::AuthenticationFailed);
    }

    #[test]
    fn test_all_error_codes_have_descriptions() {
        for i in 0..=8u8 {
            let code = WireErrorCode::from_u8(i).unwrap();
            assert!(!code.description().is_empty());
        }
    }
}
