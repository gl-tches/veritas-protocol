//! Trusted time validation for VERITAS protocol.
//!
//! Provides secure time handling to prevent time manipulation attacks:
//! - Validates timestamps are within reasonable bounds
//! - Rejects future timestamps (beyond allowed clock skew)
//! - Rejects ancient timestamps (before protocol inception)
//!
//! ## Security Properties
//!
//! - Prevents attackers from using far-future timestamps to bypass expiry
//! - Prevents replay of ancient messages
//! - Allows reasonable clock skew between nodes (5 minutes)
//!
//! ## Vulnerability Fixes
//!
//! - VERITAS-2026-0008: Key lifecycle time manipulation
//! - VERITAS-2026-0009: Message timestamp bypass

use thiserror::Error;

// === Time Validation Constants ===

/// Maximum allowed clock skew in seconds (5 minutes).
///
/// Timestamps may be up to this far in the future to account for
/// clock synchronization differences between nodes.
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;

/// Minimum valid timestamp (2024-01-01 00:00:00 UTC).
///
/// Timestamps before this are considered ancient and rejected.
/// This prevents replay of pre-protocol messages.
pub const MIN_VALID_TIMESTAMP: u64 = 1704067200;

/// Maximum valid timestamp (2100-01-01 00:00:00 UTC).
///
/// Timestamps after this are considered invalid.
/// This provides a sanity check against garbage data.
pub const MAX_VALID_TIMESTAMP: u64 = 4102444800;

/// Errors that can occur during time validation.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    /// Timestamp is too far in the future.
    #[error("Timestamp is in the future (beyond {max_skew}s allowed): {timestamp}")]
    TimestampInFuture {
        /// The invalid future timestamp.
        timestamp: u64,
        /// The maximum allowed clock skew.
        max_skew: u64,
    },

    /// Timestamp is too old (before protocol inception).
    #[error("Timestamp is too old (before {min_valid}): {timestamp}")]
    TimestampTooOld {
        /// The invalid old timestamp.
        timestamp: u64,
        /// The minimum valid timestamp.
        min_valid: u64,
    },

    /// Timestamp exceeds maximum valid value.
    #[error("Timestamp exceeds maximum valid value ({max_valid}): {timestamp}")]
    TimestampTooLarge {
        /// The invalid large timestamp.
        timestamp: u64,
        /// The maximum valid timestamp.
        max_valid: u64,
    },

    /// System time error.
    #[error("System time error: {0}")]
    SystemTimeError(String),
}

/// Result type for time operations.
pub type TimeResult<T> = std::result::Result<T, TimeError>;

/// Get the current Unix timestamp in seconds.
///
/// Uses the system clock. In production, this should ideally be
/// supplemented with NTP validation or trusted time sources.
///
/// # Errors
///
/// Returns `TimeError::SystemTimeError` if the system time is before
/// the Unix epoch.
///
/// # Example
///
/// ```
/// use veritas_core::time::now;
///
/// let current_time = now().expect("system time should be valid");
/// assert!(current_time > 1700000000);
/// ```
pub fn now() -> TimeResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| TimeError::SystemTimeError(e.to_string()))
}

/// Get the current Unix timestamp, with fallback to minimum valid time.
///
/// This is a convenience function that never fails. If the system time
/// is unavailable, it returns `MIN_VALID_TIMESTAMP` as a safe fallback.
///
/// # Security Note
///
/// The fallback ensures that even with time errors, security checks
/// will treat the situation conservatively (timestamps will appear old).
///
/// # Example
///
/// ```
/// use veritas_core::time::now_or_safe_fallback;
///
/// let current_time = now_or_safe_fallback();
/// // Always returns a valid timestamp
/// ```
pub fn now_or_safe_fallback() -> u64 {
    now().unwrap_or(MIN_VALID_TIMESTAMP)
}

/// Validate that a timestamp is within acceptable bounds.
///
/// Checks that the timestamp:
/// 1. Is not too far in the future (beyond MAX_CLOCK_SKEW_SECS)
/// 2. Is not too old (before MIN_VALID_TIMESTAMP)
/// 3. Does not exceed MAX_VALID_TIMESTAMP
///
/// # Arguments
///
/// * `timestamp` - The Unix timestamp in seconds to validate
///
/// # Errors
///
/// Returns `TimeError::TimestampInFuture` if the timestamp is too far ahead.
/// Returns `TimeError::TimestampTooOld` if the timestamp is before protocol inception.
/// Returns `TimeError::TimestampTooLarge` if the timestamp exceeds the maximum.
///
/// # Example
///
/// ```
/// use veritas_core::time::{validate_timestamp, now};
///
/// let current = now().unwrap();
/// assert!(validate_timestamp(current).is_ok());
///
/// // Future timestamp is rejected
/// assert!(validate_timestamp(current + 1000).is_err());
///
/// // Ancient timestamp is rejected
/// assert!(validate_timestamp(1000).is_err());
/// ```
pub fn validate_timestamp(timestamp: u64) -> TimeResult<()> {
    // Check maximum sanity bound first
    if timestamp > MAX_VALID_TIMESTAMP {
        return Err(TimeError::TimestampTooLarge {
            timestamp,
            max_valid: MAX_VALID_TIMESTAMP,
        });
    }

    // Check minimum bound (ancient timestamps)
    if timestamp < MIN_VALID_TIMESTAMP {
        return Err(TimeError::TimestampTooOld {
            timestamp,
            min_valid: MIN_VALID_TIMESTAMP,
        });
    }

    // Check future bound (with clock skew allowance)
    let current = now()?;
    let max_allowed = current.saturating_add(MAX_CLOCK_SKEW_SECS);
    if timestamp > max_allowed {
        return Err(TimeError::TimestampInFuture {
            timestamp,
            max_skew: MAX_CLOCK_SKEW_SECS,
        });
    }

    Ok(())
}

/// Validate a timestamp against a specific reference time.
///
/// This is useful for testing or when you have a known reference time.
///
/// # Arguments
///
/// * `timestamp` - The Unix timestamp in seconds to validate
/// * `reference_time` - The reference time to compare against
///
/// # Errors
///
/// Same as `validate_timestamp`.
///
/// # Example
///
/// ```
/// use veritas_core::time::validate_timestamp_at;
///
/// let reference = 1704067300; // Just after MIN_VALID_TIMESTAMP
/// assert!(validate_timestamp_at(reference, reference).is_ok());
/// assert!(validate_timestamp_at(reference + 1000, reference).is_err());
/// ```
pub fn validate_timestamp_at(timestamp: u64, reference_time: u64) -> TimeResult<()> {
    // Check maximum sanity bound first
    if timestamp > MAX_VALID_TIMESTAMP {
        return Err(TimeError::TimestampTooLarge {
            timestamp,
            max_valid: MAX_VALID_TIMESTAMP,
        });
    }

    // Check minimum bound (ancient timestamps)
    if timestamp < MIN_VALID_TIMESTAMP {
        return Err(TimeError::TimestampTooOld {
            timestamp,
            min_valid: MIN_VALID_TIMESTAMP,
        });
    }

    // Check future bound (with clock skew allowance)
    let max_allowed = reference_time.saturating_add(MAX_CLOCK_SKEW_SECS);
    if timestamp > max_allowed {
        return Err(TimeError::TimestampInFuture {
            timestamp,
            max_skew: MAX_CLOCK_SKEW_SECS,
        });
    }

    Ok(())
}

/// Check if a timestamp is in the future beyond allowed clock skew.
///
/// # Arguments
///
/// * `timestamp` - The Unix timestamp to check
///
/// # Returns
///
/// `true` if the timestamp is too far in the future, `false` otherwise.
pub fn is_future_timestamp(timestamp: u64) -> bool {
    let current = now().unwrap_or(MIN_VALID_TIMESTAMP);
    timestamp > current.saturating_add(MAX_CLOCK_SKEW_SECS)
}

/// Check if a timestamp is before the protocol's minimum valid time.
///
/// # Arguments
///
/// * `timestamp` - The Unix timestamp to check
///
/// # Returns
///
/// `true` if the timestamp is too old, `false` otherwise.
pub fn is_ancient_timestamp(timestamp: u64) -> bool {
    timestamp < MIN_VALID_TIMESTAMP
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_reasonable() {
        // MAX_CLOCK_SKEW_SECS should be 5 minutes
        assert_eq!(MAX_CLOCK_SKEW_SECS, 300);

        // MIN_VALID_TIMESTAMP should be 2024-01-01
        assert_eq!(MIN_VALID_TIMESTAMP, 1704067200);

        // MAX_VALID_TIMESTAMP should be 2100-01-01
        assert_eq!(MAX_VALID_TIMESTAMP, 4102444800);

        // Sanity check: min < current < max
        let current = now().unwrap();
        assert!(MIN_VALID_TIMESTAMP < current);
        assert!(current < MAX_VALID_TIMESTAMP);
    }

    #[test]
    fn test_now_returns_reasonable_time() {
        let current = now().expect("should get current time");
        // Should be after 2024-01-01
        assert!(current >= MIN_VALID_TIMESTAMP);
        // Should be before 2100-01-01
        assert!(current < MAX_VALID_TIMESTAMP);
    }

    #[test]
    fn test_now_or_safe_fallback() {
        let current = now_or_safe_fallback();
        // Should always return something reasonable
        assert!(current >= MIN_VALID_TIMESTAMP);
    }

    #[test]
    fn test_validate_timestamp_current_time() {
        let current = now().unwrap();
        assert!(validate_timestamp(current).is_ok());
    }

    #[test]
    fn test_validate_timestamp_slightly_past() {
        let current = now().unwrap();
        let slightly_past = current - 3600; // 1 hour ago
        assert!(validate_timestamp(slightly_past).is_ok());
    }

    #[test]
    fn test_validate_timestamp_future_within_skew() {
        let current = now().unwrap();
        // Within allowed clock skew
        let future = current + MAX_CLOCK_SKEW_SECS - 10;
        assert!(validate_timestamp(future).is_ok());
    }

    #[test]
    fn test_validate_timestamp_future_beyond_skew() {
        let current = now().unwrap();
        // Beyond allowed clock skew
        let future = current + MAX_CLOCK_SKEW_SECS + 100;
        let result = validate_timestamp(future);
        assert!(matches!(result, Err(TimeError::TimestampInFuture { .. })));
    }

    #[test]
    fn test_validate_timestamp_ancient() {
        // Before protocol inception
        let ancient = 1000000000; // September 2001
        let result = validate_timestamp(ancient);
        assert!(matches!(result, Err(TimeError::TimestampTooOld { .. })));
    }

    #[test]
    fn test_validate_timestamp_too_large() {
        // Way in the future
        let far_future = MAX_VALID_TIMESTAMP + 1;
        let result = validate_timestamp(far_future);
        assert!(matches!(result, Err(TimeError::TimestampTooLarge { .. })));
    }

    #[test]
    fn test_validate_timestamp_at_boundary() {
        // Exactly at MIN_VALID_TIMESTAMP
        let current = now().unwrap();
        // Only valid if MIN_VALID_TIMESTAMP is within the past
        // Since current time is after MIN_VALID_TIMESTAMP, this should pass
        if current > MIN_VALID_TIMESTAMP + MAX_CLOCK_SKEW_SECS {
            assert!(validate_timestamp(MIN_VALID_TIMESTAMP).is_ok());
        }
    }

    #[test]
    fn test_validate_timestamp_at_reference() {
        let reference = 1750000000u64; // Some time in 2025

        // Timestamp equal to reference should be OK
        assert!(validate_timestamp_at(reference, reference).is_ok());

        // Timestamp slightly before reference should be OK
        assert!(validate_timestamp_at(reference - 1000, reference).is_ok());

        // Timestamp slightly after (within skew) should be OK
        assert!(validate_timestamp_at(reference + 100, reference).is_ok());

        // Timestamp far after reference should fail
        let result = validate_timestamp_at(reference + 1000, reference);
        assert!(matches!(result, Err(TimeError::TimestampInFuture { .. })));
    }

    #[test]
    fn test_is_future_timestamp() {
        let current = now().unwrap();

        // Current time is not future
        assert!(!is_future_timestamp(current));

        // Time within skew is not future
        assert!(!is_future_timestamp(current + MAX_CLOCK_SKEW_SECS));

        // Time beyond skew is future
        assert!(is_future_timestamp(current + MAX_CLOCK_SKEW_SECS + 100));
    }

    #[test]
    fn test_is_ancient_timestamp() {
        // Before MIN_VALID_TIMESTAMP is ancient
        assert!(is_ancient_timestamp(MIN_VALID_TIMESTAMP - 1));
        assert!(is_ancient_timestamp(1000000000)); // 2001

        // At or after MIN_VALID_TIMESTAMP is not ancient
        assert!(!is_ancient_timestamp(MIN_VALID_TIMESTAMP));
        assert!(!is_ancient_timestamp(MIN_VALID_TIMESTAMP + 1));
    }

    #[test]
    fn test_time_error_display() {
        let err = TimeError::TimestampInFuture {
            timestamp: 9999999999,
            max_skew: 300,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("future"));
        assert!(msg.contains("9999999999"));

        let err = TimeError::TimestampTooOld {
            timestamp: 1000,
            min_valid: MIN_VALID_TIMESTAMP,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("old"));
        assert!(msg.contains("1000"));
    }

    #[test]
    fn test_validate_timestamp_zero() {
        // Zero timestamp should be rejected as too old
        let result = validate_timestamp(0);
        assert!(matches!(result, Err(TimeError::TimestampTooOld { .. })));
    }

    #[test]
    fn test_validate_timestamp_max_u64() {
        // Max u64 should be rejected as too large
        let result = validate_timestamp(u64::MAX);
        assert!(matches!(result, Err(TimeError::TimestampTooLarge { .. })));
    }
}
