//! Protocol limits and constants.
//!
//! All protocol-enforced limits are defined here for easy reference and modification.

// === Messages ===

/// Maximum characters per message (single chunk).
pub const MAX_MESSAGE_CHARS: usize = 300;

/// Maximum chunks per message.
pub const MAX_CHUNKS_PER_MESSAGE: usize = 3;

/// Maximum total characters across all chunks.
pub const MAX_TOTAL_MESSAGE_CHARS: usize = 900;

/// Message time-to-live in seconds (7 days).
pub const MESSAGE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

// === DoS Prevention ===

/// Maximum size of a serialized MinimalEnvelope in bytes.
/// SECURITY: Check this BEFORE deserialization to prevent OOM attacks (VERITAS-2026-0003).
pub const MAX_ENVELOPE_SIZE: usize = 2048;

/// Maximum size of a serialized InnerPayload in bytes.
/// SECURITY: Check this BEFORE deserialization to prevent OOM attacks (VERITAS-2026-0003).
pub const MAX_INNER_ENVELOPE_SIZE: usize = 1536;

/// Maximum total buffer size for chunk reassembly per session.
/// SECURITY: Prevents memory exhaustion from incomplete chunk streams.
pub const MAX_REASSEMBLY_BUFFER: usize = 4096;

/// Maximum number of concurrent pending reassembly sessions.
/// SECURITY: Prevents memory exhaustion from many incomplete messages.
pub const MAX_PENDING_REASSEMBLIES: usize = 1000;

/// Timeout for incomplete reassembly sessions in seconds.
/// SECURITY: Ensures stale sessions are cleaned up.
pub const REASSEMBLY_TIMEOUT_SECS: u64 = 300;

// === Privacy ===

/// Padding bucket sizes for hiding message length.
pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];

/// Maximum timing jitter in milliseconds (0-3 seconds).
pub const MAX_JITTER_MS: u64 = 3000;

/// Epoch duration for mailbox key rotation (1 day).
pub const EPOCH_DURATION_SECS: u64 = 24 * 60 * 60;

// === Identity ===

/// Maximum identities per device origin.
pub const MAX_IDENTITIES_PER_ORIGIN: u32 = 3;

/// Key expiry time in seconds (30 days).
pub const KEY_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;

/// Warning period before key expiry (5 days).
pub const KEY_WARNING_SECS: u64 = 5 * 24 * 60 * 60;

/// Grace period after key expiry (24 hours).
pub const EXPIRY_GRACE_PERIOD_SECS: u64 = 24 * 60 * 60;

// === Username ===

/// Minimum username length.
pub const MIN_USERNAME_LEN: usize = 3;

/// Maximum username length.
pub const MAX_USERNAME_LEN: usize = 32;

// === Groups ===

/// Maximum members per group.
pub const MAX_GROUP_SIZE: usize = 100;

/// Maximum groups per identity.
pub const MAX_GROUPS_PER_IDENTITY: usize = 50;

/// Group key rotation interval (7 days).
pub const GROUP_KEY_ROTATION_SECS: u64 = 7 * 24 * 60 * 60;

// === Reputation ===

/// Starting reputation score.
pub const REPUTATION_START: u32 = 500;

/// Maximum reputation score.
pub const REPUTATION_MAX: u32 = 1000;

/// Quarantine threshold.
pub const REPUTATION_QUARANTINE: u32 = 200;

/// Blacklist threshold.
pub const REPUTATION_BLACKLIST: u32 = 50;

// === Anti-Gaming ===

/// Minimum seconds between messages to same peer.
pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;

/// Maximum reputation gain from one peer per day.
pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;

/// Maximum total reputation gain per day.
pub const MAX_DAILY_GAIN_TOTAL: u32 = 100;

/// Number of independent reports needed for negative action.
pub const NEGATIVE_REPORT_THRESHOLD: u32 = 3;

/// Minimum reputation to file reports.
pub const MIN_REPORTER_REPUTATION: u32 = 400;

/// Suspicion threshold for cluster detection (70%).
pub const CLUSTER_SUSPICION_THRESHOLD: f32 = 0.7;

// === Validators ===

/// Minimum reputation to become a validator.
pub const MIN_VALIDATOR_STAKE: u32 = 700;

/// Maximum active validators.
pub const MAX_VALIDATORS: usize = 21;

/// Percentage of validators to rotate per epoch.
pub const VALIDATOR_ROTATION_PERCENT: f32 = 0.15;

/// Maximum validators per geographic region.
pub const MAX_VALIDATORS_PER_REGION: usize = 5;

/// Epochs stake is locked after becoming validator.
pub const STAKE_LOCK_EPOCHS: u32 = 14;

// === Validator SLA ===

/// Minimum required uptime percentage.
pub const MIN_UPTIME_PERCENT: f32 = 99.0;

/// Maximum missed blocks per epoch.
pub const MAX_MISSED_BLOCKS_PER_EPOCH: u32 = 3;

/// Maximum response latency in milliseconds.
pub const MAX_RESPONSE_LATENCY_MS: u64 = 5000;

/// Minimum blocks to produce per epoch when scheduled.
pub const MIN_BLOCKS_PER_EPOCH: u32 = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_limits_consistent() {
        assert_eq!(
            MAX_TOTAL_MESSAGE_CHARS,
            MAX_MESSAGE_CHARS * MAX_CHUNKS_PER_MESSAGE
        );
    }

    // Compile-time assertions for constant relationships
    const _: () = {
        assert!(REPUTATION_BLACKLIST < REPUTATION_QUARANTINE);
        assert!(REPUTATION_QUARANTINE < REPUTATION_START);
        assert!(REPUTATION_START < REPUTATION_MAX);
        assert!(MIN_VALIDATOR_STAKE > REPUTATION_QUARANTINE);
        // DoS prevention constants must be reasonable
        assert!(MAX_INNER_ENVELOPE_SIZE < MAX_ENVELOPE_SIZE);
        assert!(MAX_ENVELOPE_SIZE <= MAX_REASSEMBLY_BUFFER);
        assert!(REASSEMBLY_TIMEOUT_SECS > 0);
        assert!(MAX_PENDING_REASSEMBLIES > 0);
    };

    #[test]
    fn test_reputation_thresholds_ordered() {
        // Verified at compile time via const assertion above
        // Runtime test ensures constants are accessible and test runs
        let blacklist = REPUTATION_BLACKLIST;
        let quarantine = REPUTATION_QUARANTINE;
        let start = REPUTATION_START;
        let max = REPUTATION_MAX;
        assert!(blacklist < quarantine && quarantine < start && start < max);
    }

    #[test]
    fn test_validator_stake_above_quarantine() {
        // Verified at compile time via const assertion above
        // Runtime test ensures constants are accessible and test runs
        let stake = MIN_VALIDATOR_STAKE;
        let quarantine = REPUTATION_QUARANTINE;
        assert!(stake > quarantine);
    }
}
