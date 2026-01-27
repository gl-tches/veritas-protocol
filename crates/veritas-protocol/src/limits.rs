//! Protocol limits and constants.
//!
//! All protocol limits are defined here for consistent enforcement.

// === Messages ===

/// Maximum characters per message chunk.
pub const MAX_MESSAGE_CHARS: usize = 300;

/// Maximum chunks per message.
pub const MAX_CHUNKS_PER_MESSAGE: usize = 3;

/// Maximum total characters across all chunks.
pub const MAX_TOTAL_MESSAGE_CHARS: usize = 900;

/// Message time-to-live in seconds (7 days).
pub const MESSAGE_TTL_SECS: u64 = 7 * 24 * 60 * 60;

// === Privacy ===

/// Fixed-size padding buckets for messages.
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

/// Grace period after expiry before slot release (24 hours).
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

/// Group key rotation interval in seconds (7 days).
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

/// Minimum interval between messages to same peer (seconds).
pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;

/// Maximum daily reputation gain from one peer.
pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;

/// Maximum total daily reputation gain.
pub const MAX_DAILY_GAIN_TOTAL: u32 = 100;

/// Number of reports required before negative action.
pub const NEGATIVE_REPORT_THRESHOLD: u32 = 3;

/// Minimum reputation required to file reports.
pub const MIN_REPORTER_REPUTATION: u32 = 400;

/// Threshold for suspicious cluster detection (70% internal).
pub const CLUSTER_SUSPICION_THRESHOLD: f32 = 0.7;

// === Validators ===

/// Minimum reputation stake to become validator.
pub const MIN_VALIDATOR_STAKE: u32 = 700;

/// Maximum active validators.
pub const MAX_VALIDATORS: usize = 21;

/// Percentage of validators rotated per epoch.
pub const VALIDATOR_ROTATION_PERCENT: f32 = 0.15;

/// Maximum validators per geographic region.
pub const MAX_VALIDATORS_PER_REGION: usize = 5;

/// Epochs stake is locked after staking.
pub const STAKE_LOCK_EPOCHS: u32 = 14;

// === Validator SLA ===

/// Minimum uptime percentage required.
pub const MIN_UPTIME_PERCENT: f32 = 99.0;

/// Maximum missed blocks per epoch.
pub const MAX_MISSED_BLOCKS_PER_EPOCH: u32 = 3;

/// Maximum response latency in milliseconds.
pub const MAX_RESPONSE_LATENCY_MS: u64 = 5000;

/// Minimum blocks a validator must produce per epoch.
pub const MIN_BLOCKS_PER_EPOCH: u32 = 10;
