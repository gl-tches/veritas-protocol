//! Validator slashing and penalties.
//!
//! This module implements the slashing system for validator misbehavior in the
//! VERITAS blockchain. Validators can be penalized for:
//!
//! - **Missed blocks**: 0.1% penalty per missed block
//! - **SLA violations**: 1% penalty per violation
//! - **Invalid blocks**: 5% penalty
//! - **Double signing**: 100% slash + permanent ban
//!
//! ## Security
//!
//! Double-sign detection is critical for blockchain security. When a validator
//! signs two different blocks at the same height, they are permanently banned
//! and lose all staked reputation.
//!
//! ## Memory Safety (VERITAS-2026-0030, VERITAS-2026-0031)
//!
//! All collections in this module are bounded to prevent memory exhaustion attacks:
//! - Block signatures: Bounded by MAX_BLOCK_SIGNATURES
//! - Banned validators: Bounded by MAX_BANNED_VALIDATORS
//! - Slash history: Bounded by MAX_SLASH_HISTORY
//!
//! ## Example
//!
//! ```
//! use veritas_chain::slashing::{SlashingManager, SlashingOffense, SlashingConfig};
//! use veritas_identity::IdentityHash;
//!
//! let mut manager = SlashingManager::new(SlashingConfig::default());
//! let validator = IdentityHash::from_public_key(b"validator-pubkey");
//!
//! // Process a missed block offense
//! let result = manager.process_offense(
//!     &validator,
//!     SlashingOffense::MissedBlock { height: 100 },
//!     700,
//! );
//!
//! assert!(!result.banned);
//! assert!(result.penalty_amount > 0);
//! ```

use std::collections::HashMap;

// =============================================================================
// Collection Bounds (VERITAS-2026-0030, VERITAS-2026-0031)
// =============================================================================

/// Maximum number of block signatures to retain for double-sign detection.
///
/// SECURITY (VERITAS-2026-0030): Prevents memory exhaustion from unbounded
/// block signature storage. Older signatures are pruned when this limit is
/// exceeded.
pub const MAX_BLOCK_SIGNATURES: usize = 50_000;

/// Maximum number of slash history entries to retain.
///
/// SECURITY (VERITAS-2026-0030): Prevents memory exhaustion from unbounded
/// slash history. Oldest entries are pruned when this limit is exceeded.
pub const MAX_SLASH_HISTORY: usize = 10_000;

/// Maximum number of banned validators to track.
///
/// SECURITY (VERITAS-2026-0031): Prevents memory exhaustion from unbounded
/// ban list. This is a conservative limit; in practice, the number of banned
/// validators should remain much smaller. When exceeded, oldest bans are
/// pruned but a warning is logged.
pub const MAX_BANNED_VALIDATORS: usize = 1_000;

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

/// Configuration for slashing penalties.
///
/// Each offense type has an associated penalty percentage that is applied
/// to the validator's current stake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Penalty percentage for missing a block (0.1% = 0.001).
    pub missed_block_percent: f32,

    /// Penalty percentage for SLA violations (1% = 0.01).
    pub sla_violation_percent: f32,

    /// Penalty percentage for producing an invalid block (5% = 0.05).
    pub invalid_block_percent: f32,

    /// Penalty percentage for double signing (100% = 1.0).
    pub double_sign_percent: f32,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            missed_block_percent: 0.001, // 0.1%
            sla_violation_percent: 0.01, // 1%
            invalid_block_percent: 0.05, // 5%
            double_sign_percent: 1.0,    // 100%
        }
    }
}

impl SlashingConfig {
    /// Create a new slashing configuration with custom percentages.
    ///
    /// # Arguments
    ///
    /// * `missed_block_percent` - Penalty for missed blocks (0.0 to 1.0)
    /// * `sla_violation_percent` - Penalty for SLA violations (0.0 to 1.0)
    /// * `invalid_block_percent` - Penalty for invalid blocks (0.0 to 1.0)
    /// * `double_sign_percent` - Penalty for double signing (typically 1.0)
    pub fn new(
        missed_block_percent: f32,
        sla_violation_percent: f32,
        invalid_block_percent: f32,
        double_sign_percent: f32,
    ) -> Self {
        Self {
            missed_block_percent: missed_block_percent.clamp(0.0, 1.0),
            sla_violation_percent: sla_violation_percent.clamp(0.0, 1.0),
            invalid_block_percent: invalid_block_percent.clamp(0.0, 1.0),
            double_sign_percent: double_sign_percent.clamp(0.0, 1.0),
        }
    }
}

/// Types of SLA violations that can result in slashing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlaViolationType {
    /// Validator uptime fell below the required threshold.
    LowUptime {
        /// Actual uptime percentage.
        actual: f32,
        /// Required uptime percentage (typically 99%).
        required: f32,
    },

    /// Validator response latency exceeded the maximum allowed.
    HighLatency {
        /// Actual latency in milliseconds.
        actual_ms: u64,
        /// Maximum allowed latency in milliseconds.
        max_ms: u64,
    },

    /// Validator did not produce enough blocks in an epoch.
    InsufficientBlocks {
        /// Number of blocks produced.
        produced: u32,
        /// Minimum required blocks per epoch.
        required: u32,
    },

    /// Validator missed too many blocks in an epoch.
    TooManyMissed {
        /// Number of blocks missed.
        missed: u32,
        /// Maximum allowed missed blocks.
        max: u32,
    },
}

impl std::fmt::Display for SlaViolationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlaViolationType::LowUptime { actual, required } => {
                write!(f, "Low uptime: {:.2}% (required: {:.2}%)", actual, required)
            }
            SlaViolationType::HighLatency { actual_ms, max_ms } => {
                write!(f, "High latency: {}ms (max: {}ms)", actual_ms, max_ms)
            }
            SlaViolationType::InsufficientBlocks { produced, required } => {
                write!(
                    f,
                    "Insufficient blocks: {} produced (required: {})",
                    produced, required
                )
            }
            SlaViolationType::TooManyMissed { missed, max } => {
                write!(f, "Too many missed blocks: {} (max: {})", missed, max)
            }
        }
    }
}

/// Types of slashing offenses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SlashingOffense {
    /// Validator missed their turn to produce a block.
    MissedBlock {
        /// Height at which the block was missed.
        height: u64,
    },

    /// Validator violated their SLA agreement.
    SlaViolation {
        /// Type of SLA violation.
        violation_type: SlaViolationType,
    },

    /// Validator produced an invalid block.
    InvalidBlock {
        /// Height of the invalid block.
        height: u64,
        /// Reason why the block was invalid.
        reason: String,
    },

    /// Validator signed two different blocks at the same height.
    /// This is the most severe offense and results in permanent ban.
    DoubleSign {
        /// Height at which double signing occurred.
        height: u64,
        /// Hash of the first block signed.
        block_hash_1: Hash256,
        /// Hash of the second block signed.
        block_hash_2: Hash256,
    },
}

impl std::fmt::Display for SlashingOffense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashingOffense::MissedBlock { height } => {
                write!(f, "Missed block at height {}", height)
            }
            SlashingOffense::SlaViolation { violation_type } => {
                write!(f, "SLA violation: {}", violation_type)
            }
            SlashingOffense::InvalidBlock { height, reason } => {
                write!(f, "Invalid block at height {}: {}", height, reason)
            }
            SlashingOffense::DoubleSign { height, .. } => {
                write!(f, "Double signing at height {}", height)
            }
        }
    }
}

/// Result of processing a slashing offense.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashResult {
    /// The validator that was slashed.
    pub validator: IdentityHash,

    /// The offense that triggered the slash.
    pub offense: SlashingOffense,

    /// Amount of stake slashed (in reputation points).
    pub penalty_amount: u32,

    /// Remaining stake after the slash.
    pub remaining_stake: u32,

    /// Whether the validator is permanently banned.
    pub banned: bool,

    /// Unix timestamp when the slash was processed.
    pub timestamp: u64,
}

impl SlashResult {
    /// Check if the validator's stake was fully depleted.
    pub fn is_fully_slashed(&self) -> bool {
        self.remaining_stake == 0
    }

    /// Check if this was a critical offense (double sign or full depletion).
    pub fn is_critical(&self) -> bool {
        self.banned || self.is_fully_slashed()
    }
}

/// Record of a block signature for double-sign detection.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields kept for auditing/debugging purposes
struct BlockSignature {
    /// The validator who signed the block.
    validator: IdentityHash,
    /// The hash of the block that was signed.
    block_hash: Hash256,
    /// Unix timestamp when the signature was recorded.
    timestamp: u64,
}

/// Record of a banned validator with timestamp for LRU eviction.
#[derive(Debug, Clone)]
struct BannedValidator {
    /// When this validator was banned (Unix timestamp).
    banned_at: u64,
}

/// Manager for processing slashing offenses and tracking double-sign attempts.
///
/// The `SlashingManager` maintains state for detecting double-sign attacks
/// and calculates penalties based on the configured percentages.
///
/// ## Memory Safety (VERITAS-2026-0030, VERITAS-2026-0031)
///
/// All internal collections are bounded:
/// - `block_signatures`: Limited to MAX_BLOCK_SIGNATURES entries
/// - `banned_validators`: Limited to MAX_BANNED_VALIDATORS entries
/// - `slash_history`: Limited to MAX_SLASH_HISTORY entries
#[derive(Debug)]
pub struct SlashingManager {
    /// Slashing configuration.
    config: SlashingConfig,

    /// Block signatures indexed by (height, validator).
    /// Used for double-sign detection.
    /// SECURITY (VERITAS-2026-0030): Bounded by MAX_BLOCK_SIGNATURES.
    block_signatures: HashMap<(u64, IdentityHash), BlockSignature>,

    /// Map of permanently banned validators with ban timestamps.
    /// SECURITY (VERITAS-2026-0031): Bounded by MAX_BANNED_VALIDATORS.
    banned_validators: HashMap<IdentityHash, BannedValidator>,

    /// History of slash results.
    /// SECURITY (VERITAS-2026-0030): Bounded by MAX_SLASH_HISTORY.
    slash_history: Vec<SlashResult>,
}

impl SlashingManager {
    /// Create a new slashing manager with the given configuration.
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            config,
            block_signatures: HashMap::new(),
            banned_validators: HashMap::new(),
            slash_history: Vec::new(),
        }
    }

    /// Create a new slashing manager with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(SlashingConfig::default())
    }

    /// Get the slashing configuration.
    pub fn config(&self) -> &SlashingConfig {
        &self.config
    }

    /// Check if a validator is permanently banned.
    pub fn is_banned(&self, validator: &IdentityHash) -> bool {
        self.banned_validators.contains_key(validator)
    }

    /// Get the list of all banned validators.
    pub fn banned_validators(&self) -> impl Iterator<Item = &IdentityHash> {
        self.banned_validators.keys()
    }

    /// Get the number of currently banned validators.
    pub fn banned_count(&self) -> usize {
        self.banned_validators.len()
    }

    /// Get the slash history for a specific validator.
    pub fn validator_history(&self, validator: &IdentityHash) -> Vec<&SlashResult> {
        self.slash_history
            .iter()
            .filter(|r| &r.validator == validator)
            .collect()
    }

    /// Process a slashing offense.
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator being slashed
    /// * `offense` - The type of offense
    /// * `current_stake` - The validator's current stake
    ///
    /// # Returns
    ///
    /// A `SlashResult` containing the penalty details.
    ///
    /// ## Memory Safety (VERITAS-2026-0030, VERITAS-2026-0031)
    ///
    /// This method enforces collection bounds:
    /// - Prunes oldest slash history entries when MAX_SLASH_HISTORY is exceeded
    /// - Prunes oldest banned validators when MAX_BANNED_VALIDATORS is exceeded
    pub fn process_offense(
        &mut self,
        validator: &IdentityHash,
        offense: SlashingOffense,
        current_stake: u32,
    ) -> SlashResult {
        let penalty = self.calculate_penalty(&offense, current_stake);
        let remaining = current_stake.saturating_sub(penalty);
        let banned = matches!(offense, SlashingOffense::DoubleSign { .. });
        let timestamp = current_timestamp();

        if banned {
            // SECURITY (VERITAS-2026-0031): Check ban list capacity before adding
            self.enforce_ban_list_limit();

            self.banned_validators.insert(
                validator.clone(),
                BannedValidator { banned_at: timestamp },
            );
        }

        let result = SlashResult {
            validator: validator.clone(),
            offense,
            penalty_amount: penalty,
            remaining_stake: remaining,
            banned,
            timestamp,
        };

        // SECURITY (VERITAS-2026-0030): Enforce slash history limit
        self.enforce_slash_history_limit();
        self.slash_history.push(result.clone());

        result
    }

    /// Enforce the ban list size limit by removing oldest bans.
    ///
    /// SECURITY (VERITAS-2026-0031): Prevents memory exhaustion from unbounded
    /// ban list growth. When the limit is reached, the oldest bans are removed
    /// to make room for new bans. This is a safety measure; in practice, the
    /// number of banned validators should be much smaller than the limit.
    fn enforce_ban_list_limit(&mut self) {
        if self.banned_validators.len() >= MAX_BANNED_VALIDATORS {
            // Find and remove the oldest ban to make room
            let oldest = self
                .banned_validators
                .iter()
                .min_by_key(|(_, info)| info.banned_at)
                .map(|(id, _)| id.clone());

            if let Some(oldest_id) = oldest {
                self.banned_validators.remove(&oldest_id);
            }
        }
    }

    /// Enforce the slash history size limit by removing oldest entries.
    ///
    /// SECURITY (VERITAS-2026-0030): Prevents memory exhaustion from unbounded
    /// slash history growth. Oldest entries are removed first (FIFO).
    fn enforce_slash_history_limit(&mut self) {
        if self.slash_history.len() >= MAX_SLASH_HISTORY {
            // Remove oldest entries (from the front)
            let excess = self.slash_history.len() - MAX_SLASH_HISTORY + 1;
            self.slash_history.drain(0..excess);
        }
    }

    /// Calculate the penalty amount for an offense.
    ///
    /// The penalty is calculated as a percentage of the current stake,
    /// based on the offense type and configuration.
    pub fn calculate_penalty(&self, offense: &SlashingOffense, stake: u32) -> u32 {
        let percent = match offense {
            SlashingOffense::MissedBlock { .. } => self.config.missed_block_percent,
            SlashingOffense::SlaViolation { .. } => self.config.sla_violation_percent,
            SlashingOffense::InvalidBlock { .. } => self.config.invalid_block_percent,
            SlashingOffense::DoubleSign { .. } => self.config.double_sign_percent,
        };

        // Calculate penalty, rounding up to ensure at least 1 point is slashed
        // (unless stake is 0)
        if stake == 0 {
            return 0;
        }

        let penalty_float = (stake as f32) * percent;
        let penalty = penalty_float.ceil() as u32;

        // Ensure penalty doesn't exceed stake
        penalty.min(stake)
    }

    /// Check if an offense is critical (warrants immediate attention).
    ///
    /// Critical offenses include:
    /// - Double signing (security threat)
    /// - Invalid block with certain reasons
    pub fn is_critical(offense: &SlashingOffense) -> bool {
        matches!(
            offense,
            SlashingOffense::DoubleSign { .. } | SlashingOffense::InvalidBlock { .. }
        )
    }

    /// Record a block signature for double-sign detection.
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator who signed the block
    /// * `height` - The block height
    /// * `block_hash` - The hash of the signed block
    ///
    /// # Returns
    ///
    /// `Some(SlashingOffense::DoubleSign)` if double signing is detected,
    /// `None` otherwise.
    ///
    /// ## Memory Safety (VERITAS-2026-0030)
    ///
    /// This method enforces the MAX_BLOCK_SIGNATURES limit. When exceeded,
    /// signatures from older heights are pruned automatically.
    pub fn record_block_signature(
        &mut self,
        validator: &IdentityHash,
        height: u64,
        block_hash: Hash256,
    ) -> Option<SlashingOffense> {
        let key = (height, validator.clone());

        if let Some(existing) = self.block_signatures.get(&key) {
            // Check if the hashes are different (double sign)
            if existing.block_hash != block_hash {
                return Some(SlashingOffense::DoubleSign {
                    height,
                    block_hash_1: existing.block_hash.clone(),
                    block_hash_2: block_hash,
                });
            }
            // Same signature, no offense
            return None;
        }

        // SECURITY (VERITAS-2026-0030): Enforce block signature limit
        self.enforce_block_signatures_limit(height);

        // Record the new signature
        self.block_signatures.insert(
            key,
            BlockSignature {
                validator: validator.clone(),
                block_hash,
                timestamp: current_timestamp(),
            },
        );

        None
    }

    /// Enforce the block signatures size limit by pruning old signatures.
    ///
    /// SECURITY (VERITAS-2026-0030): Prevents memory exhaustion from unbounded
    /// block signature storage. Signatures from heights significantly lower
    /// than the current height are pruned.
    fn enforce_block_signatures_limit(&mut self, current_height: u64) {
        if self.block_signatures.len() >= MAX_BLOCK_SIGNATURES {
            // Find the minimum height that should be pruned
            // Keep signatures from recent blocks (within 1000 heights)
            const KEEP_RECENT_HEIGHTS: u64 = 1000;
            let prune_below = current_height.saturating_sub(KEEP_RECENT_HEIGHTS);

            self.block_signatures
                .retain(|(height, _), _| *height >= prune_below);

            // If still at limit after height-based pruning, remove oldest by timestamp
            if self.block_signatures.len() >= MAX_BLOCK_SIGNATURES {
                let oldest = self
                    .block_signatures
                    .iter()
                    .min_by_key(|(_, sig)| sig.timestamp)
                    .map(|(key, _)| key.clone());

                if let Some(oldest_key) = oldest {
                    self.block_signatures.remove(&oldest_key);
                }
            }
        }
    }

    /// Check if a validator has signed a block at the given height.
    pub fn has_signed_at_height(&self, validator: &IdentityHash, height: u64) -> bool {
        self.block_signatures
            .contains_key(&(height, validator.clone()))
    }

    /// Get the block hash that a validator signed at a given height.
    pub fn get_signed_block_hash(&self, validator: &IdentityHash, height: u64) -> Option<&Hash256> {
        self.block_signatures
            .get(&(height, validator.clone()))
            .map(|sig| &sig.block_hash)
    }

    /// Clear old block signatures to prevent memory growth.
    ///
    /// # Arguments
    ///
    /// * `min_height` - Remove all signatures below this height
    pub fn prune_signatures(&mut self, min_height: u64) {
        self.block_signatures
            .retain(|(height, _), _| *height >= min_height);
    }

    /// Calculate the cumulative penalty for multiple missed blocks.
    ///
    /// # Arguments
    ///
    /// * `missed_count` - Number of blocks missed
    /// * `initial_stake` - The validator's stake before penalties
    ///
    /// # Returns
    ///
    /// Total penalty amount for all missed blocks.
    pub fn calculate_cumulative_missed_penalty(
        &self,
        missed_count: u32,
        initial_stake: u32,
    ) -> u32 {
        let mut total_penalty = 0u32;
        let mut remaining_stake = initial_stake;

        for _ in 0..missed_count {
            let penalty = self
                .calculate_penalty(&SlashingOffense::MissedBlock { height: 0 }, remaining_stake);
            total_penalty = total_penalty.saturating_add(penalty);
            remaining_stake = remaining_stake.saturating_sub(penalty);

            if remaining_stake == 0 {
                break;
            }
        }

        total_penalty
    }
}

/// Get the current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator() -> IdentityHash {
        IdentityHash::from_public_key(b"test-validator-pubkey")
    }

    fn test_validator_2() -> IdentityHash {
        IdentityHash::from_public_key(b"test-validator-pubkey-2")
    }

    fn test_block_hash_1() -> Hash256 {
        Hash256::hash(b"block-1")
    }

    fn test_block_hash_2() -> Hash256 {
        Hash256::hash(b"block-2")
    }

    // Test 1: Missed block penalty calculation
    #[test]
    fn test_missed_block_penalty_calculation() {
        let manager = SlashingManager::with_default_config();
        let stake = 700;

        let penalty =
            manager.calculate_penalty(&SlashingOffense::MissedBlock { height: 100 }, stake);

        // 0.1% of 700 = 0.7, rounded up to 1
        assert_eq!(penalty, 1);
    }

    // Test 2: SLA violation penalty calculation
    #[test]
    fn test_sla_violation_penalty_calculation() {
        let manager = SlashingManager::with_default_config();
        let stake = 700;

        let penalty = manager.calculate_penalty(
            &SlashingOffense::SlaViolation {
                violation_type: SlaViolationType::LowUptime {
                    actual: 98.0,
                    required: 99.0,
                },
            },
            stake,
        );

        // 1% of 700 = 7
        assert_eq!(penalty, 7);
    }

    // Test 3: Invalid block penalty calculation
    #[test]
    fn test_invalid_block_penalty_calculation() {
        let manager = SlashingManager::with_default_config();
        let stake = 700;

        let penalty = manager.calculate_penalty(
            &SlashingOffense::InvalidBlock {
                height: 100,
                reason: "Invalid merkle root".to_string(),
            },
            stake,
        );

        // 5% of 700 = 35
        assert_eq!(penalty, 35);
    }

    // Test 4: Double-sign detection and 100% slash
    #[test]
    fn test_double_sign_detection_and_full_slash() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();
        let stake = 700;

        // First signature at height 100
        let result1 = manager.record_block_signature(&validator, 100, test_block_hash_1());
        assert!(result1.is_none());

        // Second different signature at same height - double sign!
        let result2 = manager.record_block_signature(&validator, 100, test_block_hash_2());
        assert!(matches!(result2, Some(SlashingOffense::DoubleSign { .. })));

        // Process the double sign offense
        if let Some(offense) = result2 {
            let slash_result = manager.process_offense(&validator, offense, stake);

            // 100% slash
            assert_eq!(slash_result.penalty_amount, 700);
            assert_eq!(slash_result.remaining_stake, 0);
        }
    }

    // Test 5: Double-sign permanent ban flag
    #[test]
    fn test_double_sign_permanent_ban() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        let offense = SlashingOffense::DoubleSign {
            height: 100,
            block_hash_1: test_block_hash_1(),
            block_hash_2: test_block_hash_2(),
        };

        let result = manager.process_offense(&validator, offense, 700);

        assert!(result.banned);
        assert!(manager.is_banned(&validator));
    }

    // Test 6: Multiple missed blocks accumulation
    #[test]
    fn test_multiple_missed_blocks_accumulation() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();
        let mut stake = 700u32;
        let mut total_penalty = 0u32;

        for height in 0..5 {
            let result =
                manager.process_offense(&validator, SlashingOffense::MissedBlock { height }, stake);
            total_penalty += result.penalty_amount;
            stake = result.remaining_stake;
        }

        // Each missed block should reduce stake
        assert!(total_penalty > 0);
        assert!(stake < 700);
    }

    // Test 7: Penalty capped at remaining stake
    #[test]
    fn test_penalty_capped_at_remaining_stake() {
        let manager = SlashingManager::with_default_config();

        // Very low stake
        let stake = 5;

        // Invalid block is 5% but penalty should not exceed stake
        let penalty = manager.calculate_penalty(
            &SlashingOffense::InvalidBlock {
                height: 100,
                reason: "test".to_string(),
            },
            stake,
        );

        assert!(penalty <= stake);
    }

    // Test 8: Critical offense detection
    #[test]
    fn test_critical_offense_detection() {
        assert!(SlashingManager::is_critical(&SlashingOffense::DoubleSign {
            height: 100,
            block_hash_1: test_block_hash_1(),
            block_hash_2: test_block_hash_2(),
        }));

        assert!(SlashingManager::is_critical(
            &SlashingOffense::InvalidBlock {
                height: 100,
                reason: "test".to_string(),
            }
        ));

        assert!(!SlashingManager::is_critical(
            &SlashingOffense::MissedBlock { height: 100 }
        ));

        assert!(!SlashingManager::is_critical(
            &SlashingOffense::SlaViolation {
                violation_type: SlaViolationType::LowUptime {
                    actual: 98.0,
                    required: 99.0,
                },
            }
        ));
    }

    // Test 9: SlashResult creation
    #[test]
    fn test_slash_result_creation() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        let result = manager.process_offense(
            &validator,
            SlashingOffense::MissedBlock { height: 100 },
            700,
        );

        assert_eq!(result.validator, validator);
        assert_eq!(result.penalty_amount, 1);
        assert_eq!(result.remaining_stake, 699);
        assert!(!result.banned);
        assert!(result.timestamp > 0);
    }

    // Test 10: Serialization roundtrip for SlashingConfig
    #[test]
    fn test_slashing_config_serialization() {
        let config = SlashingConfig::default();

        let serialized = bincode::serialize(&config).unwrap();
        let deserialized: SlashingConfig = bincode::deserialize(&serialized).unwrap();

        assert_eq!(
            deserialized.missed_block_percent,
            config.missed_block_percent
        );
        assert_eq!(
            deserialized.sla_violation_percent,
            config.sla_violation_percent
        );
        assert_eq!(
            deserialized.invalid_block_percent,
            config.invalid_block_percent
        );
        assert_eq!(deserialized.double_sign_percent, config.double_sign_percent);
    }

    // Test 11: Serialization roundtrip for SlashingOffense
    #[test]
    fn test_slashing_offense_serialization() {
        let offense = SlashingOffense::DoubleSign {
            height: 100,
            block_hash_1: test_block_hash_1(),
            block_hash_2: test_block_hash_2(),
        };

        let serialized = bincode::serialize(&offense).unwrap();
        let deserialized: SlashingOffense = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized, offense);
    }

    // Test 12: Serialization roundtrip for SlashResult
    #[test]
    fn test_slash_result_serialization() {
        let result = SlashResult {
            validator: test_validator(),
            offense: SlashingOffense::MissedBlock { height: 100 },
            penalty_amount: 1,
            remaining_stake: 699,
            banned: false,
            timestamp: 1234567890,
        };

        let serialized = bincode::serialize(&result).unwrap();
        let deserialized: SlashResult = bincode::deserialize(&serialized).unwrap();

        assert_eq!(deserialized.validator, result.validator);
        assert_eq!(deserialized.penalty_amount, result.penalty_amount);
        assert_eq!(deserialized.remaining_stake, result.remaining_stake);
        assert_eq!(deserialized.banned, result.banned);
    }

    // Test 13: Zero stake penalty is zero
    #[test]
    fn test_zero_stake_penalty() {
        let manager = SlashingManager::with_default_config();

        let penalty = manager.calculate_penalty(
            &SlashingOffense::InvalidBlock {
                height: 100,
                reason: "test".to_string(),
            },
            0,
        );

        assert_eq!(penalty, 0);
    }

    // Test 14: Same block signature is not double sign
    #[test]
    fn test_same_signature_not_double_sign() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();
        let block_hash = test_block_hash_1();

        // First signature
        let result1 = manager.record_block_signature(&validator, 100, block_hash.clone());
        assert!(result1.is_none());

        // Same signature again - not a double sign
        let result2 = manager.record_block_signature(&validator, 100, block_hash);
        assert!(result2.is_none());
    }

    // Test 15: Different validators can sign at same height
    #[test]
    fn test_different_validators_same_height() {
        let mut manager = SlashingManager::with_default_config();
        let validator1 = test_validator();
        let validator2 = test_validator_2();

        let result1 = manager.record_block_signature(&validator1, 100, test_block_hash_1());
        let result2 = manager.record_block_signature(&validator2, 100, test_block_hash_2());

        // Neither should be a double sign
        assert!(result1.is_none());
        assert!(result2.is_none());
    }

    // Test 16: Validator history tracking
    #[test]
    fn test_validator_history() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        // Process multiple offenses
        manager.process_offense(
            &validator,
            SlashingOffense::MissedBlock { height: 100 },
            700,
        );
        manager.process_offense(
            &validator,
            SlashingOffense::MissedBlock { height: 101 },
            699,
        );

        let history = manager.validator_history(&validator);
        assert_eq!(history.len(), 2);
    }

    // Test 17: Prune old signatures
    #[test]
    fn test_prune_signatures() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        // Add signatures at various heights
        for height in 0..10 {
            manager.record_block_signature(&validator, height, Hash256::hash(&[height as u8]));
        }

        assert!(manager.has_signed_at_height(&validator, 5));

        // Prune signatures below height 5
        manager.prune_signatures(5);

        assert!(!manager.has_signed_at_height(&validator, 4));
        assert!(manager.has_signed_at_height(&validator, 5));
        assert!(manager.has_signed_at_height(&validator, 9));
    }

    // Test 18: Cumulative missed penalty calculation
    #[test]
    fn test_cumulative_missed_penalty() {
        let manager = SlashingManager::with_default_config();

        let total = manager.calculate_cumulative_missed_penalty(5, 700);

        // Should be sum of 5 missed block penalties (each ~1 point)
        assert!(total >= 5);
    }

    // Test 19: Custom slashing config
    #[test]
    fn test_custom_slashing_config() {
        let config = SlashingConfig::new(
            0.01, // 1% for missed block
            0.05, // 5% for SLA
            0.10, // 10% for invalid
            1.0,  // 100% for double sign
        );
        let manager = SlashingManager::new(config);

        let stake = 1000;

        let missed_penalty =
            manager.calculate_penalty(&SlashingOffense::MissedBlock { height: 0 }, stake);
        assert_eq!(missed_penalty, 10); // 1% of 1000

        let sla_penalty = manager.calculate_penalty(
            &SlashingOffense::SlaViolation {
                violation_type: SlaViolationType::LowUptime {
                    actual: 98.0,
                    required: 99.0,
                },
            },
            stake,
        );
        assert_eq!(sla_penalty, 50); // 5% of 1000
    }

    // Test 20: SlashResult is_fully_slashed
    #[test]
    fn test_is_fully_slashed() {
        let result_partial = SlashResult {
            validator: test_validator(),
            offense: SlashingOffense::MissedBlock { height: 100 },
            penalty_amount: 10,
            remaining_stake: 690,
            banned: false,
            timestamp: 0,
        };
        assert!(!result_partial.is_fully_slashed());

        let result_full = SlashResult {
            validator: test_validator(),
            offense: SlashingOffense::DoubleSign {
                height: 100,
                block_hash_1: test_block_hash_1(),
                block_hash_2: test_block_hash_2(),
            },
            penalty_amount: 700,
            remaining_stake: 0,
            banned: true,
            timestamp: 0,
        };
        assert!(result_full.is_fully_slashed());
    }

    // Test 21: SlashResult is_critical
    #[test]
    fn test_slash_result_is_critical() {
        let non_critical = SlashResult {
            validator: test_validator(),
            offense: SlashingOffense::MissedBlock { height: 100 },
            penalty_amount: 1,
            remaining_stake: 699,
            banned: false,
            timestamp: 0,
        };
        assert!(!non_critical.is_critical());

        let critical_banned = SlashResult {
            validator: test_validator(),
            offense: SlashingOffense::DoubleSign {
                height: 100,
                block_hash_1: test_block_hash_1(),
                block_hash_2: test_block_hash_2(),
            },
            penalty_amount: 700,
            remaining_stake: 0,
            banned: true,
            timestamp: 0,
        };
        assert!(critical_banned.is_critical());

        let critical_depleted = SlashResult {
            validator: test_validator(),
            offense: SlashingOffense::InvalidBlock {
                height: 100,
                reason: "test".to_string(),
            },
            penalty_amount: 5,
            remaining_stake: 0,
            banned: false,
            timestamp: 0,
        };
        assert!(critical_depleted.is_critical());
    }

    // Test 22: Get signed block hash
    #[test]
    fn test_get_signed_block_hash() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();
        let block_hash = test_block_hash_1();

        // No signature yet
        assert!(manager.get_signed_block_hash(&validator, 100).is_none());

        // Add signature
        manager.record_block_signature(&validator, 100, block_hash.clone());

        // Should now return the hash
        let retrieved = manager.get_signed_block_hash(&validator, 100);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), &block_hash);
    }

    // Test 23: SlaViolationType Display
    #[test]
    fn test_sla_violation_type_display() {
        let low_uptime = SlaViolationType::LowUptime {
            actual: 98.5,
            required: 99.0,
        };
        assert!(low_uptime.to_string().contains("98.50%"));

        let high_latency = SlaViolationType::HighLatency {
            actual_ms: 6000,
            max_ms: 5000,
        };
        assert!(high_latency.to_string().contains("6000ms"));

        let insufficient = SlaViolationType::InsufficientBlocks {
            produced: 5,
            required: 10,
        };
        assert!(insufficient.to_string().contains("5 produced"));

        let too_many = SlaViolationType::TooManyMissed { missed: 5, max: 3 };
        assert!(too_many.to_string().contains("5"));
    }

    // Test 24: SlashingOffense Display
    #[test]
    fn test_slashing_offense_display() {
        let missed = SlashingOffense::MissedBlock { height: 100 };
        assert!(missed.to_string().contains("100"));

        let invalid = SlashingOffense::InvalidBlock {
            height: 200,
            reason: "bad merkle".to_string(),
        };
        assert!(invalid.to_string().contains("200"));
        assert!(invalid.to_string().contains("bad merkle"));

        let double_sign = SlashingOffense::DoubleSign {
            height: 300,
            block_hash_1: test_block_hash_1(),
            block_hash_2: test_block_hash_2(),
        };
        assert!(double_sign.to_string().contains("300"));
    }

    // ==========================================================================
    // Security Tests: Collection Bounds (VERITAS-2026-0030, VERITAS-2026-0031)
    // ==========================================================================

    // Test 25: Slash history is bounded at MAX_SLASH_HISTORY
    #[test]
    fn test_slash_history_bounded() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        // Add MAX_SLASH_HISTORY + 10 offenses
        for height in 0..(super::MAX_SLASH_HISTORY + 10) as u64 {
            manager.process_offense(
                &validator,
                SlashingOffense::MissedBlock { height },
                1000,
            );
        }

        // Slash history should be bounded at MAX_SLASH_HISTORY
        assert!(manager.slash_history.len() <= super::MAX_SLASH_HISTORY);
    }

    // Test 26: Ban list is bounded at MAX_BANNED_VALIDATORS
    #[test]
    fn test_ban_list_bounded() {
        let mut manager = SlashingManager::with_default_config();

        // Ban MAX_BANNED_VALIDATORS + 10 validators
        for i in 0..(super::MAX_BANNED_VALIDATORS + 10) as u32 {
            let validator = IdentityHash::from_bytes(&[
                (i & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 24) & 0xFF) as u8,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])
            .unwrap();

            manager.process_offense(
                &validator,
                SlashingOffense::DoubleSign {
                    height: i as u64,
                    block_hash_1: Hash256::hash(&[i as u8]),
                    block_hash_2: Hash256::hash(&[(i + 1) as u8]),
                },
                1000,
            );
        }

        // Ban list should be bounded at MAX_BANNED_VALIDATORS
        assert!(manager.banned_count() <= super::MAX_BANNED_VALIDATORS);
    }

    // Test 27: Recent bans are preserved during pruning
    #[test]
    fn test_recent_bans_preserved() {
        let mut manager = SlashingManager::with_default_config();

        // Ban MAX_BANNED_VALIDATORS validators
        for i in 0..super::MAX_BANNED_VALIDATORS as u32 {
            let validator = IdentityHash::from_bytes(&[
                (i & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ])
            .unwrap();

            manager.process_offense(
                &validator,
                SlashingOffense::DoubleSign {
                    height: i as u64,
                    block_hash_1: Hash256::hash(&[i as u8]),
                    block_hash_2: Hash256::hash(&[(i + 1) as u8]),
                },
                1000,
            );
        }

        // Ban one more recent validator
        let recent_validator = IdentityHash::from_bytes(&[
            0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();

        manager.process_offense(
            &recent_validator,
            SlashingOffense::DoubleSign {
                height: 9999,
                block_hash_1: Hash256::hash(b"recent1"),
                block_hash_2: Hash256::hash(b"recent2"),
            },
            1000,
        );

        // The most recent ban should be preserved
        assert!(manager.is_banned(&recent_validator));
    }

    // Test 28: Block signatures are bounded
    #[test]
    fn test_block_signatures_bounded() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        // Add MAX_BLOCK_SIGNATURES + 100 signatures (but at heights that would trigger pruning)
        for height in 0..(super::MAX_BLOCK_SIGNATURES + 100) as u64 {
            manager.record_block_signature(
                &validator,
                height,
                Hash256::hash(&height.to_le_bytes()),
            );
        }

        // Block signatures should be bounded
        // Due to height-based pruning, we expect far fewer than MAX_BLOCK_SIGNATURES
        assert!(manager.block_signatures.len() <= super::MAX_BLOCK_SIGNATURES);
    }

    // Test 29: Banned count helper works
    #[test]
    fn test_banned_count() {
        let mut manager = SlashingManager::with_default_config();
        assert_eq!(manager.banned_count(), 0);

        let v1 = test_validator();
        let v2 = test_validator_2();

        manager.process_offense(
            &v1,
            SlashingOffense::DoubleSign {
                height: 1,
                block_hash_1: test_block_hash_1(),
                block_hash_2: test_block_hash_2(),
            },
            1000,
        );
        assert_eq!(manager.banned_count(), 1);

        manager.process_offense(
            &v2,
            SlashingOffense::DoubleSign {
                height: 2,
                block_hash_1: test_block_hash_1(),
                block_hash_2: test_block_hash_2(),
            },
            1000,
        );
        assert_eq!(manager.banned_count(), 2);
    }

    // Test 30: Old signatures are pruned during limit enforcement
    #[test]
    fn test_old_signatures_pruned_during_enforcement() {
        let mut manager = SlashingManager::with_default_config();
        let validator = test_validator();

        // Add signatures at heights 0-99
        for height in 0..100 {
            manager.record_block_signature(
                &validator,
                height,
                Hash256::hash(&[height as u8]),
            );
        }

        // Verify signatures exist at low heights
        assert!(manager.has_signed_at_height(&validator, 0));
        assert!(manager.has_signed_at_height(&validator, 50));

        // Now simulate the limit being hit by calling prune_signatures with a high min_height
        manager.prune_signatures(50);

        // Old signatures should be pruned
        assert!(!manager.has_signed_at_height(&validator, 0));
        assert!(!manager.has_signed_at_height(&validator, 49));
        assert!(manager.has_signed_at_height(&validator, 50));
        assert!(manager.has_signed_at_height(&validator, 99));
    }
}
