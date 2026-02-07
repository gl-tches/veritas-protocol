//! Light validator implementation.
//!
//! Light validators store headers + ML-DSA transaction signatures only (no message bodies).
//! During epoch: can validate transactions were properly signed without seeing content.
//! After epoch: prune signatures, converge to header-only state.
//! Memory target: 256MB RAM.
//!
//! ## Validator Modes
//!
//! - **Full**: Hold complete blocks (headers + bodies + signatures). Validate consensus, produce blocks.
//! - **Light**: Hold headers + signatures only (no message bodies). After epoch: prune signatures.

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::epoch;
use crate::transaction::MessageHeader;

/// Validator operating mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorMode {
    /// Full validator: stores complete blocks (headers + bodies + signatures).
    Full,
    /// Light validator: stores headers + signatures only (no message bodies).
    Light,
}

impl std::fmt::Display for ValidatorMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidatorMode::Full => write!(f, "full-validator"),
            ValidatorMode::Light => write!(f, "light-validator"),
        }
    }
}

impl std::str::FromStr for ValidatorMode {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "full-validator" | "full" => Ok(ValidatorMode::Full),
            "light-validator" | "light" => Ok(ValidatorMode::Light),
            _ => Err(format!(
                "Unknown validator mode: '{}'. Use 'full-validator' or 'light-validator'",
                s
            )),
        }
    }
}

/// A light block containing only headers and signatures (no bodies).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightBlock {
    /// Block hash.
    pub hash: Hash256,
    /// Parent block hash.
    pub parent_hash: Hash256,
    /// Block height.
    pub height: u64,
    /// Block timestamp.
    pub timestamp: u64,
    /// Merkle root of all transactions.
    pub merkle_root: Hash256,
    /// Identity hash of the validator who created this block.
    pub validator: [u8; 32],
    /// Validator's ML-DSA signature on the block header.
    pub validator_signature: Vec<u8>,
    /// Message headers from this block (permanent).
    pub message_headers: Vec<MessageHeader>,
    /// Transaction signatures during current epoch (pruned after epoch).
    pub transaction_signatures: Vec<Vec<u8>>,
    /// Which epoch this block belongs to.
    pub epoch: u64,
}

impl LightBlock {
    /// Check if this block's signatures have been pruned.
    pub fn is_pruned(&self) -> bool {
        self.transaction_signatures.is_empty()
    }

    /// Prune transaction signatures (keep headers).
    pub fn prune_signatures(&mut self) {
        self.transaction_signatures.clear();
    }

    /// Estimated memory usage in bytes.
    pub fn estimated_memory(&self) -> usize {
        let base_size = 32 + 32 + 8 + 8 + 32 + 32; // hash fields
        let sig_size: usize = self
            .transaction_signatures
            .iter()
            .map(|s| s.len())
            .sum();
        let msg_header_size = self.message_headers.len() * (32 + 8 + 32 + 8 + 4);
        base_size + sig_size + msg_header_size + self.validator_signature.len()
    }
}

/// Light validator state and storage.
#[derive(Debug)]
pub struct LightValidatorState {
    /// Operating mode.
    pub mode: ValidatorMode,
    /// Memory budget in bytes (target: 256MB for light).
    pub memory_budget: usize,
    /// Current memory usage estimate.
    pub memory_used: usize,
    /// Number of blocks stored.
    pub blocks_stored: u64,
    /// Number of headers stored (permanent).
    pub headers_stored: u64,
    /// Current epoch.
    pub current_epoch: u64,
}

impl LightValidatorState {
    /// Create a new light validator state with 256MB budget.
    pub fn new() -> Self {
        Self {
            mode: ValidatorMode::Light,
            memory_budget: 256 * 1024 * 1024, // 256MB
            memory_used: 0,
            blocks_stored: 0,
            headers_stored: 0,
            current_epoch: epoch::current_epoch(),
        }
    }

    /// Create a new full validator state with 1GB budget.
    pub fn new_full() -> Self {
        Self {
            mode: ValidatorMode::Full,
            memory_budget: 1024 * 1024 * 1024, // 1GB
            memory_used: 0,
            blocks_stored: 0,
            headers_stored: 0,
            current_epoch: epoch::current_epoch(),
        }
    }

    /// Check if we're within memory budget.
    pub fn within_budget(&self) -> bool {
        self.memory_used <= self.memory_budget
    }

    /// Get memory usage percentage.
    pub fn memory_usage_percent(&self) -> f64 {
        if self.memory_budget == 0 {
            return 100.0;
        }
        (self.memory_used as f64 / self.memory_budget as f64) * 100.0
    }
}

impl Default for LightValidatorState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::MessageHeader;

    #[test]
    fn test_validator_mode_display() {
        assert_eq!(ValidatorMode::Full.to_string(), "full-validator");
        assert_eq!(ValidatorMode::Light.to_string(), "light-validator");
    }

    #[test]
    fn test_validator_mode_from_str() {
        assert_eq!(
            "full-validator".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Full
        );
        assert_eq!(
            "full".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Full
        );
        assert_eq!(
            "light-validator".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Light
        );
        assert_eq!(
            "light".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Light
        );
        assert!("unknown".parse::<ValidatorMode>().is_err());
    }

    #[test]
    fn test_light_block_prune() {
        let mut block = LightBlock {
            hash: Hash256::hash(b"block"),
            parent_hash: Hash256::hash(b"parent"),
            height: 100,
            timestamp: 1700000000,
            merkle_root: Hash256::hash(b"merkle"),
            validator: [1u8; 32],
            validator_signature: vec![0xAA; 3309],
            message_headers: vec![MessageHeader::new(
                [0xBB; 32],
                1700000000,
                Hash256::hash(b"body"),
                100,
                0,
            )],
            transaction_signatures: vec![vec![0xCC; 3309], vec![0xDD; 3309]],
            epoch: 0,
        };

        assert!(!block.is_pruned());
        let mem_before = block.estimated_memory();

        block.prune_signatures();
        assert!(block.is_pruned());

        let mem_after = block.estimated_memory();
        assert!(mem_after < mem_before);
        // Headers survive
        assert_eq!(block.message_headers.len(), 1);
    }

    #[test]
    fn test_light_validator_state_default() {
        let state = LightValidatorState::default();
        assert_eq!(state.mode, ValidatorMode::Light);
        assert_eq!(state.memory_budget, 256 * 1024 * 1024);
        assert!(state.within_budget());
    }

    #[test]
    fn test_full_validator_state() {
        let state = LightValidatorState::new_full();
        assert_eq!(state.mode, ValidatorMode::Full);
        assert_eq!(state.memory_budget, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_memory_usage_percent() {
        let mut state = LightValidatorState::new();
        assert_eq!(state.memory_usage_percent(), 0.0);

        state.memory_used = state.memory_budget / 2;
        let pct = state.memory_usage_percent();
        assert!((pct - 50.0).abs() < 0.01);

        state.memory_used = state.memory_budget;
        let pct = state.memory_usage_percent();
        assert!((pct - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_within_budget() {
        let mut state = LightValidatorState::new();
        assert!(state.within_budget());

        state.memory_used = state.memory_budget;
        assert!(state.within_budget()); // Equal is within

        state.memory_used = state.memory_budget + 1;
        assert!(!state.within_budget());
    }
}
