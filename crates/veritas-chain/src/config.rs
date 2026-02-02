//! Configuration for blockchain optimization features.
//!
//! This module provides the [`BlockchainConfig`] struct for configuring
//! memory management, storage optimization, and chain pruning.
//!
//! ## Default Configuration
//!
//! The default configuration is tuned for a full node with moderate resources:
//! - 512 MB memory budget
//! - 1,000 blocks in hot cache
//! - Standard pruning (keep 10,000 blocks)
//! - Compression enabled (zstd level 3)
//!
//! ## Example
//!
//! ```
//! use veritas_chain::config::{BlockchainConfig, PruningMode, DEFAULT_SLED_CACHE_MB};
//!
//! // Custom configuration for a light client
//! let config = BlockchainConfig {
//!     memory_budget_mb: 256,
//!     hot_cache_blocks: 500,
//!     pruning_mode: PruningMode::Aggressive { keep_headers_only: true },
//!     compression_enabled: true,
//!     compression_level: 3,
//!     sled_cache_mb: DEFAULT_SLED_CACHE_MB,
//! };
//! ```

use serde::{Deserialize, Serialize};

/// Default memory budget in megabytes.
pub const DEFAULT_MEMORY_BUDGET_MB: usize = 512;

/// Minimum memory budget in megabytes.
pub const MIN_MEMORY_BUDGET_MB: usize = 64;

/// Maximum memory budget in megabytes.
pub const MAX_MEMORY_BUDGET_MB: usize = 8192;

/// Default number of blocks to keep in hot cache.
pub const DEFAULT_HOT_CACHE_BLOCKS: usize = 1000;

/// Default number of blocks to keep in standard pruning mode.
pub const DEFAULT_KEEP_BLOCKS: u64 = 10_000;

/// Safety margin: never prune blocks within this distance of chain tip.
///
/// SECURITY: This ensures we never delete blocks that might be needed
/// for fork resolution or reorganization.
pub const PRUNING_SAFETY_MARGIN: u64 = 100;

/// Default compression level (1-22, where 3 is balanced).
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Default sled cache size in megabytes.
pub const DEFAULT_SLED_CACHE_MB: usize = 64;

/// Minimum sled cache size in megabytes.
pub const MIN_SLED_CACHE_MB: usize = 16;

/// Maximum size of a compressed block in bytes.
///
/// SECURITY (DoS Prevention): Reject compressed blocks larger than this
/// to prevent decompression bombs.
pub const MAX_COMPRESSED_BLOCK_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Maximum size of a decompressed block in bytes.
///
/// SECURITY (DoS Prevention): Reject blocks that decompress to more than this.
pub const MAX_DECOMPRESSED_BLOCK_SIZE: usize = 50 * 1024 * 1024; // 50 MB

/// Pruning mode for chain storage.
///
/// Controls how aggressively old blocks are removed from storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PruningMode {
    /// Standard pruning: keep a fixed number of recent blocks.
    ///
    /// Provides 85-90% storage reduction while maintaining reasonable
    /// history for validation and queries.
    Standard {
        /// Number of blocks to keep (default: 10,000).
        keep_blocks: u64,
    },

    /// Aggressive pruning: keep only headers and finalized state.
    ///
    /// Provides 96-98% storage reduction but limits historical queries.
    Aggressive {
        /// If true, only keep block headers (not full blocks).
        keep_headers_only: bool,
    },

    /// Archive mode: never prune blocks.
    ///
    /// Required for archive nodes that need full history.
    Archive,
}

impl Default for PruningMode {
    fn default() -> Self {
        PruningMode::Standard {
            keep_blocks: DEFAULT_KEEP_BLOCKS,
        }
    }
}

impl PruningMode {
    /// Create a standard pruning mode with default settings.
    pub fn standard() -> Self {
        PruningMode::Standard {
            keep_blocks: DEFAULT_KEEP_BLOCKS,
        }
    }

    /// Create an aggressive pruning mode.
    pub fn aggressive() -> Self {
        PruningMode::Aggressive {
            keep_headers_only: true,
        }
    }

    /// Create an archive mode (no pruning).
    pub fn archive() -> Self {
        PruningMode::Archive
    }

    /// Check if this is archive mode.
    pub fn is_archive(&self) -> bool {
        matches!(self, PruningMode::Archive)
    }

    /// Get the number of blocks to keep, or None for archive mode.
    pub fn keep_blocks(&self) -> Option<u64> {
        match self {
            PruningMode::Standard { keep_blocks } => Some(*keep_blocks),
            PruningMode::Aggressive { .. } => Some(1000), // Keep minimal blocks
            PruningMode::Archive => None,
        }
    }
}

/// The role of this VERITAS node, determining default resource allocation.
///
/// Each node role has optimized default settings for its use case,
/// enabling operation on hardware ranging from Raspberry Pi to archive servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum NodeRole {
    /// Message relay: forwards messages, minimal chain storage.
    ///
    /// Requirements: 256 MB RAM, 1 vCPU, 1 GB disk
    Relay,

    /// Full node: validates and stores recent chain history.
    ///
    /// Requirements: 512 MB RAM, 1 vCPU, 10 GB disk
    #[default]
    FullNode,

    /// Validator: participates in consensus, deeper history.
    ///
    /// Requirements: 1 GB RAM, 2 vCPU, 50 GB disk
    Validator,

    /// Bootstrap/genesis: serves chain data to joining peers.
    ///
    /// Requirements: 1 GB RAM, 2 vCPU, 100 GB disk
    Bootstrap,

    /// Archive: stores complete chain history, never prunes.
    ///
    /// Requirements: 2 GB RAM, 2 vCPU, unbounded disk
    Archive,
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Relay => write!(f, "relay"),
            NodeRole::FullNode => write!(f, "full_node"),
            NodeRole::Validator => write!(f, "validator"),
            NodeRole::Bootstrap => write!(f, "bootstrap"),
            NodeRole::Archive => write!(f, "archive"),
        }
    }
}

impl NodeRole {
    /// Get the default blockchain configuration for this role.
    pub fn default_config(&self) -> BlockchainConfig {
        match self {
            NodeRole::Relay => BlockchainConfig::relay(),
            NodeRole::FullNode => BlockchainConfig::full_node(),
            NodeRole::Validator => BlockchainConfig::validator(),
            NodeRole::Bootstrap => BlockchainConfig::bootstrap(),
            NodeRole::Archive => BlockchainConfig::archive(),
        }
    }

    /// Minimum recommended RAM in megabytes.
    pub fn min_ram_mb(&self) -> usize {
        match self {
            NodeRole::Relay => 256,
            NodeRole::FullNode => 512,
            NodeRole::Validator => 1024,
            NodeRole::Bootstrap => 1024,
            NodeRole::Archive => 2048,
        }
    }

    /// Minimum recommended CPU cores.
    pub fn min_cpu_cores(&self) -> usize {
        match self {
            NodeRole::Relay => 1,
            NodeRole::FullNode => 1,
            NodeRole::Validator => 2,
            NodeRole::Bootstrap => 2,
            NodeRole::Archive => 2,
        }
    }

    /// Human-readable resource requirements.
    pub fn resource_requirements(&self) -> &'static str {
        match self {
            NodeRole::Relay => "256 MB RAM, 1 vCPU, 1 GB disk",
            NodeRole::FullNode => "512 MB RAM, 1 vCPU, 10 GB disk",
            NodeRole::Validator => "1 GB RAM, 2 vCPU, 50 GB disk",
            NodeRole::Bootstrap => "1 GB RAM, 2 vCPU, 100 GB disk",
            NodeRole::Archive => "2 GB RAM, 2 vCPU, unbounded disk",
        }
    }
}

/// Configuration for blockchain optimization features.
///
/// This struct controls memory management, storage optimization,
/// and chain pruning behavior.
///
/// ## Memory Budget
///
/// The memory budget limits total RAM usage for blockchain data.
/// When the budget is exceeded, older blocks are evicted from the
/// hot cache using LRU (Least Recently Used) policy.
///
/// ## Hot Cache
///
/// The hot cache keeps frequently accessed blocks in memory for
/// fast retrieval. Typically, the most recent blocks are kept hot.
///
/// ## Pruning
///
/// Pruning removes old blocks from storage to reduce disk usage.
/// The safety margin ensures recent blocks are never pruned.
///
/// ## Compression
///
/// Block compression reduces storage size by 40-70% using zstd.
/// Compressed blocks are stored on disk and decompressed on read.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockchainConfig {
    /// Maximum memory usage in megabytes for blockchain data.
    ///
    /// Default: 512 MB
    /// Minimum: 64 MB
    /// Maximum: 8192 MB
    pub memory_budget_mb: usize,

    /// Number of recent blocks to keep in the hot cache.
    ///
    /// These blocks are always in memory for fast access.
    /// Default: 1,000 blocks
    pub hot_cache_blocks: usize,

    /// Pruning mode for old blocks.
    ///
    /// Default: Standard (keep 10,000 blocks)
    pub pruning_mode: PruningMode,

    /// Enable block compression for storage.
    ///
    /// Default: true
    pub compression_enabled: bool,

    /// Compression level (1-22).
    ///
    /// Lower = faster, higher = smaller.
    /// Default: 3 (balanced)
    pub compression_level: i32,

    /// Sled database cache size in megabytes.
    ///
    /// Controls how much RAM sled uses for its page cache.
    /// Default varies by node role. Minimum: 16 MB.
    pub sled_cache_mb: usize,
}

impl Default for BlockchainConfig {
    fn default() -> Self {
        Self {
            memory_budget_mb: DEFAULT_MEMORY_BUDGET_MB,
            hot_cache_blocks: DEFAULT_HOT_CACHE_BLOCKS,
            pruning_mode: PruningMode::default(),
            compression_enabled: true,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            sled_cache_mb: DEFAULT_SLED_CACHE_MB,
        }
    }
}

impl BlockchainConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration optimized for light clients.
    ///
    /// Uses less memory and more aggressive pruning.
    /// Alias for `relay()` with similar resource profile.
    pub fn light_client() -> Self {
        Self::relay()
    }

    /// Create a configuration for relay nodes.
    ///
    /// Minimal resources: 128 MB memory budget, aggressive pruning.
    /// Requirements: 256 MB RAM, 1 vCPU, 1 GB disk
    pub fn relay() -> Self {
        Self {
            memory_budget_mb: 128,
            hot_cache_blocks: 100,
            pruning_mode: PruningMode::Aggressive {
                keep_headers_only: true,
            },
            compression_enabled: true,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            sled_cache_mb: 32,
        }
    }

    /// Create a configuration for full nodes.
    ///
    /// Standard resources: 256 MB memory budget, standard pruning.
    /// Requirements: 512 MB RAM, 1 vCPU, 10 GB disk
    pub fn full_node() -> Self {
        Self {
            memory_budget_mb: 256,
            hot_cache_blocks: 500,
            pruning_mode: PruningMode::Standard {
                keep_blocks: 10_000,
            },
            compression_enabled: true,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            sled_cache_mb: 64,
        }
    }

    /// Create a configuration for validator nodes.
    ///
    /// Higher resources: 512 MB memory budget, deeper history.
    /// Requirements: 1 GB RAM, 2 vCPU, 50 GB disk
    pub fn validator() -> Self {
        Self {
            memory_budget_mb: 512,
            hot_cache_blocks: 1000,
            pruning_mode: PruningMode::Standard {
                keep_blocks: 50_000,
            },
            compression_enabled: true,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            sled_cache_mb: 128,
        }
    }

    /// Create a configuration for bootstrap/genesis nodes.
    ///
    /// Serves chain data to joining peers with deeper history.
    /// Requirements: 1 GB RAM, 2 vCPU, 100 GB disk
    pub fn bootstrap() -> Self {
        Self {
            memory_budget_mb: 512,
            hot_cache_blocks: 2000,
            pruning_mode: PruningMode::Standard {
                keep_blocks: 100_000,
            },
            compression_enabled: true,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            sled_cache_mb: 128,
        }
    }

    /// Create a configuration for archive nodes.
    ///
    /// No pruning, higher memory budget. Stores complete chain history.
    /// Requirements: 2 GB RAM, 2 vCPU, unbounded disk
    pub fn archive() -> Self {
        Self {
            memory_budget_mb: 1024,
            hot_cache_blocks: 2000,
            pruning_mode: PruningMode::Archive,
            compression_enabled: true,
            compression_level: DEFAULT_COMPRESSION_LEVEL,
            sled_cache_mb: 256,
        }
    }

    /// Get memory budget in bytes.
    pub fn memory_budget_bytes(&self) -> usize {
        self.memory_budget_mb * 1024 * 1024
    }

    /// Validate the configuration.
    ///
    /// Returns an error if any values are out of bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.memory_budget_mb < MIN_MEMORY_BUDGET_MB {
            return Err(format!(
                "memory_budget_mb must be at least {} MB",
                MIN_MEMORY_BUDGET_MB
            ));
        }

        if self.memory_budget_mb > MAX_MEMORY_BUDGET_MB {
            return Err(format!(
                "memory_budget_mb must be at most {} MB",
                MAX_MEMORY_BUDGET_MB
            ));
        }

        if self.hot_cache_blocks == 0 {
            return Err("hot_cache_blocks must be greater than 0".to_string());
        }

        if self.compression_level < 1 || self.compression_level > 22 {
            return Err("compression_level must be between 1 and 22".to_string());
        }

        if self.sled_cache_mb < MIN_SLED_CACHE_MB {
            return Err(format!(
                "sled_cache_mb must be at least {} MB",
                MIN_SLED_CACHE_MB
            ));
        }

        Ok(())
    }

    /// Set memory budget in megabytes.
    pub fn with_memory_budget(mut self, mb: usize) -> Self {
        self.memory_budget_mb = mb;
        self
    }

    /// Set hot cache size in blocks.
    pub fn with_hot_cache(mut self, blocks: usize) -> Self {
        self.hot_cache_blocks = blocks;
        self
    }

    /// Set pruning mode.
    pub fn with_pruning_mode(mut self, mode: PruningMode) -> Self {
        self.pruning_mode = mode;
        self
    }

    /// Enable or disable compression.
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }

    /// Set compression level.
    pub fn with_compression_level(mut self, level: i32) -> Self {
        self.compression_level = level;
        self
    }

    /// Set sled cache size in megabytes.
    pub fn with_sled_cache(mut self, mb: usize) -> Self {
        self.sled_cache_mb = mb;
        self
    }

    /// Get sled cache size in bytes.
    pub fn sled_cache_bytes(&self) -> usize {
        self.sled_cache_mb * 1024 * 1024
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = BlockchainConfig::default();
        assert_eq!(config.memory_budget_mb, DEFAULT_MEMORY_BUDGET_MB);
        assert_eq!(config.hot_cache_blocks, DEFAULT_HOT_CACHE_BLOCKS);
        assert!(config.compression_enabled);
        assert_eq!(config.compression_level, DEFAULT_COMPRESSION_LEVEL);
        assert_eq!(config.sled_cache_mb, DEFAULT_SLED_CACHE_MB);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_light_client_config() {
        let config = BlockchainConfig::light_client();
        assert_eq!(config.memory_budget_mb, 128);
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Aggressive { .. }
        ));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_relay_config() {
        let config = BlockchainConfig::relay();
        assert_eq!(config.memory_budget_mb, 128);
        assert_eq!(config.hot_cache_blocks, 100);
        assert_eq!(config.sled_cache_mb, 32);
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Aggressive { keep_headers_only: true }
        ));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_full_node_config() {
        let config = BlockchainConfig::full_node();
        assert_eq!(config.memory_budget_mb, 256);
        assert_eq!(config.hot_cache_blocks, 500);
        assert_eq!(config.sled_cache_mb, 64);
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Standard { keep_blocks: 10_000 }
        ));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validator_config() {
        let config = BlockchainConfig::validator();
        assert_eq!(config.memory_budget_mb, 512);
        assert_eq!(config.hot_cache_blocks, 1000);
        assert_eq!(config.sled_cache_mb, 128);
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Standard { keep_blocks: 50_000 }
        ));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_bootstrap_config() {
        let config = BlockchainConfig::bootstrap();
        assert_eq!(config.memory_budget_mb, 512);
        assert_eq!(config.hot_cache_blocks, 2000);
        assert_eq!(config.sled_cache_mb, 128);
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Standard { keep_blocks: 100_000 }
        ));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_archive_config() {
        let config = BlockchainConfig::archive();
        assert_eq!(config.memory_budget_mb, 1024);
        assert_eq!(config.sled_cache_mb, 256);
        assert!(config.pruning_mode.is_archive());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_all_profiles_validate() {
        assert!(BlockchainConfig::relay().validate().is_ok());
        assert!(BlockchainConfig::full_node().validate().is_ok());
        assert!(BlockchainConfig::validator().validate().is_ok());
        assert!(BlockchainConfig::bootstrap().validate().is_ok());
        assert!(BlockchainConfig::archive().validate().is_ok());
    }

    #[test]
    fn test_validator_has_larger_budget_than_full_node() {
        let full_node = BlockchainConfig::full_node();
        let validator = BlockchainConfig::validator();
        assert!(validator.memory_budget_mb > full_node.memory_budget_mb);
    }

    #[test]
    fn test_memory_budget_bytes() {
        let config = BlockchainConfig::default();
        assert_eq!(config.memory_budget_bytes(), 512 * 1024 * 1024);
    }

    #[test]
    fn test_validation_rejects_low_memory() {
        let config = BlockchainConfig::default().with_memory_budget(32);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_high_memory() {
        let config = BlockchainConfig::default().with_memory_budget(10000);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_invalid_compression_level() {
        let config = BlockchainConfig::default().with_compression_level(30);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_pruning_mode_keep_blocks() {
        let standard = PruningMode::standard();
        assert_eq!(standard.keep_blocks(), Some(DEFAULT_KEEP_BLOCKS));

        let aggressive = PruningMode::aggressive();
        assert_eq!(aggressive.keep_blocks(), Some(1000));

        let archive = PruningMode::archive();
        assert_eq!(archive.keep_blocks(), None);
    }

    #[test]
    fn test_builder_pattern() {
        let config = BlockchainConfig::new()
            .with_memory_budget(256)
            .with_hot_cache(500)
            .with_pruning_mode(PruningMode::aggressive())
            .with_compression(true)
            .with_compression_level(5)
            .with_sled_cache(32);

        assert_eq!(config.memory_budget_mb, 256);
        assert_eq!(config.hot_cache_blocks, 500);
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Aggressive { .. }
        ));
        assert!(config.compression_enabled);
        assert_eq!(config.compression_level, 5);
        assert_eq!(config.sled_cache_mb, 32);
    }

    #[test]
    fn test_sled_cache_minimum_enforced() {
        let config = BlockchainConfig::default().with_sled_cache(8);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_sled_cache_bytes() {
        let config = BlockchainConfig::default().with_sled_cache(64);
        assert_eq!(config.sled_cache_bytes(), 64 * 1024 * 1024);
    }

    // ==================== NodeRole Tests ====================

    #[test]
    fn test_node_role_default_is_full_node() {
        assert_eq!(NodeRole::default(), NodeRole::FullNode);
    }

    #[test]
    fn test_node_role_display() {
        assert_eq!(NodeRole::Relay.to_string(), "relay");
        assert_eq!(NodeRole::FullNode.to_string(), "full_node");
        assert_eq!(NodeRole::Validator.to_string(), "validator");
        assert_eq!(NodeRole::Bootstrap.to_string(), "bootstrap");
        assert_eq!(NodeRole::Archive.to_string(), "archive");
    }

    #[test]
    fn test_node_role_default_config() {
        // Each role should produce a valid config
        for role in [
            NodeRole::Relay,
            NodeRole::FullNode,
            NodeRole::Validator,
            NodeRole::Bootstrap,
            NodeRole::Archive,
        ] {
            let config = role.default_config();
            assert!(config.validate().is_ok(), "Config for {:?} should validate", role);
        }
    }

    #[test]
    fn test_node_role_resource_requirements() {
        assert!(!NodeRole::Relay.resource_requirements().is_empty());
        assert!(!NodeRole::FullNode.resource_requirements().is_empty());
        assert!(!NodeRole::Validator.resource_requirements().is_empty());
        assert!(!NodeRole::Bootstrap.resource_requirements().is_empty());
        assert!(!NodeRole::Archive.resource_requirements().is_empty());
    }

    #[test]
    fn test_node_role_min_ram() {
        assert_eq!(NodeRole::Relay.min_ram_mb(), 256);
        assert_eq!(NodeRole::FullNode.min_ram_mb(), 512);
        assert_eq!(NodeRole::Validator.min_ram_mb(), 1024);
        assert_eq!(NodeRole::Bootstrap.min_ram_mb(), 1024);
        assert_eq!(NodeRole::Archive.min_ram_mb(), 2048);
    }

    #[test]
    fn test_node_role_min_cpu() {
        assert_eq!(NodeRole::Relay.min_cpu_cores(), 1);
        assert_eq!(NodeRole::FullNode.min_cpu_cores(), 1);
        assert_eq!(NodeRole::Validator.min_cpu_cores(), 2);
        assert_eq!(NodeRole::Bootstrap.min_cpu_cores(), 2);
        assert_eq!(NodeRole::Archive.min_cpu_cores(), 2);
    }

    #[test]
    fn test_relay_uses_aggressive_pruning() {
        let config = BlockchainConfig::relay();
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Aggressive { keep_headers_only: true }
        ));
    }

    #[test]
    fn test_full_node_uses_standard_pruning() {
        let config = BlockchainConfig::full_node();
        assert!(matches!(
            config.pruning_mode,
            PruningMode::Standard { .. }
        ));
    }
}
