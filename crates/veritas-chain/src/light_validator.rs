//! Light validator mode for the VERITAS blockchain.
//!
//! ## Validator Tiers (AD-4)
//!
//! Full validators: Hold complete blocks (headers + bodies + signatures)
//! Light validators: Hold headers + signatures only (no message bodies)
//!   - After epoch: prune signatures → converge to header-only state
//!   - Target: 256MB RAM
//!
//! Light validators validate transaction history during the epoch.
//! After the epoch ends, they prune signatures and converge to header-only state.

use serde::{Deserialize, Serialize};

/// Validator operating mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorMode {
    /// Full validator: holds complete blocks.
    #[default]
    Full,
    /// Light validator: holds headers + signatures only (no message bodies).
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
            "full" | "full-validator" => Ok(ValidatorMode::Full),
            "light" | "light-validator" => Ok(ValidatorMode::Light),
            _ => Err(format!(
                "invalid validator mode: '{}'. Use 'full-validator' or 'light-validator'",
                s
            )),
        }
    }
}

/// Configuration for a light validator.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightValidatorConfig {
    /// Maximum memory usage target in bytes (default: 256MB).
    pub max_memory_bytes: u64,
    /// Whether to keep signatures during the current epoch.
    pub keep_current_epoch_signatures: bool,
    /// Whether to sync only headers (skip bodies entirely).
    pub header_only_sync: bool,
}

impl Default for LightValidatorConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 256 * 1024 * 1024, // 256 MB
            keep_current_epoch_signatures: true,
            header_only_sync: false,
        }
    }
}

/// Storage requirements for different validator modes.
#[derive(Clone, Debug)]
pub struct StorageEstimate {
    /// Estimated header storage in bytes.
    pub headers_bytes: u64,
    /// Estimated body storage in bytes (0 for light validators after pruning).
    pub bodies_bytes: u64,
    /// Estimated signature storage in bytes.
    pub signatures_bytes: u64,
    /// Total estimated storage.
    pub total_bytes: u64,
}

impl StorageEstimate {
    /// Estimate storage for a given number of transactions.
    pub fn estimate(mode: ValidatorMode, num_transactions: u64, epoch_ended: bool) -> Self {
        let header_size = 100u64; // ~100 bytes per header
        let body_size = 4096u64; // ~4KB average padded body
        let sig_size = 3309u64; // ML-DSA-65 signature

        let headers_bytes = num_transactions * header_size;

        let (bodies_bytes, signatures_bytes) = match mode {
            ValidatorMode::Full => {
                if epoch_ended {
                    (0, 0) // Pruned
                } else {
                    (num_transactions * body_size, num_transactions * sig_size)
                }
            }
            ValidatorMode::Light => {
                if epoch_ended {
                    (0, 0) // Both pruned
                } else {
                    (0, num_transactions * sig_size) // No bodies, keep sigs
                }
            }
        };

        StorageEstimate {
            headers_bytes,
            bodies_bytes,
            signatures_bytes,
            total_bytes: headers_bytes + bodies_bytes + signatures_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_mode_display() {
        assert_eq!(ValidatorMode::Full.to_string(), "full-validator");
        assert_eq!(ValidatorMode::Light.to_string(), "light-validator");
    }

    #[test]
    fn test_validator_mode_parse() {
        assert_eq!(
            "full".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Full
        );
        assert_eq!(
            "full-validator".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Full
        );
        assert_eq!(
            "light".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Light
        );
        assert_eq!(
            "light-validator".parse::<ValidatorMode>().unwrap(),
            ValidatorMode::Light
        );
        assert!("invalid".parse::<ValidatorMode>().is_err());
    }

    #[test]
    fn test_default_validator_mode() {
        assert_eq!(ValidatorMode::default(), ValidatorMode::Full);
    }

    #[test]
    fn test_light_validator_config_default() {
        let config = LightValidatorConfig::default();
        assert_eq!(config.max_memory_bytes, 256 * 1024 * 1024);
        assert!(config.keep_current_epoch_signatures);
        assert!(!config.header_only_sync);
    }

    #[test]
    fn test_storage_estimate_full_active() {
        let est = StorageEstimate::estimate(ValidatorMode::Full, 1000, false);
        assert!(est.headers_bytes > 0);
        assert!(est.bodies_bytes > 0);
        assert!(est.signatures_bytes > 0);
        assert_eq!(
            est.total_bytes,
            est.headers_bytes + est.bodies_bytes + est.signatures_bytes
        );
    }

    #[test]
    fn test_storage_estimate_full_pruned() {
        let est = StorageEstimate::estimate(ValidatorMode::Full, 1000, true);
        assert!(est.headers_bytes > 0);
        assert_eq!(est.bodies_bytes, 0);
        assert_eq!(est.signatures_bytes, 0);
    }

    #[test]
    fn test_storage_estimate_light_active() {
        let est = StorageEstimate::estimate(ValidatorMode::Light, 1000, false);
        assert!(est.headers_bytes > 0);
        assert_eq!(est.bodies_bytes, 0); // Light validators don't store bodies
        assert!(est.signatures_bytes > 0); // But keep signatures during epoch
    }

    #[test]
    fn test_storage_estimate_light_pruned() {
        let est = StorageEstimate::estimate(ValidatorMode::Light, 1000, true);
        assert!(est.headers_bytes > 0);
        assert_eq!(est.bodies_bytes, 0);
        assert_eq!(est.signatures_bytes, 0);
    }

    #[test]
    fn test_light_uses_less_storage_than_full() {
        let full = StorageEstimate::estimate(ValidatorMode::Full, 1000, false);
        let light = StorageEstimate::estimate(ValidatorMode::Light, 1000, false);
        assert!(light.total_bytes < full.total_bytes);
    }
}
