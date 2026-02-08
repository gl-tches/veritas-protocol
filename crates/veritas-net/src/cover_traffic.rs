//! Cover traffic generation for traffic analysis resistance (PRIV-D7).
//!
//! Generates dummy messages that are indistinguishable from real messages on the wire.
//! This prevents observers from determining communication patterns by monitoring
//! message frequency and timing.
//!
//! ## Design
//!
//! Cover traffic sends a fixed number of messages per time interval, mixing
//! real and dummy messages. Dummy messages:
//! - Use the same envelope format as real messages
//! - Are padded to valid bucket sizes
//! - Have random mailbox keys (no valid recipient)
//! - Are encrypted with random keys (indistinguishable from real ciphertext)
//! - Are discarded by recipients who cannot decrypt them
//!
//! ## Privacy Properties
//!
//! - **Constant Rate**: Observers see constant message rate regardless of activity
//! - **Indistinguishability**: Dummy messages are cryptographically indistinguishable
//!   from real messages without the decryption key
//! - **Configurable Bandwidth**: Users can trade bandwidth for privacy

use std::time::Duration;

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use veritas_crypto::Hash256;
use veritas_protocol::{MailboxKey, PADDING_BUCKETS};

use crate::error::{NetError, Result};
use crate::gossip::MessageAnnouncement;

/// Configuration for cover traffic generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverTrafficConfig {
    /// Whether cover traffic is enabled.
    pub enabled: bool,

    /// Target number of messages (real + dummy) per interval.
    /// A higher rate provides better privacy but uses more bandwidth.
    pub target_rate_per_interval: u32,

    /// Interval duration in seconds for the target rate.
    pub interval_secs: u64,

    /// Minimum dummy messages per interval even when real messages are sent.
    /// Ensures there are always some dummy messages mixed in.
    pub min_dummy_per_interval: u32,

    /// Maximum dummy messages per interval to cap bandwidth usage.
    pub max_dummy_per_interval: u32,

    /// Privacy level controlling the ratio of dummy to real messages.
    pub privacy_level: PrivacyLevel,
}

/// Privacy level presets for cover traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Low bandwidth overhead (~10% dummy traffic).
    Low,
    /// Medium bandwidth overhead (~50% dummy traffic).
    Medium,
    /// High bandwidth overhead (~200% dummy traffic).
    High,
    /// Custom ratio (user-defined).
    Custom,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_rate_per_interval: 10,
            interval_secs: 60,
            min_dummy_per_interval: 2,
            max_dummy_per_interval: 20,
            privacy_level: PrivacyLevel::Medium,
        }
    }
}

impl CoverTrafficConfig {
    /// Create a disabled cover traffic config.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// Create a config with low privacy (minimal bandwidth overhead).
    pub fn low_privacy() -> Self {
        Self {
            enabled: true,
            target_rate_per_interval: 5,
            interval_secs: 60,
            min_dummy_per_interval: 1,
            max_dummy_per_interval: 5,
            privacy_level: PrivacyLevel::Low,
        }
    }

    /// Create a config with high privacy (significant bandwidth overhead).
    pub fn high_privacy() -> Self {
        Self {
            enabled: true,
            target_rate_per_interval: 20,
            interval_secs: 60,
            min_dummy_per_interval: 5,
            max_dummy_per_interval: 50,
            privacy_level: PrivacyLevel::High,
        }
    }
}

/// A generated cover traffic (dummy) message announcement.
///
/// Indistinguishable from a real message announcement on the wire.
#[derive(Debug, Clone)]
pub struct DummyMessage {
    /// The announcement to publish (looks like a real message).
    pub announcement: MessageAnnouncement,
    /// Random ciphertext payload (same size as a real padded message).
    pub payload: Vec<u8>,
}

/// Cover traffic generator.
///
/// Tracks real message rate and generates dummy messages to maintain
/// a constant overall message rate, making it harder for observers
/// to determine actual communication patterns.
pub struct CoverTrafficGenerator {
    /// Configuration.
    config: CoverTrafficConfig,
    /// Number of real messages sent in the current interval.
    real_messages_this_interval: u32,
    /// Number of dummy messages sent in the current interval.
    dummy_messages_this_interval: u32,
}

impl CoverTrafficGenerator {
    /// Create a new cover traffic generator.
    pub fn new(config: CoverTrafficConfig) -> Self {
        Self {
            config,
            real_messages_this_interval: 0,
            dummy_messages_this_interval: 0,
        }
    }

    /// Create a generator with default (medium privacy) configuration.
    pub fn with_defaults() -> Self {
        Self::new(CoverTrafficConfig::default())
    }

    /// Record that a real message was sent.
    pub fn record_real_message(&mut self) {
        self.real_messages_this_interval += 1;
    }

    /// Reset interval counters (called at the start of each interval).
    pub fn reset_interval(&mut self) {
        self.real_messages_this_interval = 0;
        self.dummy_messages_this_interval = 0;
    }

    /// Get the current configuration.
    pub fn config(&self) -> &CoverTrafficConfig {
        &self.config
    }

    /// Check if cover traffic is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Calculate how many dummy messages should be sent this interval.
    ///
    /// Returns the number of dummy messages needed to reach the target rate.
    pub fn dummy_messages_needed(&self) -> u32 {
        if !self.config.enabled {
            return 0;
        }

        let real = self.real_messages_this_interval;
        let already_sent = self.dummy_messages_this_interval;
        let target = self.config.target_rate_per_interval;

        // Calculate remaining dummy messages needed
        let total_needed = if real >= target {
            // Even when we exceed target, send minimum dummy messages
            self.config.min_dummy_per_interval
        } else {
            // Fill up to target rate
            let gap = target - real;
            gap.max(self.config.min_dummy_per_interval)
        };

        // Subtract already sent
        let remaining = total_needed.saturating_sub(already_sent);

        // Cap at maximum
        remaining.min(
            self.config
                .max_dummy_per_interval
                .saturating_sub(already_sent),
        )
    }

    /// Generate a single dummy message that is indistinguishable from real traffic.
    ///
    /// The dummy message uses:
    /// - A random mailbox key (no valid recipient)
    /// - A random message hash
    /// - A random valid padding bucket size
    /// - Random ciphertext payload of the selected bucket size
    pub fn generate_dummy(&mut self) -> Result<DummyMessage> {
        if !self.config.enabled {
            return Err(NetError::Gossip("cover traffic is disabled".to_string()));
        }

        // Generate random mailbox key
        let mut mailbox_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut mailbox_bytes);
        let mailbox_key = MailboxKey::from_bytes(mailbox_bytes);

        // Generate random message hash
        let mut hash_input = [0u8; 64];
        OsRng.fill_bytes(&mut hash_input);
        let message_hash = Hash256::hash(&hash_input);

        // Pick a random valid bucket size
        let bucket_idx = (OsRng.next_u32() as usize) % PADDING_BUCKETS.len();
        let padded_size = PADDING_BUCKETS[bucket_idx];

        // Generate random payload (indistinguishable from encrypted data)
        let mut payload = vec![0u8; padded_size];
        OsRng.fill_bytes(&mut payload);

        // Create announcement (looks identical to real announcements)
        let announcement = MessageAnnouncement::new_now(mailbox_key, message_hash, padded_size)?;

        self.dummy_messages_this_interval += 1;

        debug!(
            size_bucket = padded_size,
            dummy_count = self.dummy_messages_this_interval,
            "Generated cover traffic dummy message"
        );

        Ok(DummyMessage {
            announcement,
            payload,
        })
    }

    /// Generate all dummy messages needed for the current interval.
    ///
    /// Returns a vector of dummy messages to be sent with random jitter
    /// between each one.
    pub fn generate_interval_dummies(&mut self) -> Result<Vec<DummyMessage>> {
        let count = self.dummy_messages_needed();
        let mut dummies = Vec::with_capacity(count as usize);

        for _ in 0..count {
            match self.generate_dummy() {
                Ok(dummy) => dummies.push(dummy),
                Err(e) => {
                    warn!("Failed to generate dummy message: {}", e);
                    break;
                }
            }
        }

        Ok(dummies)
    }

    /// Get statistics about cover traffic in the current interval.
    pub fn stats(&self) -> CoverTrafficStats {
        CoverTrafficStats {
            real_messages: self.real_messages_this_interval,
            dummy_messages: self.dummy_messages_this_interval,
            target_rate: self.config.target_rate_per_interval,
            privacy_level: self.config.privacy_level,
        }
    }
}

/// Statistics about cover traffic generation.
#[derive(Debug, Clone)]
pub struct CoverTrafficStats {
    /// Real messages sent this interval.
    pub real_messages: u32,
    /// Dummy messages sent this interval.
    pub dummy_messages: u32,
    /// Target total messages per interval.
    pub target_rate: u32,
    /// Current privacy level.
    pub privacy_level: PrivacyLevel,
}

impl CoverTrafficStats {
    /// Calculate the dummy-to-real ratio.
    pub fn dummy_ratio(&self) -> f64 {
        if self.real_messages == 0 {
            return f64::INFINITY;
        }
        self.dummy_messages as f64 / self.real_messages as f64
    }

    /// Total messages (real + dummy) this interval.
    pub fn total_messages(&self) -> u32 {
        self.real_messages + self.dummy_messages
    }
}

/// Get the recommended interval duration for cover traffic.
pub fn cover_traffic_interval() -> Duration {
    Duration::from_secs(CoverTrafficConfig::default().interval_secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cover_traffic_config_default() {
        let config = CoverTrafficConfig::default();
        assert!(config.enabled);
        assert_eq!(config.target_rate_per_interval, 10);
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.privacy_level, PrivacyLevel::Medium);
    }

    #[test]
    fn test_cover_traffic_config_disabled() {
        let config = CoverTrafficConfig::disabled();
        assert!(!config.enabled);
    }

    #[test]
    fn test_cover_traffic_config_presets() {
        let low = CoverTrafficConfig::low_privacy();
        assert_eq!(low.privacy_level, PrivacyLevel::Low);
        assert_eq!(low.target_rate_per_interval, 5);

        let high = CoverTrafficConfig::high_privacy();
        assert_eq!(high.privacy_level, PrivacyLevel::High);
        assert_eq!(high.target_rate_per_interval, 20);
    }

    #[test]
    fn test_generator_disabled() {
        let mut generator = CoverTrafficGenerator::new(CoverTrafficConfig::disabled());
        assert!(!generator.is_enabled());
        assert_eq!(generator.dummy_messages_needed(), 0);
        assert!(generator.generate_dummy().is_err());
    }

    #[test]
    fn test_generator_dummy_messages_needed() {
        let config = CoverTrafficConfig {
            enabled: true,
            target_rate_per_interval: 10,
            interval_secs: 60,
            min_dummy_per_interval: 2,
            max_dummy_per_interval: 20,
            privacy_level: PrivacyLevel::Medium,
        };
        let generator = CoverTrafficGenerator::new(config);

        // No real messages sent → need full target rate as dummies
        assert_eq!(generator.dummy_messages_needed(), 10);
    }

    #[test]
    fn test_generator_with_real_messages() {
        let config = CoverTrafficConfig {
            enabled: true,
            target_rate_per_interval: 10,
            interval_secs: 60,
            min_dummy_per_interval: 2,
            max_dummy_per_interval: 20,
            privacy_level: PrivacyLevel::Medium,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        // Send 5 real messages
        for _ in 0..5 {
            generator.record_real_message();
        }

        // Should need 5 more dummies to reach target of 10
        assert_eq!(generator.dummy_messages_needed(), 5);
    }

    #[test]
    fn test_generator_exceeds_target() {
        let config = CoverTrafficConfig {
            enabled: true,
            target_rate_per_interval: 5,
            interval_secs: 60,
            min_dummy_per_interval: 2,
            max_dummy_per_interval: 20,
            privacy_level: PrivacyLevel::Medium,
        };
        let mut generator = CoverTrafficGenerator::new(config);

        // Send 10 real messages (exceeds target of 5)
        for _ in 0..10 {
            generator.record_real_message();
        }

        // Still need minimum dummy messages
        assert_eq!(generator.dummy_messages_needed(), 2);
    }

    #[test]
    fn test_generate_dummy_message() {
        let mut generator = CoverTrafficGenerator::with_defaults();
        let dummy = generator.generate_dummy().unwrap();

        // Should have valid size bucket
        assert!(PADDING_BUCKETS.contains(&dummy.payload.len()));

        // Payload should not be all zeros (random fill)
        assert!(!dummy.payload.iter().all(|&b| b == 0));

        // Announcement should have valid structure
        assert!(PADDING_BUCKETS.contains(&(dummy.announcement.size_bucket as usize)));
    }

    #[test]
    fn test_generate_interval_dummies() {
        let mut generator = CoverTrafficGenerator::with_defaults();
        let dummies = generator.generate_interval_dummies().unwrap();

        // Should generate target_rate (10) dummy messages
        assert_eq!(dummies.len(), 10);

        // All should have valid bucket sizes
        for dummy in &dummies {
            assert!(PADDING_BUCKETS.contains(&dummy.payload.len()));
        }
    }

    #[test]
    fn test_reset_interval() {
        let mut generator = CoverTrafficGenerator::with_defaults();

        // Send some messages
        generator.record_real_message();
        generator.record_real_message();
        let _ = generator.generate_dummy();

        // Reset
        generator.reset_interval();

        let stats = generator.stats();
        assert_eq!(stats.real_messages, 0);
        assert_eq!(stats.dummy_messages, 0);
    }

    #[test]
    fn test_stats() {
        let mut generator = CoverTrafficGenerator::with_defaults();

        generator.record_real_message();
        generator.record_real_message();
        let _ = generator.generate_dummy();
        let _ = generator.generate_dummy();
        let _ = generator.generate_dummy();

        let stats = generator.stats();
        assert_eq!(stats.real_messages, 2);
        assert_eq!(stats.dummy_messages, 3);
        assert_eq!(stats.total_messages(), 5);
        assert!((stats.dummy_ratio() - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_dummy_messages_unique() {
        let mut generator = CoverTrafficGenerator::with_defaults();

        let dummy1 = generator.generate_dummy().unwrap();
        let dummy2 = generator.generate_dummy().unwrap();

        // Different random mailbox keys
        assert_ne!(dummy1.announcement.mailbox_key, dummy2.announcement.mailbox_key);
        // Different random hashes
        assert_ne!(dummy1.announcement.message_hash, dummy2.announcement.message_hash);
        // Different random payloads
        assert_ne!(dummy1.payload, dummy2.payload);
    }

    #[test]
    fn test_max_dummy_cap() {
        let config = CoverTrafficConfig {
            enabled: true,
            target_rate_per_interval: 100,
            interval_secs: 60,
            min_dummy_per_interval: 2,
            max_dummy_per_interval: 5,
            privacy_level: PrivacyLevel::Medium,
        };
        let generator = CoverTrafficGenerator::new(config);

        // Even though target is 100, max is 5
        assert_eq!(generator.dummy_messages_needed(), 5);
    }
}
