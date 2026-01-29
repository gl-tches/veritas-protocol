//! Rate limiting for gossip protocol.
//!
//! Implements a token bucket algorithm for rate limiting gossip announcements
//! at both per-peer and global levels. This prevents flooding attacks that
//! could exhaust network resources.
//!
//! ## Security Purpose
//!
//! This module addresses VERITAS-2026-0007: Gossip protocol flooding.
//! Without rate limiting, attackers can flood the network with announcements,
//! causing bandwidth/CPU/memory exhaustion on all nodes.
//!
//! ## Usage
//!
//! ```ignore
//! use veritas_net::rate_limiter::{RateLimiter, RateLimitConfig};
//! use libp2p::PeerId;
//!
//! let config = RateLimitConfig::default();
//! let mut limiter = RateLimiter::new(config);
//!
//! let peer_id = PeerId::random();
//! if limiter.check(&peer_id) {
//!     // Process the announcement
//! } else {
//!     // Rate limit exceeded, reject
//! }
//! ```

use std::collections::HashMap;
use std::time::{Duration, Instant};

use libp2p::PeerId;

// ============================================================================
// Constants
// ============================================================================

/// Default maximum announcements per peer per second.
pub const DEFAULT_PER_PEER_RATE: u32 = 10;

/// Default maximum global announcements per second.
pub const DEFAULT_GLOBAL_RATE: u32 = 1000;

/// Default burst multiplier for token bucket.
pub const DEFAULT_BURST_MULTIPLIER: u32 = 3;

/// Default number of violations before banning a peer.
pub const DEFAULT_VIOLATIONS_BEFORE_BAN: u32 = 5;

/// Default ban duration in seconds.
pub const DEFAULT_BAN_DURATION_SECS: u64 = 300;

/// Cleanup interval for stale peer buckets (in seconds).
const CLEANUP_INTERVAL_SECS: u64 = 60;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum announcements allowed per peer per second.
    pub per_peer_rate: u32,

    /// Maximum global announcements allowed per second.
    pub global_rate: u32,

    /// Burst multiplier - how many tokens can accumulate.
    /// Actual burst = rate * burst_multiplier.
    pub burst_multiplier: u32,

    /// Number of violations before a peer is banned.
    pub violations_before_ban: u32,

    /// Duration of a ban in seconds.
    pub ban_duration_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            per_peer_rate: DEFAULT_PER_PEER_RATE,
            global_rate: DEFAULT_GLOBAL_RATE,
            burst_multiplier: DEFAULT_BURST_MULTIPLIER,
            violations_before_ban: DEFAULT_VIOLATIONS_BEFORE_BAN,
            ban_duration_secs: DEFAULT_BAN_DURATION_SECS,
        }
    }
}

impl RateLimitConfig {
    /// Create a new rate limit configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the per-peer rate limit.
    pub fn with_per_peer_rate(mut self, rate: u32) -> Self {
        self.per_peer_rate = rate;
        self
    }

    /// Set the global rate limit.
    pub fn with_global_rate(mut self, rate: u32) -> Self {
        self.global_rate = rate;
        self
    }

    /// Set the burst multiplier.
    pub fn with_burst_multiplier(mut self, multiplier: u32) -> Self {
        self.burst_multiplier = multiplier;
        self
    }

    /// Set the number of violations before banning.
    pub fn with_violations_before_ban(mut self, count: u32) -> Self {
        self.violations_before_ban = count;
        self
    }

    /// Set the ban duration in seconds.
    pub fn with_ban_duration_secs(mut self, secs: u64) -> Self {
        self.ban_duration_secs = secs;
        self
    }
}

// ============================================================================
// Token Bucket
// ============================================================================

/// A token bucket for rate limiting.
///
/// Tokens are added at a constant rate up to a maximum (burst).
/// Each operation consumes one token. If no tokens are available,
/// the operation is rejected.
#[derive(Debug)]
struct TokenBucket {
    /// Current number of available tokens.
    tokens: f64,

    /// Maximum tokens (burst capacity).
    max_tokens: f64,

    /// Tokens added per second.
    rate: f64,

    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket.
    fn new(rate: u32, burst_multiplier: u32) -> Self {
        let rate_f64 = rate as f64;
        let max_tokens = rate_f64 * burst_multiplier as f64;

        Self {
            tokens: max_tokens, // Start with full bucket
            max_tokens,
            rate: rate_f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token. Returns true if successful.
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        // Add tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Get current token count (for testing/monitoring).
    #[cfg(test)]
    fn token_count(&self) -> f64 {
        self.tokens
    }
}

// ============================================================================
// Ban Info
// ============================================================================

/// Information about a banned peer.
#[derive(Debug)]
struct BanInfo {
    /// When the ban was issued.
    banned_at: Instant,

    /// Duration of the ban.
    duration: Duration,
}

impl BanInfo {
    /// Check if the ban has expired.
    fn is_expired(&self) -> bool {
        self.banned_at.elapsed() >= self.duration
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Rate limiter for gossip announcements.
///
/// Implements per-peer and global rate limiting using token buckets.
/// Tracks violations and bans repeat offenders.
#[derive(Debug)]
pub struct RateLimiter {
    /// Configuration.
    config: RateLimitConfig,

    /// Per-peer token buckets.
    peer_buckets: HashMap<PeerId, TokenBucket>,

    /// Global token bucket.
    global_bucket: TokenBucket,

    /// Violation counts per peer.
    violation_counts: HashMap<PeerId, u32>,

    /// Currently banned peers.
    banned_peers: HashMap<PeerId, BanInfo>,

    /// Last cleanup time.
    last_cleanup: Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        let global_bucket = TokenBucket::new(config.global_rate, config.burst_multiplier);

        Self {
            config,
            peer_buckets: HashMap::new(),
            global_bucket,
            violation_counts: HashMap::new(),
            banned_peers: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Create a rate limiter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a peer's request is allowed.
    ///
    /// Returns `true` if the request is allowed, `false` if rate limited.
    /// This does NOT automatically record a violation - use `record_violation`
    /// separately if you want to track violations.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer making the request
    ///
    /// # Returns
    ///
    /// `true` if the request should be allowed, `false` if rate limited.
    pub fn check(&mut self, peer_id: &PeerId) -> bool {
        // Periodic cleanup
        self.maybe_cleanup();

        // Check if peer is banned
        if self.is_banned(peer_id) {
            return false;
        }

        // Check global rate limit first
        if !self.global_bucket.try_consume() {
            return false;
        }

        // Get or create per-peer bucket
        let bucket = self.peer_buckets.entry(*peer_id).or_insert_with(|| {
            TokenBucket::new(self.config.per_peer_rate, self.config.burst_multiplier)
        });

        // Check per-peer rate limit
        bucket.try_consume()
    }

    /// Record a rate limit violation for a peer.
    ///
    /// If the violation count exceeds the threshold, the peer is banned.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - The peer that violated the rate limit
    ///
    /// # Returns
    ///
    /// `true` if the peer was banned as a result of this violation.
    pub fn record_violation(&mut self, peer_id: &PeerId) -> bool {
        let count = self.violation_counts.entry(*peer_id).or_insert(0);
        *count += 1;

        if *count >= self.config.violations_before_ban {
            self.ban_peer(peer_id);
            true
        } else {
            false
        }
    }

    /// Ban a peer for the configured duration.
    pub fn ban_peer(&mut self, peer_id: &PeerId) {
        let ban_info = BanInfo {
            banned_at: Instant::now(),
            duration: Duration::from_secs(self.config.ban_duration_secs),
        };

        self.banned_peers.insert(*peer_id, ban_info);
        self.violation_counts.remove(peer_id);
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&mut self, peer_id: &PeerId) -> bool {
        if let Some(ban_info) = self.banned_peers.get(peer_id) {
            if ban_info.is_expired() {
                self.banned_peers.remove(peer_id);
                false
            } else {
                true
            }
        } else {
            false
        }
    }

    /// Manually unban a peer.
    pub fn unban_peer(&mut self, peer_id: &PeerId) {
        self.banned_peers.remove(peer_id);
        self.violation_counts.remove(peer_id);
    }

    /// Get the violation count for a peer.
    pub fn violation_count(&self, peer_id: &PeerId) -> u32 {
        self.violation_counts.get(peer_id).copied().unwrap_or(0)
    }

    /// Get the number of currently banned peers.
    pub fn banned_peer_count(&self) -> usize {
        self.banned_peers.len()
    }

    /// Get all currently banned peer IDs.
    pub fn banned_peers(&self) -> Vec<PeerId> {
        self.banned_peers.keys().cloned().collect()
    }

    /// Get the current configuration.
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Perform periodic cleanup of stale entries.
    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed().as_secs() < CLEANUP_INTERVAL_SECS {
            return;
        }

        self.last_cleanup = Instant::now();

        // Remove expired bans
        self.banned_peers.retain(|_, ban_info| !ban_info.is_expired());

        // Remove stale peer buckets (inactive for > 5 minutes)
        let stale_threshold = Duration::from_secs(300);
        self.peer_buckets
            .retain(|_, bucket| bucket.last_refill.elapsed() < stale_threshold);

        // Decay violation counts for peers not recently violating
        // (This prevents permanent grudges against peers who had temporary issues)
        self.violation_counts.retain(|peer_id, _| {
            // Keep if they have a bucket (recently active) or are banned
            self.peer_buckets.contains_key(peer_id) || self.banned_peers.contains_key(peer_id)
        });
    }

    /// Reset all rate limiting state (for testing).
    #[cfg(test)]
    pub fn reset(&mut self) {
        self.peer_buckets.clear();
        self.global_bucket = TokenBucket::new(self.config.global_rate, self.config.burst_multiplier);
        self.violation_counts.clear();
        self.banned_peers.clear();
    }
}

// ============================================================================
// Rate Limit Result
// ============================================================================

/// Result of a rate limit check with additional context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Request is allowed.
    Allowed,

    /// Peer is banned.
    Banned,

    /// Per-peer rate limit exceeded.
    PeerLimitExceeded,

    /// Global rate limit exceeded.
    GlobalLimitExceeded,
}

impl RateLimiter {
    /// Check rate limit with detailed result.
    ///
    /// Unlike `check()`, this returns the specific reason for rejection.
    pub fn check_detailed(&mut self, peer_id: &PeerId) -> RateLimitResult {
        // Periodic cleanup
        self.maybe_cleanup();

        // Check if peer is banned
        if self.is_banned(peer_id) {
            return RateLimitResult::Banned;
        }

        // Check global rate limit first
        if !self.global_bucket.try_consume() {
            return RateLimitResult::GlobalLimitExceeded;
        }

        // Get or create per-peer bucket
        let bucket = self.peer_buckets.entry(*peer_id).or_insert_with(|| {
            TokenBucket::new(self.config.per_peer_rate, self.config.burst_multiplier)
        });

        // Check per-peer rate limit
        if bucket.try_consume() {
            RateLimitResult::Allowed
        } else {
            RateLimitResult::PeerLimitExceeded
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::new(10, 3);
        assert_eq!(bucket.max_tokens, 30.0);
        assert_eq!(bucket.rate, 10.0);
        assert_eq!(bucket.token_count(), 30.0);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(10, 1);

        // Should have 10 tokens initially
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }

        // 11th should fail
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(100, 1);

        // Consume all tokens
        for _ in 0..100 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());

        // Wait for refill (100 tokens/sec = 10 tokens in 100ms)
        sleep(Duration::from_millis(100));
        bucket.refill();

        // Should have ~10 tokens now
        let tokens = bucket.token_count();
        assert!(tokens >= 8.0 && tokens <= 12.0, "Expected ~10 tokens, got {}", tokens);
    }

    #[test]
    fn test_rate_limiter_per_peer() {
        let config = RateLimitConfig::default()
            .with_per_peer_rate(5)
            .with_burst_multiplier(1);
        let mut limiter = RateLimiter::new(config);

        let peer = PeerId::random();

        // Should allow 5 requests
        for _ in 0..5 {
            assert!(limiter.check(&peer));
        }

        // 6th should fail
        assert!(!limiter.check(&peer));
    }

    #[test]
    fn test_rate_limiter_global() {
        let config = RateLimitConfig::default()
            .with_per_peer_rate(100)
            .with_global_rate(10)
            .with_burst_multiplier(1);
        let mut limiter = RateLimiter::new(config);

        // Different peers should share global limit
        for i in 0..10 {
            let peer = PeerId::random();
            assert!(limiter.check(&peer), "Request {} should succeed", i);
        }

        // 11th from any peer should fail (global limit)
        let new_peer = PeerId::random();
        assert!(!limiter.check(&new_peer));
    }

    #[test]
    fn test_rate_limiter_violations_and_ban() {
        let config = RateLimitConfig::default()
            .with_violations_before_ban(3)
            .with_ban_duration_secs(1);
        let mut limiter = RateLimiter::new(config);

        let peer = PeerId::random();

        // Record violations
        assert!(!limiter.record_violation(&peer)); // 1
        assert!(!limiter.record_violation(&peer)); // 2
        assert!(limiter.record_violation(&peer));  // 3 - banned

        // Peer should be banned
        assert!(limiter.is_banned(&peer));
        assert!(!limiter.check(&peer));

        // Wait for ban to expire
        sleep(Duration::from_secs(2));

        // Should no longer be banned
        assert!(!limiter.is_banned(&peer));
        assert!(limiter.check(&peer));
    }

    #[test]
    fn test_rate_limiter_manual_ban() {
        let mut limiter = RateLimiter::with_defaults();
        let peer = PeerId::random();

        assert!(!limiter.is_banned(&peer));

        limiter.ban_peer(&peer);
        assert!(limiter.is_banned(&peer));

        limiter.unban_peer(&peer);
        assert!(!limiter.is_banned(&peer));
    }

    #[test]
    fn test_rate_limiter_detailed_check() {
        let config = RateLimitConfig::default()
            .with_per_peer_rate(2)
            .with_global_rate(100)
            .with_burst_multiplier(1);
        let mut limiter = RateLimiter::new(config);

        let peer = PeerId::random();

        // First two should be allowed
        assert_eq!(limiter.check_detailed(&peer), RateLimitResult::Allowed);
        assert_eq!(limiter.check_detailed(&peer), RateLimitResult::Allowed);

        // Third should exceed per-peer limit
        assert_eq!(limiter.check_detailed(&peer), RateLimitResult::PeerLimitExceeded);

        // Ban the peer
        limiter.ban_peer(&peer);
        assert_eq!(limiter.check_detailed(&peer), RateLimitResult::Banned);
    }

    #[test]
    fn test_rate_limiter_different_peers_isolated() {
        let config = RateLimitConfig::default()
            .with_per_peer_rate(3)
            .with_global_rate(1000)
            .with_burst_multiplier(1);
        let mut limiter = RateLimiter::new(config);

        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        // Exhaust peer1's limit
        for _ in 0..3 {
            assert!(limiter.check(&peer1));
        }
        assert!(!limiter.check(&peer1));

        // peer2 should still have full quota
        for _ in 0..3 {
            assert!(limiter.check(&peer2));
        }
        assert!(!limiter.check(&peer2));
    }

    #[test]
    fn test_rate_limit_config_builder() {
        let config = RateLimitConfig::new()
            .with_per_peer_rate(20)
            .with_global_rate(2000)
            .with_burst_multiplier(5)
            .with_violations_before_ban(10)
            .with_ban_duration_secs(600);

        assert_eq!(config.per_peer_rate, 20);
        assert_eq!(config.global_rate, 2000);
        assert_eq!(config.burst_multiplier, 5);
        assert_eq!(config.violations_before_ban, 10);
        assert_eq!(config.ban_duration_secs, 600);
    }

    #[test]
    fn test_banned_peers_list() {
        let mut limiter = RateLimiter::with_defaults();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();

        assert_eq!(limiter.banned_peer_count(), 0);
        assert!(limiter.banned_peers().is_empty());

        limiter.ban_peer(&peer1);
        limiter.ban_peer(&peer2);

        assert_eq!(limiter.banned_peer_count(), 2);

        let banned = limiter.banned_peers();
        assert!(banned.contains(&peer1));
        assert!(banned.contains(&peer2));
    }

    #[test]
    fn test_violation_count() {
        let mut limiter = RateLimiter::with_defaults();
        let peer = PeerId::random();

        assert_eq!(limiter.violation_count(&peer), 0);

        limiter.record_violation(&peer);
        assert_eq!(limiter.violation_count(&peer), 1);

        limiter.record_violation(&peer);
        assert_eq!(limiter.violation_count(&peer), 2);
    }
}
