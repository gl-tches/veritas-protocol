//! Rate limiting for reputation gain to prevent gaming.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Minimum seconds between messages to same peer for reputation gain.
pub const MIN_MESSAGE_INTERVAL_SECS: i64 = 60;

/// Maximum reputation gain from one peer per day.
pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;

/// Maximum total reputation gain per day.
pub const MAX_DAILY_GAIN_TOTAL: u32 = 100;

/// Identity hash type (32 bytes).
pub type IdentityHash = [u8; 32];

/// Peer ID type alias for identity hashes.
pub type PeerId = IdentityHash;

/// Tracks interactions with a specific peer for rate limiting.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerInteraction {
    /// The peer's identity hash.
    peer_id: IdentityHash,
    /// Timestamp of the last interaction.
    last_interaction: DateTime<Utc>,
    /// Reputation gained from this peer today.
    daily_gain: u32,
    /// Start of the current day period.
    day_start: DateTime<Utc>,
}

impl PeerInteraction {
    /// Create a new peer interaction record.
    fn new(peer_id: IdentityHash) -> Self {
        let now = Utc::now();
        Self {
            peer_id,
            last_interaction: now,
            daily_gain: 0,
            day_start: Self::start_of_day(now),
        }
    }

    /// Get the start of the day for a given timestamp.
    fn start_of_day(time: DateTime<Utc>) -> DateTime<Utc> {
        time.date_naive()
            .and_hms_opt(0, 0, 0)
            .expect("valid time")
            .and_utc()
    }

    /// Check if the daily limits should be reset.
    fn should_reset_daily(&self, now: DateTime<Utc>) -> bool {
        Self::start_of_day(now) > self.day_start
    }

    /// Reset daily limits.
    fn reset_daily(&mut self, now: DateTime<Utc>) {
        self.daily_gain = 0;
        self.day_start = Self::start_of_day(now);
    }
}

/// Result of a rate limit check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RateLimitResult {
    /// Gain is allowed with the specified amount.
    Allowed(u32),
    /// Too soon since last interaction with this peer.
    TooSoon {
        /// Seconds until next interaction is allowed.
        wait_seconds: i64,
    },
    /// Daily limit reached for this peer.
    PeerLimitReached {
        /// Amount already gained from this peer today.
        current: u32,
        /// Maximum allowed per peer per day.
        max: u32,
    },
    /// Total daily limit reached.
    TotalLimitReached {
        /// Amount already gained today.
        current: u32,
        /// Maximum allowed per day.
        max: u32,
    },
}

impl RateLimitResult {
    /// Check if the gain is allowed.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed(_))
    }
}

/// Type alias for backwards compatibility.
pub type RateLimitStatus = RateLimitResult;

/// Rate limiter for reputation gains.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScoreRateLimiter {
    /// Per-peer interaction tracking.
    peer_interactions: HashMap<IdentityHash, PeerInteraction>,
    /// Total reputation gained today.
    total_daily_gain: u32,
    /// Start of the current day period.
    day_start: DateTime<Utc>,
}

impl ScoreRateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            peer_interactions: HashMap::new(),
            total_daily_gain: 0,
            day_start: PeerInteraction::start_of_day(Utc::now()),
        }
    }

    /// Check if we can gain reputation from a peer and how much.
    pub fn can_gain_from_peer(
        &mut self,
        peer_id: &IdentityHash,
        requested_gain: u32,
    ) -> RateLimitResult {
        let now = Utc::now();
        self.maybe_reset_daily(now);

        if self.total_daily_gain >= MAX_DAILY_GAIN_TOTAL {
            return RateLimitResult::TotalLimitReached {
                current: self.total_daily_gain,
                max: MAX_DAILY_GAIN_TOTAL,
            };
        }

        let interaction = self.peer_interactions.entry(*peer_id).or_insert_with(|| {
            let mut i = PeerInteraction::new(*peer_id);
            i.last_interaction = now - Duration::seconds(MIN_MESSAGE_INTERVAL_SECS + 1);
            i
        });

        if interaction.should_reset_daily(now) {
            interaction.reset_daily(now);
        }

        let elapsed = (now - interaction.last_interaction).num_seconds();
        if elapsed < MIN_MESSAGE_INTERVAL_SECS {
            return RateLimitResult::TooSoon {
                wait_seconds: MIN_MESSAGE_INTERVAL_SECS - elapsed,
            };
        }

        if interaction.daily_gain >= MAX_DAILY_GAIN_PER_PEER {
            return RateLimitResult::PeerLimitReached {
                current: interaction.daily_gain,
                max: MAX_DAILY_GAIN_PER_PEER,
            };
        }

        let peer_remaining = MAX_DAILY_GAIN_PER_PEER - interaction.daily_gain;
        let total_remaining = MAX_DAILY_GAIN_TOTAL - self.total_daily_gain;
        let allowed = requested_gain.min(peer_remaining).min(total_remaining);

        RateLimitResult::Allowed(allowed)
    }

    /// Record a reputation gain from a peer.
    pub fn record_gain(&mut self, peer_id: &IdentityHash, amount: u32) {
        let now = Utc::now();
        self.total_daily_gain = self.total_daily_gain.saturating_add(amount);

        if let Some(interaction) = self.peer_interactions.get_mut(peer_id) {
            interaction.last_interaction = now;
            interaction.daily_gain = interaction.daily_gain.saturating_add(amount);
        } else {
            let mut interaction = PeerInteraction::new(*peer_id);
            interaction.daily_gain = amount;
            self.peer_interactions.insert(*peer_id, interaction);
        }
    }

    /// Reset all daily limits.
    pub fn reset_daily_limits(&mut self) {
        let now = Utc::now();
        self.total_daily_gain = 0;
        self.day_start = PeerInteraction::start_of_day(now);
        for interaction in self.peer_interactions.values_mut() {
            interaction.reset_daily(now);
        }
    }

    fn maybe_reset_daily(&mut self, now: DateTime<Utc>) {
        let current_day = PeerInteraction::start_of_day(now);
        if current_day > self.day_start {
            self.reset_daily_limits();
        }
    }

    /// Get the total reputation gained today.
    #[must_use]
    pub fn total_daily_gain(&self) -> u32 {
        self.total_daily_gain
    }

    /// Get the remaining reputation that can be gained today.
    #[must_use]
    pub fn remaining_daily_gain(&self) -> u32 {
        MAX_DAILY_GAIN_TOTAL.saturating_sub(self.total_daily_gain)
    }

    /// Get the number of tracked peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peer_interactions.len()
    }

    /// Clean up old peer interactions (older than 7 days).
    pub fn cleanup_old_interactions(&mut self) {
        let cutoff = Utc::now() - Duration::days(7);
        self.peer_interactions
            .retain(|_, interaction| interaction.last_interaction > cutoff);
    }
}

impl Default for ScoreRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer_id(n: u8) -> IdentityHash {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_new_rate_limiter() {
        let limiter = ScoreRateLimiter::new();
        assert_eq!(limiter.total_daily_gain(), 0);
        assert_eq!(limiter.peer_count(), 0);
    }

    #[test]
    fn test_first_interaction_allowed() {
        let mut limiter = ScoreRateLimiter::new();
        let peer = make_peer_id(1);
        let result = limiter.can_gain_from_peer(&peer, 10);
        assert!(matches!(result, RateLimitResult::Allowed(10)));
    }

    #[test]
    fn test_immediate_second_interaction_blocked() {
        let mut limiter = ScoreRateLimiter::new();
        let peer = make_peer_id(1);

        let result = limiter.can_gain_from_peer(&peer, 10);
        assert!(result.is_allowed());
        limiter.record_gain(&peer, 10);

        let result = limiter.can_gain_from_peer(&peer, 10);
        assert!(matches!(result, RateLimitResult::TooSoon { .. }));
    }

    #[test]
    fn test_peer_daily_limit() {
        let mut limiter = ScoreRateLimiter::new();
        let peer = make_peer_id(1);

        limiter.record_gain(&peer, MAX_DAILY_GAIN_PER_PEER);

        if let Some(interaction) = limiter.peer_interactions.get_mut(&peer) {
            interaction.last_interaction =
                Utc::now() - Duration::seconds(MIN_MESSAGE_INTERVAL_SECS + 1);
        }

        let result = limiter.can_gain_from_peer(&peer, 10);
        assert!(matches!(result, RateLimitResult::PeerLimitReached { .. }));
    }

    #[test]
    fn test_total_daily_limit() {
        let mut limiter = ScoreRateLimiter::new();

        for i in 0..10 {
            let peer = make_peer_id(i);
            limiter.record_gain(&peer, 10);
        }

        assert_eq!(limiter.total_daily_gain(), 100);

        let new_peer = make_peer_id(100);
        let result = limiter.can_gain_from_peer(&new_peer, 10);
        assert!(matches!(result, RateLimitResult::TotalLimitReached { .. }));
    }

    #[test]
    fn test_partial_gain_allowed() {
        let mut limiter = ScoreRateLimiter::new();
        let peer = make_peer_id(1);

        limiter.record_gain(&peer, 25);

        if let Some(interaction) = limiter.peer_interactions.get_mut(&peer) {
            interaction.last_interaction =
                Utc::now() - Duration::seconds(MIN_MESSAGE_INTERVAL_SECS + 1);
        }

        let result = limiter.can_gain_from_peer(&peer, 10);
        assert!(matches!(result, RateLimitResult::Allowed(5)));
    }

    #[test]
    fn test_reset_daily_limits() {
        let mut limiter = ScoreRateLimiter::new();
        let peer = make_peer_id(1);

        limiter.record_gain(&peer, 50);
        assert_eq!(limiter.total_daily_gain(), 50);

        limiter.reset_daily_limits();
        assert_eq!(limiter.total_daily_gain(), 0);
    }

    #[test]
    fn test_remaining_daily_gain() {
        let mut limiter = ScoreRateLimiter::new();
        assert_eq!(limiter.remaining_daily_gain(), MAX_DAILY_GAIN_TOTAL);

        limiter.total_daily_gain = 40;
        assert_eq!(limiter.remaining_daily_gain(), 60);
    }

    #[test]
    fn test_multiple_peers_independent() {
        let mut limiter = ScoreRateLimiter::new();
        let peer1 = make_peer_id(1);
        let peer2 = make_peer_id(2);

        let result = limiter.can_gain_from_peer(&peer1, 10);
        assert!(result.is_allowed());
        limiter.record_gain(&peer1, 10);

        let result = limiter.can_gain_from_peer(&peer2, 10);
        assert!(result.is_allowed());
    }
}
