//! Reputation score tracking and management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Reputation score limits and thresholds.
pub mod limits {
    /// Default starting reputation score.
    pub const REPUTATION_START: u32 = 100;

    /// Maximum reputation score.
    pub const REPUTATION_MAX: u32 = 1000;

    /// Minimum reputation score.
    pub const REPUTATION_MIN: u32 = 0;

    /// Quarantine threshold - below this, user is heavily restricted.
    pub const REPUTATION_QUARANTINE: u32 = 200;

    /// Blacklist threshold - below this, user cannot participate.
    pub const REPUTATION_BLACKLIST: u32 = 50;
}

/// Reputation tier thresholds.
pub mod tiers {
    /// Tier 1: Basic (starting tier at 100).
    pub const TIER_1_BASIC: u32 = 100;
    /// Tier 2: Established (can file reports).
    pub const TIER_2_ESTABLISHED: u32 = 300;
    /// Tier 3: Trusted (enhanced rate limits).
    pub const TIER_3_TRUSTED: u32 = 500;
    /// Tier 4: Veteran (can be validator candidate).
    pub const TIER_4_VETERAN: u32 = 700;
    /// Tier 5: Priority (full validator eligible).
    pub const TIER_5_PRIORITY: u32 = 800;
}

// Re-export limits at module level for backwards compatibility
pub use limits::*;

/// A user's reputation score with tracking of gains and losses.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Current reputation score (0-1000 range).
    current_score: u32,
    /// Total reputation gained over lifetime.
    total_gained: u32,
    /// Total reputation lost over lifetime.
    total_lost: u32,
    /// When this reputation record was created.
    created_at: DateTime<Utc>,
    /// When this reputation was last updated.
    updated_at: DateTime<Utc>,
}

impl ReputationScore {
    /// Create a new reputation score with the default starting value (100).
    #[must_use]
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            current_score: REPUTATION_START,
            total_gained: 0,
            total_lost: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a reputation score with a specific initial value.
    #[must_use]
    pub fn with_score(score: u32) -> Self {
        let now = Utc::now();
        Self {
            current_score: score.min(REPUTATION_MAX),
            total_gained: 0,
            total_lost: 0,
            created_at: now,
            updated_at: now,
        }
    }

    /// Get the current score.
    #[must_use]
    pub fn current(&self) -> u32 {
        self.current_score
    }

    /// Get total reputation gained.
    #[must_use]
    pub fn total_gained(&self) -> u32 {
        self.total_gained
    }

    /// Get total reputation lost.
    #[must_use]
    pub fn total_lost(&self) -> u32 {
        self.total_lost
    }

    /// Get when this score was created.
    #[must_use]
    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    /// Get when this score was last updated.
    #[must_use]
    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    /// Add reputation points (capped at REPUTATION_MAX).
    ///
    /// Returns the actual amount gained after capping.
    pub fn gain(&mut self, amount: u32) -> u32 {
        let old_score = self.current_score;
        self.current_score = self
            .current_score
            .saturating_add(amount)
            .min(REPUTATION_MAX);
        let actual_gain = self.current_score - old_score;
        self.total_gained = self.total_gained.saturating_add(actual_gain);
        self.updated_at = Utc::now();
        actual_gain
    }

    /// Add reputation with a multiplier applied (e.g., for collusion penalties).
    ///
    /// Returns the actual amount gained after applying multiplier and capping.
    pub fn gain_with_multiplier(&mut self, amount: u32, multiplier: f32) -> u32 {
        let adjusted = ((amount as f32) * multiplier.clamp(0.0, 1.0)) as u32;
        self.gain(adjusted)
    }

    /// Remove reputation points (floored at REPUTATION_MIN).
    ///
    /// Returns the actual amount lost after flooring.
    pub fn lose(&mut self, amount: u32) -> u32 {
        let old_score = self.current_score;
        self.current_score = self.current_score.saturating_sub(amount);
        let actual_loss = old_score - self.current_score;
        self.total_lost = self.total_lost.saturating_add(actual_loss);
        self.updated_at = Utc::now();
        actual_loss
    }

    /// Set the score directly (used for decay operations).
    pub fn set_score(&mut self, score: u32) {
        self.current_score = score.min(REPUTATION_MAX);
        self.updated_at = Utc::now();
    }

    /// Check if this identity is quarantined (heavily restricted).
    #[must_use]
    pub fn is_quarantined(&self) -> bool {
        self.current_score < REPUTATION_QUARANTINE
    }

    /// Check if this identity is blacklisted (cannot participate).
    #[must_use]
    pub fn is_blacklisted(&self) -> bool {
        self.current_score < REPUTATION_BLACKLIST
    }

    /// Check if this identity has priority status.
    #[must_use]
    pub fn is_priority(&self) -> bool {
        self.current_score >= 800
    }

    /// Check if this identity can file reports (needs >= 300 reputation).
    #[must_use]
    pub fn can_file_reports(&self) -> bool {
        self.current_score >= tiers::TIER_2_ESTABLISHED
    }

    /// Check if this identity can become a validator (needs >= 700 reputation).
    #[must_use]
    pub fn can_be_validator(&self) -> bool {
        self.current_score >= 700
    }

    /// Get the current reputation tier.
    pub fn tier(&self) -> u32 {
        if self.current_score >= tiers::TIER_5_PRIORITY {
            5
        } else if self.current_score >= tiers::TIER_4_VETERAN {
            4
        } else if self.current_score >= tiers::TIER_3_TRUSTED {
            3
        } else if self.current_score >= tiers::TIER_2_ESTABLISHED {
            2
        } else if self.current_score >= tiers::TIER_1_BASIC {
            1
        } else {
            0
        }
    }
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for ReputationScore {
    fn eq(&self, other: &Self) -> bool {
        self.current_score == other.current_score
    }
}

impl Eq for ReputationScore {}

impl PartialOrd for ReputationScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ReputationScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.current_score.cmp(&other.current_score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_score_starts_at_100() {
        let score = ReputationScore::new();
        assert_eq!(score.current(), REPUTATION_START);
        assert_eq!(score.current(), 100);
        assert_eq!(score.total_gained(), 0);
        assert_eq!(score.total_lost(), 0);
    }

    #[test]
    fn test_gain_adds_points() {
        let mut score = ReputationScore::new();
        let gained = score.gain(50);
        assert_eq!(gained, 50);
        assert_eq!(score.current(), 150);
        assert_eq!(score.total_gained(), 50);
    }

    #[test]
    fn test_gain_capped_at_max() {
        let mut score = ReputationScore::with_score(980);
        let gained = score.gain(50);
        assert_eq!(gained, 20);
        assert_eq!(score.current(), REPUTATION_MAX);
        assert_eq!(score.total_gained(), 20);
    }

    #[test]
    fn test_lose_removes_points() {
        let mut score = ReputationScore::new();
        let lost = score.lose(50);
        assert_eq!(lost, 50);
        assert_eq!(score.current(), 50);
        assert_eq!(score.total_lost(), 50);
    }

    #[test]
    fn test_lose_floored_at_zero() {
        let mut score = ReputationScore::with_score(30);
        let lost = score.lose(50);
        assert_eq!(lost, 30);
        assert_eq!(score.current(), 0);
        assert_eq!(score.total_lost(), 30);
    }

    #[test]
    fn test_gain_with_multiplier() {
        let mut score = ReputationScore::new();
        let gained = score.gain_with_multiplier(100, 0.5);
        assert_eq!(gained, 50);
        assert_eq!(score.current(), 150);
    }

    #[test]
    fn test_is_quarantined() {
        let mut score = ReputationScore::with_score(250);
        assert!(!score.is_quarantined());
        score.lose(100);
        assert!(score.is_quarantined());
    }

    #[test]
    fn test_is_blacklisted() {
        let mut score = ReputationScore::with_score(100);
        assert!(!score.is_blacklisted());
        score.lose(60);
        assert!(score.is_blacklisted());
    }

    #[test]
    fn test_is_priority() {
        let score = ReputationScore::with_score(850);
        assert!(score.is_priority());
        let score2 = ReputationScore::with_score(750);
        assert!(!score2.is_priority());
    }

    #[test]
    fn test_can_file_reports() {
        let score = ReputationScore::with_score(350);
        assert!(score.can_file_reports());
        let score2 = ReputationScore::with_score(250);
        assert!(!score2.can_file_reports());
    }

    #[test]
    fn test_can_be_validator() {
        let score = ReputationScore::with_score(750);
        assert!(score.can_be_validator());
        let score2 = ReputationScore::with_score(650);
        assert!(!score2.can_be_validator());
    }

    #[test]
    fn test_set_score() {
        let mut score = ReputationScore::new();
        score.set_score(750);
        assert_eq!(score.current(), 750);
    }

    #[test]
    fn test_set_score_capped() {
        let mut score = ReputationScore::new();
        score.set_score(1500);
        assert_eq!(score.current(), REPUTATION_MAX);
    }

    #[test]
    fn test_ordering() {
        let low = ReputationScore::with_score(300);
        let high = ReputationScore::with_score(700);
        assert!(low < high);
    }

    #[test]
    fn test_tier() {
        assert_eq!(ReputationScore::with_score(50).tier(), 0);
        assert_eq!(ReputationScore::with_score(100).tier(), 1);
        assert_eq!(ReputationScore::with_score(299).tier(), 1);
        assert_eq!(ReputationScore::with_score(300).tier(), 2);
        assert_eq!(ReputationScore::with_score(500).tier(), 3);
        assert_eq!(ReputationScore::with_score(700).tier(), 4);
        assert_eq!(ReputationScore::with_score(800).tier(), 5);
        assert_eq!(ReputationScore::with_score(1000).tier(), 5);
    }
}
