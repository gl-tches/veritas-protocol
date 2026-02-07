//! Reputation tier effects and restrictions.

use serde::{Deserialize, Serialize};

use crate::score::{REPUTATION_BLACKLIST, REPUTATION_QUARANTINE};

/// Minimum reputation to become a validator.
pub const MIN_VALIDATOR_REPUTATION: u32 = 700;

/// Minimum reputation to file reports.
pub const MIN_REPORTER_REPUTATION: u32 = 400;

/// Threshold for priority status.
pub const PRIORITY_THRESHOLD: u32 = 800;

/// Reputation tiers based on score.
///
/// Tier boundaries updated for starting score of 100:
/// - Tier 1 (Basic): 0-199 — Can receive, sending rate-limited
/// - Tier 2 (Standard): 200-499 — Normal messaging
/// - Tier 3 (Trusted): 500-699 — Higher rate limits
/// - Tier 4 (Verified): 700-999 — Can become validator candidate
/// - Tier 5 (Guardian): 1000 — Maximum trust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationTier {
    /// Score < 20: Cannot participate at all.
    Blacklisted,
    /// Score < 50: Heavily restricted.
    Quarantined,
    /// Score < 200: Basic tier (starting). Rate-limited sending.
    Basic,
    /// Score 200-499: Standard participation.
    Standard,
    /// Score 500-699: Trusted. Higher rate limits.
    Trusted,
    /// Score >= 700: Verified. Can become validator candidate.
    Verified,
}

/// Threshold for Standard tier.
pub const STANDARD_THRESHOLD: u32 = 200;

/// Threshold for Trusted tier.
pub const TRUSTED_THRESHOLD: u32 = 500;

impl ReputationTier {
    /// Get the tier for a given score.
    #[must_use]
    pub fn from_score(score: u32) -> Self {
        if score < REPUTATION_BLACKLIST {
            ReputationTier::Blacklisted
        } else if score < REPUTATION_QUARANTINE {
            ReputationTier::Quarantined
        } else if score < STANDARD_THRESHOLD {
            ReputationTier::Basic
        } else if score < TRUSTED_THRESHOLD {
            ReputationTier::Standard
        } else if score < MIN_VALIDATOR_REPUTATION {
            ReputationTier::Trusted
        } else {
            ReputationTier::Verified
        }
    }

    /// Get a human-readable name for the tier.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            ReputationTier::Blacklisted => "Blacklisted",
            ReputationTier::Quarantined => "Quarantined",
            ReputationTier::Basic => "Basic",
            ReputationTier::Standard => "Standard",
            ReputationTier::Trusted => "Trusted",
            ReputationTier::Verified => "Verified",
        }
    }
}

impl std::fmt::Display for ReputationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Effects and restrictions for a reputation tier.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TierEffects {
    /// Whether the identity can send messages.
    pub can_send_messages: bool,
    /// Whether the identity can receive messages.
    pub can_receive_messages: bool,
    /// Whether the identity can file reports.
    pub can_file_reports: bool,
    /// Whether the identity can become a validator.
    pub can_become_validator: bool,
    /// Message priority modifier (-2 to +2).
    pub message_priority: i8,
    /// Rate limit multiplier (0.5 = half, 2.0 = double).
    pub rate_limit_multiplier: f32,
    /// Description of restrictions.
    pub description: &'static str,
}

impl TierEffects {
    /// Get effects for a given tier.
    #[must_use]
    pub fn for_tier(tier: ReputationTier) -> Self {
        match tier {
            ReputationTier::Blacklisted => Self {
                can_send_messages: false,
                can_receive_messages: false,
                can_file_reports: false,
                can_become_validator: false,
                message_priority: -2,
                rate_limit_multiplier: 0.0,
                description: "Permanently banned from participation",
            },
            ReputationTier::Quarantined => Self {
                can_send_messages: true,
                can_receive_messages: true,
                can_file_reports: false,
                can_become_validator: false,
                message_priority: -2,
                rate_limit_multiplier: 0.25,
                description: "Heavily restricted: low priority, severe rate limits",
            },
            ReputationTier::Basic => Self {
                can_send_messages: true,
                can_receive_messages: true,
                can_file_reports: false,
                can_become_validator: false,
                message_priority: -1,
                rate_limit_multiplier: 0.5,
                description: "Basic tier: rate-limited sending, cannot file reports",
            },
            ReputationTier::Standard => Self {
                can_send_messages: true,
                can_receive_messages: true,
                can_file_reports: true,
                can_become_validator: false,
                message_priority: 0,
                rate_limit_multiplier: 1.0,
                description: "Standard participation with full messaging rights",
            },
            ReputationTier::Trusted => Self {
                can_send_messages: true,
                can_receive_messages: true,
                can_file_reports: true,
                can_become_validator: false,
                message_priority: 1,
                rate_limit_multiplier: 1.5,
                description: "Trusted: higher rate limits",
            },
            ReputationTier::Verified => Self {
                can_send_messages: true,
                can_receive_messages: true,
                can_file_reports: true,
                can_become_validator: true,
                message_priority: 2,
                rate_limit_multiplier: 2.0,
                description: "Verified: highest limits, can become validator",
            },
        }
    }

    /// Get effects for a given score.
    #[must_use]
    pub fn for_score(score: u32) -> Self {
        Self::for_tier(ReputationTier::from_score(score))
    }
}

/// Get the reputation tier for a score.
#[must_use]
pub fn get_tier(score: u32) -> ReputationTier {
    ReputationTier::from_score(score)
}

/// Get the effects for a tier.
#[must_use]
pub fn get_effects(tier: ReputationTier) -> TierEffects {
    TierEffects::for_tier(tier)
}

/// Get the effects for a score.
#[must_use]
pub fn get_effects_for_score(score: u32) -> TierEffects {
    TierEffects::for_score(score)
}

/// Check if a score allows sending messages (above blacklist threshold).
#[must_use]
pub fn can_send(score: u32) -> bool {
    score >= REPUTATION_BLACKLIST
}

/// Check if a score allows receiving messages (above blacklist threshold).
#[must_use]
pub fn can_receive(score: u32) -> bool {
    score >= REPUTATION_BLACKLIST
}

/// Check if a score allows filing reports.
#[must_use]
pub fn can_report(score: u32) -> bool {
    score >= MIN_REPORTER_REPUTATION
}

/// Check if a score allows becoming a validator.
#[must_use]
pub fn can_validate(score: u32) -> bool {
    score >= MIN_VALIDATOR_REPUTATION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tier_from_score() {
        assert_eq!(get_tier(0), ReputationTier::Blacklisted);
        assert_eq!(get_tier(19), ReputationTier::Blacklisted);
        assert_eq!(get_tier(20), ReputationTier::Quarantined);
        assert_eq!(get_tier(49), ReputationTier::Quarantined);
        assert_eq!(get_tier(50), ReputationTier::Basic);
        assert_eq!(get_tier(100), ReputationTier::Basic); // Starting score
        assert_eq!(get_tier(199), ReputationTier::Basic);
        assert_eq!(get_tier(200), ReputationTier::Standard);
        assert_eq!(get_tier(499), ReputationTier::Standard);
        assert_eq!(get_tier(500), ReputationTier::Trusted);
        assert_eq!(get_tier(699), ReputationTier::Trusted);
        assert_eq!(get_tier(700), ReputationTier::Verified);
        assert_eq!(get_tier(1000), ReputationTier::Verified);
    }

    #[test]
    fn test_blacklisted_effects() {
        let effects = get_effects(ReputationTier::Blacklisted);
        assert!(!effects.can_send_messages);
        assert!(!effects.can_receive_messages);
        assert!(!effects.can_file_reports);
        assert!(!effects.can_become_validator);
        assert_eq!(effects.message_priority, -2);
    }

    #[test]
    fn test_quarantined_effects() {
        let effects = get_effects(ReputationTier::Quarantined);
        assert!(effects.can_send_messages);
        assert!(effects.can_receive_messages);
        assert!(!effects.can_file_reports);
        assert!(!effects.can_become_validator);
        assert!(effects.rate_limit_multiplier < 1.0);
    }

    #[test]
    fn test_basic_effects() {
        let effects = get_effects(ReputationTier::Basic);
        assert!(effects.can_send_messages);
        assert!(!effects.can_file_reports);
        assert_eq!(effects.message_priority, -1);
    }

    #[test]
    fn test_standard_effects() {
        let effects = get_effects(ReputationTier::Standard);
        assert!(effects.can_send_messages);
        assert!(effects.can_file_reports);
        assert!(!effects.can_become_validator);
        assert_eq!(effects.rate_limit_multiplier, 1.0);
    }

    #[test]
    fn test_verified_effects() {
        let effects = get_effects(ReputationTier::Verified);
        assert!(effects.can_send_messages);
        assert!(effects.can_file_reports);
        assert!(effects.can_become_validator);
        assert!(effects.rate_limit_multiplier > 1.0);
        assert_eq!(effects.message_priority, 2);
    }

    #[test]
    fn test_can_send() {
        assert!(!can_send(0));
        assert!(!can_send(19));
        assert!(can_send(20));
        assert!(can_send(500));
    }

    #[test]
    fn test_can_report() {
        assert!(!can_report(0));
        assert!(!can_report(399));
        assert!(can_report(400));
        assert!(can_report(800));
    }

    #[test]
    fn test_can_validate() {
        assert!(!can_validate(0));
        assert!(!can_validate(699));
        assert!(can_validate(700));
        assert!(can_validate(1000));
    }

    #[test]
    fn test_effects_for_score() {
        let effects = get_effects_for_score(600);
        assert_eq!(
            TierEffects::for_tier(ReputationTier::Trusted).can_send_messages,
            effects.can_send_messages
        );
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(format!("{}", ReputationTier::Standard), "Standard");
        assert_eq!(format!("{}", ReputationTier::Verified), "Verified");
    }
}
