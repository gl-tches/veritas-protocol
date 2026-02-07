//! Reputation tier effects and restrictions.

use serde::{Deserialize, Serialize};

use crate::score::{REPUTATION_BLACKLIST, REPUTATION_QUARANTINE, REPUTATION_START};

/// Minimum reputation to become a validator.
pub const MIN_VALIDATOR_REPUTATION: u32 = 700;

/// Minimum reputation to file reports.
pub const MIN_REPORTER_REPUTATION: u32 = 400;

/// Threshold for priority status.
pub const PRIORITY_THRESHOLD: u32 = 800;

/// Reputation tiers based on score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReputationTier {
    /// Score < 50: Cannot participate at all.
    Blacklisted,
    /// Score < 200: Heavily restricted.
    Quarantined,
    /// Score 200-499: Standard participation (new users start here after initial interactions).
    Normal,
    /// Score >= 500: Trusted participation.
    Trusted,
    /// Score >= 800: Prioritized participation.
    Priority,
}

impl ReputationTier {
    /// Get the tier for a given score.
    ///
    /// New users start at score 100 (Quarantined tier) and must build
    /// reputation through positive interactions to reach Normal (200+).
    /// This is intentional: new identities are cheap to create, so the
    /// protocol requires proof of good behavior before granting full access.
    #[must_use]
    pub fn from_score(score: u32) -> Self {
        if score < REPUTATION_BLACKLIST {
            ReputationTier::Blacklisted
        } else if score < REPUTATION_QUARANTINE {
            ReputationTier::Quarantined
        } else if score < 500 {
            ReputationTier::Normal
        } else if score < PRIORITY_THRESHOLD {
            ReputationTier::Trusted
        } else {
            ReputationTier::Priority
        }
    }

    /// Get a human-readable name for the tier.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            ReputationTier::Blacklisted => "Blacklisted",
            ReputationTier::Quarantined => "Quarantined",
            ReputationTier::Normal => "Normal",
            ReputationTier::Trusted => "Trusted",
            ReputationTier::Priority => "Priority",
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
                message_priority: -1,
                rate_limit_multiplier: 0.5,
                description: "New/low-reputation: reduced rate limits, cannot file reports",
            },
            ReputationTier::Normal => Self {
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
                description: "Trusted: enhanced rate limits, full messaging rights",
            },
            ReputationTier::Priority => Self {
                can_send_messages: true,
                can_receive_messages: true,
                can_file_reports: true,
                can_become_validator: true,
                message_priority: 2,
                rate_limit_multiplier: 2.0,
                description: "Priority access: higher limits, can become validator",
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

/// Check if a score allows sending messages.
#[must_use]
pub fn can_send(score: u32) -> bool {
    score >= REPUTATION_BLACKLIST
}

/// Check if a score allows receiving messages.
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
        assert_eq!(get_tier(49), ReputationTier::Blacklisted);
        assert_eq!(get_tier(50), ReputationTier::Quarantined);
        assert_eq!(get_tier(100), ReputationTier::Quarantined); // New users start here
        assert_eq!(get_tier(199), ReputationTier::Quarantined);
        assert_eq!(get_tier(200), ReputationTier::Normal);
        assert_eq!(get_tier(499), ReputationTier::Normal);
        assert_eq!(get_tier(500), ReputationTier::Trusted);
        assert_eq!(get_tier(799), ReputationTier::Trusted);
        assert_eq!(get_tier(800), ReputationTier::Priority);
        assert_eq!(get_tier(1000), ReputationTier::Priority);
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
        assert_eq!(effects.message_priority, -1);
    }

    #[test]
    fn test_normal_effects() {
        let effects = get_effects(ReputationTier::Normal);
        assert!(effects.can_send_messages);
        assert!(effects.can_file_reports);
        assert!(!effects.can_become_validator);
        assert_eq!(effects.rate_limit_multiplier, 1.0);
    }

    #[test]
    fn test_trusted_effects() {
        let effects = get_effects(ReputationTier::Trusted);
        assert!(effects.can_send_messages);
        assert!(effects.can_file_reports);
        assert!(!effects.can_become_validator);
        assert!(effects.rate_limit_multiplier > 1.0);
        assert_eq!(effects.message_priority, 1);
    }

    #[test]
    fn test_priority_effects() {
        let effects = get_effects(ReputationTier::Priority);
        assert!(effects.can_send_messages);
        assert!(effects.can_file_reports);
        assert!(effects.can_become_validator);
        assert!(effects.rate_limit_multiplier > 1.0);
        assert_eq!(effects.message_priority, 2);
    }

    #[test]
    fn test_can_send() {
        assert!(!can_send(0));
        assert!(!can_send(49));
        assert!(can_send(50));
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
            TierEffects::for_tier(ReputationTier::Normal).can_send_messages,
            effects.can_send_messages
        );
    }

    #[test]
    fn test_tier_display() {
        assert_eq!(format!("{}", ReputationTier::Normal), "Normal");
        assert_eq!(format!("{}", ReputationTier::Trusted), "Trusted");
        assert_eq!(format!("{}", ReputationTier::Priority), "Priority");
    }
}
