//! Reputation decay toward the baseline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::score::{REPUTATION_MAX, REPUTATION_START};

/// Default weekly decay rate (1%).
pub const DEFAULT_DECAY_RATE: f32 = 0.01;

/// Default decay interval in seconds (7 days).
pub const DEFAULT_DECAY_INTERVAL_SECS: i64 = 7 * 24 * 60 * 60;

/// Configuration for reputation decay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Weekly decay rate (0.0-1.0).
    pub decay_rate: f32,
    /// Interval between decay applications in seconds.
    pub decay_interval_secs: i64,
    /// Target score to decay toward.
    pub target_score: u32,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            decay_rate: DEFAULT_DECAY_RATE,
            decay_interval_secs: DEFAULT_DECAY_INTERVAL_SECS,
            target_score: REPUTATION_START,
        }
    }
}

impl DecayConfig {
    /// Create a new decay configuration.
    #[must_use]
    pub fn new(decay_rate: f32, decay_interval_secs: i64, target_score: u32) -> Self {
        Self {
            decay_rate: decay_rate.clamp(0.0, 1.0),
            decay_interval_secs: decay_interval_secs.max(1),
            target_score: target_score.min(REPUTATION_MAX),
        }
    }
}

/// State for tracking decay timing.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecayState {
    /// When decay was last applied.
    pub last_decay: DateTime<Utc>,
    /// Configuration for decay.
    pub config: DecayConfig,
}

impl DecayState {
    /// Create a new decay state.
    #[must_use]
    pub fn new(config: DecayConfig) -> Self {
        Self {
            last_decay: Utc::now(),
            config,
        }
    }

    /// Check if decay should be applied.
    #[must_use]
    pub fn should_decay(&self, now: DateTime<Utc>) -> bool {
        let elapsed = (now - self.last_decay).num_seconds();
        elapsed >= self.config.decay_interval_secs
    }

    /// Get the number of decay periods elapsed since last decay.
    #[must_use]
    pub fn periods_elapsed(&self, now: DateTime<Utc>) -> u32 {
        let elapsed = (now - self.last_decay).num_seconds();
        (elapsed / self.config.decay_interval_secs) as u32
    }

    /// Mark decay as applied.
    pub fn mark_decayed(&mut self) {
        self.last_decay = Utc::now();
    }

    /// Mark decay as applied at a specific time.
    pub fn mark_decayed_at(&mut self, time: DateTime<Utc>) {
        self.last_decay = time;
    }
}

impl Default for DecayState {
    fn default() -> Self {
        Self::new(DecayConfig::default())
    }
}

/// Apply decay to a reputation score.
///
/// Decays toward the target score (default 500):
/// - If score > target: decrease by decay_rate toward target
/// - If score < target: increase by decay_rate toward target
///
/// # Arguments
/// * `current_score` - The current reputation score
/// * `config` - Decay configuration
/// * `periods` - Number of decay periods to apply
///
/// # Returns
/// The new score after decay
#[must_use]
pub fn apply_decay(current_score: u32, config: &DecayConfig, periods: u32) -> u32 {
    if periods == 0 {
        return current_score;
    }

    let target = config.target_score as f32;
    let mut score = current_score as f32;

    for _ in 0..periods {
        let diff = score - target;
        let adjustment = diff * config.decay_rate;
        score -= adjustment;
    }

    // Clamp to valid range
    score.round().clamp(0.0, REPUTATION_MAX as f32) as u32
}

/// Apply decay based on time elapsed.
///
/// # Arguments
/// * `current_score` - The current reputation score
/// * `state` - Decay state with configuration and timing
/// * `now` - Current time
///
/// # Returns
/// The new score after decay (if any periods elapsed)
#[must_use]
pub fn apply_decay_for_time(
    current_score: u32,
    state: &DecayState,
    now: DateTime<Utc>,
) -> u32 {
    let periods = state.periods_elapsed(now);
    apply_decay(current_score, &state.config, periods)
}

/// Calculate what score will be after a given number of decay periods.
#[must_use]
pub fn project_decay(current_score: u32, config: &DecayConfig, periods: u32) -> u32 {
    apply_decay(current_score, config, periods)
}

/// Calculate how many periods until score reaches target (within 1 point).
#[must_use]
pub fn periods_to_target(current_score: u32, config: &DecayConfig) -> u32 {
    if current_score == config.target_score {
        return 0;
    }

    let mut score = current_score;
    let mut periods = 0;

    while score != config.target_score && periods < 1000 {
        score = apply_decay(score, config, 1);
        periods += 1;
    }

    periods
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_decay_config_default() {
        let config = DecayConfig::default();
        assert!((config.decay_rate - 0.01).abs() < 0.001);
        assert_eq!(config.target_score, REPUTATION_START);
    }

    #[test]
    fn test_decay_above_target() {
        let config = DecayConfig::default();

        // 800 -> should decay toward 500
        let new_score = apply_decay(800, &config, 1);
        assert!(new_score < 800);
        assert!(new_score > 500);
    }

    #[test]
    fn test_decay_below_target() {
        let config = DecayConfig::default();

        // 300 -> should increase toward 500
        let new_score = apply_decay(300, &config, 1);
        assert!(new_score > 300);
        assert!(new_score < 500);
    }

    #[test]
    fn test_no_decay_at_target() {
        let config = DecayConfig::default();

        // 500 -> should stay at 500
        let new_score = apply_decay(500, &config, 1);
        assert_eq!(new_score, 500);
    }

    #[test]
    fn test_decay_multiple_periods() {
        let config = DecayConfig::default();

        // Multiple periods should compound
        let score1 = apply_decay(800, &config, 1);
        let score2 = apply_decay(800, &config, 2);
        let score3 = apply_decay(800, &config, 3);

        assert!(score2 < score1);
        assert!(score3 < score2);
    }

    #[test]
    fn test_decay_zero_periods() {
        let config = DecayConfig::default();
        let new_score = apply_decay(800, &config, 0);
        assert_eq!(new_score, 800);
    }

    #[test]
    fn test_decay_state_periods_elapsed() {
        let config = DecayConfig::new(0.01, 60, 500); // 60 second interval
        let mut state = DecayState::new(config);

        // Set last decay to 3 minutes ago
        state.last_decay = Utc::now() - Duration::seconds(180);

        let now = Utc::now();
        assert_eq!(state.periods_elapsed(now), 3);
    }

    #[test]
    fn test_decay_state_should_decay() {
        let config = DecayConfig::new(0.01, 60, 500);
        let mut state = DecayState::new(config);

        // Just created, should not decay
        assert!(!state.should_decay(Utc::now()));

        // Set to past
        state.last_decay = Utc::now() - Duration::seconds(120);
        assert!(state.should_decay(Utc::now()));
    }

    #[test]
    fn test_project_decay() {
        let config = DecayConfig::default();

        // Project 52 weeks (1 year)
        let final_score = project_decay(900, &config, 52);
        assert!(final_score < 900);
        assert!(final_score > 500); // Still above target after 1 year
    }

    #[test]
    fn test_periods_to_target() {
        let config = DecayConfig::default();

        // At target should be 0
        assert_eq!(periods_to_target(500, &config), 0);

        // Above target should take some periods
        let periods = periods_to_target(600, &config);
        assert!(periods > 0);

        // Below target should take some periods
        let periods = periods_to_target(400, &config);
        assert!(periods > 0);
    }

    #[test]
    fn test_decay_converges_toward_target() {
        let config = DecayConfig::default();

        // Very high score should decay toward target
        let mut score = 1000;
        for _ in 0..100 {
            score = apply_decay(score, &config, 1);
        }
        // Should be closer to 500 than we started
        assert!(score < 1000);
        assert!(score > 500);

        // Very low score should increase toward target
        score = 100;
        for _ in 0..100 {
            score = apply_decay(score, &config, 1);
        }
        // Should be closer to 500 than we started
        assert!(score > 100);
        assert!(score < 500);
    }
}
