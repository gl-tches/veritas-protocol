//! Asymmetric reputation decay.
//!
//! Scores above the upper target (500) decay toward it.
//! Scores below the upper target decay toward 0.
//! This creates a punitive model: low-reputation users trend to zero
//! while high-reputation users trend toward the equilibrium point.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::score::REPUTATION_MAX;

/// Default weekly decay rate (1%).
pub const DEFAULT_DECAY_RATE: f32 = 0.01;

/// Default decay interval in seconds (7 days).
pub const DEFAULT_DECAY_INTERVAL_SECS: i64 = 7 * 24 * 60 * 60;

/// Default upper target for asymmetric decay.
pub const DEFAULT_UPPER_TARGET: u32 = 500;

/// Configuration for asymmetric reputation decay.
///
/// Scores above `upper_target` decay toward `upper_target`.
/// Scores below `upper_target` decay toward 0.
/// Scores exactly at `upper_target` do not decay.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecayConfig {
    /// Weekly decay rate (0.0-1.0).
    pub decay_rate: f32,
    /// Interval between decay applications in seconds.
    pub decay_interval_secs: i64,
    /// Upper target: scores above this decay toward it,
    /// scores below decay toward 0.
    pub upper_target: u32,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            decay_rate: DEFAULT_DECAY_RATE,
            decay_interval_secs: DEFAULT_DECAY_INTERVAL_SECS,
            upper_target: DEFAULT_UPPER_TARGET,
        }
    }
}

impl DecayConfig {
    /// Create a new decay configuration.
    #[must_use]
    pub fn new(decay_rate: f32, decay_interval_secs: i64, upper_target: u32) -> Self {
        Self {
            decay_rate: decay_rate.clamp(0.0, 1.0),
            decay_interval_secs: decay_interval_secs.max(1),
            upper_target: upper_target.min(REPUTATION_MAX),
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

    /// Maximum number of decay periods to apply at once.
    /// Prevents CPU exhaustion from clock skew or stale timestamps.
    const MAX_PERIODS: u32 = 520; // ~10 years at weekly decay

    /// Get the number of decay periods elapsed since last decay.
    /// Returns 0 if `now` is before `last_decay` (clock skew protection).
    /// Capped at MAX_PERIODS to prevent CPU exhaustion.
    #[must_use]
    pub fn periods_elapsed(&self, now: DateTime<Utc>) -> u32 {
        let elapsed = (now - self.last_decay).num_seconds();
        if elapsed <= 0 {
            return 0;
        }
        let periods = elapsed / self.config.decay_interval_secs;
        (periods as u32).min(Self::MAX_PERIODS)
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

/// Apply asymmetric decay to a reputation score.
///
/// - If `current_score` > `upper_target`: decay toward `upper_target`
/// - If `current_score` < `upper_target`: decay toward 0 (score decreases)
/// - If `current_score` == `upper_target`: no change
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

    // Cap periods to prevent CPU exhaustion
    let capped_periods = periods.min(DecayState::MAX_PERIODS);

    let upper_target = config.upper_target as f32;
    let mut score = current_score as f32;

    for _ in 0..capped_periods {
        if score > upper_target {
            // Above upper_target: decay toward upper_target
            let diff = score - upper_target;
            let adjustment = diff * config.decay_rate;
            score -= adjustment;
        } else if score < upper_target {
            // Below upper_target: decay toward 0 (asymmetric)
            let adjustment = score * config.decay_rate;
            score -= adjustment;
        }
        // At upper_target: no change
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

/// Calculate how many periods until score reaches its asymmetric target (within 1 point).
///
/// For scores above `upper_target`, this is the number of periods to reach `upper_target`.
/// For scores below `upper_target`, this is the number of periods to reach 0.
/// For scores at `upper_target`, this returns 0.
#[must_use]
pub fn periods_to_target(current_score: u32, config: &DecayConfig) -> u32 {
    if current_score == config.upper_target {
        return 0;
    }

    let destination = if current_score > config.upper_target {
        config.upper_target
    } else {
        0
    };

    let mut score = current_score;
    let mut periods = 0;

    while score != destination && periods < 1000 {
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
        assert_eq!(config.upper_target, DEFAULT_UPPER_TARGET);
        assert_eq!(config.upper_target, 500);
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

        // 300 -> should decay toward 0 (asymmetric: below upper_target decays down)
        let new_score = apply_decay(300, &config, 1);
        assert!(new_score < 300);
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

        // Multiple periods above target should compound toward 500
        let score1 = apply_decay(800, &config, 1);
        let score2 = apply_decay(800, &config, 2);
        let score3 = apply_decay(800, &config, 3);

        assert!(score2 < score1);
        assert!(score3 < score2);
    }

    #[test]
    fn test_decay_below_target_multiple_periods() {
        let config = DecayConfig::default();

        // Multiple periods below target should compound toward 0
        let score1 = apply_decay(300, &config, 1);
        let score2 = apply_decay(300, &config, 2);
        let score3 = apply_decay(300, &config, 3);

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

        // Project 52 weeks (1 year) for score above target
        let final_score = project_decay(900, &config, 52);
        assert!(final_score < 900);
        assert!(final_score > 500); // Still above upper_target after 1 year

        // Project 52 weeks for score below target -- should decrease toward 0
        let final_score_below = project_decay(300, &config, 52);
        assert!(final_score_below < 300);
    }

    #[test]
    fn test_periods_to_target() {
        let config = DecayConfig::default();

        // At upper_target should be 0
        assert_eq!(periods_to_target(500, &config), 0);

        // Above upper_target: decays toward upper_target
        let periods = periods_to_target(600, &config);
        assert!(periods > 0);

        // Below upper_target: decays toward 0
        let periods = periods_to_target(400, &config);
        assert!(periods > 0);
    }

    #[test]
    fn test_decay_converges_above_target() {
        let config = DecayConfig::default();

        // Very high score should decay toward 500
        let mut score = 1000;
        for _ in 0..100 {
            score = apply_decay(score, &config, 1);
        }
        // Should be closer to 500 than we started
        assert!(score < 1000);
        assert!(score > 500);
    }

    #[test]
    fn test_decay_converges_below_target() {
        let config = DecayConfig::default();

        // Score below upper_target should decay toward 0
        let mut score = 300;
        for _ in 0..100 {
            score = apply_decay(score, &config, 1);
        }
        // Should have decreased (decaying toward 0)
        assert!(score < 300);
    }

    #[test]
    fn test_asymmetric_decay_behavior() {
        let config = DecayConfig::default();

        // Score above 500 decays down toward 500
        let above = apply_decay(600, &config, 10);
        assert!(above < 600);
        assert!(above >= 500);

        // Score below 500 decays down toward 0
        let below = apply_decay(400, &config, 10);
        assert!(below < 400);

        // Score at 500 stays at 500
        let at_target = apply_decay(500, &config, 10);
        assert_eq!(at_target, 500);
    }
}
