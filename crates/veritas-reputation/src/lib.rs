//! # veritas-reputation
//!
//! Reputation scoring system for VERITAS protocol.
//!
//! Provides:
//! - Reputation scoring with rate limiting
//! - Weighted negative reports
//! - Collusion detection via graph analysis
//! - Reputation decay and effects
//! - Cryptographic proof verification for interactions (VERITAS-2026-0010)
//!
//! ## Overview
//!
//! The reputation system tracks identity trustworthiness through scoring:
//!
//! - New identities start with 100 points
//! - Maximum score is 1000 points
//! - Quarantine threshold: 200 points
//! - Blacklist threshold: 50 points
//!
//! ## Anti-Gaming
//!
//! Rate limiting prevents reputation manipulation:
//!
//! - Minimum 60 seconds between messages to same peer
//! - Maximum 30 points from any single peer per day
//! - Maximum 100 points total per day
//!
//! ## Security (VERITAS-2026-0010)
//!
//! All reputation-changing interactions now require cryptographic proofs:
//!
//! - Both parties must sign the interaction proof
//! - Nonces prevent replay attacks
//! - Self-interaction is explicitly prevented
//!
//! ## Example
//!
//! ```
//! use veritas_reputation::{ReputationScore, ScoreRateLimiter, RateLimitResult};
//!
//! // Create a new reputation score
//! let mut score = ReputationScore::new();
//! assert_eq!(score.current(), 100);
//!
//! // Create a rate limiter
//! let mut limiter = ScoreRateLimiter::new();
//! let peer_id = [0u8; 32];
//!
//! // Check if we can gain reputation from this peer
//! if let RateLimitResult::Allowed(amount) = limiter.can_gain_from_peer(&peer_id, 5) {
//!     limiter.record_gain(&peer_id, amount);
//!     score.gain(amount);
//! }
//!
//! assert_eq!(score.current(), 105);
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod collusion;
pub mod decay;
pub mod effects;
pub mod error;
pub mod manager;
pub mod proof;
pub mod rate_limiter;
pub mod report;
pub mod score;

// Re-export main types
pub use collusion::{
    CLUSTER_SUSPICION_THRESHOLD, ClusterMember, CollusionDetector, InteractionRecord,
    InteractionVelocity, MAX_INTERACTION_VELOCITY, SuspiciousCluster,
};
pub use decay::{DecayConfig, DecayState, apply_decay};
pub use effects::{ReputationTier, TierEffects, get_effects, get_tier};
pub use error::{ReputationError, Result};
pub use manager::{
    DEFAULT_NONCE_EXPIRY_SECS, MAX_TRACKED_NONCES, NONCE_BUCKET_DURATION_SECS, ReputationManager,
    ReputationStats,
};
pub use proof::{
    InteractionProof, InteractionType, MAX_CLOCK_SKEW_SECS, MAX_PROOF_AGE_SECS, MAX_SIGNATURE_SIZE,
    NONCE_SIZE, PubkeyRegistry, Signature, generate_nonce,
};
pub use rate_limiter::{
    MAX_DAILY_GAIN_PER_PEER, MAX_DAILY_GAIN_TOTAL, MIN_MESSAGE_INTERVAL_SECS, PeerInteraction,
    RateLimitResult, ScoreRateLimiter,
};
pub use report::{
    BATCH_REPORT_WINDOW_SECS, EvidenceStrength, MIN_BATCH_REPORTS, MIN_REPORTER_REPUTATION,
    NEGATIVE_REPORT_THRESHOLD, NegativeReport, ReportAggregator, ReportReason,
};
pub use score::{
    REPUTATION_BLACKLIST, REPUTATION_MAX, REPUTATION_QUARANTINE, REPUTATION_START, ReputationScore,
};
