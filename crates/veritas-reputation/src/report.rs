//! Weighted negative report handling.

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{ReputationError, Result};

/// Minimum reputation required to file reports.
pub const MIN_REPORTER_REPUTATION: u32 = 400;

/// Number of weighted reports needed for action.
pub const NEGATIVE_REPORT_THRESHOLD: f32 = 3.0;

/// Identity hash type (32 bytes).
pub type IdentityHash = [u8; 32];

/// Reasons for filing a negative report.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReportReason {
    /// Unwanted or unsolicited messages.
    Spam,
    /// Abusive or harassing behavior.
    Harassment,
    /// Impersonating another user.
    Impersonation,
    /// Sharing malicious content.
    Malware,
    /// Fraudulent activity or scams.
    Scam,
    /// Other reason with description.
    Other(String),
}

impl ReportReason {
    /// Get the base penalty for this reason.
    #[must_use]
    pub fn base_penalty(&self) -> u32 {
        match self {
            ReportReason::Spam => 10,
            ReportReason::Harassment => 30,
            ReportReason::Impersonation => 50,
            ReportReason::Malware => 100,
            ReportReason::Scam => 80,
            ReportReason::Other(_) => 20,
        }
    }
}

/// A negative report filed against an identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NegativeReport {
    /// Unique report identifier.
    pub report_id: [u8; 32],
    /// Identity hash of the reporter.
    pub reporter_id: IdentityHash,
    /// Identity hash of the reported user.
    pub target_id: IdentityHash,
    /// Reporter's reputation at time of report.
    pub reporter_reputation: u32,
    /// Reason for the report.
    pub reason: ReportReason,
    /// Optional hash of evidence (e.g., message hash).
    pub evidence_hash: Option<[u8; 32]>,
    /// When the report was filed.
    pub timestamp: DateTime<Utc>,
}

impl NegativeReport {
    /// Create a new negative report.
    pub fn new(
        reporter_id: IdentityHash,
        target_id: IdentityHash,
        reporter_reputation: u32,
        reason: ReportReason,
        evidence_hash: Option<[u8; 32]>,
    ) -> Result<Self> {
        // REP-FIX-9: Prevent self-reporting
        if reporter_id == target_id {
            return Err(ReputationError::InvalidReport(
                "Cannot report yourself".to_string(),
            ));
        }

        // Validate reporter has enough reputation
        if reporter_reputation < MIN_REPORTER_REPUTATION {
            return Err(ReputationError::InsufficientReputation {
                required: MIN_REPORTER_REPUTATION,
                actual: reporter_reputation,
            });
        }

        // Generate random report ID
        let mut report_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut report_id);

        Ok(Self {
            report_id,
            reporter_id,
            target_id,
            reporter_reputation,
            reason,
            evidence_hash,
            timestamp: Utc::now(),
        })
    }

    /// Calculate the weight of this report based on reporter reputation.
    /// Rep 500 = weight 1.0, Rep 800 = weight 1.6, Rep 300 = weight 0.6
    #[must_use]
    pub fn weight(&self) -> f32 {
        self.reporter_reputation as f32 / 500.0
    }
}

/// Aggregates reports against identities and calculates penalties.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReportAggregator {
    /// Reports per target identity.
    reports: HashMap<IdentityHash, Vec<NegativeReport>>,
}

impl ReportAggregator {
    /// Create a new report aggregator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            reports: HashMap::new(),
        }
    }

    /// Add a report for a target identity.
    ///
    /// Returns error if reporter reputation is too low.
    pub fn add_report(&mut self, report: NegativeReport) -> Result<()> {
        // Double-check reporter reputation
        if report.reporter_reputation < MIN_REPORTER_REPUTATION {
            return Err(ReputationError::InsufficientReputation {
                required: MIN_REPORTER_REPUTATION,
                actual: report.reporter_reputation,
            });
        }

        // Check for duplicate reporter (one report per reporter per target)
        let reports = self.reports.entry(report.target_id).or_default();
        if reports.iter().any(|r| r.reporter_id == report.reporter_id) {
            return Err(ReputationError::InvalidReport(
                "Already reported by this identity".to_string(),
            ));
        }

        reports.push(report);
        Ok(())
    }

    /// Get the weighted count of reports for a target.
    #[must_use]
    pub fn get_weighted_count(&self, target_id: &IdentityHash) -> f32 {
        self.reports
            .get(target_id)
            .map(|reports| reports.iter().map(|r| r.weight()).sum())
            .unwrap_or(0.0)
    }

    /// Check if the weighted report count exceeds the threshold.
    #[must_use]
    pub fn should_penalize(&self, target_id: &IdentityHash) -> bool {
        self.get_weighted_count(target_id) >= NEGATIVE_REPORT_THRESHOLD
    }

    /// Calculate the penalty for a target based on reports.
    ///
    /// Returns (penalty_amount, primary_reason) or None if no penalty.
    #[must_use]
    pub fn get_penalty(&self, target_id: &IdentityHash) -> Option<(u32, ReportReason)> {
        let reports = self.reports.get(target_id)?;
        if reports.is_empty() {
            return None;
        }

        let weighted_count = self.get_weighted_count(target_id);
        if weighted_count < NEGATIVE_REPORT_THRESHOLD {
            return None;
        }

        // Find the most severe reason (highest base penalty)
        let primary_reason = reports
            .iter()
            .max_by_key(|r| r.reason.base_penalty())
            .map(|r| r.reason.clone())?;

        // Calculate penalty: base_penalty * (weighted_count / threshold)
        // Cap at 200 points per incident
        let base = primary_reason.base_penalty();
        let multiplier = weighted_count / NEGATIVE_REPORT_THRESHOLD;
        let penalty = ((base as f32) * multiplier).min(200.0) as u32;

        Some((penalty, primary_reason))
    }

    /// Get all reports for a target.
    #[must_use]
    pub fn get_reports(&self, target_id: &IdentityHash) -> Option<&Vec<NegativeReport>> {
        self.reports.get(target_id)
    }

    /// Get the number of raw (unweighted) reports for a target.
    #[must_use]
    pub fn get_report_count(&self, target_id: &IdentityHash) -> usize {
        self.reports.get(target_id).map(|r| r.len()).unwrap_or(0)
    }

    /// Clear reports for a target (after penalty applied).
    pub fn clear_reports_for(&mut self, target_id: &IdentityHash) {
        self.reports.remove(target_id);
    }

    /// Get all targets with pending reports.
    #[must_use]
    pub fn get_targets_with_reports(&self) -> Vec<IdentityHash> {
        self.reports.keys().copied().collect()
    }

    /// Clean up old reports (older than 30 days).
    pub fn cleanup_old_reports(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::days(30);
        for reports in self.reports.values_mut() {
            reports.retain(|r| r.timestamp > cutoff);
        }
        self.reports.retain(|_, reports| !reports.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_identity(n: u8) -> IdentityHash {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_report_weight_calculation() {
        let reporter = make_identity(1);
        let target = make_identity(2);

        // Rep 500 = weight 1.0
        let report = NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
        assert!((report.weight() - 1.0).abs() < 0.001);

        // Rep 800 = weight 1.6
        let report = NegativeReport::new(reporter, target, 800, ReportReason::Spam, None).unwrap();
        assert!((report.weight() - 1.6).abs() < 0.001);

        // Rep 400 = weight 0.8 (minimum)
        let report = NegativeReport::new(reporter, target, 400, ReportReason::Spam, None).unwrap();
        assert!((report.weight() - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_report_requires_min_reputation() {
        let reporter = make_identity(1);
        let target = make_identity(2);

        let result = NegativeReport::new(reporter, target, 300, ReportReason::Spam, None);
        assert!(matches!(
            result,
            Err(ReputationError::InsufficientReputation { .. })
        ));
    }

    #[test]
    fn test_aggregator_weighted_count() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // Add reports from 3 different reporters
        for i in 1..=3 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
            aggregator.add_report(report).unwrap();
        }

        // 3 reports * weight 1.0 = 3.0
        assert!((aggregator.get_weighted_count(&target) - 3.0).abs() < 0.001);
    }

    #[test]
    fn test_aggregator_should_penalize() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // 2 reports not enough
        for i in 1..=2 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
            aggregator.add_report(report).unwrap();
        }
        assert!(!aggregator.should_penalize(&target));

        // 3rd report triggers penalty
        let reporter = make_identity(3);
        let report = NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
        aggregator.add_report(report).unwrap();
        assert!(aggregator.should_penalize(&target));
    }

    #[test]
    fn test_aggregator_high_rep_reporters() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // 2 high-rep reporters (800 each = 1.6 weight)
        for i in 1..=2 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 800, ReportReason::Spam, None).unwrap();
            aggregator.add_report(report).unwrap();
        }

        // 2 * 1.6 = 3.2, should trigger penalty
        assert!(aggregator.should_penalize(&target));
    }

    #[test]
    fn test_penalty_calculation() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // Add 3 spam reports
        for i in 1..=3 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
            aggregator.add_report(report).unwrap();
        }

        let (penalty, reason) = aggregator.get_penalty(&target).unwrap();
        assert_eq!(reason, ReportReason::Spam);
        // Spam base = 10, weighted_count = 3.0, penalty = 10 * (3.0/3.0) = 10
        assert_eq!(penalty, 10);
    }

    #[test]
    fn test_most_severe_reason_used() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // Mix of reasons
        let r1 = make_identity(1);
        aggregator
            .add_report(NegativeReport::new(r1, target, 500, ReportReason::Spam, None).unwrap())
            .unwrap();

        let r2 = make_identity(2);
        aggregator
            .add_report(NegativeReport::new(r2, target, 500, ReportReason::Malware, None).unwrap())
            .unwrap();

        let r3 = make_identity(3);
        aggregator
            .add_report(
                NegativeReport::new(r3, target, 500, ReportReason::Harassment, None).unwrap(),
            )
            .unwrap();

        let (_, reason) = aggregator.get_penalty(&target).unwrap();
        // Malware has highest base penalty (100)
        assert_eq!(reason, ReportReason::Malware);
    }

    #[test]
    fn test_no_duplicate_reporters() {
        let mut aggregator = ReportAggregator::new();
        let reporter = make_identity(1);
        let target = make_identity(10);

        let report1 = NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
        aggregator.add_report(report1).unwrap();

        let report2 =
            NegativeReport::new(reporter, target, 500, ReportReason::Harassment, None).unwrap();
        let result = aggregator.add_report(report2);
        assert!(matches!(result, Err(ReputationError::InvalidReport(_))));
    }

    #[test]
    fn test_clear_reports() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        let reporter = make_identity(1);
        let report = NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
        aggregator.add_report(report).unwrap();

        assert_eq!(aggregator.get_report_count(&target), 1);
        aggregator.clear_reports_for(&target);
        assert_eq!(aggregator.get_report_count(&target), 0);
    }

    #[test]
    fn test_penalty_capped_at_200() {
        let mut aggregator = ReportAggregator::new();
        // REP-FIX-9: Use ID 0 for target so it never collides with reporter IDs (1..=10)
        let target = make_identity(0);

        // Add many high-rep malware reports
        for i in 1..=10 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 1000, ReportReason::Malware, None).unwrap();
            aggregator.add_report(report).unwrap();
        }

        let (penalty, _) = aggregator.get_penalty(&target).unwrap();
        assert!(penalty <= 200);
    }
}
