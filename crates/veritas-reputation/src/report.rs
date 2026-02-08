//! Weighted negative report handling.

use chrono::{DateTime, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{ReputationError, Result};

/// Evidence strength levels for reports.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceStrength {
    /// No evidence provided.
    None,
    /// Hash reference only (e.g., message hash).
    HashReference,
    /// Multiple corroborating hashes.
    MultipleReferences,
    /// Cryptographic proof (e.g., signed evidence).
    CryptographicProof,
}

impl EvidenceStrength {
    /// Get the weight multiplier for this evidence strength.
    pub fn weight_multiplier(&self) -> f32 {
        match self {
            EvidenceStrength::None => 0.5,
            EvidenceStrength::HashReference => 1.0,
            EvidenceStrength::MultipleReferences => 1.3,
            EvidenceStrength::CryptographicProof => 1.5,
        }
    }
}

/// Batch report detection window (1 hour).
pub const BATCH_REPORT_WINDOW_SECS: i64 = 3600;

/// Minimum reports in batch window to flag as coordinated.
pub const MIN_BATCH_REPORTS: usize = 5;

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
    /// Strength of evidence provided.
    pub evidence_strength: EvidenceStrength,
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

        let evidence_strength = if evidence_hash.is_some() {
            EvidenceStrength::HashReference
        } else {
            EvidenceStrength::None
        };

        Ok(Self {
            report_id,
            reporter_id,
            target_id,
            reporter_reputation,
            reason,
            evidence_hash,
            evidence_strength,
            timestamp: Utc::now(),
        })
    }

    /// Set the evidence strength for this report.
    pub fn with_evidence_strength(mut self, strength: EvidenceStrength) -> Self {
        self.evidence_strength = strength;
        self
    }

    /// Calculate the weight of this report based on reporter reputation and evidence strength.
    /// Rep 500 = weight 1.0 (before evidence multiplier)
    #[must_use]
    pub fn weight(&self) -> f32 {
        let rep_weight = self.reporter_reputation as f32 / 500.0;
        rep_weight * self.evidence_strength.weight_multiplier()
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

    /// Detect coordinated batch reporting (many reports in short window).
    ///
    /// Returns targets that received >= MIN_BATCH_REPORTS in the last hour.
    pub fn detect_batch_reports(&self) -> Vec<(IdentityHash, usize)> {
        let cutoff = Utc::now() - chrono::Duration::seconds(BATCH_REPORT_WINDOW_SECS);
        let mut batches = Vec::new();

        for (target, reports) in &self.reports {
            let recent_count = reports.iter().filter(|r| r.timestamp > cutoff).count();
            if recent_count >= MIN_BATCH_REPORTS {
                batches.push((*target, recent_count));
            }
        }

        batches
    }

    /// Check if a target is subject to coordinated reporting.
    pub fn is_batch_reported(&self, target_id: &IdentityHash) -> bool {
        let cutoff = Utc::now() - chrono::Duration::seconds(BATCH_REPORT_WINDOW_SECS);
        self.reports
            .get(target_id)
            .map(|reports| {
                reports.iter().filter(|r| r.timestamp > cutoff).count() >= MIN_BATCH_REPORTS
            })
            .unwrap_or(false)
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
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // Rep 500 = weight 1.0 (with hash evidence)
        let report =
            NegativeReport::new(reporter, target, 500, ReportReason::Spam, evidence).unwrap();
        assert!((report.weight() - 1.0).abs() < 0.001);

        // Rep 800 = weight 1.6 (with hash evidence)
        let report =
            NegativeReport::new(reporter, target, 800, ReportReason::Spam, evidence).unwrap();
        assert!((report.weight() - 1.6).abs() < 0.001);

        // Rep 400 = weight 0.8 (with hash evidence, minimum rep)
        let report =
            NegativeReport::new(reporter, target, 400, ReportReason::Spam, evidence).unwrap();
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
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // Add reports from 3 different reporters
        for i in 1..=3 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, evidence).unwrap();
            aggregator.add_report(report).unwrap();
        }

        // 3 reports * weight 1.0 = 3.0
        assert!((aggregator.get_weighted_count(&target) - 3.0).abs() < 0.001);
    }

    #[test]
    fn test_aggregator_should_penalize() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // 2 reports not enough
        for i in 1..=2 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, evidence).unwrap();
            aggregator.add_report(report).unwrap();
        }
        assert!(!aggregator.should_penalize(&target));

        // 3rd report triggers penalty
        let reporter = make_identity(3);
        let report =
            NegativeReport::new(reporter, target, 500, ReportReason::Spam, evidence).unwrap();
        aggregator.add_report(report).unwrap();
        assert!(aggregator.should_penalize(&target));
    }

    #[test]
    fn test_aggregator_high_rep_reporters() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // 2 high-rep reporters (800 each = 1.6 weight with hash evidence)
        for i in 1..=2 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 800, ReportReason::Spam, evidence).unwrap();
            aggregator.add_report(report).unwrap();
        }

        // 2 * 1.6 = 3.2, should trigger penalty
        assert!(aggregator.should_penalize(&target));
    }

    #[test]
    fn test_penalty_calculation() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // Add 3 spam reports with evidence
        for i in 1..=3 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, evidence).unwrap();
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
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // Mix of reasons
        let r1 = make_identity(1);
        aggregator
            .add_report(
                NegativeReport::new(r1, target, 500, ReportReason::Spam, evidence).unwrap(),
            )
            .unwrap();

        let r2 = make_identity(2);
        aggregator
            .add_report(
                NegativeReport::new(r2, target, 500, ReportReason::Malware, evidence).unwrap(),
            )
            .unwrap();

        let r3 = make_identity(3);
        aggregator
            .add_report(
                NegativeReport::new(r3, target, 500, ReportReason::Harassment, evidence).unwrap(),
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
    fn test_evidence_strength_weight() {
        assert!((EvidenceStrength::None.weight_multiplier() - 0.5).abs() < 0.001);
        assert!((EvidenceStrength::HashReference.weight_multiplier() - 1.0).abs() < 0.001);
        assert!((EvidenceStrength::MultipleReferences.weight_multiplier() - 1.3).abs() < 0.001);
        assert!((EvidenceStrength::CryptographicProof.weight_multiplier() - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_report_weight_with_evidence() {
        let reporter = make_identity(1);
        let target = make_identity(2);

        // No evidence: 500 rep * 0.5 evidence = 0.5 weight
        let report = NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
        assert!((report.weight() - 0.5).abs() < 0.001);

        // Hash evidence: 500 rep * 1.0 evidence = 1.0 weight
        let report_with_evidence =
            NegativeReport::new(reporter, target, 500, ReportReason::Spam, Some([0xAA; 32]))
                .unwrap();
        assert!((report_with_evidence.weight() - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_batch_report_detection() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // Add 5+ reports (batch)
        for i in 1..=6 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
            aggregator.add_report(report).unwrap();
        }

        let batches = aggregator.detect_batch_reports();
        assert!(!batches.is_empty());
        assert!(aggregator.is_batch_reported(&target));
    }

    #[test]
    fn test_not_batch_reported_with_few() {
        let mut aggregator = ReportAggregator::new();
        let target = make_identity(10);

        // Only 2 reports - not a batch
        for i in 1..=2 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 500, ReportReason::Spam, None).unwrap();
            aggregator.add_report(report).unwrap();
        }

        assert!(!aggregator.is_batch_reported(&target));
    }

    #[test]
    fn test_penalty_capped_at_200() {
        let mut aggregator = ReportAggregator::new();
        // REP-FIX-9: Use ID 0 for target so it never collides with reporter IDs (1..=10)
        let target = make_identity(0);
        let evidence = Some([0xBB; 32]); // HashReference evidence (1.0 multiplier)

        // Add many high-rep malware reports
        for i in 1..=10 {
            let reporter = make_identity(i);
            let report =
                NegativeReport::new(reporter, target, 1000, ReportReason::Malware, evidence)
                    .unwrap();
            aggregator.add_report(report).unwrap();
        }

        let (penalty, _) = aggregator.get_penalty(&target).unwrap();
        assert!(penalty <= 200);
    }
}
