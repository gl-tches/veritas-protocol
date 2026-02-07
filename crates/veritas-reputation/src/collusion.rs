//! Collusion detection via interaction graph analysis.

use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Suspicion threshold for cluster detection (70%).
pub const CLUSTER_SUSPICION_THRESHOLD: f32 = 0.7;

/// Minimum cluster size to analyze.
pub const MIN_CLUSTER_SIZE: usize = 3;

/// Identity hash type (32 bytes).
pub type IdentityHash = [u8; 32];

/// Records an interaction between two identities.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InteractionRecord {
    /// Identity sending positive interaction.
    pub from: IdentityHash,
    /// Identity receiving positive interaction.
    pub to: IdentityHash,
    /// Number of interactions.
    pub count: u32,
    /// When first interaction occurred.
    pub first_seen: DateTime<Utc>,
    /// When most recent interaction occurred.
    pub last_seen: DateTime<Utc>,
}

impl InteractionRecord {
    /// Create a new interaction record.
    fn new(from: IdentityHash, to: IdentityHash) -> Self {
        let now = Utc::now();
        Self {
            from,
            to,
            count: 1,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Increment the interaction count.
    fn increment(&mut self) {
        self.count = self.count.saturating_add(1);
        self.last_seen = Utc::now();
    }
}

/// A member of a suspicious cluster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClusterMember {
    /// The identity hash.
    pub identity: IdentityHash,
    /// Number of connections within the cluster.
    pub internal_connections: u32,
    /// Number of connections outside the cluster.
    pub external_connections: u32,
    /// This member's contribution to suspicion.
    pub suspicion_contribution: f32,
}

/// A detected suspicious cluster.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuspiciousCluster {
    /// Unique cluster identifier.
    pub cluster_id: [u8; 32],
    /// Members of the cluster.
    pub members: Vec<ClusterMember>,
    /// Ratio of internal to total connections (0.0-1.0).
    pub internal_density: f32,
    /// How symmetric interactions are (0.0-1.0, 1.0 = perfectly symmetric).
    pub symmetry_score: f32,
    /// Combined suspicion score (0.0-1.0).
    pub suspicion_score: f32,
    /// When this cluster was detected.
    pub detected_at: DateTime<Utc>,
}

impl SuspiciousCluster {
    /// Get the gain multiplier for members of this cluster.
    /// suspicion 0.0 = 100% gains, suspicion 0.8 = 20% gains
    #[must_use]
    pub fn gain_multiplier(&self) -> f32 {
        (1.0 - self.suspicion_score).max(0.0)
    }

    /// Check if an identity is in this cluster.
    #[must_use]
    pub fn contains(&self, identity: &IdentityHash) -> bool {
        self.members.iter().any(|m| &m.identity == identity)
    }
}

/// Detects collusion through graph analysis of interactions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CollusionDetector {
    /// Interaction graph: (from, to) -> record.
    interactions: HashMap<(IdentityHash, IdentityHash), InteractionRecord>,
    /// Detected suspicious clusters.
    suspicious_clusters: Vec<SuspiciousCluster>,
    /// Identity to cluster mapping for quick lookup.
    identity_clusters: HashMap<IdentityHash, usize>,
}

impl CollusionDetector {
    /// Create a new collusion detector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interactions: HashMap::new(),
            suspicious_clusters: Vec::new(),
            identity_clusters: HashMap::new(),
        }
    }

    /// Record a positive interaction between two identities.
    pub fn record_interaction(&mut self, from: IdentityHash, to: IdentityHash) {
        let key = (from, to);
        self.interactions
            .entry(key)
            .and_modify(|r| r.increment())
            .or_insert_with(|| InteractionRecord::new(from, to));
    }

    /// Get all identities that have interacted with the given identity.
    fn get_neighbors(&self, identity: &IdentityHash) -> HashSet<IdentityHash> {
        let mut neighbors = HashSet::new();

        for (from, to) in self.interactions.keys() {
            if from == identity {
                neighbors.insert(*to);
            }
            if to == identity {
                neighbors.insert(*from);
            }
        }

        neighbors
    }

    /// Get the interaction count between two identities (bidirectional).
    fn get_interaction_count(&self, a: &IdentityHash, b: &IdentityHash) -> u32 {
        let ab = self
            .interactions
            .get(&(*a, *b))
            .map(|r| r.count)
            .unwrap_or(0);
        let ba = self
            .interactions
            .get(&(*b, *a))
            .map(|r| r.count)
            .unwrap_or(0);
        ab + ba
    }

    /// Calculate symmetry score between two identities.
    /// 1.0 = perfectly symmetric (equal A->B and B->A)
    fn calculate_symmetry(&self, a: &IdentityHash, b: &IdentityHash) -> f32 {
        let ab = self
            .interactions
            .get(&(*a, *b))
            .map(|r| r.count)
            .unwrap_or(0) as f32;
        let ba = self
            .interactions
            .get(&(*b, *a))
            .map(|r| r.count)
            .unwrap_or(0) as f32;

        if ab == 0.0 && ba == 0.0 {
            return 0.0;
        }

        let min = ab.min(ba);
        let max = ab.max(ba);

        if max == 0.0 { 0.0 } else { min / max }
    }

    /// Find connected components in the interaction graph.
    fn find_connected_components(&self) -> Vec<HashSet<IdentityHash>> {
        let mut visited = HashSet::new();
        let mut components = Vec::new();

        // Get all unique identities
        let mut all_identities = HashSet::new();
        for (from, to) in self.interactions.keys() {
            all_identities.insert(*from);
            all_identities.insert(*to);
        }

        for identity in all_identities {
            if visited.contains(&identity) {
                continue;
            }

            // BFS to find connected component
            let mut component = HashSet::new();
            let mut queue = vec![identity];

            while let Some(current) = queue.pop() {
                if visited.contains(&current) {
                    continue;
                }

                visited.insert(current);
                component.insert(current);

                for neighbor in self.get_neighbors(&current) {
                    if !visited.contains(&neighbor) {
                        queue.push(neighbor);
                    }
                }
            }

            if component.len() >= MIN_CLUSTER_SIZE {
                components.push(component);
            }
        }

        components
    }

    /// Analyze a component for suspicious patterns.
    fn analyze_component(&self, members: &HashSet<IdentityHash>) -> Option<SuspiciousCluster> {
        if members.len() < MIN_CLUSTER_SIZE {
            return None;
        }

        let members_vec: Vec<_> = members.iter().copied().collect();
        let mut cluster_members = Vec::new();

        let mut total_internal_edges = 0u32;
        let mut total_external_edges = 0u32;
        let mut total_symmetry = 0.0f32;
        let mut symmetry_count = 0u32;

        for identity in &members_vec {
            let neighbors = self.get_neighbors(identity);

            let mut internal = 0u32;
            let mut external = 0u32;

            for neighbor in neighbors {
                let count = self.get_interaction_count(identity, &neighbor);
                if members.contains(&neighbor) {
                    internal += count;
                    total_internal_edges += count;

                    // Calculate symmetry for internal edges
                    let sym = self.calculate_symmetry(identity, &neighbor);
                    total_symmetry += sym;
                    symmetry_count += 1;
                } else {
                    external += count;
                    total_external_edges += count;
                }
            }

            cluster_members.push(ClusterMember {
                identity: *identity,
                internal_connections: internal,
                external_connections: external,
                suspicion_contribution: 0.0, // Will be calculated later
            });
        }

        // Calculate metrics
        // Internal edges are counted twice (once for each direction)
        let internal_edges = total_internal_edges / 2;
        let total_edges = internal_edges + total_external_edges;

        if total_edges == 0 {
            return None;
        }

        let internal_density = internal_edges as f32 / total_edges as f32;
        let symmetry_score = if symmetry_count > 0 {
            total_symmetry / symmetry_count as f32
        } else {
            0.0
        };

        let external_ratio = total_external_edges as f32 / total_edges as f32;

        // Calculate suspicion score
        // High internal density, high symmetry, low external connections = suspicious
        let density_factor = if internal_density > CLUSTER_SUSPICION_THRESHOLD {
            (internal_density - CLUSTER_SUSPICION_THRESHOLD) / (1.0 - CLUSTER_SUSPICION_THRESHOLD)
        } else {
            0.0
        };

        let symmetry_factor = if symmetry_score > 0.8 {
            (symmetry_score - 0.8) / 0.2
        } else {
            0.0
        };

        let external_factor = if external_ratio < 0.3 {
            (0.3 - external_ratio) / 0.3
        } else {
            0.0
        };

        let suspicion_score =
            (density_factor * 0.4 + symmetry_factor * 0.3 + external_factor * 0.3).clamp(0.0, 1.0);

        // Only flag clusters with significant suspicion
        if suspicion_score < 0.3 {
            return None;
        }

        // Update member suspicion contributions
        for member in &mut cluster_members {
            let total = member.internal_connections + member.external_connections;
            if total > 0 {
                member.suspicion_contribution =
                    member.internal_connections as f32 / total as f32 * suspicion_score;
            }
        }

        let mut cluster_id = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut cluster_id);

        Some(SuspiciousCluster {
            cluster_id,
            members: cluster_members,
            internal_density,
            symmetry_score,
            suspicion_score,
            detected_at: Utc::now(),
        })
    }

    /// Run cluster analysis on all interactions.
    pub fn analyze_clusters(&mut self) {
        self.suspicious_clusters.clear();
        self.identity_clusters.clear();

        let components = self.find_connected_components();

        for component in components.iter() {
            if let Some(cluster) = self.analyze_component(component) {
                // Use the actual index within suspicious_clusters, not the component index.
                // Previously, using the component enumeration index caused lookups to return
                // None when non-suspicious components offset the indices.
                let cluster_idx = self.suspicious_clusters.len();
                // Map identities to cluster index
                for member in &cluster.members {
                    self.identity_clusters.insert(member.identity, cluster_idx);
                }
                self.suspicious_clusters.push(cluster);
            }
        }
    }

    /// Get the suspicion penalty multiplier for an identity.
    /// Returns 1.0 if not in a suspicious cluster.
    #[must_use]
    pub fn get_suspicion_penalty(&self, identity: &IdentityHash) -> f32 {
        if let Some(&cluster_idx) = self.identity_clusters.get(identity) {
            if let Some(cluster) = self.suspicious_clusters.get(cluster_idx) {
                return cluster.gain_multiplier();
            }
        }
        1.0 // No penalty
    }

    /// Check if an identity is in a suspicious cluster.
    #[must_use]
    pub fn is_in_suspicious_cluster(&self, identity: &IdentityHash) -> bool {
        self.identity_clusters.contains_key(identity)
    }

    /// Get the suspicious cluster an identity belongs to.
    #[must_use]
    pub fn get_cluster_for(&self, identity: &IdentityHash) -> Option<&SuspiciousCluster> {
        self.identity_clusters
            .get(identity)
            .and_then(|&idx| self.suspicious_clusters.get(idx))
    }

    /// Get all detected suspicious clusters.
    #[must_use]
    pub fn get_suspicious_clusters(&self) -> &[SuspiciousCluster] {
        &self.suspicious_clusters
    }

    /// Get the number of tracked interactions.
    #[must_use]
    pub fn interaction_count(&self) -> usize {
        self.interactions.len()
    }

    /// Clean up old interactions (older than 30 days).
    pub fn cleanup_old_interactions(&mut self) {
        let cutoff = Utc::now() - Duration::days(30);
        self.interactions.retain(|_, r| r.last_seen > cutoff);
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
    fn test_record_interaction() {
        let mut detector = CollusionDetector::new();
        let a = make_identity(1);
        let b = make_identity(2);

        detector.record_interaction(a, b);
        assert_eq!(detector.interaction_count(), 1);

        detector.record_interaction(a, b);
        assert_eq!(detector.interaction_count(), 1); // Same pair, just incremented

        let key = (a, b);
        assert_eq!(detector.interactions.get(&key).unwrap().count, 2);
    }

    #[test]
    fn test_get_neighbors() {
        let mut detector = CollusionDetector::new();
        let a = make_identity(1);
        let b = make_identity(2);
        let c = make_identity(3);

        detector.record_interaction(a, b);
        detector.record_interaction(a, c);

        let neighbors = detector.get_neighbors(&a);
        assert!(neighbors.contains(&b));
        assert!(neighbors.contains(&c));
        assert_eq!(neighbors.len(), 2);
    }

    #[test]
    fn test_symmetry_calculation() {
        let mut detector = CollusionDetector::new();
        let a = make_identity(1);
        let b = make_identity(2);

        // Perfect symmetry
        detector.record_interaction(a, b);
        detector.record_interaction(b, a);
        let sym = detector.calculate_symmetry(&a, &b);
        assert!((sym - 1.0).abs() < 0.001);

        // Asymmetric
        detector.record_interaction(a, b);
        detector.record_interaction(a, b);
        let sym = detector.calculate_symmetry(&a, &b);
        assert!(sym < 1.0);
    }

    #[test]
    fn test_no_cluster_for_small_groups() {
        let mut detector = CollusionDetector::new();
        let a = make_identity(1);
        let b = make_identity(2);

        // Only 2 identities - too small
        detector.record_interaction(a, b);
        detector.record_interaction(b, a);

        detector.analyze_clusters();
        assert!(detector.suspicious_clusters.is_empty());
    }

    #[test]
    fn test_suspicious_cluster_detection() {
        let mut detector = CollusionDetector::new();

        // Create a tight cluster of 4 identities
        let ids: Vec<_> = (1..=4).map(make_identity).collect();

        // Everyone interacts with everyone (high internal density)
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    // Multiple symmetric interactions
                    for _ in 0..10 {
                        detector.record_interaction(ids[i], ids[j]);
                    }
                }
            }
        }

        detector.analyze_clusters();

        // Should detect this as suspicious
        assert!(!detector.suspicious_clusters.is_empty());

        let cluster = &detector.suspicious_clusters[0];
        assert!(cluster.internal_density > CLUSTER_SUSPICION_THRESHOLD);
    }

    #[test]
    fn test_gain_multiplier() {
        let cluster = SuspiciousCluster {
            cluster_id: [0u8; 32],
            members: vec![],
            internal_density: 0.9,
            symmetry_score: 0.95,
            suspicion_score: 0.8,
            detected_at: Utc::now(),
        };

        // 0.8 suspicion = 0.2 gain multiplier
        assert!((cluster.gain_multiplier() - 0.2).abs() < 0.001);
    }

    #[test]
    fn test_is_in_suspicious_cluster() {
        let mut detector = CollusionDetector::new();

        // Create suspicious cluster
        let ids: Vec<_> = (1..=4).map(make_identity).collect();
        for i in 0..4 {
            for j in 0..4 {
                if i != j {
                    for _ in 0..10 {
                        detector.record_interaction(ids[i], ids[j]);
                    }
                }
            }
        }

        // Add an outside identity with minimal connections
        let outsider = make_identity(99);
        detector.record_interaction(outsider, ids[0]);

        detector.analyze_clusters();

        // Check membership
        if !detector.suspicious_clusters.is_empty() {
            for id in &ids {
                assert!(detector.is_in_suspicious_cluster(id));
            }
        }
    }

    #[test]
    fn test_get_suspicion_penalty() {
        let detector = CollusionDetector::new();
        let clean = make_identity(99);

        // Clean identity has no penalty
        assert!((detector.get_suspicion_penalty(&clean) - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_collusion_cluster_index_mapping_with_non_suspicious_components() {
        let mut detector = CollusionDetector::new();

        // Create a non-suspicious component first (3 nodes, sparse interactions)
        // These nodes interact lightly and with many external connections
        let non_suspicious: Vec<_> = (50..=52).map(make_identity).collect();
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    detector.record_interaction(non_suspicious[i], non_suspicious[j]);
                }
            }
        }
        // Add many external connections to make this component non-suspicious
        for ext in 60..70 {
            let ext_id = make_identity(ext);
            for ns in &non_suspicious {
                for _ in 0..5 {
                    detector.record_interaction(*ns, ext_id);
                    detector.record_interaction(ext_id, *ns);
                }
            }
        }

        // Create a suspicious cluster of 5+ nodes with dense mutual interactions
        let suspicious: Vec<_> = (1..=6).map(make_identity).collect();
        for i in 0..6 {
            for j in 0..6 {
                if i != j {
                    for _ in 0..20 {
                        detector.record_interaction(suspicious[i], suspicious[j]);
                    }
                }
            }
        }

        detector.analyze_clusters();

        // The suspicious cluster should be detected
        assert!(
            !detector.suspicious_clusters.is_empty(),
            "Should detect at least one suspicious cluster"
        );

        // All suspicious nodes should be mapped correctly via is_in_suspicious_cluster
        for id in &suspicious {
            assert!(
                detector.is_in_suspicious_cluster(id),
                "Suspicious node should be in a suspicious cluster"
            );
        }

        // get_cluster_for should return the correct cluster for suspicious nodes
        for id in &suspicious {
            let cluster = detector.get_cluster_for(id);
            assert!(
                cluster.is_some(),
                "get_cluster_for should return a cluster for suspicious nodes"
            );
            let cluster = cluster.unwrap();
            assert!(
                cluster.contains(id),
                "Returned cluster should contain the queried identity"
            );
        }

        // get_suspicion_penalty should return a penalty < 1.0 for suspicious nodes
        for id in &suspicious {
            let penalty = detector.get_suspicion_penalty(id);
            assert!(
                penalty < 1.0,
                "Suspicious nodes should have a penalty multiplier < 1.0, got {}",
                penalty
            );
        }
    }

    #[test]
    fn test_five_node_dense_collusion_detected() {
        let mut detector = CollusionDetector::new();

        // Create exactly 5 nodes with dense mutual interactions (collusion pattern)
        let ids: Vec<_> = (1..=5).map(make_identity).collect();
        for i in 0..5 {
            for j in 0..5 {
                if i != j {
                    // Many symmetric interactions
                    for _ in 0..15 {
                        detector.record_interaction(ids[i], ids[j]);
                    }
                }
            }
        }

        detector.analyze_clusters();

        // Should detect as suspicious
        assert!(
            !detector.suspicious_clusters.is_empty(),
            "5 nodes with dense mutual interactions should be flagged as suspicious"
        );

        // All nodes should be in a suspicious cluster
        for id in &ids {
            assert!(
                detector.is_in_suspicious_cluster(id),
                "Each node in the collusion ring should be flagged"
            );
        }

        // The cluster should have high internal density
        let cluster = detector.get_cluster_for(&ids[0]).unwrap();
        assert!(
            cluster.internal_density > CLUSTER_SUSPICION_THRESHOLD,
            "Collusion cluster should have density above threshold"
        );
    }
}
