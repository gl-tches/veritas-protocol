//! Subnet diversity limiter for DHT eclipse attack prevention.
//!
//! This module implements routing table diversity to prevent eclipse attacks
//! on the Kademlia DHT. By limiting the number of peers from each /24 subnet,
//! we make it significantly harder for attackers to position Sybil nodes to
//! intercept all traffic for specific mailbox keys.
//!
//! ## Eclipse Attack Prevention
//!
//! An eclipse attack occurs when an attacker controls all peers that a victim
//! uses for DHT queries, allowing them to:
//! - Intercept all messages intended for the victim
//! - Prevent legitimate messages from being delivered
//! - Monitor communication patterns
//!
//! By enforcing subnet diversity, we ensure that peers in the routing table
//! come from a variety of network locations, making it much more expensive
//! for an attacker to execute an eclipse attack.
//!
//! ## References
//!
//! - VERITAS-2026-0006: DHT Eclipse Attack vulnerability

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId};
use tracing::{debug, warn};

/// Maximum number of peers allowed per /24 subnet.
///
/// This limit prevents attackers from filling the routing table with
/// Sybil nodes from the same network segment.
pub const MAX_PEERS_PER_SUBNET: usize = 2;

/// Subnet mask size for IPv4 (bits).
///
/// A /24 subnet contains 256 addresses (0-255 in the last octet).
pub const SUBNET_MASK_V4: u8 = 24;

/// Subnet mask size for IPv6 (bits).
///
/// A /48 subnet is commonly used for site prefixes.
pub const SUBNET_MASK_V6: u8 = 48;

/// Minimum reputation score for a peer to be considered trusted.
pub const MIN_TRUSTED_REPUTATION: i64 = 10;

/// Initial reputation score for new peers.
pub const INITIAL_REPUTATION: i64 = 0;

/// Reputation gain for successful DHT operation.
pub const REPUTATION_GAIN_SUCCESS: i64 = 1;

/// Reputation loss for failed DHT operation.
pub const REPUTATION_LOSS_FAILURE: i64 = 5;

/// Reputation loss for suspicious behavior.
pub const REPUTATION_LOSS_SUSPICIOUS: i64 = 20;

/// Maximum reputation score.
pub const MAX_REPUTATION: i64 = 100;

/// Minimum reputation score (can go negative for banning).
pub const MIN_REPUTATION: i64 = -100;

/// Duration to track peer performance (1 hour).
pub const PEER_TRACKING_DURATION: Duration = Duration::from_secs(3600);

/// Result of attempting to add a peer to the routing table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerAcceptResult {
    /// Peer was accepted.
    Accepted,
    /// Peer was rejected due to subnet limit.
    RejectedSubnetLimit {
        /// The subnet that is at capacity.
        subnet: String,
        /// Current count of peers in this subnet.
        current_count: usize,
    },
    /// Peer was rejected due to low reputation.
    RejectedLowReputation {
        /// The peer's current reputation.
        reputation: i64,
    },
    /// Peer was replaced by a higher-reputation peer.
    ReplacedLowerReputation {
        /// The peer that was replaced.
        replaced_peer: PeerId,
    },
    /// Peer is already in the routing table.
    AlreadyPresent,
}

/// Information about a tracked peer.
#[derive(Debug, Clone)]
struct PeerInfo {
    /// The peer's subnet key.
    subnet_key: SubnetKey,
    /// The peer's reputation score.
    reputation: i64,
    /// When this peer was added.
    added_at: Instant,
    /// Number of successful operations.
    successes: u64,
    /// Number of failed operations.
    failures: u64,
}

/// A key representing a subnet (either IPv4 /24 or IPv6 /48).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubnetKey {
    /// IPv4 /24 subnet (first 3 octets).
    V4([u8; 3]),
    /// IPv6 /48 subnet (first 6 bytes).
    V6([u8; 6]),
    /// Unknown or unresolvable subnet.
    Unknown,
}

impl SubnetKey {
    /// Extract a subnet key from an IP address.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                SubnetKey::V4([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(ipv6) => {
                let octets = ipv6.octets();
                SubnetKey::V6([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                ])
            }
        }
    }

    /// Extract a subnet key from a multiaddress.
    ///
    /// Returns `SubnetKey::Unknown` if no IP address can be extracted.
    pub fn from_multiaddr(addr: &Multiaddr) -> Self {
        for protocol in addr.iter() {
            match protocol {
                libp2p::multiaddr::Protocol::Ip4(ipv4) => {
                    return SubnetKey::from_ip(IpAddr::V4(ipv4));
                }
                libp2p::multiaddr::Protocol::Ip6(ipv6) => {
                    return SubnetKey::from_ip(IpAddr::V6(ipv6));
                }
                libp2p::multiaddr::Protocol::Dns(name)
                | libp2p::multiaddr::Protocol::Dns4(name)
                | libp2p::multiaddr::Protocol::Dns6(name) => {
                    // For DNS names, we can't determine subnet without resolution
                    // Treat as unknown for now
                    debug!("Cannot determine subnet for DNS address: {}", name);
                    return SubnetKey::Unknown;
                }
                _ => continue,
            }
        }
        SubnetKey::Unknown
    }
}

impl std::fmt::Display for SubnetKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubnetKey::V4(octets) => write!(f, "{}.{}.{}.0/24", octets[0], octets[1], octets[2]),
            SubnetKey::V6(octets) => write!(
                f,
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5]
            ),
            SubnetKey::Unknown => write!(f, "unknown"),
        }
    }
}

/// Statistics for the subnet limiter.
#[derive(Debug, Default)]
pub struct SubnetLimiterStats {
    /// Total peers accepted.
    pub peers_accepted: AtomicU64,
    /// Total peers rejected due to subnet limit.
    pub peers_rejected_subnet: AtomicU64,
    /// Total peers rejected due to low reputation.
    pub peers_rejected_reputation: AtomicU64,
    /// Total peers replaced.
    pub peers_replaced: AtomicU64,
    /// Total successful operations recorded.
    pub successful_operations: AtomicU64,
    /// Total failed operations recorded.
    pub failed_operations: AtomicU64,
}

impl SubnetLimiterStats {
    /// Create new statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a snapshot of current statistics.
    pub fn snapshot(&self) -> SubnetLimiterStatsSnapshot {
        SubnetLimiterStatsSnapshot {
            peers_accepted: self.peers_accepted.load(Ordering::Relaxed),
            peers_rejected_subnet: self.peers_rejected_subnet.load(Ordering::Relaxed),
            peers_rejected_reputation: self.peers_rejected_reputation.load(Ordering::Relaxed),
            peers_replaced: self.peers_replaced.load(Ordering::Relaxed),
            successful_operations: self.successful_operations.load(Ordering::Relaxed),
            failed_operations: self.failed_operations.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of subnet limiter statistics.
#[derive(Debug, Clone)]
pub struct SubnetLimiterStatsSnapshot {
    /// Total peers accepted.
    pub peers_accepted: u64,
    /// Total peers rejected due to subnet limit.
    pub peers_rejected_subnet: u64,
    /// Total peers rejected due to low reputation.
    pub peers_rejected_reputation: u64,
    /// Total peers replaced.
    pub peers_replaced: u64,
    /// Total successful operations recorded.
    pub successful_operations: u64,
    /// Total failed operations recorded.
    pub failed_operations: u64,
}

/// Configuration for the subnet limiter.
#[derive(Debug, Clone)]
pub struct SubnetLimiterConfig {
    /// Maximum peers per subnet.
    pub max_peers_per_subnet: usize,
    /// Whether to allow unknown subnets.
    pub allow_unknown_subnets: bool,
    /// Maximum peers with unknown subnets.
    pub max_unknown_subnet_peers: usize,
    /// Minimum reputation for acceptance.
    pub min_acceptance_reputation: i64,
    /// Whether to prefer higher-reputation peers when at capacity.
    pub prefer_higher_reputation: bool,
}

impl Default for SubnetLimiterConfig {
    fn default() -> Self {
        Self {
            max_peers_per_subnet: MAX_PEERS_PER_SUBNET,
            allow_unknown_subnets: true,
            max_unknown_subnet_peers: 5,
            min_acceptance_reputation: MIN_REPUTATION,
            prefer_higher_reputation: true,
        }
    }
}

/// Subnet limiter for DHT eclipse attack prevention.
///
/// Tracks peers by subnet and enforces diversity requirements to prevent
/// attackers from dominating the routing table with Sybil nodes.
pub struct SubnetLimiter {
    /// Configuration.
    config: SubnetLimiterConfig,
    /// Peers indexed by subnet.
    subnet_peers: HashMap<SubnetKey, Vec<PeerId>>,
    /// Peer information indexed by peer ID.
    peer_info: HashMap<PeerId, PeerInfo>,
    /// Statistics.
    stats: SubnetLimiterStats,
}

impl SubnetLimiter {
    /// Create a new subnet limiter with default configuration.
    pub fn new() -> Self {
        Self::with_config(SubnetLimiterConfig::default())
    }

    /// Create a new subnet limiter with custom configuration.
    pub fn with_config(config: SubnetLimiterConfig) -> Self {
        Self {
            config,
            subnet_peers: HashMap::new(),
            peer_info: HashMap::new(),
            stats: SubnetLimiterStats::new(),
        }
    }

    /// Check if a peer can be added to the routing table.
    ///
    /// This performs a read-only check without modifying state.
    pub fn can_accept_peer(&self, peer_id: &PeerId, addr: &Multiaddr) -> bool {
        // Already present is fine
        if self.peer_info.contains_key(peer_id) {
            return true;
        }

        let subnet_key = SubnetKey::from_multiaddr(addr);

        // Check unknown subnet limits
        if subnet_key == SubnetKey::Unknown {
            if !self.config.allow_unknown_subnets {
                return false;
            }
            let unknown_count = self
                .subnet_peers
                .get(&SubnetKey::Unknown)
                .map(|v| v.len())
                .unwrap_or(0);
            return unknown_count < self.config.max_unknown_subnet_peers;
        }

        // Check subnet limit
        let subnet_count = self
            .subnet_peers
            .get(&subnet_key)
            .map(|v| v.len())
            .unwrap_or(0);

        subnet_count < self.config.max_peers_per_subnet
    }

    /// Attempt to add a peer to the routing table.
    ///
    /// Returns the result of the attempt, which may include information
    /// about why the peer was rejected or which peer was replaced.
    pub fn try_add_peer(&mut self, peer_id: PeerId, addr: &Multiaddr) -> PeerAcceptResult {
        // Check if already present
        if self.peer_info.contains_key(&peer_id) {
            return PeerAcceptResult::AlreadyPresent;
        }

        let subnet_key = SubnetKey::from_multiaddr(addr);

        // Handle unknown subnets
        if subnet_key == SubnetKey::Unknown {
            if !self.config.allow_unknown_subnets {
                self.stats
                    .peers_rejected_subnet
                    .fetch_add(1, Ordering::Relaxed);
                return PeerAcceptResult::RejectedSubnetLimit {
                    subnet: "unknown".to_string(),
                    current_count: 0,
                };
            }

            let unknown_count = self
                .subnet_peers
                .get(&SubnetKey::Unknown)
                .map(|v| v.len())
                .unwrap_or(0);

            if unknown_count >= self.config.max_unknown_subnet_peers {
                self.stats
                    .peers_rejected_subnet
                    .fetch_add(1, Ordering::Relaxed);
                return PeerAcceptResult::RejectedSubnetLimit {
                    subnet: "unknown".to_string(),
                    current_count: unknown_count,
                };
            }
        }

        // Check subnet limit
        let subnet_peers = self.subnet_peers.entry(subnet_key.clone()).or_default();
        let current_count = subnet_peers.len();

        if current_count >= self.config.max_peers_per_subnet {
            // If we prefer higher reputation, try to find a lower-rep peer to replace
            if self.config.prefer_higher_reputation {
                if let Some(lowest_peer) = self.find_lowest_reputation_peer(&subnet_key) {
                    let lowest_rep = self
                        .peer_info
                        .get(&lowest_peer)
                        .map(|p| p.reputation)
                        .unwrap_or(0);

                    // New peers start at INITIAL_REPUTATION, so only replace if existing is worse
                    if lowest_rep < INITIAL_REPUTATION {
                        self.remove_peer(&lowest_peer);
                        self.add_peer_internal(peer_id, subnet_key);
                        self.stats.peers_replaced.fetch_add(1, Ordering::Relaxed);
                        return PeerAcceptResult::ReplacedLowerReputation {
                            replaced_peer: lowest_peer,
                        };
                    }
                }
            }

            self.stats
                .peers_rejected_subnet
                .fetch_add(1, Ordering::Relaxed);
            return PeerAcceptResult::RejectedSubnetLimit {
                subnet: subnet_key.to_string(),
                current_count,
            };
        }

        // Accept the peer
        self.add_peer_internal(peer_id, subnet_key);
        self.stats.peers_accepted.fetch_add(1, Ordering::Relaxed);
        PeerAcceptResult::Accepted
    }

    /// Internal method to add a peer.
    fn add_peer_internal(&mut self, peer_id: PeerId, subnet_key: SubnetKey) {
        let info = PeerInfo {
            subnet_key: subnet_key.clone(),
            reputation: INITIAL_REPUTATION,
            added_at: Instant::now(),
            successes: 0,
            failures: 0,
        };

        self.subnet_peers
            .entry(subnet_key)
            .or_default()
            .push(peer_id);
        self.peer_info.insert(peer_id, info);

        debug!("Added peer {} to routing table", peer_id);
    }

    /// Find the peer with the lowest reputation in a subnet.
    fn find_lowest_reputation_peer(&self, subnet_key: &SubnetKey) -> Option<PeerId> {
        self.subnet_peers.get(subnet_key).and_then(|peers| {
            peers
                .iter()
                .filter_map(|p| self.peer_info.get(p).map(|info| (p, info.reputation)))
                .min_by_key(|(_, rep)| *rep)
                .map(|(p, _)| *p)
        })
    }

    /// Remove a peer from the routing table.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> bool {
        if let Some(info) = self.peer_info.remove(peer_id) {
            if let Some(peers) = self.subnet_peers.get_mut(&info.subnet_key) {
                peers.retain(|p| p != peer_id);
                if peers.is_empty() {
                    self.subnet_peers.remove(&info.subnet_key);
                }
            }
            debug!("Removed peer {} from routing table", peer_id);
            true
        } else {
            false
        }
    }

    /// Record a successful DHT operation for a peer.
    ///
    /// This increases the peer's reputation score.
    pub fn record_success(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peer_info.get_mut(peer_id) {
            info.successes += 1;
            info.reputation = (info.reputation + REPUTATION_GAIN_SUCCESS).min(MAX_REPUTATION);
            self.stats
                .successful_operations
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                "Recorded success for peer {}, reputation now {}",
                peer_id, info.reputation
            );
        }
    }

    /// Record a failed DHT operation for a peer.
    ///
    /// This decreases the peer's reputation score.
    pub fn record_failure(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peer_info.get_mut(peer_id) {
            info.failures += 1;
            info.reputation = (info.reputation - REPUTATION_LOSS_FAILURE).max(MIN_REPUTATION);
            self.stats.failed_operations.fetch_add(1, Ordering::Relaxed);
            warn!(
                "Recorded failure for peer {}, reputation now {}",
                peer_id, info.reputation
            );
        }
    }

    /// Record suspicious behavior for a peer.
    ///
    /// This significantly decreases the peer's reputation score.
    pub fn record_suspicious(&mut self, peer_id: &PeerId, reason: &str) {
        if let Some(info) = self.peer_info.get_mut(peer_id) {
            info.reputation = (info.reputation - REPUTATION_LOSS_SUSPICIOUS).max(MIN_REPUTATION);
            warn!(
                "Recorded suspicious behavior for peer {}: {}, reputation now {}",
                peer_id, reason, info.reputation
            );
        }
    }

    /// Get the reputation score for a peer.
    pub fn get_reputation(&self, peer_id: &PeerId) -> Option<i64> {
        self.peer_info.get(peer_id).map(|p| p.reputation)
    }

    /// Check if a peer is trusted (has high enough reputation).
    pub fn is_trusted(&self, peer_id: &PeerId) -> bool {
        self.peer_info
            .get(peer_id)
            .map(|p| p.reputation >= MIN_TRUSTED_REPUTATION)
            .unwrap_or(false)
    }

    /// Get the number of peers in a subnet.
    pub fn subnet_peer_count(&self, subnet_key: &SubnetKey) -> usize {
        self.subnet_peers
            .get(subnet_key)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get the total number of tracked peers.
    pub fn total_peer_count(&self) -> usize {
        self.peer_info.len()
    }

    /// Get the number of unique subnets represented.
    pub fn subnet_count(&self) -> usize {
        self.subnet_peers.len()
    }

    /// Get statistics.
    pub fn stats(&self) -> SubnetLimiterStatsSnapshot {
        self.stats.snapshot()
    }

    /// Get peers sorted by reputation (highest first).
    pub fn peers_by_reputation(&self) -> Vec<(PeerId, i64)> {
        let mut peers: Vec<_> = self
            .peer_info
            .iter()
            .map(|(id, info)| (*id, info.reputation))
            .collect();
        peers.sort_by(|a, b| b.1.cmp(&a.1));
        peers
    }

    /// Prune peers that have been tracked for too long with low reputation.
    ///
    /// Returns the number of peers removed.
    pub fn prune_stale_peers(&mut self) -> usize {
        let now = Instant::now();
        let to_remove: Vec<PeerId> = self
            .peer_info
            .iter()
            .filter(|(_, info)| {
                now.duration_since(info.added_at) > PEER_TRACKING_DURATION
                    && info.reputation < INITIAL_REPUTATION
            })
            .map(|(id, _)| *id)
            .collect();

        let count = to_remove.len();
        for peer_id in to_remove {
            self.remove_peer(&peer_id);
        }
        count
    }

    /// Select diverse peers for a DHT query.
    ///
    /// Returns peers from different subnets, preferring higher-reputation peers.
    pub fn select_diverse_peers(&self, count: usize) -> Vec<PeerId> {
        let mut selected = Vec::with_capacity(count);
        let mut used_subnets = std::collections::HashSet::new();

        // First, get highest-reputation peer from each subnet
        let mut subnet_best: Vec<_> = self
            .subnet_peers
            .iter()
            .filter_map(|(subnet, peers)| {
                peers
                    .iter()
                    .filter_map(|p| self.peer_info.get(p).map(|info| (*p, info.reputation)))
                    .max_by_key(|(_, rep)| *rep)
                    .map(|(peer, rep)| (subnet.clone(), peer, rep))
            })
            .collect();

        // Sort by reputation
        subnet_best.sort_by(|a, b| b.2.cmp(&a.2));

        // Take peers from different subnets
        for (subnet, peer, _) in subnet_best {
            if selected.len() >= count {
                break;
            }
            if !used_subnets.contains(&subnet) {
                selected.push(peer);
                used_subnets.insert(subnet);
            }
        }

        selected
    }
}

impl Default for SubnetLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_multiaddr_v4(a: u8, b: u8, c: u8, d: u8) -> Multiaddr {
        format!("/ip4/{}.{}.{}.{}/tcp/9000", a, b, c, d)
            .parse()
            .unwrap()
    }

    fn create_test_peer_id(_seed: u8) -> PeerId {
        use libp2p::identity::Keypair;
        let keypair = Keypair::generate_ed25519();
        PeerId::from(keypair.public())
    }

    #[test]
    fn test_subnet_key_extraction_v4() {
        let addr = create_multiaddr_v4(192, 168, 1, 100);
        let key = SubnetKey::from_multiaddr(&addr);
        assert_eq!(key, SubnetKey::V4([192, 168, 1]));
    }

    #[test]
    fn test_subnet_key_to_string() {
        let key = SubnetKey::V4([192, 168, 1]);
        assert_eq!(key.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_accept_peer_basic() {
        let mut limiter = SubnetLimiter::new();
        let peer1 = create_test_peer_id(1);
        let addr1 = create_multiaddr_v4(192, 168, 1, 100);

        let result = limiter.try_add_peer(peer1, &addr1);
        assert_eq!(result, PeerAcceptResult::Accepted);
        assert_eq!(limiter.total_peer_count(), 1);
    }

    #[test]
    fn test_subnet_limit_enforced() {
        let mut limiter = SubnetLimiter::new();

        // Add MAX_PEERS_PER_SUBNET peers from the same subnet
        for i in 0..MAX_PEERS_PER_SUBNET {
            let peer = create_test_peer_id(i as u8);
            let addr = create_multiaddr_v4(192, 168, 1, 100 + i as u8);
            let result = limiter.try_add_peer(peer, &addr);
            assert_eq!(result, PeerAcceptResult::Accepted);
        }

        // Next peer from same subnet should be rejected
        let peer = create_test_peer_id(100);
        let addr = create_multiaddr_v4(192, 168, 1, 200);
        let result = limiter.try_add_peer(peer, &addr);
        assert!(matches!(
            result,
            PeerAcceptResult::RejectedSubnetLimit { .. }
        ));
    }

    #[test]
    fn test_different_subnets_accepted() {
        let mut limiter = SubnetLimiter::new();

        // Add peers from different subnets
        for i in 0u8..5 {
            let peer = create_test_peer_id(i);
            let addr = create_multiaddr_v4(192, 168, i, 100);
            let result = limiter.try_add_peer(peer, &addr);
            assert_eq!(result, PeerAcceptResult::Accepted);
        }

        assert_eq!(limiter.total_peer_count(), 5);
        assert_eq!(limiter.subnet_count(), 5);
    }

    #[test]
    fn test_reputation_tracking() {
        let mut limiter = SubnetLimiter::new();
        let peer = create_test_peer_id(1);
        let addr = create_multiaddr_v4(192, 168, 1, 100);

        limiter.try_add_peer(peer, &addr);
        assert_eq!(limiter.get_reputation(&peer), Some(INITIAL_REPUTATION));

        // Record successes
        limiter.record_success(&peer);
        limiter.record_success(&peer);
        assert_eq!(
            limiter.get_reputation(&peer),
            Some(INITIAL_REPUTATION + 2 * REPUTATION_GAIN_SUCCESS)
        );

        // Record failure
        limiter.record_failure(&peer);
        assert_eq!(
            limiter.get_reputation(&peer),
            Some(INITIAL_REPUTATION + 2 * REPUTATION_GAIN_SUCCESS - REPUTATION_LOSS_FAILURE)
        );
    }

    #[test]
    fn test_already_present() {
        let mut limiter = SubnetLimiter::new();
        let peer = create_test_peer_id(1);
        let addr = create_multiaddr_v4(192, 168, 1, 100);

        let result1 = limiter.try_add_peer(peer, &addr);
        assert_eq!(result1, PeerAcceptResult::Accepted);

        let result2 = limiter.try_add_peer(peer, &addr);
        assert_eq!(result2, PeerAcceptResult::AlreadyPresent);
    }

    #[test]
    fn test_remove_peer() {
        let mut limiter = SubnetLimiter::new();
        let peer = create_test_peer_id(1);
        let addr = create_multiaddr_v4(192, 168, 1, 100);

        limiter.try_add_peer(peer, &addr);
        assert_eq!(limiter.total_peer_count(), 1);

        let removed = limiter.remove_peer(&peer);
        assert!(removed);
        assert_eq!(limiter.total_peer_count(), 0);
    }

    #[test]
    fn test_select_diverse_peers() {
        let mut limiter = SubnetLimiter::new();

        // Add peers from different subnets with varying reputation
        for i in 0u8..5 {
            let peer = create_test_peer_id(i);
            let addr = create_multiaddr_v4(192, 168, i, 100);
            limiter.try_add_peer(peer, &addr);

            // Give some peers higher reputation
            for _ in 0..i {
                limiter.record_success(&peer);
            }
        }

        let selected = limiter.select_diverse_peers(3);
        assert_eq!(selected.len(), 3);

        // Verify all are from different subnets
        let subnets: std::collections::HashSet<_> = selected
            .iter()
            .filter_map(|p| limiter.peer_info.get(p))
            .map(|info| info.subnet_key.clone())
            .collect();
        assert_eq!(subnets.len(), 3);
    }

    #[test]
    fn test_can_accept_peer() {
        let mut limiter = SubnetLimiter::new();
        let addr1 = create_multiaddr_v4(192, 168, 1, 100);

        // Fill the subnet to capacity
        for i in 0..MAX_PEERS_PER_SUBNET {
            let peer = create_test_peer_id(i as u8);
            let addr = create_multiaddr_v4(192, 168, 1, 100 + i as u8);
            limiter.try_add_peer(peer, &addr);
        }

        let new_peer = create_test_peer_id(100);
        assert!(!limiter.can_accept_peer(&new_peer, &addr1));

        // Different subnet should be fine
        let addr_different = create_multiaddr_v4(192, 168, 2, 100);
        assert!(limiter.can_accept_peer(&new_peer, &addr_different));
    }
}
