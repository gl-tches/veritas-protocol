//! Local network discovery using mDNS.
//!
//! This module provides peer discovery on the local network without requiring
//! bootstrap servers. Uses libp2p's mDNS implementation to advertise and
//! discover VERITAS peers on the same network segment.

use libp2p::{PeerId, mdns, multiaddr::Multiaddr};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Default mDNS TTL (Time-To-Live) for service announcements.
const DEFAULT_MDNS_TTL: Duration = Duration::from_secs(5 * 60); // 5 minutes

/// Default interval between mDNS queries.
const DEFAULT_QUERY_INTERVAL: Duration = Duration::from_secs(30);

/// Default service name for VERITAS mDNS discovery.
const DEFAULT_SERVICE_NAME: &str = "_veritas._tcp.local";

/// Configuration for local network discovery.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Enable mDNS discovery.
    pub enable_mdns: bool,

    /// TTL for mDNS service announcements.
    pub mdns_ttl: Duration,

    /// Service name to advertise and discover.
    pub service_name: String,

    /// Interval between mDNS queries.
    pub query_interval: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_mdns: true,
            mdns_ttl: DEFAULT_MDNS_TTL,
            service_name: DEFAULT_SERVICE_NAME.to_string(),
            query_interval: DEFAULT_QUERY_INTERVAL,
        }
    }
}

impl DiscoveryConfig {
    /// Create a new discovery configuration with mDNS enabled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a configuration with mDNS disabled.
    pub fn disabled() -> Self {
        Self {
            enable_mdns: false,
            ..Default::default()
        }
    }

    /// Set whether mDNS is enabled.
    pub fn with_mdns_enabled(mut self, enabled: bool) -> Self {
        self.enable_mdns = enabled;
        self
    }

    /// Set the mDNS TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.mdns_ttl = ttl;
        self
    }

    /// Set the service name.
    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// Set the query interval.
    pub fn with_query_interval(mut self, interval: Duration) -> Self {
        self.query_interval = interval;
        self
    }
}

/// Information about a discovered peer on the local network.
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// The peer's unique identifier.
    pub peer_id: PeerId,

    /// Known addresses for the peer.
    pub addresses: Vec<Multiaddr>,

    /// When the peer was first discovered.
    pub discovered_at: Instant,

    /// When the peer was last seen.
    pub last_seen: Instant,
}

impl DiscoveredPeer {
    /// Create a new discovered peer entry.
    fn new(peer_id: PeerId, addresses: Vec<Multiaddr>) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            addresses,
            discovered_at: now,
            last_seen: now,
        }
    }

    /// Update the peer with new addresses and refresh last_seen.
    fn update(&mut self, addresses: Vec<Multiaddr>) {
        self.last_seen = Instant::now();
        // Merge addresses, avoiding duplicates
        for addr in addresses {
            if !self.addresses.contains(&addr) {
                self.addresses.push(addr);
            }
        }
    }

    /// Check if this peer entry is stale (not seen within max_age).
    pub fn is_stale(&self, max_age: Duration) -> bool {
        self.last_seen.elapsed() > max_age
    }

    /// Get the age since first discovery.
    pub fn age(&self) -> Duration {
        self.discovered_at.elapsed()
    }

    /// Get the time since last seen.
    pub fn time_since_seen(&self) -> Duration {
        self.last_seen.elapsed()
    }
}

/// Events emitted by the local discovery system.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A new peer was discovered on the local network.
    PeerDiscovered(DiscoveredPeer),

    /// A peer has expired (not seen for too long).
    PeerExpired(PeerId),
}

/// Local network discovery using mDNS.
///
/// Tracks discovered peers on the local network and maintains a cache
/// of their addresses. Uses libp2p's mDNS behavior for discovery.
pub struct LocalDiscovery {
    /// Configuration for discovery.
    config: DiscoveryConfig,

    /// Cache of discovered peers.
    peers: HashMap<PeerId, DiscoveredPeer>,

    /// Pending events to be emitted.
    pending_events: Vec<DiscoveryEvent>,
}

impl LocalDiscovery {
    /// Create a new local discovery instance with the given configuration.
    pub fn new(config: DiscoveryConfig) -> Self {
        info!(
            enabled = config.enable_mdns,
            service_name = %config.service_name,
            ttl_secs = config.mdns_ttl.as_secs(),
            "Initializing local discovery"
        );

        Self {
            config,
            peers: HashMap::new(),
            pending_events: Vec::new(),
        }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// Check if mDNS discovery is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enable_mdns
    }

    /// Get all discovered peers.
    pub fn discovered_peers(&self) -> Vec<&DiscoveredPeer> {
        self.peers.values().collect()
    }

    /// Check if there are any peers on the local network.
    pub fn has_local_peers(&self) -> bool {
        !self.peers.is_empty()
    }

    /// Get a specific peer by ID.
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&DiscoveredPeer> {
        self.peers.get(peer_id)
    }

    /// Get the number of discovered peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Handle an mDNS event from libp2p.
    ///
    /// Processes discovered and expired peer events, updating the internal
    /// peer cache and generating discovery events.
    pub fn handle_mdns_event(&mut self, event: mdns::Event) {
        match event {
            mdns::Event::Discovered(discovered_list) => {
                for (peer_id, addr) in discovered_list {
                    self.handle_peer_discovered(peer_id, addr);
                }
            }
            mdns::Event::Expired(expired_list) => {
                for (peer_id, addr) in expired_list {
                    self.handle_peer_expired(peer_id, addr);
                }
            }
        }
    }

    /// Handle a peer being discovered.
    fn handle_peer_discovered(&mut self, peer_id: PeerId, addr: Multiaddr) {
        debug!(
            peer_id = %peer_id,
            address = %addr,
            "mDNS peer discovered"
        );

        if let Some(existing) = self.peers.get_mut(&peer_id) {
            // Peer already known, update addresses and last_seen
            trace!(peer_id = %peer_id, "Updating existing peer");
            existing.update(vec![addr]);
        } else {
            // New peer discovered
            info!(
                peer_id = %peer_id,
                address = %addr,
                "New peer discovered on local network"
            );
            let peer = DiscoveredPeer::new(peer_id, vec![addr]);
            let event = DiscoveryEvent::PeerDiscovered(peer.clone());
            self.peers.insert(peer_id, peer);
            self.pending_events.push(event);
        }
    }

    /// Handle a peer address expiring.
    fn handle_peer_expired(&mut self, peer_id: PeerId, addr: Multiaddr) {
        debug!(
            peer_id = %peer_id,
            address = %addr,
            "mDNS peer address expired"
        );

        if let Some(peer) = self.peers.get_mut(&peer_id) {
            // Remove the expired address
            peer.addresses.retain(|a| a != &addr);

            // If no addresses remain, remove the peer entirely
            if peer.addresses.is_empty() {
                info!(
                    peer_id = %peer_id,
                    "Peer removed from local network (all addresses expired)"
                );
                self.peers.remove(&peer_id);
                self.pending_events
                    .push(DiscoveryEvent::PeerExpired(peer_id));
            }
        }
    }

    /// Remove stale peers that haven't been seen within max_age.
    ///
    /// Returns the number of peers that were pruned.
    pub fn prune_stale(&mut self, max_age: Duration) -> usize {
        let stale_peers: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|(_, peer)| peer.is_stale(max_age))
            .map(|(id, _)| *id)
            .collect();

        let count = stale_peers.len();

        for peer_id in stale_peers {
            warn!(
                peer_id = %peer_id,
                max_age_secs = max_age.as_secs(),
                "Pruning stale peer"
            );
            self.peers.remove(&peer_id);
            self.pending_events
                .push(DiscoveryEvent::PeerExpired(peer_id));
        }

        if count > 0 {
            debug!(
                pruned = count,
                remaining = self.peers.len(),
                "Pruned stale peers"
            );
        }

        count
    }

    /// Take all pending discovery events.
    ///
    /// Returns the events and clears the internal buffer.
    pub fn take_events(&mut self) -> Vec<DiscoveryEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Check if there are pending events.
    pub fn has_pending_events(&self) -> bool {
        !self.pending_events.is_empty()
    }

    /// Get all peer IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.keys()
    }

    /// Get all addresses for all discovered peers.
    pub fn all_addresses(&self) -> impl Iterator<Item = &Multiaddr> {
        self.peers.values().flat_map(|p| p.addresses.iter())
    }

    /// Clear all discovered peers.
    ///
    /// This does not emit expiry events.
    pub fn clear(&mut self) {
        debug!(
            peer_count = self.peers.len(),
            "Clearing all discovered peers"
        );
        self.peers.clear();
    }
}

impl std::fmt::Debug for LocalDiscovery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalDiscovery")
            .field("enabled", &self.config.enable_mdns)
            .field("peer_count", &self.peers.len())
            .field("pending_events", &self.pending_events.len())
            .finish()
    }
}
