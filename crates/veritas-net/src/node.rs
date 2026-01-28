//! libp2p node implementation for VERITAS protocol.
//!
//! This module provides the core P2P networking capabilities using libp2p,
//! including:
//! - Kademlia DHT for peer discovery and routing
//! - Gossipsub for pub/sub messaging
//! - mDNS for local network discovery
//! - Noise protocol for encrypted transport
//! - Identify protocol for peer information exchange

use std::collections::HashMap;
use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, MessageAuthenticity, MessageId, ValidationMode},
    identify,
    kad::{self, store::MemoryStore, Mode as KadMode},
    mdns,
    multiaddr::Protocol,
    noise,
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::error::{NetError, Result};

/// Default Kademlia protocol name for VERITAS.
pub const VERITAS_KAD_PROTOCOL: &str = "/veritas/kad/1.0.0";

/// Default Gossipsub protocol prefix for VERITAS.
pub const VERITAS_GOSSIPSUB_PREFIX: &str = "veritas";

/// Default channel buffer size for events.
const EVENT_CHANNEL_SIZE: usize = 256;

/// Configuration for creating a VERITAS node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Addresses to listen on.
    pub listen_addresses: Vec<Multiaddr>,

    /// Bootstrap peers for initial network connectivity.
    pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    /// Enable mDNS for local peer discovery.
    pub enable_mdns: bool,

    /// Enable Kademlia DHT.
    pub enable_kademlia: bool,

    /// Enable Gossipsub pub/sub.
    pub enable_gossipsub: bool,

    /// Optional pre-generated keypair. If None, a new one is generated.
    pub keypair: Option<libp2p::identity::Keypair>,

    /// Idle connection timeout in seconds.
    pub idle_connection_timeout_secs: u64,

    /// Gossipsub heartbeat interval in milliseconds.
    pub gossipsub_heartbeat_ms: u64,

    /// Topics to subscribe to on startup.
    pub initial_topics: Vec<String>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".parse().expect("valid multiaddr")],
            bootstrap_peers: Vec::new(),
            enable_mdns: true,
            enable_kademlia: true,
            enable_gossipsub: true,
            keypair: None,
            idle_connection_timeout_secs: 60,
            gossipsub_heartbeat_ms: 1000,
            initial_topics: vec!["veritas/messages/1.0.0".to_string()],
        }
    }
}

impl NodeConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a listen address.
    pub fn with_listen_address(mut self, addr: Multiaddr) -> Self {
        self.listen_addresses.push(addr);
        self
    }

    /// Set listen addresses, replacing any existing.
    pub fn with_listen_addresses(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.listen_addresses = addrs;
        self
    }

    /// Add a bootstrap peer.
    pub fn with_bootstrap_peer(mut self, peer_id: PeerId, addr: Multiaddr) -> Self {
        self.bootstrap_peers.push((peer_id, addr));
        self
    }

    /// Set bootstrap peers, replacing any existing.
    pub fn with_bootstrap_peers(mut self, peers: Vec<(PeerId, Multiaddr)>) -> Self {
        self.bootstrap_peers = peers;
        self
    }

    /// Enable or disable mDNS.
    pub fn with_mdns(mut self, enable: bool) -> Self {
        self.enable_mdns = enable;
        self
    }

    /// Enable or disable Kademlia.
    pub fn with_kademlia(mut self, enable: bool) -> Self {
        self.enable_kademlia = enable;
        self
    }

    /// Enable or disable Gossipsub.
    pub fn with_gossipsub(mut self, enable: bool) -> Self {
        self.enable_gossipsub = enable;
        self
    }

    /// Set a pre-generated keypair.
    pub fn with_keypair(mut self, keypair: libp2p::identity::Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Add an initial topic to subscribe to.
    pub fn with_topic(mut self, topic: String) -> Self {
        self.initial_topics.push(topic);
        self
    }
}

/// Events emitted by the VERITAS node.
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// A new peer was discovered.
    PeerDiscovered {
        /// The discovered peer's ID.
        peer_id: PeerId,
        /// Known addresses for the peer.
        addresses: Vec<Multiaddr>,
    },

    /// A peer connection was established.
    PeerConnected {
        /// The connected peer's ID.
        peer_id: PeerId,
    },

    /// A peer disconnected.
    PeerDisconnected {
        /// The disconnected peer's ID.
        peer_id: PeerId,
    },

    /// A Gossipsub message was received.
    GossipMessage {
        /// The topic the message was published to.
        topic: String,
        /// The message data.
        data: Vec<u8>,
        /// The source peer (if known).
        source: Option<PeerId>,
        /// The message ID.
        message_id: Vec<u8>,
    },

    /// We subscribed to a topic.
    Subscribed {
        /// The topic name.
        topic: String,
    },

    /// We unsubscribed from a topic.
    Unsubscribed {
        /// The topic name.
        topic: String,
    },

    /// A peer subscribed to a topic.
    PeerSubscribed {
        /// The peer that subscribed.
        peer_id: PeerId,
        /// The topic they subscribed to.
        topic: String,
    },

    /// A peer unsubscribed from a topic.
    PeerUnsubscribed {
        /// The peer that unsubscribed.
        peer_id: PeerId,
        /// The topic they unsubscribed from.
        topic: String,
    },

    /// A Kademlia query completed.
    KademliaQueryCompleted {
        /// The query ID as a string.
        query_id: String,
    },

    /// A value was found in the DHT.
    KademliaValueFound {
        /// The key that was queried.
        key: Vec<u8>,
        /// The value that was found.
        value: Vec<u8>,
    },

    /// Providers were found for a key in the DHT.
    KademliaProvidersFound {
        /// The key that was queried.
        key: Vec<u8>,
        /// The providers that were found.
        providers: Vec<PeerId>,
    },

    /// The node started listening on an address.
    ListeningOn {
        /// The address we're listening on.
        address: Multiaddr,
    },

    /// An error occurred.
    Error {
        /// Description of the error.
        message: String,
    },
}

/// Inner module to isolate NetworkBehaviour derive from Result type alias conflicts.
#[allow(missing_docs)]
mod behaviour {
    use libp2p::{
        gossipsub, identify,
        kad::{self, store::MemoryStore},
        mdns,
        swarm::NetworkBehaviour,
    };

    /// Combined network behaviour for VERITAS node.
    ///
    /// This struct combines multiple libp2p protocols:
    /// - Kademlia DHT for peer routing and content discovery
    /// - Gossipsub for pub/sub messaging
    /// - mDNS for local network discovery
    /// - Identify for peer information exchange
    #[derive(NetworkBehaviour)]
    pub struct NodeBehaviour {
        /// Kademlia DHT behaviour.
        pub kademlia: kad::Behaviour<MemoryStore>,

        /// Gossipsub pub/sub behaviour.
        pub gossipsub: gossipsub::Behaviour,

        /// mDNS local discovery behaviour.
        pub mdns: mdns::tokio::Behaviour,

        /// Identify protocol behaviour.
        pub identify: identify::Behaviour,
    }
}

pub use behaviour::NodeBehaviour;
pub use behaviour::NodeBehaviourEvent;

/// The main VERITAS P2P node.
pub struct VeritasNode {
    /// The libp2p swarm.
    swarm: Swarm<NodeBehaviour>,

    /// Event sender for external consumers.
    event_tx: mpsc::Sender<NodeEvent>,

    /// Event receiver (held until run() is called).
    event_rx: Option<mpsc::Receiver<NodeEvent>>,

    /// Tracked listen addresses.
    listen_addresses: Vec<Multiaddr>,

    /// Subscribed topics.
    subscribed_topics: HashMap<String, IdentTopic>,

    /// Configuration used to create this node.
    config: NodeConfig,
}

impl VeritasNode {
    /// Create a new VERITAS node with the given configuration.
    pub async fn new(config: NodeConfig) -> Result<Self> {
        // Generate or use provided keypair
        let keypair = config
            .keypair
            .clone()
            .unwrap_or_else(libp2p::identity::Keypair::generate_ed25519);

        let local_peer_id = PeerId::from(keypair.public());
        info!("Creating VERITAS node with peer ID: {}", local_peer_id);

        // Build the swarm with all behaviours
        let swarm = Self::build_swarm(keypair.clone(), &config)?;

        // Create event channel
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_SIZE);

        let mut node = Self {
            swarm,
            event_tx,
            event_rx: Some(event_rx),
            listen_addresses: Vec::new(),
            subscribed_topics: HashMap::new(),
            config: config.clone(),
        };

        // Start listening on configured addresses
        for addr in &config.listen_addresses {
            node.listen_on(addr.clone())?;
        }

        // Add bootstrap peers to Kademlia
        if config.enable_kademlia {
            for (peer_id, addr) in &config.bootstrap_peers {
                debug!("Adding bootstrap peer: {} at {}", peer_id, addr);
                node.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(peer_id, addr.clone());
            }

            // Start bootstrap if we have peers
            if !config.bootstrap_peers.is_empty() {
                if let Err(e) = node.swarm.behaviour_mut().kademlia.bootstrap() {
                    warn!("Failed to start Kademlia bootstrap: {:?}", e);
                }
            }
        }

        // Subscribe to initial topics
        if config.enable_gossipsub {
            for topic_name in &config.initial_topics {
                node.subscribe(topic_name)?;
            }
        }

        Ok(node)
    }

    /// Build the libp2p swarm with all configured behaviours.
    fn build_swarm(
        keypair: libp2p::identity::Keypair,
        config: &NodeConfig,
    ) -> Result<Swarm<NodeBehaviour>> {
        let local_peer_id = PeerId::from(keypair.public());

        // Build Kademlia behaviour
        let kademlia = {
            let store = MemoryStore::new(local_peer_id);
            let mut kad_config = kad::Config::default();
            kad_config.set_protocol_names(vec![libp2p::StreamProtocol::try_from_owned(
                VERITAS_KAD_PROTOCOL.to_string(),
            )
            .expect("valid protocol name")]);
            let mut kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

            // Set mode based on configuration
            if config.enable_kademlia {
                kademlia.set_mode(Some(KadMode::Server));
            }

            kademlia
        };

        // Build Gossipsub behaviour
        let gossipsub = {
            // Configure message ID function for deduplication
            let message_id_fn = |message: &gossipsub::Message| {
                // Use hash of data + source for message ID
                let mut hasher = blake3::Hasher::new();
                hasher.update(&message.data);
                if let Some(source) = message.source {
                    hasher.update(source.to_bytes().as_slice());
                }
                let hash = hasher.finalize();
                MessageId::from(hash.as_bytes().to_vec())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_millis(config.gossipsub_heartbeat_ms))
                .validation_mode(ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .map_err(|e| NetError::Transport(format!("Gossipsub config error: {}", e)))?;

            gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(keypair.clone()),
                gossipsub_config,
            )
            .map_err(|e| NetError::Transport(format!("Gossipsub creation error: {}", e)))?
        };

        // Build mDNS behaviour
        let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
            .map_err(|e| NetError::Transport(format!("mDNS error: {}", e)))?;

        // Build identify behaviour
        let identify = identify::Behaviour::new(
            identify::Config::new("/veritas/id/1.0.0".to_string(), keypair.public())
                .with_agent_version(format!("veritas/{}", env!("CARGO_PKG_VERSION"))),
        );

        // Combine all behaviours
        let behaviour = NodeBehaviour {
            kademlia,
            gossipsub,
            mdns,
            identify,
        };

        // Build the swarm
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NetError::Transport(format!("TCP transport error: {}", e)))?
            .with_dns()
            .map_err(|e| NetError::Transport(format!("DNS transport error: {}", e)))?
            .with_behaviour(|_| behaviour)
            .map_err(|e| NetError::Transport(format!("Behaviour error: {}", e)))?
            .with_swarm_config(|c| {
                c.with_idle_connection_timeout(Duration::from_secs(
                    config.idle_connection_timeout_secs,
                ))
            })
            .build();

        Ok(swarm)
    }

    /// Get the local peer ID.
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Get the current listen addresses.
    pub fn listen_addresses(&self) -> Vec<Multiaddr> {
        self.listen_addresses.clone()
    }

    /// Start listening on an address.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<()> {
        self.swarm
            .listen_on(addr.clone())
            .map_err(|e| NetError::Transport(format!("Failed to listen on {}: {}", addr, e)))?;
        Ok(())
    }

    /// Dial a peer at a specific address.
    pub async fn dial(&mut self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        debug!("Dialing peer {} at {}", peer_id, addr);

        // Add the address to Kademlia if enabled
        if self.config.enable_kademlia {
            self.swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer_id, addr.clone());
        }

        // Dial the peer
        self.swarm
            .dial(addr.clone())
            .map_err(|e| NetError::ConnectionFailed(format!("Failed to dial {}: {}", addr, e)))?;

        Ok(())
    }

    /// Subscribe to a Gossipsub topic.
    pub fn subscribe(&mut self, topic_name: &str) -> Result<()> {
        if !self.config.enable_gossipsub {
            return Err(NetError::Transport("Gossipsub is disabled".to_string()));
        }

        let topic = IdentTopic::new(topic_name);

        self.swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| {
                NetError::Gossip(format!("Failed to subscribe to {}: {}", topic_name, e))
            })?;

        self.subscribed_topics.insert(topic_name.to_string(), topic);
        info!("Subscribed to topic: {}", topic_name);

        Ok(())
    }

    /// Unsubscribe from a Gossipsub topic.
    pub fn unsubscribe(&mut self, topic_name: &str) -> Result<()> {
        if !self.config.enable_gossipsub {
            return Err(NetError::Transport("Gossipsub is disabled".to_string()));
        }

        if let Some(topic) = self.subscribed_topics.remove(topic_name) {
            self.swarm
                .behaviour_mut()
                .gossipsub
                .unsubscribe(&topic)
                .map_err(|e| {
                    NetError::Gossip(format!("Failed to unsubscribe from {}: {}", topic_name, e))
                })?;
            info!("Unsubscribed from topic: {}", topic_name);
        }

        Ok(())
    }

    /// Publish a message to a Gossipsub topic.
    pub fn publish(&mut self, topic_name: &str, data: Vec<u8>) -> Result<()> {
        if !self.config.enable_gossipsub {
            return Err(NetError::Transport("Gossipsub is disabled".to_string()));
        }

        let topic = self
            .subscribed_topics
            .get(topic_name)
            .cloned()
            .unwrap_or_else(|| IdentTopic::new(topic_name));

        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)
            .map_err(|e| NetError::Gossip(format!("Failed to publish to {}: {}", topic_name, e)))?;

        trace!("Published message to topic: {}", topic_name);
        Ok(())
    }

    /// Store a value in the Kademlia DHT.
    pub fn put_record(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<kad::QueryId> {
        if !self.config.enable_kademlia {
            return Err(NetError::Transport("Kademlia is disabled".to_string()));
        }

        let record = kad::Record::new(key, value);

        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)
            .map_err(|e| NetError::Dht(format!("Failed to put record: {:?}", e)))
    }

    /// Get a value from the Kademlia DHT.
    pub fn get_record(&mut self, key: Vec<u8>) -> Result<kad::QueryId> {
        if !self.config.enable_kademlia {
            return Err(NetError::Transport("Kademlia is disabled".to_string()));
        }

        let query_id = self
            .swarm
            .behaviour_mut()
            .kademlia
            .get_record(kad::RecordKey::new(&key));

        Ok(query_id)
    }

    /// Start providing a key in the DHT.
    pub fn start_providing(&mut self, key: Vec<u8>) -> Result<kad::QueryId> {
        if !self.config.enable_kademlia {
            return Err(NetError::Transport("Kademlia is disabled".to_string()));
        }

        self.swarm
            .behaviour_mut()
            .kademlia
            .start_providing(kad::RecordKey::new(&key))
            .map_err(|e| NetError::Dht(format!("Failed to start providing: {:?}", e)))
    }

    /// Get providers for a key in the DHT.
    pub fn get_providers(&mut self, key: Vec<u8>) -> kad::QueryId {
        self.swarm
            .behaviour_mut()
            .kademlia
            .get_providers(kad::RecordKey::new(&key))
    }

    /// Get the number of connected peers.
    pub fn connected_peers_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Get a list of connected peer IDs.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    /// Take the event receiver (can only be called once).
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.event_rx.take()
    }

    /// Run the main event loop.
    ///
    /// This method runs indefinitely, processing swarm events and emitting
    /// NodeEvents through the channel. Call `take_event_receiver()` before
    /// calling this method to receive events.
    pub async fn run(&mut self) {
        info!("Starting VERITAS node event loop");

        loop {
            let event = self.swarm.select_next_some().await;
            if let Err(e) = self.handle_swarm_event(event).await {
                error!("Error handling swarm event: {:?}", e);
                let _ = self
                    .event_tx
                    .send(NodeEvent::Error {
                        message: e.to_string(),
                    })
                    .await;
            }
        }
    }

    /// Run the event loop for a single iteration (useful for testing).
    pub async fn poll_once(&mut self) -> Option<NodeEvent> {
        tokio::select! {
            event = self.swarm.select_next_some() => {
                if let Err(e) = self.handle_swarm_event(event).await {
                    return Some(NodeEvent::Error { message: e.to_string() });
                }
                None
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => None
        }
    }

    /// Handle a swarm event.
    async fn handle_swarm_event(&mut self, event: SwarmEvent<NodeBehaviourEvent>) -> Result<()> {
        match event {
            // Connection events
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to peer: {}", peer_id);
                self.emit_event(NodeEvent::PeerConnected { peer_id }).await;
            }

            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from peer: {}", peer_id);
                self.emit_event(NodeEvent::PeerDisconnected { peer_id })
                    .await;
            }

            // Listen events
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on: {}", address);
                self.listen_addresses.push(address.clone());
                self.emit_event(NodeEvent::ListeningOn { address }).await;
            }

            SwarmEvent::ExpiredListenAddr { address, .. } => {
                debug!("Expired listen address: {}", address);
                self.listen_addresses.retain(|a| a != &address);
            }

            // Behaviour-specific events
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event).await?;
            }

            // Other events
            SwarmEvent::IncomingConnection {
                local_addr,
                send_back_addr,
                ..
            } => {
                debug!(
                    "Incoming connection from {} to {}",
                    send_back_addr, local_addr
                );
            }

            SwarmEvent::IncomingConnectionError {
                local_addr,
                send_back_addr,
                error,
                ..
            } => {
                warn!(
                    "Incoming connection error from {} to {}: {}",
                    send_back_addr, local_addr, error
                );
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    warn!("Outgoing connection error to {}: {}", peer_id, error);
                } else {
                    warn!("Outgoing connection error: {}", error);
                }
            }

            SwarmEvent::Dialing { peer_id, .. } => {
                if let Some(peer_id) = peer_id {
                    debug!("Dialing peer: {}", peer_id);
                }
            }

            _ => {
                trace!("Unhandled swarm event");
            }
        }

        Ok(())
    }

    /// Handle behaviour-specific events.
    async fn handle_behaviour_event(&mut self, event: NodeBehaviourEvent) -> Result<()> {
        match event {
            // Kademlia events
            NodeBehaviourEvent::Kademlia(kad_event) => {
                self.handle_kademlia_event(kad_event).await?;
            }

            // Gossipsub events
            NodeBehaviourEvent::Gossipsub(gossip_event) => {
                self.handle_gossipsub_event(gossip_event).await?;
            }

            // mDNS events
            NodeBehaviourEvent::Mdns(mdns_event) => {
                self.handle_mdns_event(mdns_event).await?;
            }

            // Identify events
            NodeBehaviourEvent::Identify(identify_event) => {
                self.handle_identify_event(identify_event).await?;
            }
        }

        Ok(())
    }

    /// Handle Kademlia events.
    async fn handle_kademlia_event(&mut self, event: kad::Event) -> Result<()> {
        match event {
            kad::Event::OutboundQueryProgressed { id, result, .. } => match result {
                kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(
                    kad::PeerRecord { record, .. },
                ))) => {
                    debug!("Found record in DHT: key={:?}", record.key);
                    self.emit_event(NodeEvent::KademliaValueFound {
                        key: record.key.to_vec(),
                        value: record.value,
                    })
                    .await;
                }

                kad::QueryResult::GetRecord(Err(e)) => {
                    debug!("Failed to get record: {:?}", e);
                }

                kad::QueryResult::PutRecord(Ok(_)) => {
                    debug!("Successfully stored record in DHT");
                    self.emit_event(NodeEvent::KademliaQueryCompleted {
                        query_id: format!("{:?}", id),
                    })
                    .await;
                }

                kad::QueryResult::PutRecord(Err(e)) => {
                    warn!("Failed to put record: {:?}", e);
                }

                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    key,
                    providers,
                })) => {
                    debug!("Found {} providers for key", providers.len());
                    self.emit_event(NodeEvent::KademliaProvidersFound {
                        key: key.to_vec(),
                        providers: providers.into_iter().collect(),
                    })
                    .await;
                }

                kad::QueryResult::GetProviders(Err(e)) => {
                    debug!("Failed to get providers: {:?}", e);
                }

                kad::QueryResult::StartProviding(Ok(_)) => {
                    debug!("Started providing record");
                }

                kad::QueryResult::StartProviding(Err(e)) => {
                    warn!("Failed to start providing: {:?}", e);
                }

                kad::QueryResult::Bootstrap(Ok(_)) => {
                    info!("Kademlia bootstrap completed");
                }

                kad::QueryResult::Bootstrap(Err(e)) => {
                    warn!("Kademlia bootstrap failed: {:?}", e);
                }

                _ => {
                    trace!("Unhandled Kademlia query result");
                }
            },

            kad::Event::RoutingUpdated { peer, .. } => {
                debug!("Kademlia routing table updated for peer: {}", peer);
            }

            kad::Event::UnroutablePeer { peer } => {
                debug!("Peer is unroutable: {}", peer);
            }

            kad::Event::RoutablePeer { peer, address } => {
                debug!("Peer {} is routable at {}", peer, address);
            }

            kad::Event::PendingRoutablePeer { peer, address } => {
                debug!("Pending routable peer {} at {}", peer, address);
            }

            _ => {
                trace!("Unhandled Kademlia event");
            }
        }

        Ok(())
    }

    /// Handle Gossipsub events.
    async fn handle_gossipsub_event(&mut self, event: gossipsub::Event) -> Result<()> {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            } => {
                debug!(
                    "Received gossip message from {} on topic {}",
                    propagation_source,
                    message.topic.as_str()
                );
                self.emit_event(NodeEvent::GossipMessage {
                    topic: message.topic.to_string(),
                    data: message.data,
                    source: message.source,
                    message_id: message_id.0,
                })
                .await;
            }

            gossipsub::Event::Subscribed { peer_id, topic } => {
                debug!("Peer {} subscribed to {}", peer_id, topic);
                self.emit_event(NodeEvent::PeerSubscribed {
                    peer_id,
                    topic: topic.to_string(),
                })
                .await;
            }

            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                debug!("Peer {} unsubscribed from {}", peer_id, topic);
                self.emit_event(NodeEvent::PeerUnsubscribed {
                    peer_id,
                    topic: topic.to_string(),
                })
                .await;
            }

            gossipsub::Event::GossipsubNotSupported { peer_id } => {
                debug!("Peer {} does not support Gossipsub", peer_id);
            }
        }

        Ok(())
    }

    /// Handle mDNS events.
    async fn handle_mdns_event(&mut self, event: mdns::Event) -> Result<()> {
        match event {
            mdns::Event::Discovered(peers) => {
                for (peer_id, addr) in peers {
                    info!("mDNS discovered peer: {} at {}", peer_id, addr);

                    // Add to Kademlia routing table
                    if self.config.enable_kademlia {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                    }

                    self.emit_event(NodeEvent::PeerDiscovered {
                        peer_id,
                        addresses: vec![addr],
                    })
                    .await;
                }
            }

            mdns::Event::Expired(peers) => {
                for (peer_id, addr) in peers {
                    debug!("mDNS peer expired: {} at {}", peer_id, addr);
                }
            }
        }

        Ok(())
    }

    /// Handle identify events.
    async fn handle_identify_event(&mut self, event: identify::Event) -> Result<()> {
        match event {
            identify::Event::Received { peer_id, info } => {
                debug!(
                    "Identified peer {}: protocol={}, agent={}",
                    peer_id, info.protocol_version, info.agent_version
                );

                // Add all listen addresses to Kademlia
                if self.config.enable_kademlia {
                    for addr in &info.listen_addrs {
                        self.swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                    }
                }

                self.emit_event(NodeEvent::PeerDiscovered {
                    peer_id,
                    addresses: info.listen_addrs,
                })
                .await;
            }

            identify::Event::Sent { peer_id } => {
                trace!("Sent identify info to {}", peer_id);
            }

            identify::Event::Pushed { peer_id, .. } => {
                trace!("Pushed identify info to {}", peer_id);
            }

            identify::Event::Error { peer_id, error } => {
                debug!("Identify error with {}: {}", peer_id, error);
            }
        }

        Ok(())
    }

    /// Emit an event to the channel.
    async fn emit_event(&self, event: NodeEvent) {
        if let Err(e) = self.event_tx.send(event).await {
            warn!("Failed to emit event: {}", e);
        }
    }

    /// Get mutable access to the swarm (for advanced use cases).
    pub fn swarm_mut(&mut self) -> &mut Swarm<NodeBehaviour> {
        &mut self.swarm
    }

    /// Get immutable access to the swarm.
    pub fn swarm(&self) -> &Swarm<NodeBehaviour> {
        &self.swarm
    }

    /// Add an external address for this node.
    pub fn add_external_address(&mut self, addr: Multiaddr) {
        self.swarm.add_external_address(addr);
    }

    /// Get known addresses for a peer.
    ///
    /// Note: In libp2p 0.53, direct address lookup requires maintaining
    /// an address book. This implementation is a placeholder that returns
    /// an empty vector. In production, consider storing addresses received
    /// from identify events.
    pub fn addresses_of_peer(&self, _peer_id: &PeerId) -> Vec<Multiaddr> {
        // TODO: Implement address book to track peer addresses from identify events
        Vec::new()
    }

    /// Check if Kademlia is enabled.
    pub fn kademlia_enabled(&self) -> bool {
        self.config.enable_kademlia
    }

    /// Check if Gossipsub is enabled.
    pub fn gossipsub_enabled(&self) -> bool {
        self.config.enable_gossipsub
    }

    /// Check if mDNS is enabled.
    pub fn mdns_enabled(&self) -> bool {
        self.config.enable_mdns
    }
}

/// Extract peer ID from a multiaddress if present.
pub fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|protocol| {
        if let Protocol::P2p(peer_id) = protocol {
            Some(peer_id)
        } else {
            None
        }
    })
}
