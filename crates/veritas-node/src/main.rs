//! VERITAS Protocol Node Daemon
//!
//! A standalone node that participates in the VERITAS network.
//! It can relay messages, validate transactions, and serve as a
//! bootstrap node for other peers.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::{fmt, EnvFilter};

use veritas_core::{ClientConfig, ClientConfigBuilder, VeritasClient};
use veritas_net::{NodeConfig, NodeEvent, VeritasNode};

/// VERITAS Protocol Node
///
/// A decentralized messaging node with post-quantum security.
#[derive(Parser, Debug)]
#[command(name = "veritas-node")]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to data directory
    ///
    /// NODE-FIX-5: Changed default from /var/lib/veritas (requires root) to a
    /// user-writable directory. Uses ~/.local/share/veritas on Linux/macOS.
    #[arg(short, long, env = "VERITAS_DATA_DIR", default_value = "~/.local/share/veritas")]
    data_dir: PathBuf,

    /// Listen address for P2P connections
    #[arg(short, long, env = "VERITAS_LISTEN_ADDR", default_value = "/ip4/0.0.0.0/tcp/9000")]
    listen_addr: String,

    /// WebSocket listen address (optional)
    #[arg(long, env = "VERITAS_WS_ADDR")]
    ws_addr: Option<String>,

    /// Bootstrap nodes (comma-separated multiaddrs)
    #[arg(short, long, env = "VERITAS_BOOTSTRAP_NODES")]
    bootstrap_nodes: Option<String>,

    /// Enable relay mode (relay messages for other peers)
    #[arg(long, env = "VERITAS_RELAY_MODE", default_value = "true")]
    relay_mode: bool,

    /// Enable validator mode (requires sufficient stake)
    #[arg(long, env = "VERITAS_VALIDATOR_MODE", default_value = "false")]
    validator_mode: bool,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, env = "VERITAS_LOG_LEVEL", default_value = "info")]
    log_level: String,

    /// Log format (plain, json)
    #[arg(long, env = "VERITAS_LOG_FORMAT", default_value = "plain")]
    log_format: String,

    /// Enable metrics endpoint
    #[arg(long, env = "VERITAS_METRICS_ENABLED", default_value = "false")]
    metrics_enabled: bool,

    /// Metrics listen address
    #[arg(long, env = "VERITAS_METRICS_ADDR", default_value = "0.0.0.0:9090")]
    metrics_addr: String,

    /// Health check port
    #[arg(long, env = "VERITAS_HEALTH_PORT", default_value = "8080")]
    health_port: u16,

    /// Node identity file (will be created if not exists)
    #[arg(long, env = "VERITAS_NODE_IDENTITY")]
    node_identity: Option<PathBuf>,

    /// Maximum concurrent connections
    #[arg(long, env = "VERITAS_MAX_CONNECTIONS", default_value = "1000")]
    max_connections: usize,
}

fn setup_logging(log_level: &str, log_format: &str) -> Result<()> {
    let level = match log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let filter = EnvFilter::from_default_env()
        .add_directive(level.into())
        .add_directive("hyper=warn".parse()?)
        .add_directive("libp2p=info".parse()?);

    match log_format.to_lowercase().as_str() {
        "json" => {
            let subscriber = fmt::Subscriber::builder()
                .with_env_filter(filter)
                .json()
                .flatten_event(true)
                .with_current_span(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .context("Failed to set subscriber")?;
        }
        _ => {
            let subscriber = fmt::Subscriber::builder()
                .with_env_filter(filter)
                .with_target(true)
                .with_thread_ids(false)
                .with_file(false)
                .with_line_number(false)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .context("Failed to set subscriber")?;
        }
    }

    Ok(())
}

/// Build client configuration from CLI arguments
fn build_config(args: &Args) -> Result<ClientConfig> {
    let bootstrap_nodes: Vec<String> = args
        .bootstrap_nodes
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default();

    let mut builder = ClientConfigBuilder::new()
        .with_data_dir(args.data_dir.clone())
        .with_bootstrap_peers(bootstrap_nodes);

    // Enable relay mode if requested
    if args.relay_mode {
        builder = builder.enable_local_discovery();
    }

    let config = builder.build();

    Ok(config)
}

/// Run health check server
async fn run_health_server(port: u16) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    info!(port = port, "Health check server listening");

    loop {
        let (mut socket, _) = listener.accept().await?;

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if let Ok(n) = socket.read(&mut buf).await {
                if n > 0 {
                    let request = String::from_utf8_lossy(&buf[..n]);
                    if request.contains("GET /health") || request.contains("GET /") {
                        let response = "HTTP/1.1 200 OK\r\n\
                            Content-Type: application/json\r\n\
                            Content-Length: 15\r\n\
                            Connection: close\r\n\r\n\
                            {\"status\":\"ok\"}";
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else if request.contains("GET /ready") {
                        let response = "HTTP/1.1 200 OK\r\n\
                            Content-Type: application/json\r\n\
                            Content-Length: 18\r\n\
                            Connection: close\r\n\r\n\
                            {\"ready\":\"true\"}";
                        let _ = socket.write_all(response.as_bytes()).await;
                    } else {
                        let response = "HTTP/1.1 404 Not Found\r\n\
                            Content-Length: 0\r\n\
                            Connection: close\r\n\r\n";
                        let _ = socket.write_all(response.as_bytes()).await;
                    }
                }
            }
        });
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    setup_logging(&args.log_level, &args.log_format)?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        data_dir = %args.data_dir.display(),
        listen_addr = %args.listen_addr,
        relay_mode = args.relay_mode,
        validator_mode = args.validator_mode,
        "Starting VERITAS node"
    );

    // NODE-FIX-5: Expand ~ in data directory path
    let data_dir = if args.data_dir.starts_with("~") {
        if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(args.data_dir.strip_prefix("~").unwrap_or(&args.data_dir))
        } else {
            args.data_dir.clone()
        }
    } else {
        args.data_dir.clone()
    };

    // Ensure data directory exists
    if !data_dir.exists() {
        std::fs::create_dir_all(&data_dir)
            .context("Failed to create data directory")?;
        info!(path = %data_dir.display(), "Created data directory");
    }

    // Build configuration (use expanded data_dir)
    let mut args_expanded = args;
    args_expanded.data_dir = data_dir;
    let config = build_config(&args_expanded)?;
    let args = args_expanded;

    // Start health check server
    let health_port = args.health_port;
    tokio::spawn(async move {
        if let Err(e) = run_health_server(health_port).await {
            warn!(error = %e, "Health server error");
        }
    });

    // Initialize the client
    info!("Initializing VERITAS client...");
    let client = VeritasClient::new(config).await
        .context("Failed to initialize VERITAS client")?;

    info!("VERITAS node initialized successfully");

    // Build the P2P node configuration
    let listen_addr: veritas_net::Multiaddr = args
        .listen_addr
        .parse()
        .context("Failed to parse listen address as multiaddr")?;

    let mut node_config = NodeConfig::new()
        .with_listen_addresses(vec![listen_addr]);

    // Parse and add bootstrap peers
    if let Some(ref bootstrap_str) = args.bootstrap_nodes {
        for addr_str in bootstrap_str.split(',').map(|s| s.trim()) {
            if addr_str.is_empty() {
                continue;
            }
            let addr: veritas_net::Multiaddr = addr_str
                .parse()
                .with_context(|| format!("Failed to parse bootstrap address: {}", addr_str))?;

            if let Some(peer_id) = veritas_net::peer_id_from_multiaddr(&addr) {
                node_config = node_config.with_bootstrap_peer(peer_id, addr);
            } else {
                warn!(
                    address = %addr_str,
                    "Bootstrap address does not contain a peer ID (/p2p/...), skipping"
                );
            }
        }
    }

    // Create the P2P node
    info!("Starting P2P networking layer...");
    let mut node = VeritasNode::new(node_config)
        .await
        .context("Failed to create P2P node")?;

    info!(
        peer_id = %node.local_peer_id(),
        "P2P node created"
    );

    // Take the event receiver before starting the run loop
    let mut event_rx = node
        .take_event_receiver()
        .expect("Event receiver should be available");

    // Print node info
    info!(
        listen_addr = %args.listen_addr,
        health_endpoint = format!("http://0.0.0.0:{}/health", args.health_port),
        "Node is ready to accept connections"
    );

    if args.validator_mode {
        info!("Validator mode enabled - will participate in consensus");
    }

    if args.relay_mode {
        info!("Relay mode enabled - will relay messages for other peers");
    }

    // Spawn a task to process node events (peer connections, gossip messages, etc.)
    tokio::spawn(async move {
        let mut maintenance_interval = tokio::time::interval(Duration::from_secs(30));
        maintenance_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                event = event_rx.recv() => {
                    match event {
                        Some(NodeEvent::PeerConnected { peer_id }) => {
                            info!(peer = %peer_id, "Peer connected");
                        }
                        Some(NodeEvent::PeerDisconnected { peer_id }) => {
                            info!(peer = %peer_id, "Peer disconnected");
                        }
                        Some(NodeEvent::ListeningOn { address }) => {
                            info!(address = %address, "Now listening on address");
                        }
                        Some(NodeEvent::GossipMessage { topic, source, .. }) => {
                            debug!(
                                topic = %topic,
                                source = ?source,
                                "Received gossip message"
                            );
                        }
                        Some(NodeEvent::Error { message }) => {
                            warn!(error = %message, "Node event error");
                        }
                        Some(_) => {
                            debug!("Received node event");
                        }
                        None => {
                            warn!("Event channel closed");
                            break;
                        }
                    }
                }
                _ = maintenance_interval.tick() => {
                    debug!("Periodic maintenance tick");
                }
            }
        }
    });

    // Run the P2P event loop on the main task.
    // node.run() drives the libp2p swarm and processes network events.
    // It runs until interrupted by Ctrl+C.
    info!("Press Ctrl+C to stop the node");
    tokio::select! {
        _ = node.run() => {
            error!("P2P event loop exited unexpectedly");
        }
        _ = tokio::signal::ctrl_c() => {
            info!("Received shutdown signal");
        }
    }

    info!("Shutting down VERITAS node...");

    // Graceful shutdown
    client.shutdown().await.context("Failed to shut down client")?;

    info!("VERITAS node stopped");
    Ok(())
}
