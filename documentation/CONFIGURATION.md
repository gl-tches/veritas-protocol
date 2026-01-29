# VERITAS Configuration Reference

Complete reference for all configuration options.

## Table of Contents

- [Configuration Methods](#configuration-methods)
- [Environment Variables](#environment-variables)
- [Command Line Arguments](#command-line-arguments)
- [Configuration File](#configuration-file)
- [Client Configuration](#client-configuration)
- [Network Configuration](#network-configuration)
- [Storage Configuration](#storage-configuration)
- [Security Configuration](#security-configuration)

## Configuration Methods

VERITAS supports three configuration methods (in order of precedence):

1. **Command Line Arguments** - Highest priority
2. **Environment Variables** - Medium priority
3. **Configuration File** - Lowest priority

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_DATA_DIR` | `/var/lib/veritas` | Data storage directory |
| `VERITAS_CONFIG_FILE` | None | Path to configuration file |

### Network Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_LISTEN_ADDR` | `/ip4/0.0.0.0/tcp/9000` | P2P listen multiaddr |
| `VERITAS_WS_ADDR` | None | WebSocket listen address |
| `VERITAS_BOOTSTRAP_NODES` | None | Comma-separated bootstrap multiaddrs |
| `VERITAS_RELAY_MODE` | `true` | Enable message relay |
| `VERITAS_MAX_CONNECTIONS` | `1000` | Maximum peer connections |

### Node Operation

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_VALIDATOR_MODE` | `false` | Enable validator mode |
| `VERITAS_NODE_IDENTITY` | None | Path to node identity file |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_LOG_LEVEL` | `info` | Log level: trace, debug, info, warn, error |
| `VERITAS_LOG_FORMAT` | `plain` | Log format: plain, json |

### Health & Metrics

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_HEALTH_PORT` | `8080` | Health check HTTP port |
| `VERITAS_METRICS_ENABLED` | `false` | Enable Prometheus metrics |
| `VERITAS_METRICS_ADDR` | `0.0.0.0:9090` | Metrics endpoint address |

## Command Line Arguments

```bash
veritas-node [OPTIONS]

Options:
  -d, --data-dir <PATH>
          Path to data directory
          [env: VERITAS_DATA_DIR]
          [default: /var/lib/veritas]

  -l, --listen-addr <MULTIADDR>
          Listen address for P2P connections
          [env: VERITAS_LISTEN_ADDR]
          [default: /ip4/0.0.0.0/tcp/9000]

      --ws-addr <MULTIADDR>
          WebSocket listen address (optional)
          [env: VERITAS_WS_ADDR]

  -b, --bootstrap-nodes <NODES>
          Bootstrap nodes (comma-separated multiaddrs)
          [env: VERITAS_BOOTSTRAP_NODES]

      --relay-mode <BOOL>
          Enable relay mode
          [env: VERITAS_RELAY_MODE]
          [default: true]

      --validator-mode <BOOL>
          Enable validator mode
          [env: VERITAS_VALIDATOR_MODE]
          [default: false]

      --log-level <LEVEL>
          Log level (trace, debug, info, warn, error)
          [env: VERITAS_LOG_LEVEL]
          [default: info]

      --log-format <FORMAT>
          Log format (plain, json)
          [env: VERITAS_LOG_FORMAT]
          [default: plain]

      --metrics-enabled <BOOL>
          Enable metrics endpoint
          [env: VERITAS_METRICS_ENABLED]
          [default: false]

      --metrics-addr <ADDR>
          Metrics listen address
          [env: VERITAS_METRICS_ADDR]
          [default: 0.0.0.0:9090]

      --health-port <PORT>
          Health check port
          [env: VERITAS_HEALTH_PORT]
          [default: 8080]

      --node-identity <PATH>
          Node identity file path
          [env: VERITAS_NODE_IDENTITY]

      --max-connections <NUM>
          Maximum concurrent connections
          [env: VERITAS_MAX_CONNECTIONS]
          [default: 1000]

  -h, --help
          Print help

  -V, --version
          Print version
```

## Configuration File

Create a configuration file at `~/.veritas/config.toml` or specify with `--config`:

```toml
# VERITAS Node Configuration

[storage]
# Data directory for blockchain, messages, and keys
data_dir = "/var/lib/veritas"
# Use in-memory storage (for testing only)
in_memory = false
# Encrypt the database
encrypt_database = true

[network]
# P2P listen address (libp2p multiaddr format)
listen_addr = "/ip4/0.0.0.0/tcp/9000"
# WebSocket address for browser clients
ws_addr = "/ip4/0.0.0.0/tcp/9001/ws"
# Enable internet connectivity
enable_internet = true
# Enable local network discovery (mDNS)
enable_local_discovery = true
# Enable Bluetooth relay
enable_bluetooth = false
# Bootstrap peers
bootstrap_peers = [
    "/dns4/bootstrap1.veritas.network/tcp/9000/p2p/12D3KooW...",
    "/dns4/bootstrap2.veritas.network/tcp/9000/p2p/12D3KooW...",
]
# Connection timeout in seconds
connection_timeout_secs = 30
# Maximum connections
max_connections = 1000

[node]
# Enable relay mode (forward messages for other peers)
relay_mode = true
# Enable validator mode (participate in consensus)
validator_mode = false
# Node identity file (auto-generated if not specified)
# identity_file = "/var/lib/veritas/node-identity.key"

[logging]
# Log level: trace, debug, info, warn, error
level = "info"
# Log format: plain, json
format = "plain"
# Log file (optional, logs to stdout if not specified)
# file = "/var/log/veritas/node.log"

[health]
# Health check HTTP port
port = 8080
# Enable health endpoint
enabled = true

[metrics]
# Enable Prometheus metrics
enabled = false
# Metrics endpoint address
addr = "0.0.0.0:9090"

[reputation]
# Track peer reputation
enabled = true
# Decay rate percentage per week
decay_rate_percent = 1.0
# Enable weekly decay
enable_decay = true

[features]
# Add timing jitter for privacy
enable_timing_jitter = true
# Enable delivery receipts
enable_receipts = true
# Maximum queued messages
max_queued_messages = 1000
```

## Client Configuration (Library)

When using VERITAS as a library, configure via the builder:

```rust
use veritas_core::{ClientConfig, ClientConfigBuilder};
use std::path::PathBuf;
use std::time::Duration;

// Method 1: Use defaults
let config = ClientConfig::default();

// Method 2: In-memory configuration (for testing)
let config = ClientConfig::in_memory();

// Method 3: Builder pattern
let config = ClientConfigBuilder::new()
    // Storage
    .with_data_dir(PathBuf::from("/var/lib/veritas"))
    .with_encrypted_database()

    // Network
    .enable_internet()
    .enable_local_discovery()
    .disable_bluetooth()
    .with_bootstrap_peer("/dns4/bootstrap.veritas.network/tcp/9000/p2p/...".into())
    .with_connection_timeout(Duration::from_secs(30))

    // Features
    .enable_timing_jitter()
    .enable_receipts()
    .with_max_queued_messages(1000)

    .build();

// Method 4: Validate configuration
let config = ClientConfigBuilder::new()
    .with_data_dir(PathBuf::from("/var/lib/veritas"))
    .build_validated()?;  // Returns error if invalid
```

### ClientConfigBuilder Methods

#### Storage Configuration

| Method | Description |
|--------|-------------|
| `.with_data_dir(path)` | Set data directory |
| `.with_in_memory_storage()` | Use in-memory storage |
| `.with_disk_storage()` | Use disk storage (default) |
| `.with_encrypted_database()` | Enable database encryption (default) |
| `.with_unencrypted_database()` | Disable database encryption |

#### Network Configuration

| Method | Description |
|--------|-------------|
| `.enable_internet()` | Enable internet connectivity (default) |
| `.disable_internet()` | Disable internet connectivity |
| `.enable_local_discovery()` | Enable mDNS discovery (default) |
| `.disable_local_discovery()` | Disable mDNS discovery |
| `.enable_bluetooth()` | Enable Bluetooth relay (default) |
| `.disable_bluetooth()` | Disable Bluetooth relay |
| `.with_bootstrap_peer(addr)` | Add a bootstrap peer |
| `.with_bootstrap_peers(addrs)` | Set all bootstrap peers |
| `.with_connection_timeout(duration)` | Set connection timeout |

#### Reputation Configuration

| Method | Description |
|--------|-------------|
| `.enable_reputation_tracking()` | Enable reputation system (default) |
| `.disable_reputation_tracking()` | Disable reputation system |
| `.with_decay_rate(percent)` | Set decay rate (0.0-100.0) |
| `.enable_decay()` | Enable reputation decay (default) |
| `.disable_decay()` | Disable reputation decay |

#### Feature Configuration

| Method | Description |
|--------|-------------|
| `.enable_timing_jitter()` | Enable timing jitter for privacy (default) |
| `.disable_timing_jitter()` | Disable timing jitter |
| `.enable_receipts()` | Enable delivery receipts (default) |
| `.disable_receipts()` | Disable delivery receipts |
| `.with_max_queued_messages(n)` | Set maximum queued messages |

## Network Configuration

### Multiaddr Format

VERITAS uses libp2p multiaddrs for network addresses:

```
# IPv4 TCP
/ip4/192.168.1.100/tcp/9000

# IPv4 TCP with peer ID
/ip4/192.168.1.100/tcp/9000/p2p/12D3KooWExample...

# IPv6 TCP
/ip6/::1/tcp/9000

# DNS
/dns4/node.example.com/tcp/9000

# WebSocket
/ip4/0.0.0.0/tcp/9001/ws

# Combined (DNS + TCP + Peer ID)
/dns4/bootstrap.veritas.network/tcp/9000/p2p/12D3KooWExample...
```

### Port Assignments

| Port | Protocol | Purpose |
|------|----------|---------|
| 9000/tcp | libp2p | P2P communication |
| 9001/tcp | WebSocket | Browser clients |
| 8080/tcp | HTTP | Health checks |
| 9090/tcp | HTTP | Prometheus metrics |

### Bootstrap Nodes

Connect to the VERITAS network using bootstrap nodes:

```bash
# Single bootstrap node
veritas-node --bootstrap-nodes "/dns4/bootstrap1.veritas.network/tcp/9000/p2p/12D3KooW..."

# Multiple bootstrap nodes
veritas-node --bootstrap-nodes "/dns4/bootstrap1.veritas.network/tcp/9000/p2p/12D3KooW...,/dns4/bootstrap2.veritas.network/tcp/9000/p2p/12D3KooW..."
```

## Storage Configuration

### Data Directory Structure

```
/var/lib/veritas/
├── blockchain/         # Blockchain data
├── messages/           # Message queue
├── identities/         # Identity keyrings
├── peers/              # Peer information
└── node-identity.key   # Node identity (auto-generated)
```

### Database Encryption

By default, the database is encrypted using:
- **Key Derivation**: Argon2id (64 MiB memory, 3 iterations)
- **Encryption**: XChaCha20-Poly1305
- **Salt**: Stored in database metadata

## Security Configuration

### TLS/Noise

P2P connections are secured using:
- **Noise Protocol**: XX handshake pattern
- **Cipher**: ChaChaPoly
- **Key Exchange**: X25519

### Identity Protection

- Identity keys are encrypted at rest
- Password-protected keyring
- Zeroization on memory drop
- No plaintext key storage

### Recommended Settings

```toml
[storage]
encrypt_database = true

[network]
# Use specific listen address instead of 0.0.0.0 in production
listen_addr = "/ip4/YOUR_IP/tcp/9000"

[features]
enable_timing_jitter = true
```

## Example Configurations

### Development

```bash
veritas-node \
    --data-dir ./dev-data \
    --log-level debug \
    --relay-mode false
```

### Production

```bash
veritas-node \
    --data-dir /var/lib/veritas \
    --listen-addr /ip4/YOUR_PUBLIC_IP/tcp/9000 \
    --bootstrap-nodes "BOOTSTRAP_NODES" \
    --log-level info \
    --log-format json \
    --metrics-enabled true \
    --relay-mode true
```

### Testing

```rust
let config = ClientConfigBuilder::new()
    .with_in_memory_storage()
    .disable_timing_jitter()
    .build();
```

## Next Steps

- [Deployment Guide](DEPLOYMENT.md) - Production deployment
- [Troubleshooting](TROUBLESHOOTING.md) - Configuration issues
- [CLI Reference](CLI_REFERENCE.md) - Command line help
