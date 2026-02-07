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
- [Rate Limiting Configuration](#rate-limiting-configuration) (v0.3.0-beta)
- [Subnet Limiting Configuration](#subnet-limiting-configuration) (v0.3.0-beta)
- [Time Validation Configuration](#time-validation-configuration) (v0.3.0-beta)
- [Security Constants](#security-constants) (v0.3.0-beta)
- [Hardware Attestation Configuration](#hardware-attestation-configuration) (v0.3.0-beta)
- [Encrypted Storage Configuration](#encrypted-storage-configuration) (v0.3.0-beta)
- [Reputation System Configuration](#reputation-system-configuration) (v0.3.0-beta)

## Configuration Methods

VERITAS supports three configuration methods (in order of precedence):

1. **Command Line Arguments** - Highest priority
2. **Environment Variables** - Medium priority
3. **Configuration File** - Lowest priority

## Environment Variables

### Core Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_DATA_DIR` | `~/.local/share/veritas` | Data storage directory |
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
          [default: ~/.local/share/veritas]

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
~/.local/share/veritas/      # Default on Linux/macOS
├── blockchain/               # Blockchain data (headers, transactions, epochs)
├── messages/                 # Message queue
├── identities/               # Identity keyrings
├── peers/                    # Peer information
└── node-identity.key         # Node identity (auto-generated)
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

## Rate Limiting Configuration

**New in v0.3.0-beta** - Addresses VERITAS-2026-0007 (Gossip protocol flooding)

Rate limiting prevents flooding attacks that could exhaust network resources. VERITAS implements a token bucket algorithm for rate limiting at both per-peer and global levels.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_RATE_LIMIT_PER_PEER` | `10` | Max announcements per peer per second |
| `VERITAS_RATE_LIMIT_GLOBAL` | `1000` | Max global announcements per second |
| `VERITAS_RATE_LIMIT_BURST` | `3` | Burst multiplier for token bucket |
| `VERITAS_RATE_LIMIT_VIOLATIONS` | `5` | Violations before peer is banned |
| `VERITAS_RATE_LIMIT_BAN_DURATION` | `300` | Ban duration in seconds |

### Configuration File

```toml
[rate_limiting]
# Maximum announcements allowed per peer per second
# Default: 10
# Range: 1-100
# Security: Lower values provide stronger DoS protection but may impact
# legitimate high-traffic peers
per_peer_rate = 10

# Maximum global announcements allowed per second
# Default: 1000
# Range: 100-10000
# Security: Set based on your node's capacity; too high allows flooding
global_rate = 1000

# Burst multiplier - how many tokens can accumulate
# Actual burst = rate * burst_multiplier
# Default: 3
# Range: 1-10
# Security: Higher values allow more burst traffic but reduce protection
burst_multiplier = 3

# Number of violations before a peer is banned
# Default: 5
# Range: 1-20
# Security: Lower values are stricter; higher values are more tolerant
violations_before_ban = 5

# Duration of a ban in seconds
# Default: 300 (5 minutes)
# Range: 60-86400
# Security: Longer bans deter repeat offenders but risk blocking
# legitimate peers with transient issues
ban_duration_secs = 300
```

### Library Configuration

```rust
use veritas_net::rate_limiter::{RateLimiter, RateLimitConfig};

let config = RateLimitConfig::new()
    .with_per_peer_rate(10)
    .with_global_rate(1000)
    .with_burst_multiplier(3)
    .with_violations_before_ban(5)
    .with_ban_duration_secs(300);

let limiter = RateLimiter::new(config);
```

### Tuning for Different Network Conditions

| Environment | per_peer_rate | global_rate | burst | Notes |
|-------------|---------------|-------------|-------|-------|
| Low-bandwidth | 5 | 500 | 2 | Conservative for limited resources |
| Standard | 10 | 1000 | 3 | Default, suitable for most deployments |
| High-traffic relay | 20 | 5000 | 5 | For dedicated relay infrastructure |
| Testing | 100 | 10000 | 10 | Permissive for development |

### Security Implications

- **Too permissive**: Attackers can flood your node with announcements, causing bandwidth/CPU/memory exhaustion
- **Too restrictive**: Legitimate peers may be rate-limited or banned, reducing network connectivity
- **Burst multiplier**: Allows temporary traffic spikes but must be balanced against sustained attack resistance

---

## Subnet Limiting Configuration

**New in v0.3.0-beta** - Addresses VERITAS-2026-0006 (DHT Eclipse Attack)

Subnet limiting enforces routing table diversity to prevent eclipse attacks on the Kademlia DHT. By limiting peers from each /24 subnet, it becomes significantly harder for attackers to position Sybil nodes to intercept traffic.

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_MAX_PEERS_PER_SUBNET` | `2` | Max peers from same /24 subnet |
| `VERITAS_ALLOW_UNKNOWN_SUBNETS` | `true` | Accept peers without IP info |
| `VERITAS_MAX_UNKNOWN_SUBNET_PEERS` | `5` | Max peers with unknown subnets |

### Configuration File

```toml
[subnet_limiting]
# Maximum peers allowed per /24 subnet (IPv4) or /48 subnet (IPv6)
# Default: 2
# Range: 1-10
# Security: Lower values provide stronger eclipse attack protection
# but may limit connectivity in networks with many peers on same subnet
max_peers_per_subnet = 2

# Whether to allow peers with unknown subnets (DNS-based addresses)
# Default: true
# Security: Setting to false provides stricter protection but may
# reject legitimate peers using DNS addresses
allow_unknown_subnets = true

# Maximum peers with unknown subnets allowed
# Default: 5
# Range: 0-20
# Security: Limits exposure from DNS-based peer addresses
max_unknown_subnet_peers = 5

# Minimum reputation score for peer acceptance
# Default: -100 (allow all)
# Range: -100 to 100
# Security: Higher values only accept peers with good history
min_acceptance_reputation = -100

# Whether to prefer higher-reputation peers when subnet is at capacity
# Default: true
# Security: Enables replacing low-reputation peers with better ones
prefer_higher_reputation = true
```

### Library Configuration

```rust
use veritas_net::subnet_limiter::{SubnetLimiter, SubnetLimiterConfig};

let config = SubnetLimiterConfig {
    max_peers_per_subnet: 2,
    allow_unknown_subnets: true,
    max_unknown_subnet_peers: 5,
    min_acceptance_reputation: -100,
    prefer_higher_reputation: true,
};

let limiter = SubnetLimiter::with_config(config);
```

### DHT Reputation Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `INITIAL_REPUTATION` | 0 | Starting reputation for new peers |
| `MIN_TRUSTED_REPUTATION` | 10 | Threshold for trusted peer status |
| `REPUTATION_GAIN_SUCCESS` | +1 | Gain for successful DHT operation |
| `REPUTATION_LOSS_FAILURE` | -5 | Loss for failed DHT operation |
| `REPUTATION_LOSS_SUSPICIOUS` | -20 | Loss for suspicious behavior |
| `MAX_REPUTATION` | 100 | Maximum reputation score |
| `MIN_REPUTATION` | -100 | Minimum reputation score |

### Security Implications

- **Eclipse attacks**: Without subnet limiting, an attacker controlling multiple IPs in the same /24 can monopolize your routing table, intercepting all DHT queries
- **IPv4 vs IPv6**: IPv4 uses /24 mask (256 addresses), IPv6 uses /48 mask
- **Unknown subnets**: DNS addresses cannot be subnet-checked; limit their count to reduce risk

---

## Time Validation Configuration

**New in v0.3.0-beta** - Addresses VERITAS-2026-0008 and VERITAS-2026-0009 (Time manipulation attacks)

Time validation prevents attackers from using manipulated timestamps to bypass key expiry or replay old messages.

### Constants (Compile-Time)

These are security-critical constants that cannot be changed at runtime:

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CLOCK_SKEW_SECS` | 300 (5 min) | Maximum allowed future timestamp |
| `MIN_VALID_TIMESTAMP` | 1704067200 | Minimum valid timestamp (2024-01-01) |
| `MAX_VALID_TIMESTAMP` | 4102444800 | Maximum valid timestamp (2100-01-01) |

### Handling Clock Synchronization Issues

If your node experiences clock synchronization problems:

1. **Ensure NTP is running**:
   ```bash
   # Linux (systemd)
   sudo systemctl enable --now systemd-timesyncd
   timedatectl status

   # Linux (ntpd)
   sudo systemctl enable --now ntpd
   ntpq -p
   ```

2. **Check clock drift**:
   ```bash
   # Compare with remote NTP server
   ntpdate -q pool.ntp.org
   ```

3. **Force time sync if needed**:
   ```bash
   sudo ntpdate pool.ntp.org
   ```

### Configuration File

```toml
[time_validation]
# Enable strict time validation (recommended)
# Default: true
# Security: Disabling allows replay attacks and timestamp manipulation
strict_validation = true

# Trusted NTP servers for time verification (optional)
# Default: [] (use system time)
# Security: Using trusted NTP servers adds defense against local clock attacks
ntp_servers = [
    "time.google.com",
    "time.cloudflare.com",
    "pool.ntp.org",
]

# Enable NTP time verification alongside system time
# Default: false
# Security: Provides additional assurance but adds network latency
enable_ntp_verification = false
```

### Validation Behavior

```
Timeline:
                                   MAX_CLOCK_SKEW_SECS
                                         (5 min)
                                           |
                                           v
MIN_VALID_TIMESTAMP             now()    now()+300s    MAX_VALID_TIMESTAMP
     |                            |         |                |
     v                            v         v                v
-----|----------------------------[=========]----------------|-----
     ^                            ^         ^                ^
     |                            |         |                |
  REJECTED                      VALID    VALID           REJECTED
 (too old)                               (within         (too far
                                          skew)           future)
```

### Security Implications

- **Clock skew**: 5 minutes allows reasonable tolerance for clock drift while preventing gross manipulation
- **Minimum timestamp**: Prevents replay of pre-protocol messages
- **Maximum timestamp**: Sanity check against garbage or malicious data

---

## Security Constants

**New in v0.3.0-beta** - Comprehensive protocol security limits

These constants define security boundaries for the VERITAS protocol. They are enforced at the protocol level and cannot be overridden by configuration.

### Message Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_MESSAGE_CHARS` | 300 | Maximum characters per message chunk |
| `MAX_CHUNKS_PER_MESSAGE` | 3 | Maximum chunks per message |
| `MAX_TOTAL_MESSAGE_CHARS` | 900 | Total characters across all chunks |
| `MESSAGE_TTL_SECS` | 604800 (7 days) | Message time-to-live |

### DoS Prevention Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_ENVELOPE_SIZE` | 8192 bytes | Maximum serialized envelope size |
| `MAX_INNER_ENVELOPE_SIZE` | 1536 bytes | Maximum inner payload size (pre-padding) |
| `MAX_REASSEMBLY_BUFFER` | 4096 bytes | Maximum chunk reassembly buffer |
| `MAX_PENDING_REASSEMBLIES` | 1000 | Maximum concurrent reassembly sessions |
| `REASSEMBLY_TIMEOUT_SECS` | 300 (5 min) | Timeout for incomplete reassembly |

**Security Note**: `MAX_ENVELOPE_SIZE` is checked BEFORE deserialization to prevent OOM attacks (VERITAS-2026-0003).

### Privacy Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PADDING_BUCKETS` | [1024, 2048, 4096, 8192] | Message padding sizes |
| `MAX_JITTER_MS` | 3000 (3 sec) | Maximum timing jitter |
| `EPOCH_DURATION_SECS` | 2592000 (30 days) | Epoch duration for pruning |

### Identity Limits

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_IDENTITIES_PER_ORIGIN` | 3 | Maximum identities per device |
| `KEY_EXPIRY_SECS` | 2592000 (30 days) | Key expiry time |
| `KEY_WARNING_SECS` | 432000 (5 days) | Warning period before expiry |
| `EXPIRY_GRACE_PERIOD_SECS` | 86400 (24 hours) | Grace period after expiry |
| `MIN_USERNAME_LEN` | 3 | Minimum username length |
| `MAX_USERNAME_LEN` | 32 | Maximum username length |

### Configuration File Reference

```toml
# These values are INFORMATIONAL ONLY - they cannot be overridden
# They are enforced at the protocol level for security

[protocol_limits]
# Message constraints
max_message_chars = 300
max_chunks_per_message = 3
message_ttl_secs = 604800

# DoS prevention
max_envelope_size = 8192
max_inner_envelope_size = 1536

# Identity limits
max_identities_per_origin = 3
key_expiry_secs = 2592000
```

---

## Hardware Attestation Configuration

**New in v0.3.0-beta** - Addresses VERITAS-2026-0001 (Sybil Attack via unlimited identity creation)

Hardware attestation ensures that origin fingerprints are bound to physical devices, preventing unlimited identity creation by malicious actors.

### Platform Support

| Platform | Attestation Method | Binding Strength |
|----------|-------------------|------------------|
| Linux/Windows | TPM 2.0 | Strong |
| macOS/iOS | Secure Enclave | Strong |
| Android | Hardware-backed Keystore | Strong |
| Other | Generic Hardware | Weak (rejected in production) |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VERITAS_REQUIRE_HARDWARE_ATTESTATION` | `true` | Require hardware binding |
| `VERITAS_ATTESTATION_MAX_AGE_SECS` | `300` | Maximum attestation age |

### Configuration File

```toml
[hardware_attestation]
# Require hardware-bound origin fingerprints
# Default: true (production), false (testing)
# Security: MUST be true in production to prevent Sybil attacks
require_hardware_binding = true

# Maximum age of attestation before re-collection required (seconds)
# Default: 300 (5 minutes)
# Range: 60-600
# Security: Shorter times are more secure but require more frequent
# attestation collection
attestation_max_age_secs = 300

# Allow generic hardware attestation (development only)
# Default: false
# Security: MUST be false in production; generic attestation can be spoofed
allow_generic_attestation = false

# Fallback behavior when hardware attestation is unavailable
# Options: "deny", "warn", "allow_once"
# Default: "deny"
# Security: "deny" is recommended; "allow_once" permits single identity
# without hardware binding for user onboarding
fallback_behavior = "deny"
```

### Library Configuration

```rust
use veritas_identity::hardware::HardwareAttestation;
use veritas_identity::limits::OriginFingerprint;

// Collect hardware attestation (platform-specific)
let attestation = HardwareAttestation::collect()?;

// Verify the attestation is valid
attestation.verify()?;

// Create a hardware-bound origin fingerprint
let origin = OriginFingerprint::from_hardware(&attestation)?;
```

### Attestation Verification

The attestation system enforces:

1. **Hardware ID validation**: 16-256 bytes
2. **Signature validation**: Non-empty, max 512 bytes
3. **Timestamp freshness**: Within `ATTESTATION_MAX_AGE_SECS`
4. **Platform verification**: Platform-specific cryptographic proof

### Security Implications

- **Without hardware attestation**: Attackers can create unlimited origin fingerprints, bypassing the 3-identity-per-device limit
- **Strong binding required**: Only TPM 2.0, Secure Enclave, and Android Keystore provide sufficient security guarantees
- **Attestation age**: Prevents reuse of stale attestations that may have been compromised

---

## Encrypted Storage Configuration

**New in v0.3.0-beta** - Enhanced database and queue encryption

All sensitive data is encrypted at rest using ChaCha20-Poly1305 with keys derived from Argon2id.

### Argon2id Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Memory | 65536 KiB (64 MiB) | Memory-hard to resist GPU attacks |
| Iterations | 3 | Time cost for key derivation |
| Parallelism | 4 | Parallel lanes for multi-core CPUs |
| Output Length | 32 bytes | Derived key size |

### Configuration File

```toml
[storage]
# Data directory for blockchain, messages, and keys
data_dir = "/var/lib/veritas"

# Encrypt the database (mandatory in v0.3.0-beta)
# Default: true
# Security: CANNOT be disabled; all storage is encrypted
encrypt_database = true

# Use in-memory storage (for testing only)
# Default: false
# Security: Data is lost on restart; only for development
in_memory = false

[storage.encryption]
# Argon2id memory cost in KiB
# Default: 65536 (64 MiB)
# Range: 16384-262144 (16 MiB - 256 MiB)
# Security: Higher values provide better resistance to GPU/ASIC attacks
# but increase memory usage and derivation time
argon2_memory_kib = 65536

# Argon2id time cost (iterations)
# Default: 3
# Range: 1-10
# Security: Higher values increase derivation time, improving security
# but adding latency to database open
argon2_iterations = 3

# Argon2id parallelism (lanes)
# Default: 4
# Range: 1-8
# Security: Should match or be less than CPU core count
# Higher values improve performance but increase memory usage
argon2_parallelism = 4

[storage.message_queue]
# Message queue encryption is MANDATORY in v0.3.0-beta
# This setting is informational only
queue_encryption = "mandatory"

# Maximum queued messages per identity
# Default: 1000
# Range: 100-10000
# Security: Limits storage exhaustion from queued messages
max_queued_messages = 1000
```

### Library Configuration

```rust
use veritas_store::encrypted_db::EncryptedDb;
use std::path::Path;

// Open encrypted database with password
let db = EncryptedDb::open(
    Path::new("/var/lib/veritas/data"),
    b"secure-password"
)?;

// All operations automatically encrypt/decrypt
db.put(b"key", b"sensitive-value")?;
let value = db.get(b"key")?;
```

### Security Properties

| Property | Description |
|----------|-------------|
| Password never stored | Only derived key used for encryption |
| Unique nonce per value | XChaCha20-Poly1305 with random nonce |
| Salt stored in metadata | Enables consistent key derivation |
| Key zeroized on drop | Prevents memory disclosure |

### Performance Considerations

| Argon2 Memory | Derivation Time | Security Level |
|---------------|-----------------|----------------|
| 16 MiB | ~100ms | Minimum acceptable |
| 64 MiB (default) | ~300ms | Recommended |
| 128 MiB | ~600ms | High security |
| 256 MiB | ~1200ms | Maximum |

---

## Reputation System Configuration

**New in v0.3.0-beta** - Enhanced anti-gaming measures with interaction proofs

The reputation system tracks peer behavior and prevents gaming through rate limiting, interaction proofs, and cluster detection.

### Reputation Thresholds

| Threshold | Value | Description |
|-----------|-------|-------------|
| `REPUTATION_START` | 100 | Initial reputation for new identities |
| `REPUTATION_MAX` | 1000 | Maximum possible reputation |
| `REPUTATION_QUARANTINE` | 200 | Below this, messages may be delayed |
| `REPUTATION_BLACKLIST` | 50 | Below this, messages are rejected |

### Anti-Gaming Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MIN_MESSAGE_INTERVAL_SECS` | 60 | Min seconds between messages to same peer |
| `MAX_DAILY_GAIN_PER_PEER` | 30 | Max reputation gain from one peer per day |
| `MAX_DAILY_GAIN_TOTAL` | 100 | Max total reputation gain per day |
| `NEGATIVE_REPORT_THRESHOLD` | 3 | Reports needed for negative action |
| `MIN_REPORTER_REPUTATION` | 400 | Min reputation to file reports |
| `CLUSTER_SUSPICION_THRESHOLD` | 0.7 | Threshold for cluster detection (70%) |

### Configuration File

```toml
[reputation]
# Enable reputation tracking
# Default: true
# Security: Disabling removes anti-spam protection
enabled = true

# Decay rate percentage per week
# Default: 1.0
# Range: 0.0-10.0
# Security: Higher decay rates prevent reputation hoarding
# but may penalize inactive legitimate users
decay_rate_percent = 1.0

# Enable weekly decay
# Default: true
# Security: Decay prevents permanent high reputation from past activity
enable_decay = true

[reputation.anti_gaming]
# Minimum seconds between messages to the same peer
# for reputation gain eligibility
# Default: 60
# Range: 30-300
# Security: Prevents rapid-fire reputation farming
min_message_interval_secs = 60

# Maximum reputation gain from any single peer per 24h period
# Default: 30
# Range: 10-100
# Security: Prevents Sybil pairs from farming each other
max_daily_gain_per_peer = 30

# Maximum total reputation gain per 24h period
# Default: 100
# Range: 50-500
# Security: Absolute cap on daily reputation growth
max_daily_gain_total = 100

# Number of independent negative reports required
# before taking action against an identity
# Default: 3
# Range: 2-10
# Security: Prevents single malicious reporter from griefing
negative_report_threshold = 3

[reputation.interaction_proofs]
# Require cryptographic interaction proofs for reputation changes
# Default: true (mandatory in v0.3.0-beta)
# Security: Prevents fake reputation without actual interaction
require_proofs = true

# Proof nonce expiry time in seconds
# Default: 86400 (24 hours)
# Range: 3600-604800
# Security: Shorter times prevent nonce reuse attacks but require
# more frequent proof generation
nonce_expiry_secs = 86400
```

### Interaction Proof System

Reputation changes now require cryptographic proof of actual interaction:

```rust
use veritas_reputation::proof::InteractionProof;

// Generate proof when sending a message
let proof = InteractionProof::new(
    &sender_keypair,
    &recipient_public_key,
    interaction_type,
)?;

// Verify proof before recording reputation
proof.verify(&sender_pubkey, Some(&recipient_pubkey))?;

// Record interaction with verified proof
reputation_manager.record_positive_interaction(
    sender_hash,
    recipient_hash,
    &proof,
)?;
```

### Validator Requirements

| Requirement | Value | Description |
|-------------|-------|-------------|
| `MIN_VALIDATOR_STAKE` | 700 | Minimum reputation to become validator |
| `MAX_VALIDATORS` | 21 | Maximum active validators |
| `VALIDATOR_ROTATION_PERCENT` | 15% | Validators rotated per epoch |
| `MAX_VALIDATORS_PER_REGION` | 5 | Geographic distribution limit |
| `MIN_UPTIME_PERCENT` | 99.0% | Required validator uptime |
| `MAX_MISSED_BLOCKS_PER_EPOCH` | 3 | Maximum missed blocks |

### Security Implications

- **Without interaction proofs**: Attackers can generate fake reputation through Sybil identities
- **Without rate limits**: Colluding identities can rapidly inflate each other's reputation
- **Cluster detection**: Identifies suspicious patterns of mutual reputation boosting at 70% threshold

---

## Example Complete Configuration

```toml
# VERITAS Node Configuration - v0.3.0-beta
# Production-ready configuration with all security features

[storage]
data_dir = "/var/lib/veritas"
encrypt_database = true
in_memory = false

[storage.encryption]
argon2_memory_kib = 65536
argon2_iterations = 3
argon2_parallelism = 4

[network]
listen_addr = "/ip4/0.0.0.0/tcp/9000"
ws_addr = "/ip4/0.0.0.0/tcp/9001/ws"
enable_internet = true
enable_local_discovery = true
enable_bluetooth = false
connection_timeout_secs = 30
max_connections = 1000

[rate_limiting]
per_peer_rate = 10
global_rate = 1000
burst_multiplier = 3
violations_before_ban = 5
ban_duration_secs = 300

[subnet_limiting]
max_peers_per_subnet = 2
allow_unknown_subnets = true
max_unknown_subnet_peers = 5
prefer_higher_reputation = true

[hardware_attestation]
require_hardware_binding = true
attestation_max_age_secs = 300
allow_generic_attestation = false
fallback_behavior = "deny"

[time_validation]
strict_validation = true
enable_ntp_verification = false

[reputation]
enabled = true
decay_rate_percent = 1.0
enable_decay = true

[reputation.anti_gaming]
min_message_interval_secs = 60
max_daily_gain_per_peer = 30
max_daily_gain_total = 100
negative_report_threshold = 3

[reputation.interaction_proofs]
require_proofs = true
nonce_expiry_secs = 86400

[node]
relay_mode = true
validator_mode = false

[logging]
level = "info"
format = "json"

[health]
port = 8080
enabled = true

[metrics]
enabled = true
addr = "0.0.0.0:9090"

[features]
enable_timing_jitter = true
enable_receipts = true
max_queued_messages = 1000
```

---

## Next Steps

- [Deployment Guide](../guides/DEPLOYMENT.md) - Production deployment
- [Troubleshooting](../guides/TROUBLESHOOTING.md) - Configuration issues
- [CLI Reference](../guides/CLI_REFERENCE.md) - Command line help
