# VERITAS CLI Reference

Complete command-line reference for VERITAS tools.

## Table of Contents

- [veritas-node](#veritas-node)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)
- [Examples](#examples)

## veritas-node

The main VERITAS node daemon.

### Synopsis

```
veritas-node [OPTIONS]
```

### Options

#### Core Options

```
-d, --data-dir <PATH>
    Path to data directory for blockchain, messages, and keys.

    Default: /var/lib/veritas
    Env: VERITAS_DATA_DIR

-l, --listen-addr <MULTIADDR>
    Listen address for P2P connections in libp2p multiaddr format.

    Default: /ip4/0.0.0.0/tcp/9000
    Env: VERITAS_LISTEN_ADDR

    Examples:
      /ip4/0.0.0.0/tcp/9000         # Listen on all interfaces, port 9000
      /ip4/192.168.1.100/tcp/9000   # Listen on specific IP
      /ip6/::1/tcp/9000             # Listen on IPv6 localhost

--ws-addr <MULTIADDR>
    WebSocket listen address for browser clients.

    Default: None (disabled)
    Env: VERITAS_WS_ADDR

    Example: /ip4/0.0.0.0/tcp/9001/ws
```

#### Network Options

```
-b, --bootstrap-nodes <NODES>
    Comma-separated list of bootstrap node multiaddrs.

    Default: None
    Env: VERITAS_BOOTSTRAP_NODES

    Example:
      --bootstrap-nodes "/dns4/boot1.veritas.net/tcp/9000/p2p/12D3KooW...,
                         /dns4/boot2.veritas.net/tcp/9000/p2p/12D3KooW..."

--max-connections <NUM>
    Maximum number of concurrent peer connections.

    Default: 1000
    Env: VERITAS_MAX_CONNECTIONS
```

#### Mode Options

```
--relay-mode <BOOL>
    Enable message relay mode. When enabled, the node will forward
    messages for other peers on the network.

    Default: true
    Env: VERITAS_RELAY_MODE

--validator-mode <BOOL>
    Enable validator mode. Requires sufficient stake to participate
    in consensus.

    Default: false
    Env: VERITAS_VALIDATOR_MODE

--node-identity <PATH>
    Path to node identity file. If not specified, a new identity
    will be generated and stored in the data directory.

    Default: <data-dir>/node-identity.key
    Env: VERITAS_NODE_IDENTITY
```

#### Logging Options

```
--log-level <LEVEL>
    Set the logging verbosity level.

    Values: trace, debug, info, warn, error
    Default: info
    Env: VERITAS_LOG_LEVEL

--log-format <FORMAT>
    Set the log output format.

    Values: plain, json
    Default: plain
    Env: VERITAS_LOG_FORMAT

    Plain format:
      2026-01-29T12:00:00.000Z INFO veritas_node: Starting VERITAS node

    JSON format:
      {"timestamp":"2026-01-29T12:00:00.000Z","level":"INFO","target":"veritas_node","message":"Starting VERITAS node"}
```

#### Health & Metrics Options

```
--health-port <PORT>
    Port for the HTTP health check endpoint.

    Default: 8080
    Env: VERITAS_HEALTH_PORT

    Endpoints:
      GET /health  - Returns {"status":"ok"} if healthy
      GET /ready   - Returns {"ready":"true"} if ready to serve

--metrics-enabled <BOOL>
    Enable Prometheus metrics endpoint.

    Default: false
    Env: VERITAS_METRICS_ENABLED

--metrics-addr <ADDR>
    Address for the Prometheus metrics endpoint.

    Default: 0.0.0.0:9090
    Env: VERITAS_METRICS_ADDR
```

#### General Options

```
-h, --help
    Print help information and exit.

-V, --version
    Print version information and exit.
```

## Environment Variables

All options can be set via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `VERITAS_DATA_DIR` | Data directory | `/var/lib/veritas` |
| `VERITAS_LISTEN_ADDR` | P2P listen address | `/ip4/0.0.0.0/tcp/9000` |
| `VERITAS_WS_ADDR` | WebSocket address | None |
| `VERITAS_BOOTSTRAP_NODES` | Bootstrap nodes | None |
| `VERITAS_MAX_CONNECTIONS` | Max connections | `1000` |
| `VERITAS_RELAY_MODE` | Enable relay | `true` |
| `VERITAS_VALIDATOR_MODE` | Enable validator | `false` |
| `VERITAS_NODE_IDENTITY` | Identity file path | None |
| `VERITAS_LOG_LEVEL` | Log level | `info` |
| `VERITAS_LOG_FORMAT` | Log format | `plain` |
| `VERITAS_HEALTH_PORT` | Health port | `8080` |
| `VERITAS_METRICS_ENABLED` | Enable metrics | `false` |
| `VERITAS_METRICS_ADDR` | Metrics address | `0.0.0.0:9090` |

Environment variables can be combined with command-line arguments.
Command-line arguments take precedence.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | General error |
| `2` | Configuration error |
| `3` | Network error |
| `4` | Storage error |

## Examples

### Basic Usage

```bash
# Start with defaults
veritas-node

# Specify data directory
veritas-node --data-dir /custom/path

# Use a different port
veritas-node --listen-addr /ip4/0.0.0.0/tcp/9001
```

### Network Configuration

```bash
# Connect to bootstrap nodes
veritas-node --bootstrap-nodes "/dns4/bootstrap.veritas.network/tcp/9000/p2p/12D3KooWExample..."

# Enable WebSocket for browsers
veritas-node --ws-addr /ip4/0.0.0.0/tcp/9001/ws

# Limit connections
veritas-node --max-connections 500
```

### Mode Configuration

```bash
# Disable relay mode
veritas-node --relay-mode false

# Enable validator mode
veritas-node --validator-mode true

# Specify node identity
veritas-node --node-identity /etc/veritas/node.key
```

### Logging Configuration

```bash
# Enable debug logging
veritas-node --log-level debug

# JSON logging for log aggregation
veritas-node --log-format json

# Verbose tracing
veritas-node --log-level trace
```

### Monitoring Configuration

```bash
# Enable metrics
veritas-node --metrics-enabled true --metrics-addr 0.0.0.0:9090

# Custom health port
veritas-node --health-port 8081
```

### Production Configuration

```bash
veritas-node \
    --data-dir /var/lib/veritas \
    --listen-addr /ip4/YOUR_PUBLIC_IP/tcp/9000 \
    --bootstrap-nodes "BOOTSTRAP_NODES" \
    --log-level info \
    --log-format json \
    --relay-mode true \
    --metrics-enabled true
```

### Using Environment Variables

```bash
# Set environment variables
export VERITAS_DATA_DIR=/var/lib/veritas
export VERITAS_LOG_LEVEL=info
export VERITAS_BOOTSTRAP_NODES="/dns4/boot1.veritas.net/tcp/9000/p2p/..."

# Run with environment configuration
veritas-node
```

### Docker

```bash
docker run -d \
    --name veritas-node \
    -p 9000:9000 \
    -p 8080:8080 \
    -v veritas-data:/var/lib/veritas \
    -e VERITAS_LOG_LEVEL=info \
    -e VERITAS_BOOTSTRAP_NODES="..." \
    ghcr.io/veritas-protocol/veritas-node:latest
```

### Systemd

```bash
# Check status
systemctl status veritas-node

# View logs
journalctl -u veritas-node -f

# Restart
systemctl restart veritas-node
```

## Health Check Endpoints

### GET /health

Returns the node health status.

**Response:**
```json
{"status": "ok"}
```

**Status Codes:**
- `200` - Node is healthy
- `503` - Node is unhealthy

### GET /ready

Returns the node readiness status.

**Response:**
```json
{"ready": "true"}
```

**Status Codes:**
- `200` - Node is ready
- `503` - Node is not ready

### Usage

```bash
# Check health
curl http://localhost:8080/health

# Check readiness
curl http://localhost:8080/ready

# Use in scripts
if curl -sf http://localhost:8080/health > /dev/null; then
    echo "Node is healthy"
else
    echo "Node is unhealthy"
fi
```

## See Also

- [Configuration Guide](CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
- [Troubleshooting](TROUBLESHOOTING.md)
