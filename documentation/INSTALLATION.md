# VERITAS Installation Guide

Complete installation instructions for all platforms and deployment methods.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installing Rust](#installing-rust)
- [Building from Source](#building-from-source)
- [Docker Installation](#docker-installation)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Verifying Installation](#verifying-installation)
- [Post-Installation](#post-installation)

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **CPU** | 2 cores, x86_64 or ARM64 |
| **RAM** | 2 GB |
| **Disk** | 10 GB free space |
| **OS** | Linux (Ubuntu 20.04+), macOS 12+, Windows 10+ |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| **CPU** | 4+ cores |
| **RAM** | 8 GB |
| **Disk** | 50 GB SSD |
| **Network** | Static IP, open ports 9000/tcp, 8080/tcp |

### Software Dependencies

| Software | Version | Purpose |
|----------|---------|---------|
| **Rust** | 1.75+ | Build toolchain |
| **Git** | 2.x | Source control |
| **OpenSSL** | 1.1+ | TLS support |
| **pkg-config** | Any | Build dependency resolution |

## Installing Rust

### Using rustup (Recommended)

```bash
# Install rustup (Linux/macOS)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Follow the prompts, then reload your shell
source $HOME/.cargo/env

# Verify installation
rustc --version
# Output: rustc 1.75.0 (or higher)

cargo --version
# Output: cargo 1.75.0 (or higher)
```

### Windows Installation

1. Download rustup-init.exe from https://rustup.rs
2. Run the installer
3. Follow the prompts (install Visual Studio Build Tools if prompted)
4. Open a new terminal and verify:
   ```powershell
   rustc --version
   cargo --version
   ```

### Update Rust

```bash
# Update to the latest stable version
rustup update stable

# Set stable as default
rustup default stable
```

## Building from Source

### Step 1: Install System Dependencies

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    git
```

#### Fedora/RHEL

```bash
sudo dnf install -y \
    gcc \
    gcc-c++ \
    pkg-config \
    openssl-devel \
    clang-devel \
    cmake \
    git
```

#### macOS

```bash
# Install Xcode command line tools
xcode-select --install

# Install Homebrew dependencies
brew install openssl pkg-config cmake
```

#### Windows

```powershell
# Install Visual Studio Build Tools 2019 or later
# Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/

# Or use winget
winget install Microsoft.VisualStudio.2022.BuildTools
```

### Step 2: Clone the Repository

```bash
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol
```

### Step 3: Build

```bash
# Debug build (faster compilation, slower runtime)
cargo build

# Release build (slower compilation, optimized runtime)
cargo build --release

# Build specific binary only
cargo build --release --bin veritas-node
```

### Step 4: Install (Optional)

```bash
# Install to ~/.cargo/bin
cargo install --path crates/veritas-node

# Verify installation
veritas-node --version
```

### Build Options

```bash
# Build with all features
cargo build --release --all-features

# Build without default features
cargo build --release --no-default-features

# Build specific crates only
cargo build --release -p veritas-core -p veritas-node
```

## Docker Installation

### Prerequisites

- Docker 20.10+
- Docker Compose 2.0+ (optional)

### Using Pre-built Image

```bash
# Pull the latest image
docker pull ghcr.io/gl-tches/veritas-protocol:latest

# Run the node
docker run -d \
    --name veritas-node \
    -p 9000:9000 \
    -p 8080:8080 \
    -v veritas-data:/var/lib/veritas \
    ghcr.io/gl-tches/veritas-protocol:latest
```

### Building Docker Image Locally

```bash
# Clone the repository
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol

# Build the image
docker build -t veritas-node:local .

# Run the locally built image
docker run -d \
    --name veritas-node \
    -p 9000:9000 \
    -p 8080:8080 \
    -v veritas-data:/var/lib/veritas \
    veritas-node:local
```

### Using Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f veritas-node

# Stop services
docker-compose down
```

## Platform-Specific Instructions

### Linux (systemd Service)

```bash
# Create systemd service file
sudo tee /etc/systemd/system/veritas-node.service > /dev/null << 'EOF'
[Unit]
Description=VERITAS Protocol Node
After=network.target

[Service]
Type=simple
User=veritas
Group=veritas
ExecStart=/usr/local/bin/veritas-node --data-dir /var/lib/veritas
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/veritas
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Create user and directories
sudo useradd -r -s /bin/false veritas
sudo mkdir -p /var/lib/veritas
sudo chown veritas:veritas /var/lib/veritas

# Copy binary
sudo cp target/release/veritas-node /usr/local/bin/

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable veritas-node
sudo systemctl start veritas-node

# Check status
sudo systemctl status veritas-node
```

### macOS (launchd Service)

```bash
# Create launchd plist
cat > ~/Library/LaunchAgents/com.veritas.node.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.veritas.node</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/veritas-node</string>
        <string>--data-dir</string>
        <string>/Users/your-username/.veritas</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/veritas-node.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/veritas-node.error.log</string>
</dict>
</plist>
EOF

# Load the service
launchctl load ~/Library/LaunchAgents/com.veritas.node.plist
```

### Windows (Service)

```powershell
# Using NSSM (Non-Sucking Service Manager)
# Download from https://nssm.cc/

# Install as service
nssm install VeritasNode "C:\Program Files\Veritas\veritas-node.exe"
nssm set VeritasNode AppParameters "--data-dir C:\ProgramData\Veritas"
nssm set VeritasNode AppDirectory "C:\Program Files\Veritas"
nssm set VeritasNode Start SERVICE_AUTO_START

# Start the service
nssm start VeritasNode
```

## Verifying Installation

### Check Binary

```bash
# Version check
veritas-node --version
# Output: veritas-node 0.1.0-rc.1

# Help
veritas-node --help
```

### Health Check

```bash
# Start the node
veritas-node --data-dir ./data &

# Wait for startup
sleep 5

# Check health
curl http://localhost:8080/health
# Output: {"status":"ok"}

# Check readiness
curl http://localhost:8080/ready
# Output: {"ready":"true"}
```

### Run Tests

```bash
# Run all tests
cargo test --all

# Run with output
cargo test --all -- --nocapture

# Run specific test
cargo test -p veritas-core test_client_lifecycle
```

## Post-Installation

### Configure Firewall

```bash
# UFW (Ubuntu)
sudo ufw allow 9000/tcp comment "VERITAS P2P"
sudo ufw allow 8080/tcp comment "VERITAS Health"

# firewalld (Fedora/RHEL)
sudo firewall-cmd --permanent --add-port=9000/tcp
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

### Create Data Directory

```bash
# Create directory with proper permissions
sudo mkdir -p /var/lib/veritas
sudo chown $USER:$USER /var/lib/veritas
chmod 700 /var/lib/veritas
```

### Set Up Logging

```bash
# Create log directory
sudo mkdir -p /var/log/veritas
sudo chown $USER:$USER /var/log/veritas

# Run with logging
veritas-node --data-dir /var/lib/veritas \
    --log-level info \
    --log-format json 2>&1 | tee /var/log/veritas/node.log
```

## Upgrading

### From Source

```bash
cd veritas
git pull origin main
cargo build --release
sudo systemctl restart veritas-node  # If using systemd
```

### Docker

```bash
docker pull ghcr.io/gl-tches/veritas-protocol:latest
docker-compose down
docker-compose up -d
```

## Uninstalling

### From Source

```bash
# Remove binary
sudo rm /usr/local/bin/veritas-node

# Remove service (Linux)
sudo systemctl stop veritas-node
sudo systemctl disable veritas-node
sudo rm /etc/systemd/system/veritas-node.service
sudo systemctl daemon-reload

# Remove data (CAUTION: This deletes all data!)
sudo rm -rf /var/lib/veritas
```

### Docker

```bash
docker-compose down -v  # -v removes volumes
docker rmi veritas-node:local
```

## Next Steps

- [Configuration Guide](CONFIGURATION.md) - Configure your node
- [Deployment Guide](DEPLOYMENT.md) - Production deployment
- [Troubleshooting](TROUBLESHOOTING.md) - Common issues
