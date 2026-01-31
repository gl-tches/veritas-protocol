# VERITAS Troubleshooting Guide

Common issues and solutions for VERITAS.

## Table of Contents

- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Network Issues](#network-issues)
- [Storage Issues](#storage-issues)
- [Identity Issues](#identity-issues)
- [Docker Issues](#docker-issues)
- [Common Errors](#common-errors)
- [Getting Help](#getting-help)

## Build Issues

### Rust Version Too Old

**Symptom:**
```
error: package `veritas-core v0.2.1-beta` cannot be built because it requires
rustc 1.85 or newer
```

**Solution:**
```bash
# Update Rust
rustup update stable
rustup default stable

# Verify version
rustc --version
# Should be 1.85.0 or higher
```

### Missing System Dependencies

**Symptom:**
```
error: failed to run custom build command for `openssl-sys`
```

**Solution (Ubuntu/Debian):**
```bash
sudo apt install -y build-essential pkg-config libssl-dev
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install -y gcc openssl-devel
```

**Solution (macOS):**
```bash
brew install openssl
export OPENSSL_DIR=$(brew --prefix openssl)
```

### Linker Errors

**Symptom:**
```
error: linking with `cc` failed
```

**Solution:**
```bash
# Ubuntu/Debian
sudo apt install -y build-essential

# macOS
xcode-select --install

# Verify
cc --version
```

### Out of Memory During Build

**Symptom:**
```
error: could not compile `veritas-chain` due to previous error
# Or system becomes unresponsive during build
```

**Solution:**
```bash
# Reduce parallelism
cargo build --jobs 2

# Or use release profile for less memory
cargo build --release
```

### Cargo Lock Conflict

**Symptom:**
```
error: failed to select a version for `some-crate`
```

**Solution:**
```bash
# Remove lock file and rebuild
rm Cargo.lock
cargo build
```

## Runtime Issues

### Node Won't Start

**Symptom:**
```
Error: Failed to initialize VERITAS client
```

**Check 1: Data directory permissions**
```bash
# Create directory with correct permissions
sudo mkdir -p /var/lib/veritas
sudo chown $USER:$USER /var/lib/veritas
chmod 700 /var/lib/veritas
```

**Check 2: Port already in use**
```bash
# Check what's using port 9000
lsof -i :9000
# or
netstat -tlnp | grep 9000

# Use different port
veritas-node --listen-addr /ip4/0.0.0.0/tcp/9001
```

**Check 3: Insufficient resources**
```bash
# Check available memory
free -h

# Check disk space
df -h /var/lib/veritas
```

### High CPU Usage

**Symptom:** Node consumes excessive CPU

**Solutions:**
1. Reduce max connections:
   ```bash
   veritas-node --max-connections 100
   ```

2. Disable features not needed:
   ```bash
   veritas-node --relay-mode false
   ```

3. Check for network issues (see Network Issues)

### High Memory Usage

**Symptom:** Node consumes too much memory

**Solutions:**
1. Limit connections:
   ```bash
   veritas-node --max-connections 500
   ```

2. Restart node periodically (if running for long periods)

3. Check for memory leaks (report as bug if consistent growth)

### Node Keeps Restarting

**Symptom:** Node crashes and restarts repeatedly

**Check logs:**
```bash
# Systemd
journalctl -u veritas-node -n 100

# Docker
docker logs veritas-node

# Log file
tail -100 /var/log/veritas/node.log
```

**Common causes:**
- Corrupted data directory
- Insufficient disk space
- Network configuration issues

## Network Issues

### Can't Connect to Peers

**Symptom:**
```
WARN veritas_net: No peers connected
```

**Check 1: Firewall**
```bash
# UFW
sudo ufw allow 9000/tcp

# iptables
sudo iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
```

**Check 2: Bootstrap nodes**
```bash
# Verify bootstrap nodes are accessible
nc -zv bootstrap1.veritas.network 9000
```

**Check 3: Network connectivity**
```bash
# Check outbound connectivity
curl -v https://api.ipify.org
```

### Connection Timeouts

**Symptom:**
```
WARN veritas_net: Connection timeout to peer
```

**Solutions:**
1. Increase timeout:
   ```rust
   .with_connection_timeout(Duration::from_secs(60))
   ```

2. Check network latency:
   ```bash
   ping bootstrap1.veritas.network
   ```

3. Check for NAT/firewall issues

### NAT Traversal Issues

**Symptom:** Can receive but can't send connections

**Solutions:**
1. Enable UPnP on router
2. Configure port forwarding for port 9000
3. Use a relay node

### mDNS Discovery Not Working

**Symptom:** Can't find local peers

**Check:**
```bash
# Verify mDNS is running
systemctl status avahi-daemon

# Check firewall for mDNS
sudo ufw allow 5353/udp
```

## Storage Issues

### Database Corruption

**Symptom:**
```
error: Storage error: Corruption detected
```

**Solution:**
```bash
# Backup current data
cp -r /var/lib/veritas /var/lib/veritas.backup

# Remove corrupted data (WARNING: data loss)
rm -rf /var/lib/veritas/*

# Restart node
systemctl restart veritas-node
```

### Disk Full

**Symptom:**
```
error: No space left on device
```

**Solutions:**
1. Check disk usage:
   ```bash
   df -h /var/lib/veritas
   du -sh /var/lib/veritas/*
   ```

2. Clean old data:
   ```bash
   # Remove old logs
   find /var/log/veritas -name "*.log" -mtime +30 -delete
   ```

3. Move data directory:
   ```bash
   # Stop node
   systemctl stop veritas-node

   # Move data
   mv /var/lib/veritas /new/location/veritas

   # Update configuration
   veritas-node --data-dir /new/location/veritas
   ```

### Permission Denied

**Symptom:**
```
error: Permission denied: /var/lib/veritas
```

**Solution:**
```bash
# Fix ownership
sudo chown -R $USER:$USER /var/lib/veritas

# Fix permissions
chmod -R 700 /var/lib/veritas
```

## Identity Issues

### Can't Create More Identities

**Symptom:**
```
error: Identity limit reached (3/3)
```

**Explanation:** VERITAS limits each device to 3 identities.

**Solutions:**
1. Wait for an identity to expire (30 days + 24h grace)
2. Delete an unused identity (if implemented)
3. Use a different device

### Wrong Password

**Symptom:**
```
error: Invalid password
```

**Solutions:**
1. Verify you're using the correct password
2. If forgotten, data must be reset (WARNING: data loss):
   ```bash
   rm -rf /var/lib/veritas/identities
   ```

### Identity Not Found

**Symptom:**
```
error: Identity not found: abc123...
```

**Causes:**
- Identity hash is incorrect
- Identity was on a different device
- Data was corrupted/deleted

**Solution:**
Verify the identity hash is correct and exists in your keyring.

## Docker Issues

### Container Won't Start

**Check logs:**
```bash
docker logs veritas-node
```

**Check resources:**
```bash
docker stats veritas-node
```

**Common fixes:**
```bash
# Remove and recreate
docker rm -f veritas-node
docker run -d --name veritas-node ...
```

### Volume Permission Issues

**Symptom:**
```
error: Permission denied: /var/lib/veritas
```

**Solution:**
```bash
# Fix volume permissions
docker run --rm -v veritas-data:/data alpine chown -R 1000:1000 /data
```

### Health Check Failing

**Check health:**
```bash
docker inspect --format='{{.State.Health.Status}}' veritas-node
```

**Check logs:**
```bash
docker logs veritas-node | tail -50
```

## Common Errors

### CoreError::NotUnlocked

**Cause:** Trying to use client before unlocking

**Solution:**
```rust
client.unlock(b"password").await?;
// Now you can use the client
```

### CoreError::MessageTooLong

**Cause:** Message exceeds 300 character limit

**Solution:**
```rust
// Check length before sending
if message.chars().count() <= 300 {
    client.send_message(&recipient, &message).await?;
}
```

### NetworkError::NoBootstrapPeers

**Cause:** No bootstrap peers configured

**Solution:**
```bash
veritas-node --bootstrap-nodes "/dns4/bootstrap.veritas.network/tcp/9000/p2p/..."
```

### StorageError::EncryptionFailed

**Cause:** Database encryption issue

**Solutions:**
1. Check disk space
2. Verify password is correct
3. Check file permissions

## Diagnostic Commands

### Check Node Status

```bash
# Health check
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready
```

### View Logs

```bash
# Systemd
journalctl -u veritas-node -f

# Docker
docker logs -f veritas-node

# File
tail -f /var/log/veritas/node.log
```

### Check Connectivity

```bash
# Check port is listening
netstat -tlnp | grep 9000

# Check firewall
sudo iptables -L -n | grep 9000

# Test connection
nc -zv localhost 9000
```

### Debug Mode

```bash
# Run with debug logging
veritas-node --log-level debug

# Run with trace logging (very verbose)
veritas-node --log-level trace
```

## Getting Help

### Before Asking for Help

1. Check this troubleshooting guide
2. Search existing issues on GitHub
3. Collect relevant information:
   - VERITAS version: `veritas-node --version`
   - Rust version: `rustc --version`
   - OS and version
   - Full error message
   - Relevant logs

### Reporting Issues

Open an issue at: https://github.com/gl-tches/veritas-protocol/issues

Include:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- System information
- Relevant logs (redact sensitive data)

### Community Support

- GitHub Discussions: https://github.com/gl-tches/veritas-protocol/discussions
- Discord: (if available)

## See Also

- [Installation Guide](INSTALLATION.md)
- [Configuration Guide](CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
