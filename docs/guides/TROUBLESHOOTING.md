# VERITAS Troubleshooting Guide

Common issues and solutions for VERITAS.

> **Version Note**: This guide has been updated for v0.3.0-beta with new error patterns
> for rate limiting, hardware attestation, time validation, and security features.

## Table of Contents

- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Network Issues](#network-issues)
- [Storage Issues](#storage-issues)
- [Identity Issues](#identity-issues)
- [Docker Issues](#docker-issues)
- [GitHub Actions / CI Issues](#github-actions--ci-issues)
- [Common Errors](#common-errors)
- [Security Errors (v0.3.0-beta)](#security-errors-v030-beta)
  - [Rate Limiting Errors](#rate-limiting-errors)
  - [Time Validation Errors](#time-validation-errors)
  - [Envelope Size Errors](#envelope-size-errors)
  - [Block Validation Errors](#block-validation-errors)
  - [Reputation System Errors](#reputation-system-errors)
- [Hardware Attestation Errors](#hardware-attestation-errors)
- [Username Registration Errors](#username-registration-errors)
- [Key Rotation and Forward Secrecy](#key-rotation-and-forward-secrecy)
- [Diagnostic Commands](#diagnostic-commands)
- [Getting Help](#getting-help)
- [Quick Error Reference (v0.3.0-beta)](#quick-error-reference-v030-beta)

## Build Issues

### Rust Version Too Old

**Symptom:**
```
error: package `veritas-core v0.3.0-beta` cannot be built because it requires
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

## GitHub Actions / CI Issues

### `fallocate: fallocate failed: Text file busy`

**Symptom:**
```
fallocate: fallocate failed: Text file busy
Error: Process completed with exit code 1.
```

**Cause:** GitHub Actions Ubuntu runners ship with a pre-existing `/swapfile` that is
actively mounted as swap. `fallocate` cannot overwrite a file the kernel holds open.

**Solution:** The `ghcr-publish` workflow handles this automatically by disabling
existing swap before creating a new file. If you see this error on a self-hosted
runner, ensure no swap file is active at the target path:

```bash
sudo swapoff -a
sudo rm -f /swapfile /mnt/swapfile
```

Then create your swap file:

```bash
sudo fallocate -l 8G /mnt/swapfile
sudo chmod 600 /mnt/swapfile
sudo mkswap /mnt/swapfile
sudo swapon /mnt/swapfile
```

### CI Build OOM (Out of Memory)

**Symptom:** Build fails with signal 9 (SIGKILL) or the runner becomes unresponsive.

**Cause:** GitHub Actions free-tier runners have ~7GB RAM, which can be insufficient
for large Rust builds with high parallelism.

**Solutions:**

1. **Limit build parallelism** (already configured in `rust.yml`):
   ```yaml
   env:
     CARGO_BUILD_JOBS: 2
   ```

2. **Add swap space** (already configured in `ghcr-publish.yml`):
   ```bash
   sudo swapoff -a
   sudo fallocate -l 8G /mnt/swapfile
   sudo chmod 600 /mnt/swapfile
   sudo mkswap /mnt/swapfile
   sudo swapon /mnt/swapfile
   ```

3. **Free disk space** for Docker builds:
   ```bash
   sudo rm -rf /usr/share/dotnet
   sudo rm -rf /usr/local/lib/android
   sudo rm -rf /opt/ghc
   sudo rm -rf /opt/hostedtoolcache/CodeQL
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

## Security Errors (v0.3.0-beta)

This section documents new security-related errors introduced in v0.3.0-beta. These errors
are part of enhanced security measures and DoS prevention mechanisms.

### Rate Limiting Errors

Rate limiting protects the network from abuse and DoS attacks. When you see rate limit
errors, it may indicate either legitimate high traffic or a potential attack.

#### GossipError::RateLimitExceeded

**Symptom:**
```
ERROR veritas_net::gossip: Rate limit exceeded for peer 12D3KooW...
GossipError::RateLimitExceeded { peer_id: "12D3KooW...", limit: 10, window_secs: 1 }
```

**Cause:** A peer is sending more than `MAX_ANNOUNCEMENTS_PER_PEER_PER_SEC` (default: 10)
gossip announcements per second.

**Solutions:**

1. **If you're the affected peer** - Reduce announcement frequency:
   ```rust
   // Add delay between announcements
   for announcement in announcements {
       client.announce(announcement).await?;
       tokio::time::sleep(Duration::from_millis(200)).await;
   }
   ```

2. **If you're receiving from a misbehaving peer** - The rate limiter will automatically
   handle this. You can check the violation count:
   ```bash
   # View rate limiter stats (if metrics enabled)
   curl http://localhost:8080/metrics | grep rate_limit
   ```

3. **If this happens frequently**, the peer may be compromised or malicious:
   ```bash
   # Check peer violation history in logs
   grep "RateLimitExceeded" /var/log/veritas/node.log | sort | uniq -c
   ```

4. **Adjust rate limits** if your use case requires higher throughput (not recommended
   for production):
   ```rust
   let config = NetworkConfig {
       max_announcements_per_peer_per_sec: 20,  // Default is 10
       ..Default::default()
   };
   ```

#### DhtError::RateLimitExceeded

**Symptom:**
```
ERROR veritas_net::dht: DHT rate limit exceeded
DhtError::RateLimitExceeded { operation: "lookup", limit: 100, window_secs: 60 }
```

**Cause:** Too many DHT operations (lookups, puts, gets) in a short time window.

**Solutions:**

1. **Batch your DHT operations**:
   ```rust
   // Instead of individual lookups
   for key in keys {
       dht.get(&key).await?;  // May trigger rate limit
   }

   // Use batch operations when available
   let results = dht.get_many(&keys).await?;
   ```

2. **Add backoff logic**:
   ```rust
   use tokio::time::{sleep, Duration};

   let mut backoff = Duration::from_millis(100);
   loop {
       match dht.get(&key).await {
           Ok(value) => break Ok(value),
           Err(DhtError::RateLimitExceeded { .. }) => {
               sleep(backoff).await;
               backoff = (backoff * 2).min(Duration::from_secs(30));
           }
           Err(e) => break Err(e),
       }
   }
   ```

3. **Check for runaway loops** in your code that may be causing excessive DHT queries.

### Time Validation Errors

VERITAS validates timestamps to prevent replay attacks and ensure message freshness.
The maximum allowed clock skew is defined by `MAX_CLOCK_SKEW_SECS` (default: 300 seconds / 5 minutes).

#### TimeError::TimestampInFuture

**Symptom:**
```
ERROR veritas_protocol: Message timestamp is in the future
TimeError::TimestampInFuture { timestamp: 1738500000, now: 1738499700, skew_secs: 300 }
```

**Cause:** The message timestamp is more than `MAX_CLOCK_SKEW_SECS` ahead of the
receiving node's system time.

**Solutions:**

1. **Sync your system clock with NTP**:
   ```bash
   # Check current time sync status
   timedatectl status

   # Enable NTP synchronization
   sudo timedatectl set-ntp true

   # Force immediate sync (systemd)
   sudo systemctl restart systemd-timesyncd

   # Or using ntpdate
   sudo ntpdate -s pool.ntp.org
   ```

2. **Verify time is correct**:
   ```bash
   # Compare with known good time source
   date
   curl -s http://worldtimeapi.org/api/ip | jq '.utc_datetime'
   ```

3. **Check for VM clock drift** (common in virtual environments):
   ```bash
   # Install guest additions/tools for your hypervisor
   # VMware: open-vm-tools
   # VirtualBox: virtualbox-guest-utils
   ```

#### TimeError::TimestampTooOld

**Symptom:**
```
ERROR veritas_protocol: Message timestamp has expired
TimeError::TimestampTooOld { timestamp: 1737000000, min_valid: 1737500000 }
```

**Cause:** The message timestamp is older than the minimum valid timestamp. Messages
have a maximum TTL defined by `MESSAGE_TTL_SECS` (default: 7 days).

**Solutions:**

1. **If receiving old messages**: This is normal for queued/offline messages that
   exceeded their TTL. The message cannot be delivered.

2. **If your messages are being rejected as too old**:
   - Sync your system clock (see above)
   - Check that your system isn't using a stale timestamp

3. **If you need to process older messages** (not recommended for production):
   ```rust
   // This reduces security - use only for testing
   let config = ProtocolConfig {
       message_ttl_secs: 30 * 24 * 60 * 60,  // 30 days instead of 7
       ..Default::default()
   };
   ```

#### TimeError::ClockSkewExceeded

**Symptom:**
```
ERROR veritas_core::time: Clock skew between local and network time exceeds threshold
TimeError::ClockSkewExceeded { local: 1738499000, network: 1738500000, max_skew: 300 }
```

**Cause:** Your system clock differs from the network consensus time by more than
the allowed threshold.

**Solutions:**

1. **Sync with NTP** (see above)

2. **Check if your hardware clock is drifting**:
   ```bash
   # Compare hardware clock with system clock
   sudo hwclock --show
   date

   # Sync hardware clock from system
   sudo hwclock --systohc
   ```

3. **For servers, configure chrony for better accuracy**:
   ```bash
   sudo apt install chrony
   sudo systemctl enable chrony
   sudo systemctl start chrony

   # Check sync status
   chronyc tracking
   ```

### Envelope Size Errors

VERITAS enforces strict size limits on message envelopes to prevent DoS attacks
and ensure efficient network transmission.

#### ProtocolError::InvalidEnvelope("too large")

**Symptom:**
```
ERROR veritas_protocol: Envelope size validation failed
ProtocolError::InvalidEnvelope("too large: 4096 bytes exceeds maximum 2048 bytes")
```

**Cause:** The serialized envelope exceeds `MAX_ENVELOPE_SIZE` (2048 bytes).

**Solutions:**

1. **Reduce your message size**:
   ```rust
   // Check message size before sending
   if message.chars().count() > MAX_MESSAGE_CHARS {
       return Err(ProtocolError::MessageTooLong);
   }

   // Use chunking for longer content
   let chunks = client.chunk_message(&long_message)?;
   for chunk in chunks {
       client.send_chunk(&recipient, chunk).await?;
   }
   ```

2. **Check for malformed data** - If you're receiving this error on incoming messages:
   ```rust
   // Log envelope details for debugging
   tracing::debug!(
       envelope_size = bytes.len(),
       max_size = MAX_ENVELOPE_SIZE,
       "Received oversized envelope"
   );
   ```

3. **Verify your serialization** isn't adding extra data:
   ```rust
   // Check serialized size
   let serialized = bincode::serialize(&envelope)?;
   println!("Envelope size: {} bytes", serialized.len());
   ```

4. **Use appropriate padding buckets** - VERITAS pads messages to fixed sizes
   (256, 512, 1024 bytes) for privacy. Ensure your content fits within a bucket:
   ```
   Bucket 1: Up to ~200 chars (256 bytes total)
   Bucket 2: Up to ~450 chars (512 bytes total)
   Bucket 3: Up to ~950 chars (1024 bytes total)
   ```

### Block Validation Errors

These errors occur during blockchain validation and indicate potential issues with
the validator network or synchronization.

#### ChainError::InvalidSignature

**Symptom:**
```
ERROR veritas_chain: Block signature verification failed
ChainError::InvalidSignature { block_height: 12345, validator: "val_abc123..." }
```

**Cause:** The block's cryptographic signature doesn't match the claimed validator's
public key.

**Solutions:**

1. **Sync with the network** - You may have stale validator set information:
   ```bash
   # Restart node to force resync
   systemctl restart veritas-node

   # Or trigger manual sync
   veritas-cli chain sync --force
   ```

2. **Check if you're on a fork**:
   ```bash
   # Compare your chain head with network
   veritas-cli chain status
   veritas-cli chain compare --network
   ```

3. **Verify validator set is current**:
   ```rust
   // Check validator set epoch
   let validators = client.get_validator_set().await?;
   println!("Validator set epoch: {}", validators.epoch);
   ```

4. **If this persists**, report to network operators - it may indicate a malicious
   validator or network attack.

#### ChainError::ValidatorKeyMismatch

**Symptom:**
```
ERROR veritas_chain: Validator public key doesn't match claimed identity
ChainError::ValidatorKeyMismatch {
    claimed_validator: "val_abc123...",
    derived_from_key: "val_def456..."
}
```

**Cause:** The public key used to sign the block doesn't derive to the validator ID
claimed in the block header.

**Solutions:**

1. **This is a serious error** - It indicates either:
   - A bug in the validator software
   - A malicious block injection attempt
   - Corrupted block data during transmission

2. **Verify block integrity**:
   ```rust
   // Manually verify the block
   let block = client.get_block(height).await?;
   let expected_id = ValidatorId::from_pubkey(&block.header.validator_pubkey);
   println!("Claimed: {}", block.header.validator);
   println!("Derived: {}", expected_id);
   ```

3. **Report to network** if you see this error consistently:
   ```bash
   # Collect diagnostic information
   veritas-cli chain export-block --height 12345 --output suspicious_block.json
   ```

4. **Check your local chain** for corruption:
   ```bash
   veritas-cli chain verify --full
   ```

### Reputation System Errors

The reputation system in v0.3.0-beta requires cryptographic proofs for all
interactions to prevent gaming and Sybil attacks.

#### ReputationError::InvalidInteractionProof

**Symptom:**
```
ERROR veritas_reputation: Interaction proof verification failed
ReputationError::InvalidInteractionProof {
    reason: "Signature verification failed"
}
```

**Cause:** The cryptographic proof attached to a reputation interaction is invalid.
This could be due to:
- Corrupted proof data
- Mismatched keys
- Attempted forgery

**Solutions:**

1. **Generate fresh proofs** for each interaction:
   ```rust
   // Create a new interaction proof
   let proof = InteractionProof::new(
       &from_keypair,
       &to_identity_hash,
       InteractionType::PositiveMessage,
       timestamp,
   )?;

   // Verify locally before submitting
   proof.verify(&from_pubkey, Some(&to_pubkey))?;

   client.record_interaction(from, to, &proof).await?;
   ```

2. **Ensure keys match identities**:
   ```rust
   // Verify the signing key matches the claimed identity
   let expected_hash = IdentityHash::from_pubkey(&from_keypair.public());
   assert_eq!(expected_hash, from_identity);
   ```

3. **Check for clock synchronization issues** - Proofs include timestamps that
   must be valid.

#### ReputationError::NonceAlreadyUsed

**Symptom:**
```
ERROR veritas_reputation: Replay attack detected - nonce already used
ReputationError::NonceAlreadyUsed { nonce: [123, 45, ...] }
```

**Cause:** The nonce in the interaction proof has been seen before. This prevents
replay attacks where someone tries to submit the same reputation boost multiple times.

**Solutions:**

1. **Generate a new nonce** for each interaction:
   ```rust
   // Nonces are automatically generated in InteractionProof::new()
   let proof = InteractionProof::new(...)?;  // Fresh nonce each time

   // Never reuse proof objects
   // BAD: Reusing the same proof
   client.record_interaction(from, to1, &proof).await?;
   client.record_interaction(from, to2, &proof).await?;  // Will fail!

   // GOOD: Create new proof for each interaction
   let proof1 = InteractionProof::new(&keypair, &to1, ...)?;
   let proof2 = InteractionProof::new(&keypair, &to2, ...)?;
   client.record_interaction(from, to1, &proof1).await?;
   client.record_interaction(from, to2, &proof2).await?;
   ```

2. **If you're seeing this unexpectedly**, check for:
   - Duplicate code paths that submit the same proof
   - Race conditions in concurrent code
   - Stale proof objects being reused

#### ReputationError::SelfInteractionNotAllowed

**Symptom:**
```
ERROR veritas_reputation: Cannot record interaction with self
ReputationError::SelfInteractionNotAllowed { identity: "abc123..." }
```

**Cause:** An attempt was made to boost one's own reputation, which is not allowed.

**Solutions:**

1. **Verify sender and recipient are different**:
   ```rust
   // Check before recording
   if from_identity == to_identity {
       return Err(AppError::InvalidOperation("Cannot interact with self"));
   }

   client.record_positive_interaction(from_identity, to_identity, &proof).await?;
   ```

2. **If using multiple identities**, ensure you're not accidentally using the same
   identity for both sides of an interaction.

## Hardware Attestation Errors

Hardware attestation is a new feature in v0.3.0-beta that binds identities to
physical devices for enhanced security.

### IdentityError::HardwareAttestationFailed

**Symptom:**
```
ERROR veritas_identity::hardware: Hardware attestation failed
IdentityError::HardwareAttestationFailed {
    reason: "TPM attestation verification failed"
}
```

**Cause:** The hardware attestation process failed. This could be due to:
- TPM/Secure Enclave unavailable
- Attestation key mismatch
- Hardware security module error

**Solutions:**

1. **Check hardware security module status**:
   ```bash
   # Linux - Check TPM
   ls /dev/tpm*
   tpm2_getcap properties-fixed

   # macOS - Check Secure Enclave (T2/M1+ only)
   system_profiler SPiBridgeDataType
   ```

2. **Enable TPM in BIOS/UEFI** if disabled:
   - Restart and enter BIOS setup
   - Find "Security" or "Trusted Computing" section
   - Enable "TPM Device" or "Security Chip"

3. **Install required software**:
   ```bash
   # Ubuntu/Debian
   sudo apt install tpm2-tools tpm2-abrmd
   sudo systemctl enable tpm2-abrmd
   sudo systemctl start tpm2-abrmd

   # Fedora
   sudo dnf install tpm2-tools tpm2-abrmd
   ```

4. **Use fallback mode** if hardware attestation is not available:
   ```rust
   let config = IdentityConfig {
       hardware_attestation: HardwareAttestation::Optional,  // Allow software-only
       ..Default::default()
   };
   ```

### IdentityError::UnsupportedHardware

**Symptom:**
```
WARN veritas_identity::hardware: Hardware attestation not supported on this device
IdentityError::UnsupportedHardware {
    reason: "No TPM or Secure Enclave detected"
}
```

**Cause:** The device doesn't have supported hardware security features.

**Solutions:**

1. **Check supported hardware**:
   - **Linux**: TPM 2.0 module (most modern PCs)
   - **macOS**: Secure Enclave (T2 chip or Apple Silicon)
   - **Windows**: TPM 2.0 (required for Windows 11)
   - **Mobile**: iOS Secure Enclave, Android StrongBox/TEE

2. **Configure fallback options**:
   ```rust
   let identity_config = IdentityConfig {
       hardware_attestation: HardwareAttestation::Optional,
       fallback_to_software: true,
       ..Default::default()
   };

   // Create identity with optional hardware binding
   let identity = client.create_identity_with_config(identity_config).await?;
   ```

3. **Understand the security implications**:
   - Hardware attestation provides stronger identity binding
   - Software-only identities are still secure but not hardware-bound
   - Some features may require hardware attestation

4. **For virtual machines**, hardware attestation is typically not available.
   Use software-only mode:
   ```bash
   veritas-node --hardware-attestation disabled
   ```

## Username Registration Errors

Username registration provides human-readable identifiers linked to cryptographic
identities.

### ChainError::UsernameTaken

**Symptom:**
```
ERROR veritas_chain: Username registration failed
ChainError::UsernameTaken { username: "alice", registered_by: "0x123..." }
```

**Cause:** The requested username is already registered on the blockchain.

**Solutions:**

1. **Choose a different username**:
   ```rust
   // Check availability before registering
   if client.is_username_available("alice").await? {
       client.register_username("alice").await?;
   } else {
       println!("Username 'alice' is taken. Try a different one.");
   }
   ```

2. **Note that usernames are case-insensitive**:
   ```
   "Alice", "ALICE", and "alice" are all the same username
   ```

3. **Try variations**:
   ```rust
   let variations = ["alice_veritas", "alice2024", "alice_crypto"];
   for username in variations {
       if client.is_username_available(username).await? {
           client.register_username(username).await?;
           break;
       }
   }
   ```

### IdentityError::UsernameTaken

**Symptom:**
```
ERROR veritas_identity: Local username validation failed
IdentityError::UsernameTaken { username: "alice" }
```

**Cause:** Local validation detected the username is taken before blockchain submission.

**Solutions:**

1. **This is a local cache check** - Your node has cached that this username is taken.

2. **Refresh your username cache**:
   ```bash
   veritas-cli identity refresh-usernames
   ```

3. **The username may have become available** if the original registration expired.
   Force a fresh check:
   ```rust
   let available = client.is_username_available_fresh("alice").await?;
   ```

## Key Rotation and Forward Secrecy

v0.3.0-beta implements Perfect Forward Secrecy (PFS), which has important implications
for key rotation.

### Understanding Key Rotation Behavior

**Important**: When you rotate keys, the old keys are securely destroyed. This is
intentional and provides forward secrecy.

**Symptom:**
```
WARN veritas_crypto: Cannot decrypt message - key has been rotated
CryptoError::KeyNotFound { key_id: "old_key_123..." }
```

**This is expected behavior, not an error.**

### What Happens During Key Rotation

1. New encryption keys are generated
2. Old keys are securely zeroed from memory
3. Old key material is deleted from storage
4. Messages encrypted with old keys cannot be decrypted

### Solutions and Best Practices

1. **Export messages before key rotation** if you need to preserve them:
   ```rust
   // Before rotating
   let messages = client.export_all_messages().await?;
   save_to_backup(&messages)?;

   // Now safe to rotate
   client.rotate_keys().await?;
   ```

2. **Set up automatic message backup**:
   ```rust
   let config = ClientConfig {
       auto_backup_before_rotation: true,
       backup_path: PathBuf::from("/secure/backup"),
       ..Default::default()
   };
   ```

3. **Understand the security trade-off**:
   - **With PFS**: Past messages are protected even if current keys are compromised
   - **Without PFS**: An attacker with your current keys could decrypt past messages

4. **Key rotation schedule** - Keys are rotated:
   - Automatically every `KEY_EXPIRY_SECS` (default: 30 days)
   - Manually when you call `rotate_keys()`
   - When a potential compromise is detected

5. **If you need to keep messages long-term**, consider:
   ```rust
   // Re-encrypt messages with a separate storage key
   let storage_key = client.get_storage_key()?;
   for message in messages {
       let archived = message.re_encrypt_for_storage(&storage_key)?;
       archive_store.save(archived)?;
   }
   ```

### Common Questions

**Q: Can I recover messages after key rotation?**
A: No. This is intentional for security. Always backup before rotating.

**Q: How do I know when rotation will happen?**
A: Check key expiry:
```rust
let key_info = client.get_current_key_info()?;
println!("Key expires: {:?}", key_info.expires_at);
```

**Q: Can I disable automatic key rotation?**
A: Not recommended, but for testing:
```rust
let config = CryptoConfig {
    auto_key_rotation: false,  // Security risk!
    ..Default::default()
};
```

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

## Quick Error Reference (v0.3.0-beta)

This table provides a quick reference for new errors introduced in v0.3.0-beta.

| Error | Category | Common Cause | Quick Fix |
|-------|----------|--------------|-----------|
| `GossipError::RateLimitExceeded` | Rate Limiting | Too many announcements | Add delay between announcements |
| `DhtError::RateLimitExceeded` | Rate Limiting | Too many DHT ops | Batch operations, add backoff |
| `TimeError::TimestampInFuture` | Time Validation | Clock ahead of network | Sync with NTP |
| `TimeError::TimestampTooOld` | Time Validation | Message expired | Check clock, message TTL |
| `TimeError::ClockSkewExceeded` | Time Validation | Clock out of sync | Sync with NTP, check hardware clock |
| `ProtocolError::InvalidEnvelope` | Envelope Size | Message too large | Reduce size, use chunking |
| `ChainError::InvalidSignature` | Block Validation | Stale validator info | Resync with network |
| `ChainError::ValidatorKeyMismatch` | Block Validation | Key/ID mismatch | Report to network, verify chain |
| `ChainError::UsernameTaken` | Username | Username in use | Choose different username |
| `IdentityError::UsernameTaken` | Username | Cached as taken | Refresh cache |
| `IdentityError::HardwareAttestationFailed` | Hardware | TPM/SE unavailable | Enable TPM, use fallback |
| `IdentityError::UnsupportedHardware` | Hardware | No security hardware | Use software-only mode |
| `ReputationError::InvalidInteractionProof` | Reputation | Invalid signature | Generate fresh proof |
| `ReputationError::NonceAlreadyUsed` | Reputation | Replay detected | Use unique nonce each time |
| `ReputationError::SelfInteractionNotAllowed` | Reputation | Self-boost attempt | Use different identities |
| `CryptoError::KeyNotFound` | Key Rotation | Key was rotated (PFS) | Expected behavior - backup first |

## See Also

- [Installation Guide](../getting-started/INSTALLATION.md)
- [Configuration Guide](../getting-started/CONFIGURATION.md)
- [Deployment Guide](DEPLOYMENT.md)
