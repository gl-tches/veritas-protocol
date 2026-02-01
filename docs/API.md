# VERITAS API Documentation

Complete API reference for the VERITAS Protocol library.

**Version**: 0.3.0-beta

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [VeritasClient](#veritasclient)
- [Identity Management](#identity-management)
- [Messaging](#messaging)
- [Group Messaging](#group-messaging)
- [Safety Numbers](#safety-numbers)
- [Verification and Proofs](#verification-and-proofs)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [FFI Bindings](#ffi-bindings)
- [WASM Bindings](#wasm-bindings)
- [Python Bindings](#python-bindings)
- [Security APIs (v0.3.0-beta)](#security-apis-v030-beta)
  - [Hardware Attestation API](#hardware-attestation-api)
  - [Rate Limiting API](#rate-limiting-api)
  - [Subnet Limiting API](#subnet-limiting-api)
  - [Interaction Proofs API](#interaction-proofs-api)
  - [Trusted Time API](#trusted-time-api)
  - [Block Signature API](#block-signature-api)
  - [Username Registration API](#username-registration-api)
- [Protocol Limits Reference](#protocol-limits-reference)

---

## Overview

The VERITAS library provides a high-level, async-safe API for post-quantum secure messaging. The main entry point is the `VeritasClient` struct, which manages all protocol operations.

### Crate Structure

| Crate | Purpose |
|-------|---------|
| `veritas-core` | High-level client API (start here) |
| `veritas-crypto` | Cryptographic primitives |
| `veritas-identity` | Identity management |
| `veritas-protocol` | Wire protocol and message formats |
| `veritas-net` | P2P networking |
| `veritas-chain` | Blockchain verification |
| `veritas-store` | Encrypted local storage |
| `veritas-reputation` | Reputation system |
| `veritas-ffi` | C/FFI bindings |
| `veritas-wasm` | WebAssembly bindings |
| `veritas-py` | Python bindings |

---

## Quick Start

```rust
use veritas_core::{VeritasClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client with default configuration
    let client = VeritasClient::new(ClientConfig::default()).await?;

    // Unlock with password
    client.unlock(b"secure_password").await?;

    // Create an identity
    let my_hash = client.create_identity(Some("Personal")).await?;
    println!("My identity: {}", my_hash);

    // Lock when done
    client.lock().await?;

    Ok(())
}
```

---

## VeritasClient

The main client for interacting with the VERITAS protocol.

### Client Lifecycle

```
    new() ──────────────┐
                        │
                        ▼
                   ┌─────────┐
                   │ Created │
                   └────┬────┘
                        │
                  unlock()
                        │
                        ▼
                   ┌──────────┐◄────────┐
                   │ Unlocked │         │
                   └────┬─────┘   unlock()
                        │              │
                   lock()         ┌────┴────┐
                        │         │ Locked  │
                        └────────►└────┬────┘
                                       │
                                 shutdown()
                                       │
                                       ▼
                              ┌─────────────────┐
                              │ ShuttingDown    │
                              └─────────────────┘
```

### Creating a Client

```rust
use veritas_core::{VeritasClient, ClientConfig};

// With default configuration
let client = VeritasClient::new(ClientConfig::default()).await?;

// With custom data directory
let client = VeritasClient::with_data_dir("/custom/path").await?;

// In-memory (for testing)
let client = VeritasClient::in_memory().await?;
```

### Authentication

```rust
// Unlock the client (initializes services, decrypts keys)
client.unlock(b"password").await?;

// Check if unlocked
if client.is_unlocked().await {
    println!("Client is ready");
}

// Lock when idle (zeroizes sensitive data)
client.lock().await?;

// Clean shutdown
client.shutdown().await?;
```

### Client State

```rust
use veritas_core::ClientState;

let state = client.state().await;
match state {
    ClientState::Created => println!("Not initialized"),
    ClientState::Locked => println!("Locked"),
    ClientState::Unlocked => println!("Ready"),
    ClientState::ShuttingDown => println!("Shutting down"),
}
```

---

## Identity Management

### IdentityHash

A unique 32-byte identifier derived from public keys using BLAKE3.

```rust
use veritas_identity::IdentityHash;

// Get your identity hash
let my_hash: IdentityHash = client.identity_hash().await?;
println!("Identity: {}", my_hash);

// Identity hashes can be shared with others for communication
```

### Creating Identities

```rust
// Create with a label
let hash = client.create_identity(Some("Personal")).await?;

// Create without a label
let hash = client.create_identity(None).await?;
```

### Listing Identities

```rust
use veritas_core::internal::IdentityInfo;

let identities: Vec<IdentityInfo> = client.list_identities().await?;
for identity in identities {
    println!("{}: {} (primary: {})",
        identity.hash,
        identity.label.unwrap_or_default(),
        identity.is_primary
    );
}
```

### Setting Primary Identity

```rust
// Set which identity is used by default
client.set_primary_identity(&some_identity_hash).await?;
```

### Identity Slots

Each device is limited to 3 identities to prevent spam.

```rust
use veritas_identity::IdentitySlotInfo;

let slots: IdentitySlotInfo = client.identity_slots().await?;
println!("Used: {}/{}", slots.used, slots.max);
println!("Available: {}", slots.available);

if slots.can_create() {
    client.create_identity(Some("Work")).await?;
}
```

### Public Keys

```rust
use veritas_identity::IdentityPublicKeys;

// Get your public keys to share with others
let public_keys: IdentityPublicKeys = client.public_keys().await?;

// Public keys contain:
// - exchange: X25519 public key for key exchange
// - signing: Optional ML-DSA public key for signatures
```

### Key Lifecycle

Keys expire after 30 days with a 5-day warning period.

```rust
use veritas_identity::{KeyLifecycle, KeyState};

// Key states
enum KeyState {
    Active,     // Valid for all operations
    Expiring,   // Within 5 days of expiry
    Expired,    // Cannot be used
    Rotated,    // Replaced with new key
    Revoked,    // Manually revoked
}
```

---

## Messaging

### Sending Messages

```rust
use veritas_core::messaging::{SendOptions, MessageHash};
use veritas_identity::IdentityHash;

// Simple send
let hash: MessageHash = client.send_message(
    &recipient_hash,
    "Hello, VERITAS!",
    SendOptions::default()
).await?;

// With delivery receipt request
let options = SendOptions::default().with_receipt();
let hash = client.send_message(&recipient_hash, "Hello!", options).await?;

// As a reply
let options = SendOptions::default().reply_to(original_message_hash);
let hash = client.send_message(&recipient_hash, "Reply text", options).await?;

// Combined options
let options = SendOptions::default()
    .with_receipt()
    .reply_to(original_hash)
    .without_jitter();  // Warning: reduces privacy
```

### SendOptions

| Option | Default | Description |
|--------|---------|-------------|
| `request_delivery_receipt` | false | Request confirmation of delivery |
| `reply_to` | None | Hash of message being replied to |
| `skip_jitter` | false | Skip random timing delay (reduces privacy) |

### Receiving Messages

```rust
use veritas_core::messaging::ReceivedMessage;

let messages: Vec<ReceivedMessage> = client.receive_messages().await?;

for msg in messages {
    // Get text content
    if let Some(text) = msg.text() {
        println!("From {}: {}", msg.sender, text);
    }

    // Check if it's a delivery receipt
    if msg.is_receipt() {
        let receipt = msg.receipt().unwrap();
        println!("Receipt for: {}", receipt.message_id);
    }

    // Check signature verification
    if msg.is_verified() {
        println!("Signature verified");
    }
}
```

### ReceivedMessage Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `MessageId` | Local storage identifier |
| `message_hash` | `Hash256` | Unique message identifier |
| `sender` | `IdentityHash` | Sender's identity |
| `content` | `MessageContent` | Decrypted content |
| `timestamp` | `u64` | Sender's timestamp |
| `received_at` | `i64` | Local receive time |
| `reply_to` | `Option<MessageHash>` | Reply reference |
| `read` | `bool` | Read status |
| `signature_verified` | `bool` | Signature check result |

### Message Status

```rust
use veritas_core::messaging::MessageStatus;

let status: MessageStatus = client.message_status(&hash).await?;

match status {
    MessageStatus::Pending => println!("Waiting to send"),
    MessageStatus::Sending => println!("Currently sending"),
    MessageStatus::Sent => println!("Sent to network"),
    MessageStatus::Delivered => println!("Delivered to recipient"),
    MessageStatus::Read => println!("Read by recipient"),
    MessageStatus::Failed => println!("Delivery failed"),
}

// Helper methods
status.is_terminal()   // true for Delivered, Read, Failed
status.is_pending()    // true for Pending, Sending
status.is_delivered()  // true for Delivered, Read
status.is_failed()     // true for Failed
```

### Message Limits

| Limit | Value |
|-------|-------|
| Max characters per chunk | 300 |
| Max chunks per message | 3 |
| Max total characters | 900 |
| Message TTL | 7 days |

---

## Group Messaging

### Creating Groups

```rust
use veritas_core::groups::GroupId;

let group_id: GroupId = client.create_group(Some("Project Team")).await?;
```

### Listing Groups

```rust
use veritas_core::groups::GroupInfo;

let groups: Vec<GroupInfo> = client.list_groups().await?;

for group in groups {
    println!("Group: {:?}", group.name);
    println!("Members: {}", group.member_count);
    println!("My role: {:?}", group.my_role);
}
```

### GroupInfo Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `GroupId` | Unique group identifier |
| `name` | `Option<String>` | Human-readable name |
| `member_count` | `usize` | Number of members |
| `my_role` | `GroupRole` | Your role in the group |
| `created_at` | `u64` | Creation timestamp |
| `key_generation` | `u32` | Current key version |

### Group Roles

```rust
use veritas_core::groups::GroupRole;

enum GroupRole {
    Admin,     // Full control
    Moderator, // Can add/remove members
    Member,    // Can send/receive only
}

// Check permissions
role.can_add_members()     // Admin, Moderator
role.can_remove_members()  // Admin, Moderator (but not other admins)
role.can_rotate_keys()     // Admin only
```

### Managing Members

```rust
use veritas_core::groups::GroupRole;

// Add a member
client.add_group_member(
    &group_id,
    &member_identity_hash,
    GroupRole::Member
).await?;
```

### Group Messages

```rust
use veritas_core::groups::GroupMessage;

let messages: Vec<GroupMessage> = client.get_group_messages(&group_id).await?;

for msg in messages {
    println!("[{}] {}: {}",
        msg.group_id,
        msg.sender,
        msg.text
    );
}
```

### Group Limits

| Limit | Value |
|-------|-------|
| Max members per group | 100 |
| Max groups per identity | 50 |
| Key rotation interval | 7 days |

---

## Safety Numbers

Safety numbers allow out-of-band verification that you're communicating with the correct party.

### Computing Safety Numbers

```rust
use veritas_core::SafetyNumber;
use veritas_identity::IdentityKeyPair;

let alice = IdentityKeyPair::generate();
let bob = IdentityKeyPair::generate();

// Both parties compute the same number
let alice_sees = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
let bob_sees = SafetyNumber::compute(bob.public_keys(), alice.public_keys());

assert_eq!(alice_sees, bob_sees);
```

### Display Formats

```rust
// Numeric format for verbal comparison (60 digits)
let numeric = safety_number.to_numeric_string();
// "12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890"

// Hex format for QR codes (64 characters)
let hex = safety_number.to_qr_string();
// "a1b2c3d4e5f6..."

// Display uses numeric format
println!("Verify: {}", safety_number);
```

### Properties

- **Symmetric**: Both parties compute the same number
- **Deterministic**: Same keys always produce the same number
- **Unique**: Different keys produce different numbers
- **32 bytes**: Uses BLAKE3 with domain separation

---

## Verification and Proofs

### Message Proofs

Proofs demonstrate that a message was recorded on the blockchain.

```rust
use veritas_core::verification::MessageProof;

let proof: MessageProof = client.get_message_proof(&message_hash).await?;

// Verify Merkle inclusion
if proof.verify_inclusion() {
    println!("Message in block {} at height {}",
        proof.block_hash,
        proof.block_height
    );
}
```

### MessageProof Fields

| Field | Type | Description |
|-------|------|-------------|
| `proof` | `MerkleProof` | Merkle tree inclusion proof |
| `block_height` | `u64` | Block number |
| `block_hash` | `Hash256` | Block identifier |
| `entry` | `ChainEntry` | On-chain record |

### Sync Status

```rust
use veritas_core::verification::SyncStatus;

let status: SyncStatus = client.sync_status().await?;

if status.is_synced() {
    println!("Fully synced at height {}", status.local_height);
} else {
    println!("Syncing: {:.1}% ({} blocks behind)",
        status.progress_percent,
        status.blocks_behind()
    );
}
```

### SyncStatus Fields

| Field | Type | Description |
|-------|------|-------------|
| `local_height` | `u64` | Local chain height |
| `network_height` | `u64` | Known network height |
| `is_syncing` | `bool` | Currently syncing |
| `pending_headers` | `usize` | Headers to process |
| `pending_blocks` | `usize` | Blocks to process |
| `progress_percent` | `f32` | Sync progress (0-100) |

---

## Configuration

### ClientConfig

```rust
use veritas_core::config::{ClientConfig, ClientConfigBuilder};
use std::time::Duration;

// Default configuration
let config = ClientConfig::default();

// Builder pattern
let config = ClientConfigBuilder::new()
    .with_data_dir("/custom/path".into())
    .disable_bluetooth()
    .with_bootstrap_peer("/dns4/peer.example.com/tcp/4001".into())
    .with_connection_timeout(Duration::from_secs(60))
    .enable_read_receipts()
    .build();

// In-memory configuration
let config = ClientConfig::in_memory();

// Validate configuration
config.validate()?;
```

### StorageConfig

| Option | Default | Description |
|--------|---------|-------------|
| `data_dir` | Platform-specific | Data storage directory |
| `in_memory` | false | Use RAM instead of disk |
| `encrypt_database` | true | Encrypt stored data |

### NetworkConfig

| Option | Default | Description |
|--------|---------|-------------|
| `enable_internet` | true | Allow internet connections |
| `enable_local_discovery` | true | mDNS peer discovery |
| `enable_bluetooth` | true | BLE relay transport |
| `bootstrap_peers` | [] | Initial peer addresses |
| `listen_addresses` | [] | Addresses to listen on |
| `connection_timeout` | 30s | Connection timeout |

### ReputationConfig

| Option | Default | Description |
|--------|---------|-------------|
| `enabled` | true | Enable reputation system |
| `enable_collusion_detection` | true | Graph analysis for gaming |
| `decay_rate_percent` | 1.0 | Daily decay rate |

### FeatureConfig

| Option | Default | Description |
|--------|---------|-------------|
| `timing_jitter` | true | Random send delays |
| `auto_queue_offline` | true | Queue when offline |
| `max_queued_messages` | 1000 | Max queued messages |
| `delivery_receipts` | true | Send delivery confirmations |
| `read_receipts` | false | Send read confirmations |

---

## Error Handling

### CoreError

All operations return `Result<T, CoreError>`.

```rust
use veritas_core::error::CoreError;

match client.send_message(&recipient, "Hello", options).await {
    Ok(hash) => println!("Sent: {}", hash),
    Err(CoreError::Locked) => println!("Client is locked"),
    Err(CoreError::NotInitialized) => println!("Not initialized"),
    Err(CoreError::AuthenticationFailed) => println!("Wrong password"),
    Err(CoreError::NoPrimaryIdentity) => println!("Create identity first"),
    Err(e) => println!("Error: {}", e),
}
```

### Error Types

| Error | Description |
|-------|-------------|
| `CoreError::Crypto` | Cryptographic operation failed |
| `CoreError::Identity` | Identity operation failed |
| `CoreError::Protocol` | Protocol error |
| `CoreError::Chain` | Blockchain error |
| `CoreError::Net` | Network error |
| `CoreError::Store` | Storage error |
| `CoreError::Reputation` | Reputation error |
| `CoreError::NotInitialized` | Client not unlocked |
| `CoreError::Locked` | Client is locked |
| `CoreError::ShuttingDown` | Client shutting down |
| `CoreError::NoPrimaryIdentity` | No identity set |
| `CoreError::AuthenticationFailed` | Wrong password |
| `CoreError::NotImplemented` | Feature not ready |

---

## FFI Bindings

C-compatible bindings for use from other languages.

### Header Generation

```bash
cd crates/veritas-ffi
cargo build --release
# Header generated at target/veritas.h
```

### Example Usage (C)

```c
#include "veritas.h"

int main() {
    VeritasClient* client = NULL;
    VeritasError err;

    // Create client
    err = veritas_client_new(&client);
    if (err != VERITAS_OK) {
        printf("Error: %d\n", err);
        return 1;
    }

    // Unlock
    err = veritas_client_unlock(client, "password", 8);
    if (err != VERITAS_OK) {
        veritas_client_free(client);
        return 1;
    }

    // Create identity
    char identity_hash[65];
    err = veritas_create_identity(client, "Personal", identity_hash, 65);

    // Clean up
    veritas_client_lock(client);
    veritas_client_free(client);

    return 0;
}
```

### Error Codes

| Code | Meaning |
|------|---------|
| `VERITAS_OK` (0) | Success |
| `VERITAS_ERR_NULL_POINTER` (1) | Null pointer argument |
| `VERITAS_ERR_INVALID_UTF8` (2) | Invalid UTF-8 string |
| `VERITAS_ERR_BUFFER_TOO_SMALL` (3) | Output buffer too small |
| `VERITAS_ERR_NOT_INITIALIZED` (4) | Client not initialized |
| `VERITAS_ERR_LOCKED` (5) | Client is locked |
| `VERITAS_ERR_AUTH_FAILED` (6) | Authentication failed |
| `VERITAS_ERR_INTERNAL` (99) | Internal error |

---

## WASM Bindings

WebAssembly bindings for browser and Node.js.

### Building

```bash
cd crates/veritas-wasm
wasm-pack build --target web      # For browsers
wasm-pack build --target nodejs   # For Node.js
```

### Browser Usage

```javascript
import init, { VeritasClient } from 'veritas-wasm';

async function main() {
    await init();

    const client = new VeritasClient();
    await client.unlock('password');

    const identityHash = await client.createIdentity('Personal');
    console.log('Identity:', identityHash);

    await client.lock();
}
```

### Node.js Usage

```javascript
const { VeritasClient } = require('veritas-wasm');

async function main() {
    const client = new VeritasClient();
    await client.unlock('password');

    const hash = await client.createIdentity('Personal');
    console.log('Created identity:', hash);

    await client.lock();
}
```

### TypeScript Types

```typescript
interface VeritasClient {
    unlock(password: string): Promise<void>;
    lock(): Promise<void>;
    createIdentity(label?: string): Promise<string>;
    identityHash(): Promise<string>;
    computeSafetyNumber(ourKeys: string, theirKeys: string): string;
}
```

---

## Python Bindings

Python bindings using PyO3.

### Installation

```bash
cd crates/veritas-py
maturin develop       # Development build
maturin build --release  # Release build
pip install target/wheels/veritas_py-*.whl
```

### Usage

```python
from veritas_py import VeritasClient

# Create client
client = VeritasClient()

# Unlock
client.unlock(b"password")

# Create identity
identity_hash = client.create_identity("Personal")
print(f"Identity: {identity_hash}")

# Lock when done
client.lock()
```

### Safety Numbers

```python
from veritas_py import compute_safety_number

# Compute safety number from public keys (hex encoded)
safety_number = compute_safety_number(our_public_keys_hex, their_public_keys_hex)
print(f"Safety Number: {safety_number}")
```

### Error Handling

```python
from veritas_py import VeritasClient, VeritasError

try:
    client.unlock(b"wrong_password")
except VeritasError as e:
    print(f"Error: {e}")
```

---

## Security APIs (v0.3.0-beta)

The following APIs were added in v0.3.0-beta to address security vulnerabilities identified in the security audit.

---

### Hardware Attestation API

**Module**: `veritas-identity::hardware`

Hardware attestation provides cryptographic proof that operations originate from genuine secure hardware, preventing Sybil attacks via unlimited identity creation.

#### Platform Support

| Platform | Attestation Type |
|----------|------------------|
| Linux/Windows | TPM 2.0 |
| macOS/iOS | Secure Enclave |
| Android | Hardware-backed Keystore |

#### HardwareAttestation

```rust
use veritas_identity::hardware::{HardwareAttestation, AttestationPlatform};

// Collect attestation from secure hardware (platform-specific)
let attestation = HardwareAttestation::collect()?;

// Verify the attestation is valid
attestation.verify()?;

// Check attestation properties
if attestation.is_strong_binding() {
    println!("Platform: {:?}", attestation.platform());
    println!("Timestamp: {}", attestation.timestamp());
}

// Get deterministic fingerprint for identity limiting
let fingerprint = attestation.fingerprint();
```

#### OriginFingerprint

```rust
use veritas_identity::limits::OriginFingerprint;
use veritas_identity::hardware::HardwareAttestation;

// Create a hardware-bound origin fingerprint (PRODUCTION)
let attestation = HardwareAttestation::collect()?;
let origin = OriginFingerprint::from_hardware(&attestation)?;

// The same hardware always produces the same fingerprint
// This limits each device to MAX_IDENTITIES_PER_ORIGIN (3) identities
```

#### AttestationPlatform

| Variant | Strong Binding | Description |
|---------|----------------|-------------|
| `Tpm2` | Yes | TPM 2.0 attestation |
| `SecureEnclave` | Yes | Apple Secure Enclave |
| `AndroidKeystore` | Yes | Android hardware keystore |
| `GenericHardware` | No | Fallback (rejected in production) |

#### Error Types

| Error | Description |
|-------|-------------|
| `IdentityError::HardwareNotAvailable` | No supported secure hardware detected |
| `IdentityError::HardwareAttestationFailed` | Attestation collection or verification failed |

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ATTESTATION_MAX_AGE_SECS` | 300 | Attestation staleness threshold (5 min) |
| `MIN_HARDWARE_ID_LEN` | 16 | Minimum hardware ID length |
| `MAX_HARDWARE_ID_LEN` | 256 | Maximum hardware ID length |
| `MAX_ATTESTATION_SIGNATURE_LEN` | 512 | Maximum signature length |

#### Security Considerations

- **Production Requirement**: `OriginFingerprint::from_hardware()` is the ONLY way to create fingerprints in production. The `generate()` method is only available in tests.
- **Replay Prevention**: Attestations include timestamps and nonces to prevent replay attacks.
- **Platform Verification**: In production, only strong binding platforms (TPM, Secure Enclave, Android Keystore) are accepted.

---

### Rate Limiting API

**Module**: `veritas-net::rate_limiter`

Rate limiting prevents gossip protocol flooding attacks that could exhaust network resources.

#### RateLimiter

```rust
use veritas_net::rate_limiter::{RateLimiter, RateLimitConfig, RateLimitResult};
use libp2p::PeerId;

// Create with default configuration
let mut limiter = RateLimiter::with_defaults();

// Or with custom configuration
let config = RateLimitConfig::new()
    .with_per_peer_rate(10)      // 10 requests/second per peer
    .with_global_rate(1000)       // 1000 requests/second globally
    .with_burst_multiplier(3)     // Allow 3x burst
    .with_violations_before_ban(5)
    .with_ban_duration_secs(300);
let mut limiter = RateLimiter::new(config);

// Check if a request is allowed
let peer_id: PeerId = /* ... */;
if limiter.check(&peer_id) {
    // Process the request
    process_announcement(&peer_id);
} else {
    // Rate limit exceeded - record violation
    if limiter.record_violation(&peer_id) {
        println!("Peer {} has been banned", peer_id);
    }
}
```

#### Detailed Rate Limit Checking

```rust
use veritas_net::rate_limiter::RateLimitResult;

match limiter.check_detailed(&peer_id) {
    RateLimitResult::Allowed => {
        // Process request
    }
    RateLimitResult::Banned => {
        // Peer is banned, reject silently
    }
    RateLimitResult::PeerLimitExceeded => {
        // This specific peer is rate limited
        limiter.record_violation(&peer_id);
    }
    RateLimitResult::GlobalLimitExceeded => {
        // System-wide limit reached, don't penalize peer
    }
}
```

#### Ban Management

```rust
// Manually ban a peer
limiter.ban_peer(&peer_id);

// Check ban status
if limiter.is_banned(&peer_id) {
    println!("Peer is banned");
}

// Unban a peer
limiter.unban_peer(&peer_id);

// Get all banned peers
let banned: Vec<PeerId> = limiter.banned_peers();
println!("Banned peer count: {}", limiter.banned_peer_count());

// Get violation count for a peer
let violations = limiter.violation_count(&peer_id);
```

#### RateLimitConfig Options

| Option | Default | Description |
|--------|---------|-------------|
| `per_peer_rate` | 10 | Max requests per peer per second |
| `global_rate` | 1000 | Max requests globally per second |
| `burst_multiplier` | 3 | Burst capacity multiplier |
| `violations_before_ban` | 5 | Violations before automatic ban |
| `ban_duration_secs` | 300 | Ban duration (5 minutes) |

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DEFAULT_PER_PEER_RATE` | 10 | Default per-peer rate |
| `DEFAULT_GLOBAL_RATE` | 1000 | Default global rate |
| `DEFAULT_BURST_MULTIPLIER` | 3 | Default burst multiplier |
| `DEFAULT_VIOLATIONS_BEFORE_BAN` | 5 | Default violation threshold |
| `DEFAULT_BAN_DURATION_SECS` | 300 | Default ban duration |

---

### Subnet Limiting API

**Module**: `veritas-net::subnet_limiter`

Subnet limiting enforces DHT routing table diversity to prevent eclipse attacks where an attacker controls all peers used for DHT queries.

#### SubnetLimiter

```rust
use veritas_net::subnet_limiter::{SubnetLimiter, SubnetLimiterConfig, PeerAcceptResult};
use libp2p::{PeerId, Multiaddr};

// Create with default configuration
let mut limiter = SubnetLimiter::new();

// Or with custom configuration
let config = SubnetLimiterConfig {
    max_peers_per_subnet: 2,
    allow_unknown_subnets: true,
    max_unknown_subnet_peers: 5,
    min_acceptance_reputation: -100,
    prefer_higher_reputation: true,
};
let mut limiter = SubnetLimiter::with_config(config);

// Attempt to add a peer
let peer_id: PeerId = /* ... */;
let addr: Multiaddr = "/ip4/192.168.1.100/tcp/9000".parse()?;

match limiter.try_add_peer(peer_id, &addr) {
    PeerAcceptResult::Accepted => {
        println!("Peer accepted");
    }
    PeerAcceptResult::RejectedSubnetLimit { subnet, current_count } => {
        println!("Subnet {} at capacity ({} peers)", subnet, current_count);
    }
    PeerAcceptResult::RejectedLowReputation { reputation } => {
        println!("Peer reputation too low: {}", reputation);
    }
    PeerAcceptResult::ReplacedLowerReputation { replaced_peer } => {
        println!("Replaced peer {} with lower reputation", replaced_peer);
    }
    PeerAcceptResult::AlreadyPresent => {
        println!("Peer already in routing table");
    }
}
```

#### Read-Only Checks

```rust
// Check without modifying state
if limiter.can_accept_peer(&peer_id, &addr) {
    // Peer would be accepted
}

// Get peer count for a subnet
let subnet_key = SubnetKey::from_multiaddr(&addr);
let count = limiter.subnet_peer_count(&subnet_key);
```

#### Reputation Tracking

```rust
// Record successful DHT operation
limiter.record_success(&peer_id);

// Record failed DHT operation
limiter.record_failure(&peer_id);

// Record suspicious behavior
limiter.record_suspicious(&peer_id, "invalid response format");

// Check reputation
if let Some(rep) = limiter.get_reputation(&peer_id) {
    println!("Reputation: {}", rep);
}

// Check if peer is trusted
if limiter.is_trusted(&peer_id) {
    // Use peer for sensitive operations
}
```

#### Diverse Peer Selection

```rust
// Select diverse peers for DHT queries (from different subnets)
let peers = limiter.select_diverse_peers(5);
for peer in peers {
    query_dht(&peer);
}
```

#### Statistics

```rust
let stats = limiter.stats();
println!("Peers accepted: {}", stats.peers_accepted);
println!("Rejected (subnet): {}", stats.peers_rejected_subnet);
println!("Rejected (reputation): {}", stats.peers_rejected_reputation);
println!("Total peers: {}", limiter.total_peer_count());
println!("Unique subnets: {}", limiter.subnet_count());
```

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PEERS_PER_SUBNET` | 2 | Max peers per /24 (IPv4) or /48 (IPv6) |
| `SUBNET_MASK_V4` | 24 | IPv4 subnet mask bits |
| `SUBNET_MASK_V6` | 48 | IPv6 subnet mask bits |
| `MIN_TRUSTED_REPUTATION` | 10 | Reputation threshold for trusted peers |
| `REPUTATION_GAIN_SUCCESS` | 1 | Points gained per success |
| `REPUTATION_LOSS_FAILURE` | 5 | Points lost per failure |
| `REPUTATION_LOSS_SUSPICIOUS` | 20 | Points lost for suspicious behavior |

---

### Interaction Proofs API

**Module**: `veritas-reputation::proof`

Interaction proofs provide cryptographic evidence that interactions occurred, preventing unauthorized reputation farming.

#### InteractionProof

```rust
use veritas_reputation::proof::{
    InteractionProof, InteractionType, Signature, generate_nonce
};

// Generate a unique nonce for replay protection
let nonce = generate_nonce();

// Create signatures (implementation depends on key type)
let from_signature = Signature::from_bytes(sign(&payload, &from_key))?;
let to_signature = Signature::from_bytes(sign(&payload, &to_key))?;

// Create an interaction proof
let proof = InteractionProof::new(
    from_identity,           // Initiating party
    to_identity,             // Receiving party
    InteractionType::MessageDelivery,
    timestamp,
    nonce,
    from_signature,
    Some(to_signature),      // Required for most interaction types
)?;

// Verify the proof
proof.verify(|identity, message, signature| {
    // Your signature verification logic
    verify_signature(identity, message, signature)
})?;

// Validate timestamp
proof.validate_timestamp(current_time)?;
```

#### InteractionType

| Type | Base Gain | Counter-Sig Required | Description |
|------|-----------|---------------------|-------------|
| `MessageRelay` | 3 | Yes | Relayed a message |
| `MessageStorage` | 5 | Yes | Stored for offline delivery |
| `MessageDelivery` | 5 | Yes | Delivered to recipient |
| `DhtParticipation` | 2 | Yes | DHT operations |
| `BlockValidation` | 10 | No | Validated a block |

#### Using Proofs with ReputationManager

```rust
use veritas_reputation::manager::ReputationManager;

// Proofs are REQUIRED for reputation changes
let result = manager.record_positive_interaction(
    from_identity,
    to_identity,
    &proof,  // Must provide valid proof
)?;

println!("New reputation score: {}", result);
```

#### Replay Protection

```rust
// Each nonce can only be used once
let nonce = proof.nonce();

// Track used nonces to prevent replay
if used_nonces.contains(nonce) {
    return Err(ReputationError::NonceAlreadyUsed);
}
used_nonces.insert(*nonce);
```

#### Error Types

| Error | Description |
|-------|-------------|
| `ReputationError::SelfInteractionNotAllowed` | from == to |
| `ReputationError::MissingCounterSignature` | Required counter-sig not provided |
| `ReputationError::InvalidSignature` | Signature verification failed |
| `ReputationError::InvalidProof` | Timestamp validation failed |
| `ReputationError::NonceAlreadyUsed` | Replay attack detected |

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CLOCK_SKEW_SECS` | 300 | Allowed clock skew (5 min) |
| `MAX_PROOF_AGE_SECS` | 86400 | Max proof age (24 hours) |
| `NONCE_SIZE` | 32 | Nonce size in bytes |
| `MAX_SIGNATURE_SIZE` | 4096 | Max signature size |

---

### Trusted Time API

**Module**: `veritas-core::time`

Trusted time validation prevents time manipulation attacks that could bypass key expiry or message TTL.

#### Basic Time Functions

```rust
use veritas_core::time::{now, now_or_safe_fallback, validate_timestamp};

// Get current timestamp (may fail)
let current_time = now()?;

// Get current timestamp with fallback (never fails)
let safe_time = now_or_safe_fallback();

// Validate a timestamp
match validate_timestamp(some_timestamp) {
    Ok(()) => println!("Timestamp is valid"),
    Err(e) => println!("Invalid timestamp: {}", e),
}
```

#### Timestamp Validation

```rust
use veritas_core::time::{
    validate_timestamp, validate_timestamp_at,
    is_future_timestamp, is_ancient_timestamp,
    TimeError
};

// Validate against current time
validate_timestamp(message_timestamp)?;

// Validate against a specific reference time (for testing)
validate_timestamp_at(timestamp, reference_time)?;

// Quick checks
if is_future_timestamp(timestamp) {
    return Err("timestamp is in the future");
}

if is_ancient_timestamp(timestamp) {
    return Err("timestamp is too old");
}
```

#### TimeError Types

```rust
use veritas_core::time::TimeError;

match validate_timestamp(timestamp) {
    Err(TimeError::TimestampInFuture { timestamp, max_skew }) => {
        println!("Too far in future: {} (max skew: {}s)", timestamp, max_skew);
    }
    Err(TimeError::TimestampTooOld { timestamp, min_valid }) => {
        println!("Too old: {} (min valid: {})", timestamp, min_valid);
    }
    Err(TimeError::TimestampTooLarge { timestamp, max_valid }) => {
        println!("Exceeds max: {} (max: {})", timestamp, max_valid);
    }
    Err(TimeError::SystemTimeError(msg)) => {
        println!("System time error: {}", msg);
    }
    Ok(()) => {
        println!("Timestamp is valid");
    }
}
```

#### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CLOCK_SKEW_SECS` | 300 | Allowed future skew (5 min) |
| `MIN_VALID_TIMESTAMP` | 1704067200 | 2024-01-01 00:00:00 UTC |
| `MAX_VALID_TIMESTAMP` | 4102444800 | 2100-01-01 00:00:00 UTC |

#### Security Considerations

- Timestamps beyond `MAX_CLOCK_SKEW_SECS` in the future are rejected
- Timestamps before `MIN_VALID_TIMESTAMP` (protocol inception) are rejected
- The fallback function returns `MIN_VALID_TIMESTAMP` on system time errors, ensuring conservative security behavior

---

### Block Signature API

**Module**: `veritas-chain::block`

Block signatures provide cryptographic proof that blocks were produced by authorized validators, preventing block forgery attacks.

#### Creating Signed Blocks

```rust
use veritas_chain::{Block, BlockHeader};
use veritas_crypto::MlDsaPrivateKey;

// Generate or load validator keys
let validator_private_key: MlDsaPrivateKey = /* ... */;

// Create a SIGNED block (required for production)
let block = Block::new_signed(
    parent_hash,
    height,
    timestamp,
    entries,
    validator_identity,
    &validator_private_key,
)?;

// Verify the block has a signature
assert!(block.has_signature());
```

#### Verifying Block Signatures

```rust
use veritas_chain::Block;

// CRITICAL: Always verify signatures before trusting block data
block.verify_with_signature()?;

// Or verify just the header signature
block.header.verify_signature()?;
```

#### BlockHeader Signature Methods

```rust
use veritas_chain::BlockHeader;

// Get the signing payload (domain-separated)
let payload = header.compute_signing_payload();
// payload = "VERITAS-BLOCK-SIGNATURE-v1" || block_hash

// Check if signature is present
if header.has_signature() {
    // Verify the signature
    header.verify_signature()?;
}
```

#### Verification Steps

`verify_signature()` performs the following checks for non-genesis blocks:

1. Signature is present (non-empty)
2. Public key is present (non-empty)
3. Public key derives to the claimed validator identity
4. ML-DSA signature is valid over the signing payload

#### Error Types

| Error | Description |
|-------|-------------|
| `ChainError::MissingSignature` | Block lacks required signature |
| `ChainError::ValidatorKeyMismatch` | Public key doesn't match validator ID |
| `ChainError::InvalidSignature` | Signature verification failed |

#### Block Validation with Signatures

```rust
use veritas_chain::chain::BlockValidation;

// Validate a block including signature verification
BlockValidation::validate_producer(&block, &authorized_validators)?;

// This checks:
// 1. Genesis blocks have the correct genesis validator
// 2. Non-genesis blocks have valid signatures
// 3. The validator is in the authorized set
```

#### Security Considerations

- Genesis blocks (height 0) are exempt from signature requirements
- `Block::new()` creates UNSIGNED blocks (test only)
- `Block::new_signed()` creates SIGNED blocks (required for production)
- Signature verification happens BEFORE checking the validator set
- The signing payload includes a domain separator to prevent cross-protocol attacks

---

### Username Registration API

**Module**: `veritas-chain::chain`

Username registration provides case-insensitive unique username allocation on the blockchain.

#### Looking Up Usernames

```rust
use veritas_chain::chain::Blockchain;

// Look up the owner of a username (case-insensitive)
if let Some(owner) = blockchain.lookup_username("Alice") {
    println!("Username 'Alice' is owned by: {}", owner.to_hex());
} else {
    println!("Username 'Alice' is available");
}

// Check availability
if blockchain.is_username_available("alice") {
    println!("Username is available for registration");
}

// All case variants resolve to the same owner
assert_eq!(
    blockchain.lookup_username("alice"),
    blockchain.lookup_username("ALICE")
);
assert_eq!(
    blockchain.lookup_username("alice"),
    blockchain.lookup_username("Alice")
);
```

#### Registering Usernames

```rust
use veritas_chain::chain::Blockchain;
use veritas_identity::IdentityHash;

let identity: IdentityHash = /* your identity */;

// Register a username
match blockchain.register_username("alice", &identity) {
    Ok(()) => println!("Username registered successfully"),
    Err(ChainError::UsernameTaken { username, owner }) => {
        println!("'{}' is already taken by {}", username, owner);
    }
    Err(ChainError::InvalidUsername(reason)) => {
        println!("Invalid username: {}", reason);
    }
    Err(e) => println!("Error: {}", e),
}

// Re-registration by same owner is idempotent (succeeds)
blockchain.register_username("alice", &identity)?; // OK
```

#### Username Validation Rules

| Rule | Example |
|------|---------|
| Minimum length | "ab" rejected (too short) |
| Cannot start with underscore | "_alice" rejected |
| Alphanumeric + underscore only | "alice@bob" rejected |
| Reserved names blocked | "admin", "system", "veritas", "support" |
| Case-insensitive uniqueness | "Alice" and "ALICE" are the same |

#### Error Types

| Error | Description |
|-------|-------------|
| `ChainError::UsernameTaken` | Username registered to different identity |
| `ChainError::InvalidUsername` | Format violation or reserved name |

#### Username Count

```rust
// Get total registered usernames
let count = blockchain.username_count();
println!("Total registered usernames: {}", count);
```

#### Index Rebuilding

```rust
// Rebuild username index from blockchain (used during sync/reorg)
blockchain.rebuild_username_index()?;
```

#### Security Considerations

- Usernames are normalized to lowercase for storage and lookup
- Case-insensitive collision detection prevents spoofing (e.g., "Admin" vs "admin")
- Reserved names are blocked to prevent impersonation
- Same-owner re-registration is allowed (idempotent) for update/renewal scenarios
- The index survives chain reorganizations via rebuilding

---

## Protocol Limits Reference

### Messages

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_MESSAGE_CHARS` | 300 | Max chars per chunk |
| `MAX_CHUNKS_PER_MESSAGE` | 3 | Max chunks |
| `MAX_TOTAL_MESSAGE_CHARS` | 900 | Max total chars |
| `MESSAGE_TTL_SECS` | 604800 | 7 days |

### Privacy

| Constant | Value | Description |
|----------|-------|-------------|
| `PADDING_BUCKETS` | [256, 512, 1024] | Size buckets |
| `MAX_JITTER_MS` | 3000 | Max timing jitter |
| `EPOCH_DURATION_SECS` | 86400 | 1 day |

### Identity

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_IDENTITIES_PER_ORIGIN` | 3 | Per device limit |
| `KEY_EXPIRY_SECS` | 2592000 | 30 days |
| `KEY_WARNING_SECS` | 432000 | 5 days |

### Groups

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_GROUP_SIZE` | 100 | Max members |
| `MAX_GROUPS_PER_IDENTITY` | 50 | Max groups |
| `GROUP_KEY_ROTATION_SECS` | 604800 | 7 days |

### Reputation

| Constant | Value | Description |
|----------|-------|-------------|
| `REPUTATION_START` | 500 | Initial score |
| `REPUTATION_MAX` | 1000 | Maximum score |
| `REPUTATION_QUARANTINE` | 200 | Quarantine threshold |
| `REPUTATION_BLACKLIST` | 50 | Blacklist threshold |

### Validators

| Constant | Value | Description |
|----------|-------|-------------|
| `MIN_VALIDATOR_STAKE` | 700 | Min reputation |
| `MAX_VALIDATORS` | 21 | Max active |
| `MIN_UPTIME_PERCENT` | 99.0 | Required uptime |

---

## See Also

- [Architecture Guide](ARCHITECTURE.md) - System design and data flow
- [Security Guide](SECURITY.md) - Threat model and cryptographic design
- [Setup Guide](SETUP.md) - Installation and configuration
