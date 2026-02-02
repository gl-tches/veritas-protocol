# CLAUDE.md — VERITAS Protocol

> Instructions for Claude Code sessions working on this project

## Project Context

VERITAS (Verified Encrypted Real-time Integrity Transmission And Signing) is a post-quantum secure, decentralized messaging protocol with blockchain verification and offline P2P capability.

**Type**: Rust Library + Multi-platform Bindings
**Stack**: Rust, ML-KEM, ML-DSA, ChaCha20-Poly1305, libp2p, sled
**Security Level**: HARDENED + POST-QUANTUM
**Edition**: Rust 2024
**MSRV**: 1.85
**Version**: 0.3.0-beta

## ✅ Completed Work Streams

### 1. Security Remediation (COMPLETED — v0.3.0-beta)

All 90 actionable vulnerabilities from SECURITY_AUDIT_REPORT.md have been addressed.
- **90 vulnerabilities**: Fixed and verified
- **1 design-level issue**: VERITAS-2026-0004 (validator consensus) requires architecture redesign
- **Hardware attestation**: Framework complete, platform-specific stubs remain

### 2. Rust 2024 Edition Migration (COMPLETED — v0.3.0-beta)

**Status**: All 12 crates migrated to Rust 2024 edition
**MSRV**: 1.85
**Tracking**: See TASKS.md for detailed completion log

**Key Changes Applied**:
- All Cargo.toml files updated to `edition = "2024"`, `rust-version = "1.85"`
- 12 `#[no_mangle]` → `#[unsafe(no_mangle)]` in FFI crate
- 13 clippy warnings fixed for Rust 2024 stricter lints
- cbindgen 0.26 → 0.29, PyO3 0.20 → 0.23 for compatibility

## 📋 Remaining Work

| Item | Priority | Status |
|------|----------|--------|
| VERITAS-2026-0004 (validator consensus) | P2 | Design needed |
| Hardware attestation (TPM/SecureEnclave/AndroidKeystore) | P2 | Platform stubs |
| Post-quantum crypto stabilization (ML-KEM/ML-DSA) | P3 | Waiting upstream |
| Bluetooth implementation (btleplug) | P3 | Stubbed |
| Async closures refactoring (TASK-170) | P4 | Optional |

-----

## Sub-Agent Team Structure

Claude Code operates as the **Lead Developer** coordinating a team of specialized sub-agents.

### Core Team

|Agent          |Role             |Responsibilities                           |
|---------------|-----------------|-------------------------------------------|
|**🏗️ Architect**|System Design    |Architecture, module boundaries, API design|
|**🔒 Security** |Security Engineer|Security reviews, crypto, threat analysis  |
|**⚡ Backend**  |Core Developer   |Protocol, networking, blockchain, storage  |
|**🧪 QA**       |Test Engineer    |Unit/integration/property tests, fuzzing   |
|**📚 Docs**     |Technical Writer |Documentation, code comments, API docs     |
|**🔌 Bindings** |FFI Developer    |C/WASM/Python bindings, cross-platform     |

### Security Remediation Specialists

|Agent                  |Specialization           |
|-----------------------|-------------------------|
|**🛡️ CryptoAuditor**    |Cryptographic security   |
|**🆔 IdentityAuditor**  |Identity & authentication|
|**📡 ProtocolAuditor**  |Wire protocol security   |
|**⛓️ ChainAuditor**     |Blockchain security      |
|**🌐 NetworkAuditor**   |P2P networking security  |
|**💾 StorageAuditor**   |Data security            |
|**⭐ ReputationAuditor**|Anti-gaming measures     |

### Agent Spawning Rules

**ALWAYS spawn sub-agents for:**

- Security fixes → Relevant auditor + QA + Security review
- Cryptographic code → Security agent MUST review
- Wire protocol changes → Architect + Security
- FFI changes → Bindings + Security
- Edition migration → QA (for thorough testing)

**Spawn agents IN PARALLEL when possible.**

-----

## Commands

### Development

```bash
cargo build --release        # Build all crates
cargo test --all             # Run all tests
cargo clippy --all-targets   # Lint check
cargo fmt --all              # Format code
cargo audit                  # Security audit
```

### Edition Migration

```bash
# Check compatibility before migration
cargo +1.85 check --all

# Auto-fix edition issues for a crate
cargo fix --edition -p veritas-crypto --allow-dirty

# Verify after migration
cargo test -p veritas-crypto
cargo clippy -p veritas-crypto -- -D warnings
```

### Crate-Specific

```bash
cargo test -p veritas-crypto     # Test specific crate
cargo doc --no-deps --open       # Generate docs
```

### WASM Build

```bash
cd crates/veritas-wasm
wasm-pack build --target web
wasm-pack build --target nodejs
```

### Python Build

```bash
cd crates/veritas-py
maturin develop              # Dev build
maturin build --release      # Release build
```

-----

## Rust 2024 Edition Migration Guide

### Migration Order (Follow TASKS.md)

```
Phase 1: Leaf Crates (no internal deps)
  ├── veritas-crypto
  ├── veritas-identity  
  └── veritas-reputation

Phase 2: Protocol & Storage
  ├── veritas-protocol
  ├── veritas-store
  └── veritas-chain

Phase 3: Networking
  └── veritas-net

Phase 4: High-Level API
  └── veritas-core

Phase 5: FFI & Bindings (most changes)
  ├── veritas-ffi
  ├── veritas-wasm
  └── veritas-py

Phase 6: Workspace & Docs
```

### Per-Crate Migration Steps

```bash
# 1. Run auto-fix
cargo fix --edition -p <crate-name> --allow-dirty

# 2. Update Cargo.toml
edition = "2024"
rust-version = "1.85"

# 3. Manual review (see below)

# 4. Test
cargo test -p <crate-name>
cargo clippy -p <crate-name> -- -D warnings
```

### Rust 2024 Required Changes

#### 1. `unsafe extern` Blocks (FFI crates)

```rust
// ❌ Rust 2021
extern "C" {
    fn external_function();
}

// ✅ Rust 2024
unsafe extern "C" {
    fn external_function();
    
    // NEW: Can mark safe items explicitly
    pub safe fn sqrt(x: f64) -> f64;
}
```

#### 2. Unsafe Attributes (FFI crates)

```rust
// ❌ Rust 2021
#[no_mangle]
pub extern "C" fn veritas_init() -> i32 { 0 }

// ✅ Rust 2024
#[unsafe(no_mangle)]
pub extern "C" fn veritas_init() -> i32 { 0 }
```

#### 3. Explicit Unsafe in Unsafe Functions

```rust
// ❌ Rust 2021 — implicit unsafe
unsafe fn process_ptr(ptr: *const u8) -> u8 {
    *ptr  // No marker needed
}

// ✅ Rust 2024 — explicit unsafe required
unsafe fn process_ptr(ptr: *const u8) -> u8 {
    unsafe { *ptr }  // Must wrap unsafe ops
}
```

#### 4. `static mut` References (if any exist)

```rust
// ❌ Rust 2024 — ERROR
static mut COUNTER: u64 = 0;
let r = unsafe { &mut COUNTER };

// ✅ Rust 2024 — use raw pointers
static mut COUNTER: u64 = 0;
let ptr = unsafe { &raw mut COUNTER };
unsafe { *ptr += 1; }

// ✅✅ Better — use atomics
static COUNTER: AtomicU64 = AtomicU64::new(0);
COUNTER.fetch_add(1, Ordering::SeqCst);
```

### Rust 2024 Semantic Changes (Review Carefully)

#### Lock Scoping in `if let`

```rust
// Behavior CHANGES in Rust 2024
// MutexGuard now drops EARLIER

// Review this pattern in veritas-store, veritas-chain:
if let Some(data) = mutex.lock().unwrap().get(&key) {
    // 2021: lock held here
    // 2024: lock already dropped!
    process(data);
}
```

If `cargo fix` adds explicit blocks, **review whether the old behavior was intentional**.

#### Tail Expression Temporaries

```rust
// Behavior CHANGES in Rust 2024
fn get_value(map: &Mutex<HashMap<K, V>>) -> V {
    map.lock().unwrap().get(&key).cloned()
    // 2021: MutexGuard dropped after this line
    // 2024: MutexGuard dropped before return
}
```

### Rust 2024 Opportunities (Optional Refactoring)

#### Async Closures (veritas-net)

```rust
// ❌ Rust 2021 — verbose
let futures: Vec<_> = peers.iter()
    .map(|peer| {
        let peer = peer.clone();  // Must clone
        async move {
            send_to_peer(&peer).await
        }
    })
    .collect();

// ✅ Rust 2024 — native async closures
let futures: Vec<_> = peers.iter()
    .map(async |peer| {  // Direct capture!
        send_to_peer(peer).await
    })
    .collect();
```

**Note**: This refactoring is OPTIONAL. The protocol works without it.

-----

## Transport Selection Rules

**CRITICAL: Network-first transport selection**

```rust
pub async fn select_transport(&self) -> TransportType {
    // 1. ALWAYS try internet first
    if self.internet.is_connected().await {
        return TransportType::Internet;
    }
    
    // 2. Try local WiFi relay
    if self.local.has_peers().await {
        return TransportType::LocalNetwork;
    }
    
    // 3. Fall back to Bluetooth relay
    if self.bluetooth.has_peers().await {
        return TransportType::Bluetooth;
    }
    
    // 4. No connectivity — queue locally
    TransportType::Queued
}
```

### Bluetooth Rules

- **NO PIN verification** — BLE is pure relay, not security boundary
- **NO pairing required** — Any VERITAS node can relay
- **Security from E2E encryption** — Not from transport layer

### Contact Requirement

- **Must know recipient hash to send** — No discovery mechanism
- **Share hash out-of-band** — QR code, in person, etc.

-----

## Minimal Metadata Envelope

**CRITICAL: Hide all identifiable metadata**

```rust
/// Minimal envelope — leaks NO identifiable information
pub struct Envelope {
    pub mailbox_key: [u8; 32],      // Derived, rotates per epoch
    pub ephemeral_public: [u8; 32], // Single-use per message
    pub nonce: [u8; 24],            // Random
    pub ciphertext: Vec<u8>,        // Encrypted + padded
}

/// All sensitive data INSIDE encrypted payload
struct InnerPayload {
    sender_id: IdentityHash,   // HIDDEN from relays
    timestamp: u64,            // HIDDEN from relays
    content: MessageContent,   // HIDDEN from relays
    signature: Vec<u8>,        // HIDDEN from relays
}
```

### Metadata Rules

|DO                                              |DON’T                       |
|------------------------------------------------|----------------------------|
|Derive mailbox key from recipient + epoch + salt|Put recipient ID in envelope|
|Use ephemeral key per message                   |Reuse keys across messages  |
|Pad to fixed size buckets (256/512/1024)        |Reveal true message size    |
|Put sender/timestamp inside encrypted payload   |Put on envelope             |
|Add timing jitter (0-3 sec)                     |Send immediately            |

-----

## Security Patterns

### Size Validation BEFORE Deserialization

```rust
pub const MAX_ENVELOPE_SIZE: usize = 2048;

pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
    // SECURITY: Check size BEFORE deserialization
    if bytes.len() > MAX_ENVELOPE_SIZE {
        return Err(ProtocolError::InvalidEnvelope("too large".into()));
    }
    let envelope: Self = bincode::deserialize(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}
```

### Cryptographic Signature Verification

```rust
impl BlockHeader {
    pub fn verify_signature(&self) -> Result<(), ChainError> {
        let payload = self.compute_signing_payload();
        self.validator_pubkey.verify(&payload, &self.signature)?;
        
        // Also verify pubkey matches claimed identity
        let expected_id = ValidatorId::from_pubkey(&self.validator_pubkey);
        if expected_id != self.validator {
            return Err(ChainError::ValidatorKeyMismatch);
        }
        Ok(())
    }
}
```

### Rate Limiting

```rust
pub async fn handle_announcement(&mut self, peer_id: PeerId, data: Vec<u8>) -> Result<()> {
    // Check rate limit BEFORE processing
    if !self.rate_limiter.check(&peer_id) {
        self.record_violation(&peer_id);
        return Err(GossipError::RateLimitExceeded);
    }
    self.process_announcement(peer_id, data).await
}
```

### Timestamp Validation

```rust
const MAX_CLOCK_SKEW_SECS: u64 = 300;

pub fn validate_timestamp(timestamp: u64) -> Result<(), TimeError> {
    let now = trusted_time::now();
    if timestamp > now + MAX_CLOCK_SKEW_SECS {
        return Err(TimeError::TimestampInFuture);
    }
    if timestamp < MIN_VALID_TIMESTAMP {
        return Err(TimeError::TimestampTooOld);
    }
    Ok(())
}
```

### Interaction Proof Authentication

```rust
pub fn record_positive_interaction(
    &mut self,
    from: IdentityHash,
    to: IdentityHash,
    proof: &InteractionProof,  // REQUIRED
) -> Result<u32, ReputationError> {
    if from == to { return Err(ReputationError::SelfInteractionNotAllowed); }
    
    proof.verify(&from_pubkey, Some(&to_pubkey))?;
    
    if self.used_nonces.contains(&proof.nonce) {
        return Err(ReputationError::NonceAlreadyUsed);
    }
    self.used_nonces.insert(proof.nonce);
    
    self.apply_score_change(to, base_gain)
}
```

-----

## Code Patterns

### Error Handling

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Decryption failed: invalid ciphertext or key")]
    Decryption,
}
```

### Zeroization (ALL secret data)

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

// NEVER derive Clone on secret keys
```

### Constant-Time Comparisons

```rust
use subtle::ConstantTimeEq;

pub fn verify_tag(expected: &[u8], actual: &[u8]) -> bool {
    expected.ct_eq(actual).into()
}
```

-----

## Security Requirements

### Cryptographic Rules

1. **NEVER** implement crypto primitives — use audited libraries
1. **ALWAYS** use `OsRng` for randomness
1. **ALWAYS** use `zeroize` for secrets
1. **ALWAYS** use `subtle` for constant-time comparisons
1. **NEVER** log key material or secrets
1. **ALWAYS** verify signatures before trusting data
1. **ALWAYS** check sizes before deserialization

### DoS Prevention Rules

1. **ALWAYS** validate size BEFORE deserialization
1. **ALWAYS** implement rate limiting on network inputs
1. **ALWAYS** bound collection sizes
1. **ALWAYS** set timeouts on async operations

### Approved Crypto Libraries

|Purpose          |Crate               |Version      |
|-----------------|--------------------|-------------|
|ML-KEM           |`ml-kem`            |0.1.x        |
|ML-DSA           |`ml-dsa`            |0.1.x        |
|X25519           |`x25519-dalek`      |2.x          |
|ChaCha20-Poly1305|`chacha20poly1305`  |0.10.x       |
|BLAKE3           |`blake3`            |1.x          |
|Argon2           |`argon2`            |0.5.x        |
|Secure RNG       |`rand` + `getrandom`|0.8.x / 0.2.x|
|Zeroization      |`zeroize`           |1.x          |
|Constant-time    |`subtle`            |2.x          |

-----

## Protocol Limits

```rust
pub mod limits {
    // Messages
    pub const MAX_MESSAGE_CHARS: usize = 300;
    pub const MAX_CHUNKS_PER_MESSAGE: usize = 3;
    pub const MESSAGE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
    
    // DoS Prevention
    pub const MAX_ENVELOPE_SIZE: usize = 2048;
    pub const MAX_ANNOUNCEMENTS_PER_PEER_PER_SEC: u32 = 10;
    
    // Privacy
    pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];
    pub const MAX_JITTER_MS: u64 = 3000;
    
    // Time Validation
    pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
    
    // Identity
    pub const MAX_IDENTITIES_PER_ORIGIN: u32 = 3;
    pub const KEY_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
    
    // Reputation
    pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;
    pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;
    pub const NEGATIVE_REPORT_THRESHOLD: u32 = 3;
    
    // Validators
    pub const MIN_VALIDATOR_STAKE: u32 = 700;
    pub const MAX_VALIDATORS: usize = 21;
    pub const MIN_UPTIME_PERCENT: f32 = 99.0;
}
```

-----

## File Organization

### Crate Dependencies

```
veritas-core
├── veritas-protocol
│   ├── veritas-crypto
│   ├── veritas-identity
│   └── veritas-reputation
├── veritas-chain
├── veritas-net
└── veritas-store
```

### New Files (from Security Remediation)

- `crates/veritas-identity/src/hardware.rs` — Hardware attestation
- `crates/veritas-net/src/rate_limiter.rs` — Rate limiting
- `crates/veritas-reputation/src/proof.rs` — Interaction proofs
- `crates/veritas-core/src/time.rs` — Trusted time

-----

## Testing Requirements

### Unit Tests

Every public function needs tests.

### Security Tests

```rust
#[cfg(test)]
mod security_tests {
    #[test]
    fn test_oversized_envelope_rejected() { ... }
    
    #[test]
    fn test_forged_block_rejected() { ... }
    
    #[test]
    fn test_replay_attack_prevented() { ... }
}
```

### Edition Migration Tests

After migrating each crate:

```bash
cargo test -p <crate-name>
cargo clippy -p <crate-name> -- -D warnings
```

-----

## Git Workflow

### Edition Migration Branch

```bash
git checkout -b chore/rust-2024-edition-upgrade
# Migrate crate by crate
# Commit each crate separately
git commit -m "chore(veritas-crypto): migrate to Rust 2024 edition

- Updated edition to 2024
- Updated rust-version to 1.85
- Added explicit unsafe blocks in unsafe fns

Task-ID: TASK-110"
```

### Commit Format

```
{type}({scope}): {description}

- {change 1}
- {change 2}

Task-ID: TASK-XXX
```

### PR Requirements

- **Security agent MUST approve** all FFI changes
- **QA agent MUST verify** test coverage
- **Full test suite MUST pass**

-----

## Mandatory Agent Involvement

|Change Type         |Required Agents              |
|--------------------|-----------------------------|
|Any code change     |Security (review), QA (tests)|
|Crypto code         |Security (lead), QA, Docs    |
|FFI changes         |Bindings, Security, QA       |
|Edition migration   |QA (thorough testing)        |
|Lock pattern changes|Security (review scoping)    |

-----

## Performance Targets

|Operation             |Target|
|----------------------|------|
|Key generation        |< 50ms|
|Message encryption    |< 10ms|
|Signature verification|< 20ms|
|Size validation       |< 1μs |

-----

## Environment

No environment variables required for core library.

For testing:

```bash
VERITAS_TEST_BOOTSTRAP_NODES="..."
VERITAS_TEST_STORAGE_PATH="/tmp/veritas-test"
```

-----

## MCP Servers

- **Cloudflare** — Future hosted validator infrastructure
- **GitHub** — Repository operations

Check available servers at session start.
