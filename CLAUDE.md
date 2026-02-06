# CLAUDE.md — VERITAS Protocol

> Instructions for Claude Code sessions working on this project

## Project Context

VERITAS (Verified Encrypted Real-time Integrity Transmission And Signing) is a post-quantum secure, decentralized messaging protocol. The blockchain IS the message transport layer — every encrypted message is a transaction. Epoch-based pruning keeps the chain small enough that a phone can be a relay.

**Type**: Rust Library + Multi-platform Bindings
**Stack**: Rust, ML-KEM, ML-DSA (FIPS 204), ChaCha20-Poly1305, BLAKE3, libp2p, sled
**Signing**: ML-DSA-65 (lattice-based, post-quantum) — NO Ed25519
**Security Level**: HARDENED + POST-QUANTUM
**Edition**: Rust 2024
**MSRV**: 1.85
**Version**: 0.3.1-beta

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

### 3. Milestone 1: Critical Code Fixes (COMPLETED — v0.3.1-beta)

**Status**: All ~60 bugs fixed across 12 crates (44 files changed)
**Tracking**: See VERITAS_TODO_V2.md sections 1.1–1.20, TASKS.md for summary

All 20 fix categories (1.1–1.20) from the comprehensive code review have been implemented:
- **1 CRITICAL**: Collusion detection cluster index mapping (REP-FIX-1)
- **16 HIGH**: Identity keypair loss, FFI UB, WASM salt, ephemeral key validation, mailbox salt, receipt forgery, sync validation, nonce replay, signature verification skip, self-interaction bypass, gossip replay window, DHT unbounded deserialization, plaintext zeroization, node binary non-functional
- **~23 MEDIUM**: Zeroize/ZeroizeOnDrop on PQ keys, constant-time checks, chain state fixes, reputation fixes, rate limiter ordering, bounded collections, WASM mutex/lock fixes, Python/FFI fixes
- **~20 LOW**: Clone on secret types, error variants, timestamp validation, dead code removal, overflow fixes, shutdown handling, formatting fixes
- **All 1,549 tests pass** (0 failures), build succeeds cleanly

## 📋 Remaining Work

| Item | Priority | Status |
|------|----------|--------|
| M1: Critical code fixes (~60 bugs) | P0 | Completed (v0.3.1-beta) |
| M2: ML-DSA signing + wire format v2 | P0 | Design complete |
| M2: Message-as-transaction chain model | P0 | Design complete |
| M2: Epoch-based pruning (30-day) | P0 | Design complete |
| M2: Light validator mode | P1 | Design complete |
| M3: BFT consensus + validator trust model | P1 | Design needed |
| Hardware attestation (TPM/SecureEnclave/AndroidKeystore) | P2 | Platform stubs |
| Bluetooth last-mile relay | P3 | Deferred to v2.0 |
| Async closures refactoring (TASK-170) | P4 | Optional |

-----

## 🏛️ Architecture Decisions

These are owner-confirmed decisions. All implementation MUST conform to them.

### AD-1: Chain as Message Transport

The blockchain IS the message exchange layer. Every encrypted message is a transaction on-chain. Blocks contain ordered batches of message transactions plus identity registrations, key rotations, and reputation changes. The chain provides ordering, integrity, delivery guarantees, and proof of communication.

**Implications for agents**: Any change to `veritas-chain` or `veritas-protocol` must account for the fact that messages ARE transactions. There is no separate message delivery path — the chain is the delivery mechanism.

### AD-2: Epoch-Based Pruning (30-Day Retention)

```
During epoch (30 days):
  Full transaction on-chain: ML-DSA signature + encrypted body + header

After epoch ends:
  Body + signature PRUNED → only header remains permanently
  Headers are unsigned (signature was pruned with body)
  Headers verifiable via Merkle proof against signed block header
```

- **Client-side messages persist independently** — users keep their own messages
- **This is a deliberate privacy feature**, not just an optimization
- **Pruning is deterministic** — all nodes prune at the same epoch boundary

**Implications for agents**: Storage format must support efficient body-only deletion. `veritas-chain` and `veritas-store` must coordinate on pruning. ChainAuditor must verify pruning never loses headers.

### AD-3: ML-DSA Signing (No Ed25519)

All signing uses ML-DSA-65 (FIPS 204, lattice-based). There is NO Ed25519 transition. The existing placeholder HMAC-BLAKE3 signing is replaced directly with ML-DSA. This is a hard cutover — existing chain data has no real signatures to preserve.

```
ML-DSA-65 sizes:
  Public key:  1,952 bytes
  Signature:   3,309 bytes
  Private key: 4,032 bytes
```

These signature sizes are pruned after epoch end, so permanent storage is unaffected.

**Implementation**: Use `ml-dsa` crate (RustCrypto, 0.1.x, already in Cargo.toml). FIPS 204 final. Passes NIST test vectors. Not independently audited — this is accepted risk based on NIST standardization and Cloudflare production deployment of lattice crypto.

**Implications for agents**: CryptoAuditor must verify `OsRng` for all ML-DSA key generation. Envelope sizes must accommodate 3,309-byte signatures. All `MAX_ENVELOPE_SIZE` constants must be updated.

### AD-4: Two Validator Tiers

```
Full validators:
  Hold complete blocks (headers + bodies + signatures)
  Validate consensus, produce blocks
  Hosted by trusted organizations/individuals

Light validators:
  Hold headers + signatures only (no message bodies)
  Validate transaction history during epoch
  After epoch: prune signatures → converge to header-only state
  Target: 256MB RAM
```

Users maintain a list of trusted validators with 3 lines of trust as fallback. More validators = more anonymity (traffic blends across more nodes).

**Implications for agents**: `veritas-node` needs `--mode full-validator` and `--mode light-validator` flags. Sync protocol must support header-only sync for light validators. NetworkAuditor must verify light validators cannot be tricked into accepting invalid transactions.

### AD-5: Bluetooth Last-Mile Relay (Future — v2.0)

Bluetooth mesh is a **last-mile relay to get messages back onto the chain**, NOT offline chat. Messages hop device-to-device over BLE until one device has internet connectivity to a validator, then that device submits the transaction on behalf of the original sender.

- Native app only (requires BLE permissions)
- Known metadata risk: relaying device knows approximate location/timing of sender
- If trusted validators are all unreachable, user gets a warning to review validator list
- **Deferred** until core protocol is solid

### AD-6: P2P Image Exchange with On-Chain Proof

Images transfer P2P (direct connection), NOT on-chain. Only a proof/receipt goes on-chain (image hash + delivery confirmation). User gets explicit warning that P2P transfer can break anonymity (direct connection = IP exposure). On-chain proof follows same epoch pruning rules.

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

### Security Audit Specialists

Each specialist has a crate scope AND an architecture-aware checklist.

|Agent                  |Crate Scope         |Architecture Checklist|
|-----------------------|--------------------|----------------------|
|**🛡️ CryptoAuditor**    |`veritas-crypto`    |ML-DSA key generation uses `OsRng`. `Zeroize`/`ZeroizeOnDrop` on all ML-DSA private keys. No `Clone` on secret types. `ConstantTimeEq` for secret comparisons. No hardcoded keys/nonces. ML-DSA signature sizes match FIPS 204 spec (3,309 bytes for ML-DSA-65).|
|**🆔 IdentityAuditor**  |`veritas-identity`  |Identity lifecycle (creation, rotation, revocation). Username validation and limits. Origin fingerprint integrity. Key hierarchy: master key > signing key > encryption key.|
|**📡 ProtocolAuditor**  |`veritas-protocol`  |Size validation BEFORE deserialization (new limit: 8192 bytes). Envelope padding applied (new buckets: 1024/2048/4096/8192). Chunk reassembly bounds. Nonce uniqueness. Domain separation format: `"VERITAS-v1." \|\| purpose \|\| "." \|\| context_length \|\| context`. Transcript binding in HKDF. Cipher suite field present. Protocol version field present.|
|**⛓️ ChainAuditor**     |`veritas-chain`     |Block signature verification (ML-DSA). Validator set integrity. Merkle proof validation. **Epoch pruning correctness**: headers survive pruning, bodies+signatures removed, deterministic boundary. **Transaction model**: messages are transactions, not separate delivery path. **Light validator sync**: header-only sync never accepts invalid transactions. Fixed-point `u64` arithmetic (no `f32`) in validator scoring.|
|**🌐 NetworkAuditor**   |`veritas-net`       |Rate limiting on all inputs. DHT eclipse vector protection. Gossip flood protection. Peer authentication. Timeouts on all async operations. **Validator discovery**: trusted list integrity, 3-line trust fallback verification.|
|**💾 StorageAuditor**   |`veritas-store`     |`encrypted_db` usage for sensitive data. Keyring access controls. No plaintext secrets in storage. **Epoch pruning storage**: body-only deletion without header corruption. Sled backend integrity during pruning.|
|**⭐ ReputationAuditor**|`veritas-reputation`|Interaction proof requirements. Collusion detection. Nonce replay protection (time-partitioned sets). Score bounds enforcement. **Starting score is 100** (not 500). Asymmetric decay: above 500 → decay toward 500; below 500 → decay toward 0.|

### Agent Spawning Rules

**ALWAYS spawn sub-agents for:**

- Security fixes → Relevant auditor + QA + Security review
- Cryptographic code → CryptoAuditor + Security agent MUST BOTH review
- Wire protocol changes → Architect + ProtocolAuditor + Security
- Chain/transaction changes → ChainAuditor + Security + Architect
- Epoch pruning changes → ChainAuditor + StorageAuditor + Security
- Validator mode changes → ChainAuditor + NetworkAuditor
- FFI changes → Bindings + Security
- ML-DSA signing changes → CryptoAuditor + Security (MANDATORY dual review)

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

**CRITICAL: Messages are submitted as transactions to validators, not sent peer-to-peer.**

The primary message path is: Client → Validator → Chain → Recipient polls chain.

```rust
pub async fn submit_message(&self, transaction: MessageTransaction) -> SubmitResult {
    // 1. ALWAYS try submitting to a trusted validator via internet
    for validator in self.trusted_validators.iter() {
        if let Ok(result) = validator.submit(transaction.clone()).await {
            return result;
        }
    }
    
    // 2. Try trusted validators' trusted peers (3-line trust fallback)
    for fallback in self.fallback_validators.iter() {
        if let Ok(result) = fallback.submit(transaction.clone()).await {
            return result;
        }
    }
    
    // 3. Fall back to Bluetooth last-mile relay (future — v2.0)
    // BLE mesh hops until a device with internet submits to a validator
    if self.bluetooth.has_peers().await {
        return self.bluetooth.relay_to_chain(transaction).await;
    }
    
    // 4. No connectivity — queue locally, warn user to review validator list
    self.warn_user_validator_list_review();
    TransportType::Queued
}
```

### Bluetooth Last-Mile Relay Rules (Future — v2.0)

- **Purpose**: Get messages to the chain when internet is unavailable
- **NOT offline chat** — messages must reach a validator to be on-chain
- **NO PIN verification** — BLE is pure relay, not security boundary
- **NO pairing required** — Any VERITAS node can relay
- **Security from E2E encryption** — Not from transport layer
- **Known metadata risk**: Relaying device learns sender's approximate location and timing
- **Native app only** — Requires BLE permissions (iOS foreground-only constraint)

### Contact Requirement

- **Must know recipient hash to send** — No discovery mechanism
- **Share hash out-of-band** — QR code, in person, etc.

-----

## Message Transaction Structure

**CRITICAL: Messages are on-chain transactions. The chain IS the message delivery mechanism.**

```rust
/// A message transaction — lives on-chain for one epoch (30 days)
pub struct MessageTransaction {
    pub header: MessageHeader,       // PERMANENT — survives epoch pruning
    pub body: EncryptedBody,         // PRUNED after epoch
    pub signature: MlDsaSignature,   // PRUNED after epoch (3,309 bytes)
}

/// Permanent header — stays on-chain forever
pub struct MessageHeader {
    pub mailbox_key: [u8; 32],       // Derived from sender+recipient DH
    pub timestamp_bucket: u64,       // Coarse timestamp (privacy)
    pub body_hash: Blake3Hash,       // BLAKE3 of encrypted body
    pub block_height: u64,           // Which block included this tx
}

/// Encrypted body — pruned after epoch
pub struct EncryptedBody {
    pub ephemeral_public: [u8; 32],  // Single-use X25519 per message
    pub nonce: [u8; 24],             // Random
    pub ciphertext: Vec<u8>,         // Encrypted + padded to bucket
}

/// All sensitive data INSIDE encrypted payload
struct InnerPayload {
    sender_id: IdentityHash,         // HIDDEN from validators
    timestamp: u64,                  // HIDDEN from validators (precise)
    content: MessageContent,         // HIDDEN from validators
    signature: Vec<u8>,              // HIDDEN from validators (sender proof)
    cipher_suite: u8,                // Which crypto suite was used
    protocol_version: u8,            // Wire format version
}
```

### Epoch Pruning Lifecycle

```
Block produced at height H, epoch E:
  +-------------------------------------+
  | MessageTransaction                   |
  |   header: MessageHeader (100 bytes)  | <- PERMANENT
  |   body: EncryptedBody (~4KB padded)  | <- PRUNED after epoch E ends
  |   signature: MlDsaSignature (3,309B) | <- PRUNED after epoch E ends
  +-------------------------------------+

After epoch E ends (30 days):
  +-------------------------------------+
  | MessageHeader only (100 bytes)       | <- Verifiable via Merkle proof
  |   body_hash proves content existed   |    against signed block header
  +-------------------------------------+
```

### Other Transaction Types

```rust
/// All on-chain transaction types
pub enum Transaction {
    Message(MessageTransaction),         // Encrypted message delivery
    IdentityRegistration { /* ... */ },   // New identity on-chain
    UsernameRegistration { /* ... */ },   // Username claim
    KeyRotation { /* ... */ },            // Key update announcement
    KeyRevocation { /* ... */ },          // Key revocation (future)
    ReputationChange { /* ... */ },       // Score adjustment
    ImageProof {                          // P2P image transfer proof
        image_hash: Blake3Hash,
        delivery_receipt: Vec<u8>,
    },
}
```

### Metadata Rules

|DO                                                |DON'T                          |
|--------------------------------------------------|-------------------------------|
|Derive mailbox key from sender+recipient DH output|Put recipient ID in header     |
|Use ephemeral X25519 key per message              |Reuse keys across messages     |
|Pad to fixed size buckets (1024/2048/4096/8192)   |Reveal true message size       |
|Put sender/timestamp inside encrypted payload     |Put on header or transaction   |
|Add timing jitter (exponential/Poisson)           |Send immediately               |
|Use domain separation: `"VERITAS-v1." || purpose` |Mix key derivation contexts    |
|Sign transactions with ML-DSA-65                  |Use placeholder HMAC-BLAKE3    |

### Image Transfer Rules

- Transfer images P2P (direct connection), NOT on-chain
- Put only hash + delivery proof on-chain
- **Warn user**: "P2P transfer may reveal your IP address to the recipient"
- User must acknowledge warning before proceeding

-----

## Security Patterns

### Size Validation BEFORE Deserialization

```rust
// NEW: Post-quantum envelope size (ML-DSA-65 signature = 3,309 bytes)
pub const MAX_ENVELOPE_SIZE: usize = 8192;

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

### Cryptographic Signature Verification (ML-DSA-65)

```rust
impl BlockHeader {
    pub fn verify_signature(&self) -> Result<(), ChainError> {
        let payload = self.compute_signing_payload();
        // ML-DSA-65 verification (FIPS 204)
        self.validator_pubkey.verify(&payload, &self.signature)?;
        
        // Also verify pubkey matches claimed identity
        let expected_id = ValidatorId::from_pubkey(&self.validator_pubkey);
        if expected_id != self.validator {
            return Err(ChainError::ValidatorKeyMismatch);
        }
        Ok(())
    }
}

// ML-DSA key generation — ALWAYS use OsRng
use ml_dsa::MlDsa65;
use rand::rngs::OsRng;

let signing_key = MlDsa65::generate_signing_key(&mut OsRng);
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
1. **ALWAYS** use `OsRng` for randomness (NEVER `thread_rng`)
1. **ALWAYS** use `zeroize` + `ZeroizeOnDrop` for secrets
1. **ALWAYS** use `subtle::ConstantTimeEq` for secret comparisons
1. **NEVER** log key material, secrets, or message content
1. **ALWAYS** verify ML-DSA signatures before trusting data
1. **ALWAYS** check sizes before deserialization (limit: 8192 bytes)
1. **NEVER** derive `Clone` on secret key types
1. **ALWAYS** use domain separation: `"VERITAS-v1." || purpose || "." || context_length || context`
1. **ALWAYS** include transcript binding in HKDF: `sender_id || recipient_id || session_id || counter`

### ML-DSA Specific Rules

1. **ALWAYS** use ML-DSA-65 (NIST security level 3) — not ML-DSA-44 or ML-DSA-87
1. **ALWAYS** verify ML-DSA public key size is exactly 1,952 bytes before use
1. **ALWAYS** verify ML-DSA signature size is exactly 3,309 bytes before verification
1. **NEVER** persist ML-DSA signatures beyond epoch boundary (they are pruned)
1. **ALWAYS** use the `ml-dsa` RustCrypto crate (0.1.x) — no alternative implementations

### Epoch Pruning Rules

1. **ALWAYS** prune message bodies AND signatures at epoch boundary
1. **NEVER** prune message headers — they are permanent
1. **ALWAYS** verify Merkle proof when validating pruned headers
1. **ALWAYS** ensure pruning is deterministic — same epoch boundary on all nodes

### DoS Prevention Rules

1. **ALWAYS** validate size BEFORE deserialization
1. **ALWAYS** implement rate limiting on network inputs
1. **ALWAYS** bound collection sizes
1. **ALWAYS** set timeouts on async operations
1. **ALWAYS** use fixed-point `u64` arithmetic for validator scoring (NEVER `f32`)

### Approved Crypto Libraries

|Purpose          |Crate               |Version      |Notes|
|-----------------|--------------------|-------------|-----|
|ML-KEM           |`ml-kem`            |0.1.x        |Post-quantum key exchange|
|ML-DSA           |`ml-dsa`            |0.1.x        |**Primary signing algorithm** — FIPS 204|
|X25519           |`x25519-dalek`      |2.x          |Key exchange (ECDH)|
|ChaCha20-Poly1305|`chacha20poly1305`  |0.10.x       |Symmetric encryption|
|BLAKE3           |`blake3`            |1.x          |Hashing, message digests|
|Argon2           |`argon2`            |0.5.x        |Password-based KDF|
|Secure RNG       |`rand` + `getrandom`|0.8.x / 0.2.x|**OsRng only** for crypto|
|Zeroization      |`zeroize`           |1.x          |Secret memory clearing|
|Constant-time    |`subtle`            |2.x          |Timing-safe comparisons|

-----

## Protocol Limits

```rust
pub mod limits {
    // Messages
    pub const MAX_MESSAGE_CHARS: usize = 300;
    pub const MAX_CHUNKS_PER_MESSAGE: usize = 3;
    pub const MESSAGE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
    
    // DoS Prevention (updated for ML-DSA-65 signature sizes)
    pub const MAX_ENVELOPE_SIZE: usize = 8192;
    pub const MAX_ANNOUNCEMENTS_PER_PEER_PER_SEC: u32 = 10;
    
    // Privacy (updated buckets for post-quantum envelope sizes)
    pub const PADDING_BUCKETS: &[usize] = &[1024, 2048, 4096, 8192];
    pub const MAX_JITTER_MS: u64 = 3000;  // TODO: switch to exponential/Poisson
    
    // ML-DSA-65 sizes (FIPS 204)
    pub const ML_DSA_65_PK_SIZE: usize = 1952;
    pub const ML_DSA_65_SIG_SIZE: usize = 3309;
    pub const ML_DSA_65_SK_SIZE: usize = 4032;
    
    // Epoch pruning
    pub const EPOCH_DURATION_SECS: u64 = 30 * 24 * 60 * 60; // 30 days
    
    // Time Validation
    pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
    
    // Identity
    pub const MAX_IDENTITIES_PER_ORIGIN: u32 = 3;
    pub const KEY_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;
    
    // Reputation (starting score lowered to 100 per AD)
    pub const DEFAULT_REPUTATION: u32 = 100;   // Tier 1 / Basic
    pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;
    pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;
    pub const NEGATIVE_REPORT_THRESHOLD: u32 = 3;
    
    // Validators
    pub const MIN_VALIDATOR_REPUTATION: u32 = 700; // Reputation-based, not stake
    pub const MAX_VALIDATORS: usize = 21;
    pub const VALIDATOR_TRUST_DEPTH: usize = 3;    // 3 lines of trust fallback
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

### Files Expected (from Architecture Decisions)

- `crates/veritas-chain/src/transaction.rs` — MessageTransaction, Transaction enum
- `crates/veritas-chain/src/epoch.rs` — Epoch management, pruning logic
- `crates/veritas-chain/src/light_validator.rs` — Light validator sync + storage
- `crates/veritas-chain/src/validator_trust.rs` — Trusted validator list, 3-line fallback
- `crates/veritas-crypto/src/ml_dsa.rs` — ML-DSA-65 signing (activate existing stubs)
- `crates/veritas-protocol/src/domain_separation.rs` — VERITAS-v1 domain separator
- `crates/veritas-protocol/src/transcript.rs` — Transcript binding for HKDF
- `crates/veritas-protocol/src/image_transfer.rs` — P2P image exchange + on-chain proof

-----

## Testing Requirements

### Unit Tests

Every public function needs tests.

### Security Tests

```rust
#[cfg(test)]
mod security_tests {
    #[test]
    fn test_oversized_envelope_rejected() { ... }     // 8192 byte limit
    
    #[test]
    fn test_forged_block_rejected() { ... }            // ML-DSA sig verification
    
    #[test]
    fn test_replay_attack_prevented() { ... }
    
    #[test]
    fn test_ml_dsa_signature_roundtrip() { ... }       // Sign + verify
    
    #[test]
    fn test_epoch_pruning_preserves_headers() { ... }  // Headers survive
    
    #[test]
    fn test_epoch_pruning_removes_bodies() { ... }     // Bodies deleted
    
    #[test]
    fn test_pruned_header_merkle_verification() { ... }// Merkle proof valid
    
    #[test]
    fn test_light_validator_rejects_invalid_tx() { ... }
    
    #[test]
    fn test_message_transaction_on_chain() { ... }     // Message IS a tx
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
- **CryptoAuditor + Security MUST BOTH approve** any ML-DSA changes
- **ChainAuditor MUST approve** any epoch pruning or transaction model changes
- **QA agent MUST verify** test coverage
- **Full test suite MUST pass** (`cargo test --all` AND `cargo test --all --release`)

-----

## Mandatory Agent Involvement

|Change Type                |Required Agents                              |
|---------------------------|---------------------------------------------|
|Any code change            |Security (review), QA (tests)                |
|Crypto code                |CryptoAuditor (lead), Security, QA, Docs     |
|ML-DSA signing changes     |CryptoAuditor + Security (dual review, MANDATORY)|
|Wire protocol / envelope   |Architect, ProtocolAuditor, Security         |
|Chain / transaction model  |ChainAuditor, Architect, Security            |
|Epoch pruning logic        |ChainAuditor, StorageAuditor, Security       |
|Validator mode changes     |ChainAuditor, NetworkAuditor                 |
|FFI changes                |Bindings, Security, QA                       |
|Reputation scoring         |ReputationAuditor, Security                  |
|Lock pattern changes       |Security (review scoping)                    |

-----

## Performance Targets

|Operation                    |Target  |Notes|
|-----------------------------|--------|-----|
|ML-DSA-65 key generation     |< 100ms |Larger keys than Ed25519|
|ML-DSA-65 signing            |< 50ms  |Per-transaction|
|ML-DSA-65 verification       |< 30ms  |Per-transaction|
|X25519 key exchange          |< 10ms  ||
|Message encryption (ChaCha20)|< 10ms  ||
|Size validation              |< 1μs   ||
|Epoch pruning (per block)    |< 500ms |Body + sig deletion|
|Light validator sync (header)|< 5ms   |Per block header|

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
