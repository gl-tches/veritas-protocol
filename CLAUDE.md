# CLAUDE.md — VERITAS Protocol

> Instructions for Claude Code sessions working on this project

## Project Context

VERITAS (Verified Encrypted Real-time Integrity Transmission And Signing) is a post-quantum secure, decentralized messaging protocol with blockchain verification and offline P2P capability.

**Type**: Rust Library + Multi-platform Bindings  
**Stack**: Rust, ML-KEM, ML-DSA, ChaCha20-Poly1305, libp2p, sled  
**Security Level**: HARDENED + POST-QUANTUM  
**Current Status**: SECURITY REMEDIATION IN PROGRESS (See SECURITY_AUDIT_REPORT.md)

## ⚠️ SECURITY AUDIT STATUS

**CRITICAL**: This codebase has undergone security audit identifying **90 vulnerabilities**:

- **22 CRITICAL** — Must fix before ANY deployment
- **31 HIGH** — Must fix before beta
- **26 MEDIUM** — Must fix before production
- **11 LOW** — Post-launch hardening

**Reference Files**:

- `SECURITY_AUDIT_REPORT.md` — Full vulnerability details
- `VERITAS_REMEDIATION_INSTRUCTIONS.md` — Implementation guide (if present)

**DO NOT deploy to production until all CRITICAL and HIGH issues are resolved.**

-----

## Sub-Agent Team Structure

Claude Code operates as the **Lead Developer** coordinating a team of specialized sub-agents. Spawn sub-agents using `Task(...)` or by explicitly delegating work.

### Core Team Composition

|Agent          |Role             |Responsibilities                                                         |
|---------------|-----------------|-------------------------------------------------------------------------|
|**🏗️ Architect**|System Design    |Architecture decisions, module boundaries, API design, crate organization|
|**🔒 Security** |Security Engineer|Security reviews, crypto implementation, key management, threat analysis |
|**⚡ Backend**  |Core Developer   |Protocol implementation, networking, blockchain, storage                 |
|**🧪 QA**       |Test Engineer    |Unit tests, integration tests, property tests, fuzzing                   |
|**📚 Docs**     |Technical Writer |Documentation, code comments, README updates, API docs                   |
|**🔌 Bindings** |FFI Developer    |C bindings, WASM compilation, Python bindings, cross-platform            |

### Security Remediation Specialists (Spawn for Audit Fixes)

|Agent                  |Specialization        |Spawn For                                                   |
|-----------------------|----------------------|------------------------------------------------------------|
|**🛡️ CryptoAuditor**    |Cryptographic Security|ML-KEM, ML-DSA, timing attacks, key handling, zeroization   |
|**🆔 IdentityAuditor**  |Identity & Auth       |DIDs, Sybil resistance, key lifecycle, origin fingerprinting|
|**📡 ProtocolAuditor**  |Wire Protocol         |Serialization, DoS, message handling, metadata privacy      |
|**⛓️ ChainAuditor**     |Blockchain Security   |Consensus, signatures, validators, slashing, Merkle proofs  |
|**🌐 NetworkAuditor**   |P2P Networking        |libp2p, DHT, gossip, rate limiting, eclipse attacks         |
|**💾 StorageAuditor**   |Data Security         |Encryption at rest, key storage, metadata leakage           |
|**⭐ ReputationAuditor**|Anti-Gaming           |Score manipulation, Sybil attacks, collusion detection      |

-----

## Security Remediation Mode

### When to Enter Remediation Mode

Enter this mode when:

1. Working on any `security/*` branch
1. Fixing any VERITAS-2026-XXXX vulnerability
1. Touching code flagged in SECURITY_AUDIT_REPORT.md
1. Implementing fixes from VERITAS_REMEDIATION_INSTRUCTIONS.md

### Parallel Agent Spawning for Critical Fixes

**ALWAYS spawn multiple specialized agents in parallel for CRITICAL fixes:**

```
# Phase 1 Critical Fixes — Spawn ALL simultaneously

/agent spawn CryptoAuditor "Review and fix VERITAS-2026-0023, 0024: X25519 secret key memory handling in crates/veritas-crypto/src/x25519.rs. Ensure Zeroize on all paths, remove Clone on secrets."

/agent spawn IdentityAuditor "Fix VERITAS-2026-0001, 0014: Sybil attack via OriginFingerprint. File: crates/veritas-identity/src/limits.rs. Implement hardware attestation, make generate() test-only."

/agent spawn ChainAuditor "Fix VERITAS-2026-0002: Missing block signature verification. File: crates/veritas-chain/src/chain.rs. Add MlDsaSignature to BlockHeader, implement verify_signature()."

/agent spawn ProtocolAuditor "Fix VERITAS-2026-0003: Unbounded deserialization DoS. Files: crates/veritas-protocol/src/envelope/*.rs. Add MAX_ENVELOPE_SIZE checks before bincode::deserialize."

/agent spawn StorageAuditor "Fix VERITAS-2026-0005: Message queue metadata leakage. File: crates/veritas-store/src/message_queue.rs. Replace sled::Db with EncryptedDb."

/agent spawn NetworkAuditor "Fix VERITAS-2026-0006, 0007: DHT eclipse attack and gossip flooding. Files: crates/veritas-net/src/node.rs, gossip.rs. Implement rate limiting and routing diversity."

/agent spawn ReputationAuditor "Fix VERITAS-2026-0010: Reputation interaction authentication. File: crates/veritas-reputation/src/manager.rs. Require cryptographic proofs for all reputation changes."
```

### Agent Coordination Protocol

```
Lead Developer receives security fix task
    │
    ├─→ Read SECURITY_AUDIT_REPORT.md for vulnerability details
    │
    ├─→ Read VERITAS_REMEDIATION_INSTRUCTIONS.md for fix code
    │
    ├─→ Spawn specialized auditor agents IN PARALLEL:
    │       ├─→ CryptoAuditor (if crypto-related)
    │       ├─→ IdentityAuditor (if identity-related)
    │       ├─→ ChainAuditor (if blockchain-related)
    │       ├─→ ProtocolAuditor (if protocol-related)
    │       ├─→ NetworkAuditor (if networking-related)
    │       ├─→ StorageAuditor (if storage-related)
    │       └─→ ReputationAuditor (if reputation-related)
    │
    ├─→ Spawn QA agent (REQUIRED for all security fixes)
    │       └─→ Returns: Tests verifying fix, regression tests
    │
    ├─→ Spawn Security agent (REQUIRED final review)
    │       └─→ Returns: Security approval or rejection
    │
    └─→ Lead Developer merges, commits with vulnerability ID

IMPORTANT: Agents work IN PARALLEL, not sequentially!
```

### Security Fix Commit Format

```
security({crate}): fix VERITAS-2026-XXXX {brief description}

- {What was vulnerable}
- {How it was fixed}
- {Tests added}

Fixes: VERITAS-2026-XXXX
Severity: CRITICAL/HIGH/MEDIUM/LOW
```

Example:

```
security(identity): fix VERITAS-2026-0001 Sybil fingerprint bypass

- OriginFingerprint::generate() allowed unlimited identity creation
- Now requires HardwareAttestation with platform-specific binding
- generate() restricted to #[cfg(test)] only
- Added hardware.rs module with TPM/Secure Enclave support

Fixes: VERITAS-2026-0001
Severity: CRITICAL
```

-----

## Agent Spawning Rules

### ALWAYS spawn sub-agents for:

- **Security fixes** — Spawn relevant auditor + QA + Security review
- **Cryptographic code** — Security agent MUST review
- **Wire protocol changes** — Architect + Security + ProtocolAuditor
- **FFI boundary changes** — Bindings + Security
- **Test writing** — QA agent
- **Documentation updates** — Docs agent

### Lead Developer responsibilities:

- Coordinate task distribution
- **Spawn agents IN PARALLEL when possible**
- Merge sub-agent outputs
- Resolve conflicts between agents
- Ensure Security agent reviews ALL crypto-related PRs
- Final approval before commit
- **Track vulnerability IDs in commits**

### Standard Agent Communication Pattern

```
Lead Developer receives task
    │
    ├─→ Spawn Architect (if design needed)
    │       └─→ Returns: Design doc, interfaces
    │
    ├─→ Spawn Backend (core implementation)
    │       └─→ Returns: Code implementation
    │
    ├─→ Spawn Security (REQUIRED for all crypto/protocol PRs)
    │       └─→ Returns: Security review, approved/blocked
    │
    ├─→ Spawn QA (REQUIRED for all PRs)
    │       └─→ Returns: Tests, coverage report
    │
    ├─→ Spawn Bindings (if FFI/WASM changes)
    │       └─→ Returns: Binding implementations
    │
    └─→ Spawn Docs (if public API changes)
            └─→ Returns: Updated documentation

Lead Developer merges, commits, creates PR
```

-----

## Commands

### Development

```bash
cargo build --release        # Build all crates
cargo test --all             # Run all tests
cargo clippy --all-targets   # Lint check
cargo fmt --all              # Format code
cargo audit                  # Security audit
cargo bench                  # Run benchmarks (when added)
```

### Security-Specific Commands

```bash
# Run security-related tests
cargo test security --all
cargo test dos --all
cargo test sybil --all
cargo test replay --all

# Check for unsafe code
grep -rn "unsafe" crates/ --include="*.rs"

# Check for panics in production code
grep -rn "unwrap()\|expect(\|panic!" crates/ --include="*.rs" | grep -v "#\[cfg(test)\]" | grep -v "tests.rs"

# Dependency audit
cargo audit
cargo deny check

# Fuzz testing (when configured)
cd fuzz && cargo +nightly fuzz run fuzz_envelope -- -max_len=4096
```

### Crate-Specific

```bash
cargo test -p veritas-crypto     # Test crypto crate only
cargo test -p veritas-protocol   # Test protocol crate only
cargo doc --no-deps --open       # Generate and view docs
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

## Critical Security Patterns

### Size Validation BEFORE Deserialization (VERITAS-2026-0003)

**ALWAYS check size before bincode::deserialize:**

```rust
pub const MAX_ENVELOPE_SIZE: usize = 2048;

pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
    // SECURITY: Check size BEFORE deserialization to prevent OOM
    if bytes.len() > MAX_ENVELOPE_SIZE {
        return Err(ProtocolError::InvalidEnvelope("too large".into()));
    }
    
    // Now safe to deserialize
    let envelope: Self = bincode::deserialize(bytes)?;
    envelope.validate()?;
    Ok(envelope)
}
```

### Cryptographic Signature Verification (VERITAS-2026-0002)

**ALWAYS verify signatures on untrusted data:**

```rust
impl BlockHeader {
    pub fn verify_signature(&self) -> Result<(), ChainError> {
        let payload = self.compute_signing_payload();
        
        self.validator_pubkey
            .verify(&payload, &self.signature)
            .map_err(|_| ChainError::InvalidSignature)?;
        
        // Also verify pubkey matches claimed identity
        let expected_id = ValidatorId::from_pubkey(&self.validator_pubkey);
        if expected_id != self.validator {
            return Err(ChainError::ValidatorKeyMismatch);
        }
        
        Ok(())
    }
}
```

### Hardware-Bound Origin Fingerprinting (VERITAS-2026-0001)

**Production fingerprints MUST be hardware-bound:**

```rust
// Test-only: random fingerprint
#[cfg(test)]
pub fn generate() -> Self { /* random */ }

// Production: require hardware attestation
pub fn from_hardware(attestation: &HardwareAttestation) -> Result<Self, IdentityError> {
    attestation.verify()?;  // Cryptographic proof required
    let hardware_fingerprint = attestation.fingerprint();
    Ok(Self::new(&hardware_fingerprint, None, &installation_id))
}
```

### Rate Limiting (VERITAS-2026-0007)

**ALWAYS rate limit untrusted input:**

```rust
pub struct RateLimiter {
    per_peer_rate: u32,      // Max per peer per second
    global_rate: u32,        // Max total per second
    // ...
}

pub async fn handle_announcement(&mut self, peer_id: PeerId, data: Vec<u8>) -> Result<()> {
    // Check rate limit BEFORE processing
    if !self.rate_limiter.check(&peer_id) {
        self.record_violation(&peer_id);
        return Err(GossipError::RateLimitExceeded);
    }
    
    // Now safe to process
    self.process_announcement(peer_id, data).await
}
```

### Timestamp Validation (VERITAS-2026-0008, 0009)

**ALWAYS validate timestamps:**

```rust
const MAX_CLOCK_SKEW_SECS: u64 = 300;  // 5 minutes

pub fn validate_timestamp(timestamp: u64) -> Result<(), TimeError> {
    let now = trusted_time::now();
    
    // Reject future timestamps
    if timestamp > now + MAX_CLOCK_SKEW_SECS {
        return Err(TimeError::TimestampInFuture);
    }
    
    // Reject ancient timestamps
    if timestamp < MIN_VALID_TIMESTAMP {
        return Err(TimeError::TimestampTooOld);
    }
    
    Ok(())
}
```

### Interaction Proof Authentication (VERITAS-2026-0010)

**ALWAYS require cryptographic proof for reputation changes:**

```rust
pub fn record_positive_interaction(
    &mut self,
    from: IdentityHash,
    to: IdentityHash,
    proof: &InteractionProof,  // REQUIRED
) -> Result<u32, ReputationError> {
    // Prevent self-interaction
    if from == to {
        return Err(ReputationError::SelfInteractionNotAllowed);
    }
    
    // Verify cryptographic proof
    let from_pubkey = self.pubkey_registry.get(&from)?;
    let to_pubkey = self.pubkey_registry.get(&to)?;
    proof.verify(&from_pubkey, Some(&to_pubkey))?;
    
    // Check nonce for replay protection
    if self.used_nonces.contains(&proof.nonce) {
        return Err(ReputationError::NonceAlreadyUsed);
    }
    self.used_nonces.insert(proof.nonce);
    
    // Now safe to update reputation
    self.apply_score_change(to, base_gain)
}
```

### Encrypted Storage for Sensitive Data (VERITAS-2026-0005)

**ALWAYS use EncryptedDb for sensitive metadata:**

```rust
// WRONG: Plaintext storage
pub struct MessageQueue {
    db: sled::Db,  // BAD: Metadata visible on disk
}

// CORRECT: Encrypted storage
pub struct MessageQueue {
    db: EncryptedDb,  // GOOD: All data encrypted at rest
    inbox: EncryptedTree,
    outbox: EncryptedTree,
}
```

-----

## Transport Selection Rules

**CRITICAL: Network-first transport selection**

```rust
// Transport priority — ALWAYS check in this order
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
- **Relay only** — BLE peers forward to network-connected nodes

### Contact Requirement

```rust
// MUST have recipient hash to send — no exceptions
pub async fn send_message(
    &self,
    recipient: &IdentityHash,  // REQUIRED — no discovery
    content: &str,
) -> Result<MessageHash, Error>
```

- **No user discovery mechanism** — By design
- **Must know hash to contact** — Share out-of-band
- **Optional username resolution** — If they registered one

-----

## Minimal Metadata Envelope

**CRITICAL: Hide all identifiable metadata**

### Envelope Structure

```rust
/// Minimal envelope — leaks NO identifiable information
pub struct Envelope {
    /// Derived mailbox key (unlinkable, rotates per epoch)
    /// NOT recipient's identity hash
    pub mailbox_key: [u8; 32],
    
    /// Ephemeral public key (single-use per message)
    /// NOT linkable to sender's identity
    pub ephemeral_public: [u8; 32],
    
    /// Random nonce
    pub nonce: [u8; 24],
    
    /// Encrypted + padded payload (fixed size bucket)
    pub ciphertext: Vec<u8>,
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
|Put sender ID inside encrypted payload          |Put sender ID on envelope   |
|Put timestamp inside encrypted payload          |Put timestamp on envelope   |
|Add timing jitter (0-3 sec)                     |Send immediately            |

-----

## Code Patterns

### Error Handling

Each crate defines its own error type with `thiserror`:

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    
    #[error("Encryption failed: {0}")]
    Encryption(String),
    
    #[error("Decryption failed: invalid ciphertext or key")]
    Decryption,
    
    #[error("Signature verification failed")]
    SignatureVerification,
    
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
}
```

### Zeroization Pattern

ALL secret data MUST use `Zeroize`:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

// NEVER derive Clone on secret keys (VERITAS-2026-0024)
// #[derive(Clone)]  // BAD
```

### Constant-Time Comparisons

ALWAYS use `subtle` for comparing secrets:

```rust
use subtle::ConstantTimeEq;

pub fn verify_tag(expected: &[u8], actual: &[u8]) -> bool {
    expected.ct_eq(actual).into()
}
```

### Input Validation Pattern

Validate at module boundaries:

```rust
impl Message {
    pub fn new(content: &str) -> Result<Self, ProtocolError> {
        // Validate at construction
        let char_count = content.chars().count();
        if char_count > MAX_MESSAGE_CHARS {
            return Err(ProtocolError::MessageTooLong {
                max: MAX_MESSAGE_CHARS,
                actual: char_count,
            });
        }
        
        // ... construct message
    }
}
```

-----

## Security Requirements

**CRITICAL — DO NOT SKIP**

### Cryptographic Rules

1. **NEVER** implement cryptographic primitives — use audited libraries only
1. **ALWAYS** use `OsRng` for random number generation
1. **ALWAYS** use `zeroize` for secret data
1. **ALWAYS** use `subtle` for constant-time comparisons
1. **NEVER** log key material or secrets
1. **NEVER** include secrets in error messages
1. **ALWAYS** validate nonces are unique (random + message ID)
1. **ALWAYS** verify signatures before trusting data (VERITAS-2026-0002)
1. **ALWAYS** check sizes before deserialization (VERITAS-2026-0003)

### Metadata Rules

1. **NEVER** put sender ID on envelope — hide inside encrypted payload
1. **NEVER** put timestamp on envelope — hide inside encrypted payload
1. **ALWAYS** derive mailbox key (don’t use recipient ID directly)
1. **ALWAYS** use ephemeral keys per message (no key reuse)
1. **ALWAYS** pad messages to fixed size buckets
1. **ALWAYS** add timing jitter before sending
1. **ALWAYS** encrypt message queue metadata (VERITAS-2026-0005)

### DoS Prevention Rules

1. **ALWAYS** validate size BEFORE deserialization (VERITAS-2026-0003)
1. **ALWAYS** implement rate limiting on network inputs (VERITAS-2026-0007)
1. **ALWAYS** bound collection sizes (VERITAS-2026-0017, 0030-0034)
1. **ALWAYS** set timeouts on async operations
1. **ALWAYS** limit reassembly buffer memory (VERITAS-2026-0027)

### Authentication Rules

1. **ALWAYS** require hardware attestation for origin fingerprints (VERITAS-2026-0001)
1. **ALWAYS** verify block signatures (VERITAS-2026-0002)
1. **ALWAYS** require cryptographic proofs for reputation (VERITAS-2026-0010)
1. **ALWAYS** validate timestamps with trusted time (VERITAS-2026-0008, 0009)
1. **ALWAYS** prevent replay attacks with nonces

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

## Reputation Anti-Gaming (F2)

**CRITICAL: Implement all anti-gaming measures**

### Rate Limiting

```rust
pub struct AntiGamingConfig {
    // Rate limiting
    pub min_message_interval_secs: u64,      // 60 seconds between msgs to same peer
    pub max_daily_gain_per_peer: u32,        // 30 points max from one peer/day
    pub max_daily_gain_total: u32,           // 100 points max total/day
    
    // Report validation
    pub negative_report_threshold: u32,       // 3 independent reports needed
    pub weight_by_reporter_reputation: bool,  // true — weight by rep
    pub min_reporter_reputation: u32,         // 400 min to file reports
    
    // Collusion detection
    pub enable_graph_analysis: bool,          // true
    pub cluster_suspicion_threshold: f32,     // 0.7 (70% internal = suspicious)
}
```

-----

## Protocol Limits (Enforced)

```rust
pub mod limits {
    // === Messages ===
    pub const MAX_MESSAGE_CHARS: usize = 300;
    pub const MAX_CHUNKS_PER_MESSAGE: usize = 3;
    pub const MAX_TOTAL_MESSAGE_CHARS: usize = 900;
    pub const MESSAGE_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
    
    // === DoS Prevention (NEW) ===
    pub const MAX_ENVELOPE_SIZE: usize = 2048;
    pub const MAX_INNER_ENVELOPE_SIZE: usize = 1536;
    pub const MAX_REASSEMBLY_BUFFER: usize = 4096;
    pub const MAX_PENDING_REASSEMBLIES: usize = 1000;
    pub const REASSEMBLY_TIMEOUT_SECS: u64 = 300;
    
    // === Rate Limiting (NEW) ===
    pub const MAX_ANNOUNCEMENTS_PER_PEER_PER_SEC: u32 = 10;
    pub const MAX_GLOBAL_ANNOUNCEMENTS_PER_SEC: u32 = 1000;
    
    // === Privacy ===
    pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];
    pub const MAX_JITTER_MS: u64 = 3000; // 0-3 seconds
    pub const EPOCH_DURATION_SECS: u64 = 24 * 60 * 60; // 1 day
    
    // === Time Validation (NEW) ===
    pub const MAX_CLOCK_SKEW_SECS: u64 = 300; // 5 minutes
    pub const MIN_VALID_TIMESTAMP: u64 = 1704067200; // 2024-01-01
    pub const MAX_VALID_TIMESTAMP: u64 = 4102444800; // 2100-01-01
    
    // === Identity ===
    pub const MAX_IDENTITIES_PER_ORIGIN: u32 = 3;
    pub const KEY_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60; // 30 days
    pub const KEY_WARNING_SECS: u64 = 5 * 24 * 60 * 60; // 5 days
    pub const EXPIRY_GRACE_PERIOD_SECS: u64 = 24 * 60 * 60; // 24 hours
    
    // === Username ===
    pub const MIN_USERNAME_LEN: usize = 3;
    pub const MAX_USERNAME_LEN: usize = 32;
    
    // === Groups ===
    pub const MAX_GROUP_SIZE: usize = 100;
    pub const MAX_GROUPS_PER_IDENTITY: usize = 50;
    pub const GROUP_KEY_ROTATION_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
    
    // === Reputation ===
    pub const REPUTATION_START: u32 = 500;
    pub const REPUTATION_MAX: u32 = 1000;
    pub const REPUTATION_QUARANTINE: u32 = 200;
    pub const REPUTATION_BLACKLIST: u32 = 50;
    
    // === Anti-Gaming ===
    pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;
    pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;
    pub const MAX_DAILY_GAIN_TOTAL: u32 = 100;
    pub const NEGATIVE_REPORT_THRESHOLD: u32 = 3;
    pub const MIN_REPORTER_REPUTATION: u32 = 400;
    pub const CLUSTER_SUSPICION_THRESHOLD: f32 = 0.7;
    
    // === Validators ===
    pub const MIN_VALIDATOR_STAKE: u32 = 700;
    pub const MAX_VALIDATORS: usize = 21;
    pub const VALIDATOR_ROTATION_PERCENT: f32 = 0.15;
    pub const MAX_VALIDATORS_PER_REGION: usize = 5;
    pub const STAKE_LOCK_EPOCHS: u32 = 14;
    
    // === Validator SLA ===
    pub const MIN_UPTIME_PERCENT: f32 = 99.0;
    pub const MAX_MISSED_BLOCKS_PER_EPOCH: u32 = 3;
    pub const MAX_RESPONSE_LATENCY_MS: u64 = 5000;
    pub const MIN_BLOCKS_PER_EPOCH: u32 = 10;
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
│   │   └── veritas-crypto
│   └── veritas-reputation
├── veritas-chain
│   ├── veritas-protocol
│   └── veritas-crypto
├── veritas-net
│   ├── veritas-protocol
│   └── veritas-reputation
└── veritas-store
    ├── veritas-protocol
    └── veritas-crypto
```

### When Creating New Files

- **Crypto code** → `crates/veritas-crypto/src/`
- **Identity/DID** → `crates/veritas-identity/src/`
- **Message formats** → `crates/veritas-protocol/src/`
- **Blockchain** → `crates/veritas-chain/src/`
- **Networking** → `crates/veritas-net/src/`
- **Storage** → `crates/veritas-store/src/`
- **High-level API** → `crates/veritas-core/src/`
- **C bindings** → `crates/veritas-ffi/src/`
- **WASM bindings** → `crates/veritas-wasm/src/`
- **Python bindings** → `crates/veritas-py/src/`

### Security-Related New Files (From Remediation)

- **Hardware attestation** → `crates/veritas-identity/src/hardware.rs`
- **Rate limiting** → `crates/veritas-net/src/rate_limiter.rs`
- **Interaction proofs** → `crates/veritas-reputation/src/proof.rs`
- **Trusted time** → `crates/veritas-core/src/time.rs`

-----

## Testing Requirements

### Unit Tests

Every public function needs tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = SymmetricKey::generate();
        let plaintext = b"Hello, VERITAS!";
        
        let ciphertext = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        
        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
```

### Security-Specific Tests

**REQUIRED for all security fixes:**

```rust
#[cfg(test)]
mod security_tests {
    use super::*;
    
    #[test]
    fn test_oversized_envelope_rejected() {
        let oversized = vec![0u8; MAX_ENVELOPE_SIZE + 1];
        let result = MinimalEnvelope::from_bytes(&oversized);
        assert!(matches!(result, Err(ProtocolError::InvalidEnvelope(_))));
    }
    
    #[test]
    fn test_forged_block_rejected() {
        let legit_keypair = MlDsaKeypair::generate();
        let attacker_keypair = MlDsaKeypair::generate();
        // ... verify signature check works
    }
    
    #[test]
    fn test_replay_attack_prevented() {
        // ... verify nonce deduplication
    }
    
    #[test]
    fn test_sybil_fingerprint_requires_hardware() {
        // ... verify generate() is test-only
    }
}
```

### Property Tests

Use `proptest` for input validation:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn fuzz_deserialization_safe(data: Vec<u8>) {
        // Should never panic or OOM
        let _ = MinimalEnvelope::from_bytes(&data);
    }
}
```

-----

## Git Workflow

### Security Fix Branches

```bash
# For security fixes, use security/ prefix
git checkout -b security/VERITAS-2026-0001-sybil-fingerprint
git checkout -b security/VERITAS-2026-0002-block-signatures
```

### After Completing Security Fix

```bash
# 1. Update VERSION_HISTORY.md
# 2. Update SECURITY_AUDIT_REPORT.md status (mark as FIXED)
# 3. Commit with vulnerability ID
git commit -m "security(identity): fix VERITAS-2026-0001 Sybil fingerprint bypass

- OriginFingerprint::generate() now test-only
- Added HardwareAttestation requirement
- Added platform-specific hardware binding

Fixes: VERITAS-2026-0001
Severity: CRITICAL"
```

### PR Requirements for Security Fixes

- **Security agent MUST approve** all security fixes
- **QA agent MUST provide tests** that verify the fix
- **Include vulnerability ID** in PR title and description
- **Update SECURITY_AUDIT_REPORT.md** to mark as FIXED
- **Reference VERITAS_REMEDIATION_INSTRUCTIONS.md** implementation

-----

## Mandatory Agent Involvement

|Change Type          |Required Agents                     |
|---------------------|------------------------------------|
|Any code change      |Security (review), QA (tests)       |
|Crypto implementation|Security (lead), QA, Docs           |
|Protocol changes     |Architect, Security, QA             |
|Network changes      |Backend, Security, QA               |
|Storage changes      |Backend, Security, QA               |
|FFI/WASM changes     |Bindings, Security, QA              |
|API changes          |Architect, Docs, QA                 |
|**Security fixes**   |**Relevant Auditor + Security + QA**|

-----

## Flagged Security Items

### Resolved (Design Level)

1. **F1: Bluetooth security** — ✅ Network-first, BLE is pure relay, no PIN
1. **F2: Reputation gaming** — ✅ Rate limiting + weighted reports + graph analysis
1. **F3: Metadata leakage** — ✅ Minimal envelope, sender/timestamp hidden, padding
1. **F4: Validator collusion** — ✅ PoS selection + 99% SLA + slashing
1. **F5: Identity spam** — ✅ Max 3 per device, wait for expiry

### Implementation Vulnerabilities (From Audit)

See `SECURITY_AUDIT_REPORT.md` for complete list. Key items:

|ID               |Severity|Status|Summary                    |
|-----------------|--------|------|---------------------------|
|VERITAS-2026-0001|CRITICAL|OPEN  |Sybil fingerprint bypass   |
|VERITAS-2026-0002|CRITICAL|OPEN  |Missing block signatures   |
|VERITAS-2026-0003|CRITICAL|OPEN  |Unbounded deserialization  |
|VERITAS-2026-0005|CRITICAL|OPEN  |Message queue metadata leak|
|VERITAS-2026-0007|CRITICAL|OPEN  |Gossip flooding DoS        |
|VERITAS-2026-0010|CRITICAL|OPEN  |Reputation auth bypass     |

### Still Flagged (v2)

1. **F6: Offline sync load** — Pagination for large syncs
1. **F7: Group privacy** — Encrypt group existence metadata
1. **F8: PQ library maturity** — Monitor ml-kem/ml-dsa advisories

-----

## Environment

No environment variables required for core library.

For integration testing:

```bash
# Optional: Override test network
VERITAS_TEST_BOOTSTRAP_NODES="..."

# Optional: Test storage path
VERITAS_TEST_STORAGE_PATH="/tmp/veritas-test"
```

-----

## Known Issues / TODOs

### Security Remediation (Priority)

- [ ] Fix all 22 CRITICAL vulnerabilities
- [ ] Fix all 31 HIGH vulnerabilities
- [ ] Fix all 26 MEDIUM vulnerabilities
- [ ] Fix all 11 LOW vulnerabilities

### Implementation

- [ ] ml-kem and ml-dsa crates are new — monitor for updates
- [ ] Bluetooth transport not yet implemented
- [ ] WASM bindings need Web Crypto integration
- [ ] Python bindings need async support (pyo3-asyncio)
- [ ] Fuzz testing infrastructure not yet set up

-----

## Performance Targets

|Operation                     |Target |
|------------------------------|-------|
|Key generation                |< 50ms |
|Message encryption (300 chars)|< 10ms |
|Message signing               |< 20ms |
|Signature verification        |< 20ms |
|Blockchain proof verification |< 100ms|
|Size validation (DoS check)   |< 1μs  |

-----

## MCP Servers

This project may use:

- **Cloudflare** — For any future hosted validator infrastructure
- **GitHub** — For repository operations (if connected)

Check available servers at session start.