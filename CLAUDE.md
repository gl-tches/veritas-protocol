# CLAUDE.md — VERITAS Protocol

> Instructions for Claude Code sessions working on this project

## Project Context

VERITAS (Verified Encrypted Real-time Integrity Transmission And Signing) is a post-quantum secure, decentralized messaging protocol with blockchain verification and offline P2P capability.

**Type**: Rust Library + Multi-platform Bindings  
**Stack**: Rust, ML-KEM, ML-DSA, ChaCha20-Poly1305, libp2p, sled  
**Security Level**: HARDENED + POST-QUANTUM

## Sub-Agent Team Structure

Claude Code operates as the **Lead Developer** coordinating a team of 6 specialized sub-agents. Spawn sub-agents using `Task(...)` or by explicitly delegating work.

### Team Composition

|Agent          |Role             |Responsibilities                                                         |
|---------------|-----------------|-------------------------------------------------------------------------|
|**🏗️ Architect**|System Design    |Architecture decisions, module boundaries, API design, crate organization|
|**🔒 Security** |Security Engineer|Security reviews, crypto implementation, key management, threat analysis |
|**⚡ Backend**  |Core Developer   |Protocol implementation, networking, blockchain, storage                 |
|**🧪 QA**       |Test Engineer    |Unit tests, integration tests, property tests, fuzzing                   |
|**📚 Docs**     |Technical Writer |Documentation, code comments, README updates, API docs                   |
|**🔌 Bindings** |FFI Developer    |C bindings, WASM compilation, Python bindings, cross-platform            |

### Agent Spawning Rules

**ALWAYS spawn sub-agents for:**

- Any task that touches cryptographic code (Security agent MUST review)
- Changes to wire protocol or message format (Architect + Security)
- FFI boundary changes (Bindings + Security)
- Test writing (QA agent)
- Documentation updates (Docs agent)

**Lead Developer responsibilities:**

- Coordinate task distribution
- Merge sub-agent outputs
- Resolve conflicts between agents
- Ensure Security agent reviews ALL crypto-related PRs
- Final approval before commit

### Sub-Agent Communication Pattern

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

### Padding

```rust
pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];

// ALWAYS pad to hide true size
let padded = pad_to_bucket(&payload_bytes);
```

### Mailbox Key Derivation

```rust
/// Mailbox key changes every epoch — unlinkable across time
pub fn derive_mailbox_key(
    recipient_id: &IdentityHash,
    epoch: u64,           // Changes daily
    salt: &[u8; 16],      // Random per-message
) -> [u8; 32] {
    Hash256::hash_many(&[
        recipient_id.as_bytes(),
        &epoch.to_be_bytes(),
        salt,
    ]).to_bytes()
}
```

## Code Patterns

### Error Handling

Each crate defines its own error type with `thiserror`:

```rust
// In veritas-crypto/src/error.rs
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

pub type Result<T> = std::result::Result<T, CryptoError>;
```

### Zeroization Pattern

ALL secret data MUST use `Zeroize`:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

// For wrapper types
pub struct SecretWrapper(Zeroizing<Vec<u8>>);
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

### Async Pattern

Use `tokio` for all async code:

```rust
use tokio::sync::{mpsc, oneshot};

pub async fn send_message(
    &self,
    recipient: &IdentityHash,
    content: &str,
) -> Result<MessageHash, Error> {
    // Validate first (sync)
    let message = Message::new(content)?;
    
    // Then async operations
    let encrypted = self.crypto.encrypt(&message, recipient).await?;
    let hash = self.network.send(encrypted).await?;
    
    Ok(hash)
}
```

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

### Metadata Rules

1. **NEVER** put sender ID on envelope — hide inside encrypted payload
1. **NEVER** put timestamp on envelope — hide inside encrypted payload
1. **ALWAYS** derive mailbox key (don’t use recipient ID directly)
1. **ALWAYS** use ephemeral keys per message (no key reuse)
1. **ALWAYS** pad messages to fixed size buckets
1. **ALWAYS** add timing jitter before sending

### Transport Rules

1. **ALWAYS** check internet connectivity first
1. **NEVER** require PIN/pairing for Bluetooth (it’s just relay)
1. **ALWAYS** require recipient hash to send message
1. **NEVER** implement user discovery (by design)

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

### FFI Safety Rules

1. **ALWAYS** validate all inputs at FFI boundary before processing
1. **NEVER** expose raw pointers to callers
1. **ALWAYS** use error codes, not exceptions/panics
1. **ALWAYS** provide `_free` functions for allocated memory
1. **ALWAYS** check for null pointers first

### WASM Constraints

1. **NO** filesystem access — use browser storage APIs
1. **NO** direct network access — use browser fetch
1. **ALWAYS** use `getrandom` with `js` feature for randomness
1. **CONSIDER** Web Crypto API where beneficial

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

### Collusion Detection

Detect suspicious clusters via graph analysis:

- Internal density > 70% = suspicious
- Few external connections = suspicious
- Symmetric interaction patterns = suspicious
- Apply score gain penalty (suspicion 0.8 = only 20% gains)

### Weighted Reports

```rust
// Reports weighted by reporter reputation
// Rep 500 = weight 1.0, Rep 800 = weight 1.6, Rep 300 = weight 0.6
let weighted_count = reports.iter()
    .map(|r| r.reporter_reputation as f32 / 500.0)
    .sum();
```

## Validator Selection — PoS + SLA (F4)

**CRITICAL: Use stake-weighted selection with SLA enforcement**

### Validator Requirements

```rust
pub struct SelectionConfig {
    pub min_stake: u32,              // 700+ reputation required
    pub max_validators: usize,       // 21 active validators
    pub rotation_percent: f32,       // 15% rotate per epoch
    pub require_geo_diversity: bool, // true
    pub max_per_region: usize,       // Max 5 per region
    pub stake_lock_epochs: u32,      // 14 epoch lock
}
```

### SLA Requirements

```rust
pub struct ValidatorSla {
    pub min_uptime_percent: f32,          // 99% uptime required
    pub max_missed_blocks_per_epoch: u32, // Max 3 missed blocks
    pub max_response_latency_ms: u64,     // 5000ms max latency
    pub min_blocks_per_epoch: u32,        // Must produce 10+ blocks
}
```

### Selection Weight

```rust
// Weight = stake * performance_multiplier * sla_bonus
let stake_weight = staked_reputation as f32;
let perf_multiplier = 0.5 + (performance_score / 100.0);  // 0.5-1.5
let sla_bonus = if compliant { 1.0 + (streak * 0.05).min(0.5) } else { 0.7 };
```

### Slashing

|Offense      |Slash %             |
|-------------|--------------------|
|Missed block |0.1% per block      |
|SLA violation|1% per violation    |
|Invalid block|5%                  |
|Double sign  |100% + permanent ban|

## Identity Limits (F5)

**CRITICAL: Max 3 identities per origin, wait for expiry**

### Limits

```rust
pub struct IdentityLimitConfig {
    pub max_identities_per_origin: u32,    // 3 max
    pub allow_recycle_on_expiry: bool,     // true
    pub expiry_grace_period_secs: u64,     // 24 hours after expiry
}
```

### Identity Lifecycle

```
Active (30 days) → Expiring (5 day warning) → Expired → Released (24h grace)
                                                              ↓
                                                    Slot becomes available
```

### Origin Fingerprinting

```rust
// Privacy-preserving device fingerprint for limiting only
pub fn generate_origin() -> Hash256 {
    Hash256::hash_many(&[
        &hardware_id,        // Platform-specific
        &enclave_binding,    // If available
        &installation_id,    // Random, stored locally
    ])
}
```

### User Status API

```rust
pub struct IdentitySlotInfo {
    pub used: u32,           // Current count
    pub max: u32,            // Always 3
    pub available: u32,      // Slots free
    pub next_slot_available: Option<DateTime<Utc>>,  // If at limit
}
```

## Protocol Limits (Enforced)

```rust
// crates/veritas-protocol/src/limits.rs
pub mod limits {
    // === Messages ===
    pub const MAX_MESSAGE_CHARS: usize = 300;
    pub const MAX_CHUNKS_PER_MESSAGE: usize = 3;
    pub const MAX_TOTAL_MESSAGE_CHARS: usize = 900;
    pub const MESSAGE_TTL_SECS: u64 = 7 * 24 * 60 * 60; // 7 days
    
    // === Privacy ===
    pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];
    pub const MAX_JITTER_MS: u64 = 3000; // 0-3 seconds
    pub const EPOCH_DURATION_SECS: u64 = 24 * 60 * 60; // 1 day
    
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

### Module Structure

Each crate follows this pattern:

```
crates/veritas-{name}/
├── Cargo.toml
└── src/
    ├── lib.rs          # Public exports
    ├── error.rs        # Error types
    ├── {feature}.rs    # Feature modules
    └── tests.rs        # Unit tests (or tests/ dir)
```

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
    
    #[test]
    fn test_decrypt_fails_with_wrong_key() {
        let key1 = SymmetricKey::generate();
        let key2 = SymmetricKey::generate();
        let plaintext = b"Secret";
        
        let ciphertext = encrypt(&key1, plaintext).unwrap();
        let result = decrypt(&key2, &ciphertext);
        
        assert!(matches!(result, Err(CryptoError::Decryption)));
    }
}
```

### Property Tests

Use `proptest` for input validation:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn encrypt_decrypt_any_data(data: Vec<u8>) {
        let key = SymmetricKey::generate();
        let ciphertext = encrypt(&key, &data).unwrap();
        let decrypted = decrypt(&key, &ciphertext).unwrap();
        prop_assert_eq!(data, decrypted);
    }
    
    #[test]
    fn message_validation_rejects_oversized(
        content in ".{301,1000}"  // 301-1000 chars
    ) {
        let result = Message::new(&content);
        prop_assert!(matches!(result, Err(ProtocolError::MessageTooLong { .. })));
    }
}
```

### Integration Tests

Place in `tests/` directory:

```rust
// tests/integration_messaging.rs
use veritas_core::VeritasClient;

#[tokio::test]
async fn test_send_receive_message() {
    let alice = VeritasClient::create_identity().await.unwrap();
    let bob = VeritasClient::create_identity().await.unwrap();
    
    // Alice sends to Bob
    let hash = alice.send_message(bob.identity_hash(), "Hello Bob!")
        .await
        .unwrap();
    
    // Bob receives
    let messages = bob.receive_messages().await.unwrap();
    assert_eq!(messages.len(), 1);
    
    let content = bob.decrypt_message(&messages[0]).unwrap();
    assert_eq!(content.text, "Hello Bob!");
}
```

### Fuzz Testing

For input parsing (add later):

```rust
// fuzz/fuzz_targets/message_parse.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
use veritas_protocol::Message;

fuzz_target!(|data: &[u8]| {
    // Should never panic
    let _ = Message::from_bytes(data);
});
```

## Git Workflow

**CRITICAL: Follow this workflow for EVERY task. No exceptions.**

### Before Starting Any Task

```bash
git fetch origin
git checkout main
git pull origin main
git checkout -b {type}/{task-id}-{description}
```

### After Completing Task

```bash
# 1. Update VERSION_HISTORY.md first!
# 2. Stage and commit
git add .
git commit -m "{type}({scope}): {description}"

# 3. Push and create PR
git push -u origin {branch-name}
gh pr create --title "{type}({scope}): {description}" --body "..." --base main
```

### After PR is Merged

```bash
git checkout main
git pull origin main
git branch -d {branch-name}
# Then start next task
```

### Branch Naming

|Type               |Use               |
|-------------------|------------------|
|`feat/XXX-desc`    |New features      |
|`fix/XXX-desc`     |Bug fixes         |
|`security/XXX-desc`|Security changes  |
|`refactor/XXX-desc`|Code restructuring|
|`docs/XXX-desc`    |Documentation     |
|`chore/XXX-desc`   |Maintenance       |

### Commit Format

```
{type}({scope}): {short description}

{optional body with details}

Task-ID: {XXX}
```

Examples:

```
feat(crypto): implement ML-KEM key encapsulation

- Add MlKemKeyPair struct with generate/encapsulate/decapsulate
- Integrate ml-kem crate v0.1
- Add zeroize on private key drop

Task-ID: 001
```

```
security(protocol): add message nonce validation

- Verify nonce uniqueness before processing
- Add nonce to message hash computation
- Reject messages with duplicate nonces

Task-ID: 015
```

### PR Requirements

- **Never merge your own PRs** — Wait for maintainer approval
- **Security agent MUST approve** all crypto-related changes
- **QA agent MUST provide tests** for every PR
- **Update VERSION_HISTORY.md** in every PR
- **One task = one branch = one PR**

## Mandatory Agent Involvement

|Change Type          |Required Agents              |
|---------------------|-----------------------------|
|Any code change      |Security (review), QA (tests)|
|Crypto implementation|Security (lead), QA, Docs    |
|Protocol changes     |Architect, Security, QA      |
|Network changes      |Backend, Security, QA        |
|Storage changes      |Backend, Security, QA        |
|FFI/WASM changes     |Bindings, Security, QA       |
|API changes          |Architect, Docs, QA          |

## Flagged Security Items

Track these during implementation:

### Resolved

1. **F1: Bluetooth security** — ✅ Network-first, BLE is pure relay, no PIN
1. **F2: Reputation gaming** — ✅ Rate limiting + weighted reports + graph analysis
1. **F3: Metadata leakage** — ✅ Minimal envelope, sender/timestamp hidden, padding
1. **F4: Validator collusion** — ✅ PoS selection + 99% SLA + slashing
1. **F5: Identity spam** — ✅ Max 3 per device, wait for expiry

### Still Flagged (v2)

1. **F6: Offline sync load** — Pagination for large syncs (progressive sync implemented)
1. **F7: Group privacy** — Encrypt group existence metadata
1. **F8: PQ library maturity** — Monitor ml-kem/ml-dsa advisories, hybrid mode default

## Dependencies Policy

### Adding New Dependencies

1. Check if functionality exists in current deps
1. Verify crate is actively maintained (commits in last 6 months)
1. Check for security advisories (`cargo audit`)
1. Prefer crates with security audits for crypto
1. Minimize features — disable defaults, enable only needed
1. Security agent must approve crypto-related deps

### Approved New Crates (Pre-approved)

- `tokio` ecosystem crates
- `serde` ecosystem crates
- RustCrypto crates (`sha2`, `hmac`, `hkdf`, etc.)
- `libp2p` sub-crates
- `tracing` ecosystem

### Requires Security Review

- Any crate touching crypto
- Any crate with `unsafe` code
- Any crate with network access
- Any crate parsing untrusted input

## Environment

No environment variables required for core library.

For integration testing:

```bash
# Optional: Override test network
VERITAS_TEST_BOOTSTRAP_NODES="..."

# Optional: Test storage path
VERITAS_TEST_STORAGE_PATH="/tmp/veritas-test"
```

## Known Issues / TODOs

- [ ] ml-kem and ml-dsa crates are new — monitor for updates
- [ ] Bluetooth transport not yet implemented
- [ ] WASM bindings need Web Crypto integration
- [ ] Python bindings need async support (pyo3-asyncio)
- [ ] Fuzz testing infrastructure not yet set up

## Performance Targets

|Operation                     |Target |
|------------------------------|-------|
|Key generation                |< 50ms |
|Message encryption (300 chars)|< 10ms |
|Message signing               |< 20ms |
|Signature verification        |< 20ms |
|Blockchain proof verification |< 100ms|

## MCP Servers

This project may use:

- **Cloudflare** — For any future hosted validator infrastructure
- **GitHub** — For repository operations (if connected)

Check available servers at session start.