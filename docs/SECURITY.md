# VERITAS Security Considerations

Threat model, cryptographic design, and security best practices for the VERITAS Protocol.

## Table of Contents

- [Security Overview](#security-overview)
- [Threat Model](#threat-model)
- [Cryptographic Design](#cryptographic-design)
- [Post-Quantum Readiness](#post-quantum-readiness)
- [Metadata Protection](#metadata-protection)
- [Key Management](#key-management)
- [Transport Security](#transport-security)
- [Reputation Security](#reputation-security)
- [Recommended Practices](#recommended-practices)
- [Security Audit Status](#security-audit-status)

---

## Security Overview

VERITAS is designed with a defense-in-depth approach, combining multiple security mechanisms:

| Layer | Protection | Mechanism |
|-------|------------|-----------|
| Cryptographic | Confidentiality | ChaCha20-Poly1305 + ML-KEM/X25519 |
| Cryptographic | Integrity | BLAKE3 + ML-DSA signatures |
| Protocol | Privacy | Minimal metadata envelope |
| Transport | Flexibility | Multi-transport with E2E encryption |
| Network | Censorship resistance | Decentralized P2P |
| Verification | Non-repudiation | Blockchain proofs |

### Security Goals

1. **Confidentiality**: Only sender and recipient can read message content
2. **Integrity**: Messages cannot be modified without detection
3. **Authenticity**: Sender identity is cryptographically verified
4. **Forward Secrecy**: Past messages remain secure if keys are compromised
5. **Metadata Privacy**: Minimize information leaked to observers
6. **Post-Quantum Security**: Resist future quantum computer attacks

---

## Threat Model

### Adversary Capabilities

VERITAS defends against adversaries with:

| Capability | Description | Mitigation |
|------------|-------------|------------|
| Network surveillance | Monitor all network traffic | E2E encryption, metadata hiding |
| Network manipulation | Drop, delay, or modify packets | Signatures, message queuing |
| Server compromise | Control some relay nodes | No trusted servers, E2E encryption |
| Endpoint compromise | Access to device (not keys) | Encrypted storage, key zeroization |
| Cryptanalysis | Classical computation | Strong cryptographic algorithms |
| Quantum computation | Quantum computers | Post-quantum algorithms (hybrid) |

### What VERITAS Does NOT Protect Against

| Threat | Limitation |
|--------|------------|
| Device compromise with unlocked keys | Physical security required |
| Targeted malware | Endpoint security required |
| Coerced key disclosure | Legal/physical security required |
| Traffic analysis (timing) | Partial mitigation with jitter |
| Social engineering | User education required |

### Trust Assumptions

1. **Cryptographic primitives**: BLAKE3, ChaCha20-Poly1305, X25519, ML-KEM, ML-DSA are secure
2. **Random number generation**: OS provides cryptographically secure randomness
3. **Implementation correctness**: Code correctly implements protocols
4. **Physical security**: User's device is not physically compromised while unlocked

---

## Cryptographic Design

### Algorithm Selection

| Purpose | Algorithm | Security Level | Post-Quantum |
|---------|-----------|----------------|--------------|
| Hashing | BLAKE3 | 256-bit | Yes |
| Symmetric encryption | ChaCha20-Poly1305 | 256-bit | Yes |
| Key exchange | X25519 | 128-bit classical | No |
| Key encapsulation | ML-KEM-768 | NIST Level 3 | Yes |
| Digital signatures | ML-DSA-65 | NIST Level 3 | Yes |
| Key derivation | Argon2id | Configurable | Yes |

### Message Encryption

```
┌─────────────────────────────────────────────────────────────────┐
│                    Message Encryption Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Sender                                                          │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  1. Generate ephemeral key pair (X25519)                 │    │
│  │     ephemeral_private, ephemeral_public                  │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │  2. Compute shared secret (ECDH)                         │    │
│  │     shared = X25519(ephemeral_private, recipient_public) │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │  3. Derive message key (BLAKE3-KDF)                      │    │
│  │     msg_key = BLAKE3(domain || shared || context)        │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │  4. Encrypt payload (ChaCha20-Poly1305)                  │    │
│  │     nonce = random(24 bytes)                             │    │
│  │     ciphertext = AEAD_Encrypt(msg_key, nonce, payload)   │    │
│  └──────────────────────────┬──────────────────────────────┘    │
│                             │                                    │
│  ┌──────────────────────────▼──────────────────────────────┐    │
│  │  5. Construct envelope                                   │    │
│  │     { mailbox_key, ephemeral_public, nonce, ciphertext } │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Signature Scheme

```
Signing:
  1. Construct signing data:
     data = domain_separator || sender_id || timestamp || message_hash

  2. Sign with ML-DSA:
     signature = ML_DSA_Sign(private_key, data)

Verification:
  1. Reconstruct signing data (same as above)

  2. Verify with ML-DSA:
     valid = ML_DSA_Verify(public_key, data, signature)
```

### Key Derivation

Password-based key derivation uses Argon2id:

```
Parameters:
  - Memory: 64 MB
  - Iterations: 3
  - Parallelism: 4
  - Output: 32 bytes

storage_key = Argon2id(password, salt, params)
```

---

## Post-Quantum Readiness

### Current Status

VERITAS uses a **hybrid approach** combining classical and post-quantum algorithms:

| Operation | Classical | Post-Quantum | Hybrid Mode |
|-----------|-----------|--------------|-------------|
| Key Exchange | X25519 | ML-KEM-768 | X25519 + ML-KEM |
| Signatures | Ed25519 | ML-DSA-65 | ML-DSA only |
| Encryption | ChaCha20 | ChaCha20 | Same (PQ-safe) |
| Hashing | BLAKE3 | BLAKE3 | Same (PQ-safe) |

### Hybrid Key Exchange

```
┌─────────────────────────────────────────────────────────────────┐
│                    Hybrid Key Exchange                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Classical component (X25519):                               │
│     shared_classical = X25519(ephemeral, recipient_public)      │
│                                                                  │
│  2. Post-quantum component (ML-KEM):                            │
│     (ciphertext, shared_pq) = ML_KEM_Encaps(recipient_pq_public)│
│                                                                  │
│  3. Combine shared secrets:                                     │
│     final_key = BLAKE3(shared_classical || shared_pq)           │
│                                                                  │
│  Security: Secure if EITHER X25519 OR ML-KEM is secure          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Migration Plan

| Phase | Timeline | Action |
|-------|----------|--------|
| 1. Current | Now | X25519 + optional ML-KEM |
| 2. Transition | ml-kem/ml-dsa stable | Hybrid mode default |
| 3. Post-Quantum | When required | ML-KEM only (classical deprecated) |

### Post-Quantum Algorithm Status

The ML-KEM and ML-DSA implementations are based on NIST FIPS standards:

- **ML-KEM (FIPS 203)**: Module-Lattice-Based Key-Encapsulation Mechanism
- **ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm

> **Note**: The underlying crates (ml-kem, ml-dsa) are under active development.
> Monitor advisories and update promptly when stable releases are available.

---

## Metadata Protection

### Minimal Envelope Design

The outer envelope visible to network observers contains only:

```rust
pub struct MinimalEnvelope {
    /// Derived mailbox key (NOT recipient identity)
    pub mailbox_key: [u8; 32],

    /// Ephemeral public key (single-use)
    pub ephemeral_public: [u8; 32],

    /// Random nonce
    pub nonce: [u8; 24],

    /// Encrypted + padded payload
    pub ciphertext: Vec<u8>,
}
```

### What Observers Can See

| Information | Visible? | Mitigation |
|-------------|----------|------------|
| Recipient identity | No | Derived mailbox key |
| Sender identity | No | Inside encrypted payload |
| Timestamp | No | Inside encrypted payload |
| Message content | No | Encrypted |
| Exact message size | No | Padded to fixed buckets |
| Communication graph | Partial | Mailbox keys rotate |

### What Observers CANNOT See

- Who is sending to whom (identity hashes hidden)
- When messages were composed (timestamps encrypted)
- Message content (encrypted)
- Message type (text, receipt, group)

### Mailbox Key Derivation

```rust
/// Mailbox key changes every epoch (24 hours)
pub fn derive_mailbox_key(
    recipient_id: &IdentityHash,
    epoch: u64,           // Changes daily
    salt: &[u8; 16],      // Random per-message
) -> [u8; 32] {
    BLAKE3::hash(&[
        recipient_id.as_bytes(),
        &epoch.to_be_bytes(),
        salt,
    ])
}
```

Benefits:
- Different mailbox key each day
- Cannot link messages across epochs
- Salt prevents pre-computation attacks

### Padding Strategy

Messages are padded to fixed-size buckets:

```rust
pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];

// Example: 150-byte message -> padded to 256 bytes
// Example: 300-byte message -> padded to 512 bytes
// Example: 600-byte message -> padded to 1024 bytes
```

### Timing Protection

```rust
// Random delay before sending (0-3 seconds)
pub const MAX_JITTER_MS: u64 = 3000;

// Applied automatically unless explicitly disabled
let jitter = OsRng.gen_range(0..MAX_JITTER_MS);
tokio::time::sleep(Duration::from_millis(jitter)).await;
```

---

## Key Management

### Key Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                      Key Lifecycle                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Generation ────► Active (30 days) ────► Expiring (5 days) ─┐  │
│                         │                        │           │  │
│                         │                        │           │  │
│                    (rotate)                 (warning)        │  │
│                         │                        │           │  │
│                         ▼                        ▼           │  │
│                    Rotated                   Expired ◄───────┘  │
│                         │                        │              │
│                         │                        │ (24h grace)  │
│                         ▼                        ▼              │
│                    Archived              Slot Released          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Key States

| State | Duration | Allowed Operations |
|-------|----------|-------------------|
| Active | 25 days | All operations |
| Expiring | 5 days | All + warning shown |
| Expired | - | Receive only |
| Rotated | - | Historical decrypt only |
| Revoked | - | None |

### Key Storage

```
┌─────────────────────────────────────────────────────────────────┐
│                    Encrypted Key Storage                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Password ────► Argon2id ────► Storage Key                      │
│                                     │                            │
│                                     ▼                            │
│                            ┌───────────────┐                     │
│                            │   Encrypted   │                     │
│                            │    Keyring    │                     │
│                            └───────┬───────┘                     │
│                                    │                             │
│                    ┌───────────────┼───────────────┐             │
│                    ▼               ▼               ▼             │
│              ┌──────────┐   ┌──────────┐   ┌──────────┐         │
│              │Identity 1│   │Identity 2│   │Identity 3│         │
│              │ (primary)│   │          │   │          │         │
│              └──────────┘   └──────────┘   └──────────┘         │
│                                                                  │
│  Each identity contains:                                         │
│  • Exchange private key (X25519)                                │
│  • Signing private key (ML-DSA)                                 │
│  • ML-KEM private key (optional)                                │
│  • Metadata (label, created, expires)                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Zeroization

All secret data implements `Zeroize` for secure memory cleanup:

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey {
    bytes: [u8; 32],
}

// Automatically zeroized when dropped
// Also zeroized on client.lock()
```

### Constant-Time Operations

Security-sensitive comparisons use constant-time operations:

```rust
use subtle::ConstantTimeEq;

// Prevents timing attacks
pub fn verify_tag(expected: &[u8], actual: &[u8]) -> bool {
    expected.ct_eq(actual).into()
}
```

---

## Transport Security

### Security Model

All transports are treated as **untrusted relays**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Transport Security Model                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Security comes from END-TO-END ENCRYPTION, not transport       │
│                                                                  │
│  ┌──────────┐          ┌──────────┐          ┌──────────┐      │
│  │  Sender  │──────────│  Relay   │──────────│ Recipient│      │
│  │          │ encrypted│  (any)   │ encrypted│          │      │
│  └──────────┘          └──────────┘          └──────────┘      │
│                              │                                   │
│                              │                                   │
│                        Cannot read:                              │
│                        • Message content                         │
│                        • Sender identity                         │
│                        • Timestamp                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Transport-Specific Notes

#### Internet (Primary)

- TLS optional (data already E2E encrypted)
- libp2p Noise protocol for peer authentication
- DHT and GossipSub for message routing

#### Local WiFi

- mDNS for peer discovery
- Same E2E encryption as internet
- No additional authentication required

#### Bluetooth

- **NO PIN verification required**
- **NO pairing required**
- Pure relay transport
- Security from E2E encryption only

Why no Bluetooth pairing?
1. Bluetooth is just a relay mechanism
2. Message security is independent of transport
3. Any VERITAS node can relay without trust

---

## Reputation Security

### Anti-Gaming Measures

| Mechanism | Purpose |
|-----------|---------|
| Rate limiting | Prevent spam and farming |
| Daily caps | Limit reputation manipulation |
| Weighted reports | Trusted users have more impact |
| Collusion detection | Graph analysis for coordinated abuse |

### Rate Limits

```rust
pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;    // 1 min between msgs to same peer
pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;      // Max from one peer per day
pub const MAX_DAILY_GAIN_TOTAL: u32 = 100;        // Max total per day
```

### Collusion Detection

```
┌─────────────────────────────────────────────────────────────────┐
│                    Collusion Detection                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Suspicious patterns:                                            │
│  • Internal density > 70% (mostly interact within cluster)      │
│  • Few external connections                                      │
│  • Symmetric interaction patterns                                │
│  • Rapid reputation gain                                         │
│                                                                  │
│  Detection:                                                      │
│  1. Build interaction graph                                      │
│  2. Identify clusters via community detection                    │
│  3. Calculate internal vs external interaction ratio             │
│  4. Flag clusters above suspicion threshold                      │
│                                                                  │
│  Penalty:                                                        │
│  • Suspicion score 0.8 = only 20% of reputation gains apply     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Validator Security

| Requirement | Value | Purpose |
|-------------|-------|---------|
| Min stake | 700 reputation | Sybil resistance |
| Max validators | 21 | Limit attack surface |
| Uptime | 99% | Availability |
| Geo diversity | Max 5/region | Jurisdictional resistance |

### Slashing

Validators face penalties for misbehavior:

| Offense | Penalty |
|---------|---------|
| Missed block | 0.1% stake |
| SLA violation | 1% stake |
| Invalid block | 5% stake |
| Double signing | 100% + permanent ban |

---

## Recommended Practices

### For Users

1. **Strong passwords**: Use long, unique passwords
2. **Lock when idle**: Always lock the client when not in use
3. **Verify contacts**: Compare safety numbers out-of-band
4. **Keep updated**: Install security updates promptly
5. **Secure devices**: Use device encryption, strong PINs

### For Developers

1. **Input validation**: Validate all inputs at API boundaries
2. **Error handling**: Never expose sensitive data in errors
3. **Logging**: Never log key material or message content
4. **Dependencies**: Audit and minimize dependencies
5. **Testing**: Include security-focused tests

### For Integrators

```rust
// DO: Use constant-time comparisons
use subtle::ConstantTimeEq;
if expected_tag.ct_eq(&actual_tag).into() { ... }

// DON'T: Use regular comparison for secrets
if expected_tag == actual_tag { ... }  // WRONG
```

```rust
// DO: Zeroize sensitive data
let mut key = get_key();
// ... use key ...
key.zeroize();  // Or use ZeroizeOnDrop

// DON'T: Leave secrets in memory
let key = get_key();
// ... key may remain in memory
```

```rust
// DO: Use secure random
use rand::rngs::OsRng;
let random_bytes: [u8; 32] = OsRng.gen();

// DON'T: Use weak random
use rand::thread_rng;  // May not be cryptographically secure
```

### Secure Configuration

```rust
// Recommended configuration for high-security environments
let config = ClientConfigBuilder::new()
    .with_encrypted_database()     // Always encrypt storage
    .enable_timing_jitter()        // Prevent timing analysis
    .disable_read_receipts()       // Minimize metadata
    .enable_collusion_detection()  // Detect reputation gaming
    .build();
```

---

## Security Audit Status

### Current Status

| Component | Audit Status | Notes |
|-----------|--------------|-------|
| veritas-crypto | Not audited | Uses audited libraries |
| veritas-protocol | Not audited | Review pending |
| veritas-identity | Not audited | Review pending |
| veritas-core | Not audited | Review pending |

### Dependency Audit

Run regularly:

```bash
cargo audit
```

### Known Limitations

1. **ML-KEM/ML-DSA**: Underlying crates are pre-release
2. **Side-channel resistance**: Not formally verified
3. **Formal verification**: Protocol not formally verified
4. **Fuzzing**: Limited coverage currently

### Reporting Vulnerabilities

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security@veritas-protocol.org
3. Include detailed reproduction steps
4. Allow 90 days for fix before disclosure

---

## See Also

- [API Documentation](API.md) - Complete API reference
- [Architecture Guide](ARCHITECTURE.md) - System design and data flow
- [Setup Guide](SETUP.md) - Installation and configuration
