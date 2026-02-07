# VERITAS Architecture Guide

System architecture, design decisions, and data flow for the VERITAS Protocol.

**Version**: v0.4.0-beta
**Last Updated**: 2026-02-07
**Edition**: Rust 2024
**MSRV**: 1.85

## Table of Contents

- [Overview](#overview)
- [Version History](#version-history)
- [System Architecture](#system-architecture)
- [Security Architecture](#security-architecture)
- [Crate Dependency Graph](#crate-dependency-graph)
- [Component Details](#component-details)
- [Security Components](#security-components)
- [Data Flow](#data-flow)
- [Network Topology](#network-topology)
- [Storage Architecture](#storage-architecture)
- [Blockchain Integration](#blockchain-integration)
- [Transport Selection](#transport-selection)

---

## Overview

VERITAS (Verified Encrypted Real-time Integrity Transmission And Signing) is a post-quantum secure, decentralized messaging protocol with blockchain verification and offline P2P capability.

### Design Principles

1. **Privacy First**: Minimize metadata exposure at all layers
2. **Post-Quantum Security**: Prepare for quantum computing threats
3. **Decentralization**: No central points of failure or control
4. **Offline Capability**: Function without continuous connectivity
5. **Verifiability**: Cryptographic proofs for all claims
6. **Defense in Depth**: Multiple security layers at every boundary

### Key Features

- End-to-end encryption with forward secrecy
- Post-quantum cryptography (ML-KEM, ML-DSA)
- Metadata minimization (sender/timestamp hidden)
- Multi-transport networking (Internet, WiFi, Bluetooth)
- Blockchain-based message verification
- Reputation system with anti-gaming measures
- Hardware-bound identity limiting (Sybil resistance)
- Comprehensive DoS protection

---

## Version History

### v0.3.0-beta (2026-02-01)

**Major Release: Security Hardening + Rust 2024 Migration**

#### Security Audit Compliance

All **90 vulnerabilities** from the comprehensive security audit have been addressed:

| Severity | Count | Status |
|----------|-------|--------|
| CRITICAL | 24 | All Fixed |
| HIGH | 31 | All Fixed |
| MEDIUM | 26 | All Fixed |
| LOW | 11 | All Fixed |

Key security fixes include:

- **Username Uniqueness**: Now enforced at blockchain level (VERITAS-2026-0090)
- **Perfect Forward Secrecy**: Old keys destroyed on rotation (VERITAS-2026-0091)
- **Block Signatures**: Cryptographic verification in consensus (VERITAS-2026-0002)
- **DoS Protection**: Size validation, rate limiting, bounded collections
- **Sybil Resistance**: Hardware attestation for origin fingerprinting

#### Rust 2024 Edition Migration

- All 11 crates migrated to Rust 2024 edition
- MSRV upgraded from 1.75 to 1.85
- FFI crates use `#[unsafe(no_mangle)]` syntax
- PyO3 upgraded to 0.23, cbindgen to 0.29

#### New Security Components

- `veritas-identity/src/hardware.rs` - Hardware attestation
- `veritas-net/src/rate_limiter.rs` - Gossip rate limiting
- `veritas-net/src/subnet_limiter.rs` - DHT eclipse attack prevention
- `veritas-reputation/src/proof.rs` - Interaction proofs
- `veritas-core/src/time.rs` - Trusted time validation

### v0.3.1-beta (2026-02-05)

**Milestone 1: Critical Code Fixes** — ~60 bugs fixed across 12 crates (44 files changed).

- 1 CRITICAL, 16 HIGH, ~23 MEDIUM, ~20 LOW severity fixes
- Node binary now fully functional with P2P networking
- Default data directory changed to `~/.local/share/veritas`
- All 1,549 tests pass

### v0.4.0-beta (2026-02-07)

**Milestone 2: Wire Format v2 + ML-DSA Signing**

- **ML-DSA-65 (FIPS 204)**: Real post-quantum signing replaces all placeholder HMAC-BLAKE3
- **Wire Format v2**: MAX_ENVELOPE_SIZE 8192, padding buckets [1024,2048,4096,8192], protocol version and cipher suite fields
- **Chain-as-Transport**: Messages are on-chain transactions — the blockchain IS the delivery mechanism
- **Epoch Pruning**: 30-day epochs, bodies+signatures pruned, headers permanent
- **Light Validator**: Header-only sync, 256MB RAM target
- **Reputation Rebalance**: Starting score 100, asymmetric decay

#### New Modules

- `veritas-protocol/src/domain_separation.rs` - Structured domain separation
- `veritas-protocol/src/transcript.rs` - Transcript binding for HKDF
- `veritas-protocol/src/wire_error.rs` - Generic wire error codes
- `veritas-chain/src/transaction.rs` - Message transactions
- `veritas-chain/src/epoch.rs` - Epoch management and pruning
- `veritas-chain/src/light_validator.rs` - Light validator sync + storage

---

## System Architecture

```
+-----------------------------------------------------------------------------+
|                              APPLICATION LAYER                               |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +-----------------------------------------------------------------------+  |
|  |                           veritas-core                                 |  |
|  |  +---------------+ +---------------+ +---------------+                 |  |
|  |  | VeritasClient | | ClientConfig  | | SafetyNumber  |                 |  |
|  |  +-------+-------+ +---------------+ +---------------+                 |  |
|  |          |                                                             |  |
|  |          v                                                             |  |
|  |  +------------------------------------------------------------------+  |  |
|  |  |                     Internal Services                             |  |  |
|  |  |  +--------------+ +--------------+ +--------------+               |  |  |
|  |  |  |   Identity   | |   Message    | |    Chain     |               |  |  |
|  |  |  |   Manager    | |   Service    | |   Service    |               |  |  |
|  |  |  +--------------+ +--------------+ +--------------+               |  |  |
|  |  |  +--------------+ +--------------+                                |  |  |
|  |  |  |  Reputation  | | TrustedTime  |   <- NEW: Time validation      |  |  |
|  |  |  |   Service    | |    Module    |                                |  |  |
|  |  |  +--------------+ +--------------+                                |  |  |
|  |  +------------------------------------------------------------------+  |  |
|  +-----------------------------------------------------------------------+  |
|                                                                              |
+-----------------------------------------------------------------------------+
|                              SECURITY LAYER (NEW)                            |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +----------------+  +----------------+  +----------------+                  |
|  |  Rate Limiter  |  | Subnet Limiter |  |  Hardware      |                  |
|  |   (per-peer +  |  | (DHT eclipse   |  |  Attestation   |                  |
|  |    global)     |  |  prevention)   |  |  (Sybil)       |                  |
|  +----------------+  +----------------+  +----------------+                  |
|                                                                              |
|  +----------------+  +----------------+  +----------------+                  |
|  |  Size          |  |  Timestamp     |  |  Interaction   |                  |
|  |  Validation    |  |  Validation    |  |  Proofs        |                  |
|  +----------------+  +----------------+  +----------------+                  |
|                                                                              |
+-----------------------------------------------------------------------------+
|                              PROTOCOL LAYER                                  |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +----------------+  +----------------+  +------------------+                |
|  |veritas-protocol|  |veritas-identity|  |veritas-reputation|               |
|  |                |  |                |  |                  |               |
|  | - Envelope     |  | - IdentityHash |  | - Score          |               |
|  | - Encryption   |  | - KeyPair      |  | - InteractionProof <- NEW        |
|  | - Groups       |  | - Lifecycle    |  | - Collusion      |               |
|  | - Receipts     |  | - Limits       |  | - Reports        |               |
|  | - Chunking     |  | - Username     |  | - Decay          |               |
|  | - SizeValidate |  | - Hardware  <- NEW                   |               |
|  +----------------+  +----------------+  +------------------+                |
|                                                                              |
+-----------------------------------------------------------------------------+
|                            INFRASTRUCTURE LAYER                              |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +----------------+  +----------------+  +----------------+                  |
|  |  veritas-net   |  | veritas-chain  |  | veritas-store  |                  |
|  |                |  |                |  |                |                  |
|  | - Transport    |  | - Block        |  | - EncryptedDb  |                  |
|  | - DHT          |  | - Merkle       |  | - MessageQueue |                  |
|  | - Gossip       |  | - Validator    |  |   (encrypted!) | <- FIXED        |
|  | - Discovery    |  | - Slashing     |  | - Keyring      |                  |
|  | - Bluetooth    |  | - Sync         |  |                |                  |
|  | - RateLimiter  |  | - BlockSig  <- NEW (signature verification)          |
|  | - SubnetLimiter|  | - UsernameIdx  | <- NEW (uniqueness)                  |
|  +----------------+  +----------------+  +----------------+                  |
|                                                                              |
+-----------------------------------------------------------------------------+
|                            CRYPTOGRAPHY LAYER                                |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +-----------------------------------------------------------------------+  |
|  |                           veritas-crypto                               |  |
|  |                                                                        |  |
|  |  +----------+ +----------+ +----------+ +----------+ +----------+     |  |
|  |  |  Hash256 | |Symmetric | |  X25519  | |  ML-KEM  | |  ML-DSA  |     |  |
|  |  | (BLAKE3) | |(ChaCha20)| | (ECDH)   | |  (KEM)   | | (Sigs)   |     |  |
|  |  +----------+ +----------+ +----------+ +----------+ +----------+     |  |
|  |                                                                        |  |
|  +-----------------------------------------------------------------------+  |
|                                                                              |
+-----------------------------------------------------------------------------+
|                              BINDINGS LAYER                                  |
+-----------------------------------------------------------------------------+
|                                                                              |
|  +----------------+  +----------------+  +----------------+                  |
|  |  veritas-ffi   |  |  veritas-wasm  |  |  veritas-py    |                  |
|  |  (C Bindings)  |  |  (WebAssembly) |  |  (Python)      |                  |
|  |                |  |                |  |                |                  |
|  | #[unsafe(      |  | wasm-pack 0.13 |  | PyO3 0.23      |                  |
|  |   no_mangle)]  |  |                |  | maturin 1.5    |                  |
|  +----------------+  +----------------+  +----------------+                  |
|                                                                              |
+-----------------------------------------------------------------------------+
```

---

## Security Architecture

### Security Boundary Model

The v0.3.0-beta release implements a comprehensive security boundary model with validation at every layer:

```
                     EXTERNAL INPUT
                           |
                           v
+--------------------------------------------------------+
|                   SIZE VALIDATION                       |
|  - MAX_ENVELOPE_SIZE = 2048 bytes                      |
|  - Check BEFORE deserialization (not after!)           |
|  - Prevents memory exhaustion attacks                  |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
|                   RATE LIMITING                         |
|  - Per-peer: 10 announcements/sec (token bucket)       |
|  - Global: 1000 announcements/sec                      |
|  - Violations tracked, repeat offenders banned         |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
|                   TIMESTAMP VALIDATION                  |
|  - MAX_CLOCK_SKEW_SECS = 300 (5 minutes)              |
|  - MIN_VALID_TIMESTAMP = 2024-01-01                    |
|  - Rejects future timestamps (TTL bypass prevention)   |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
|                   SIGNATURE VERIFICATION                |
|  - Block signatures (ML-DSA/Ed25519)                   |
|  - Validator key matches claimed identity              |
|  - Interaction proofs for reputation                   |
+--------------------------------------------------------+
                           |
                           v
+--------------------------------------------------------+
|                   SUBNET DIVERSITY                      |
|  - MAX_PEERS_PER_SUBNET = 2 per /24                   |
|  - Prevents DHT eclipse attacks                        |
|  - Reputation-based peer replacement                   |
+--------------------------------------------------------+
                           |
                           v
                    TRUSTED DATA
```

### Security Validation Checkpoints

| Checkpoint | Location | Validates |
|------------|----------|-----------|
| `from_bytes()` | Protocol crate | Size before deserialization |
| `handle_announcement()` | Network crate | Rate limits before processing |
| `validate_timestamp()` | Core crate | Time bounds on all timestamps |
| `verify_signature()` | Chain crate | Block producer authenticity |
| `try_add_peer()` | Network crate | Subnet diversity for DHT |
| `record_positive_interaction()` | Reputation crate | Cryptographic interaction proof |
| `register_username()` | Chain crate | Username uniqueness |
| `rotate_identity()` | Identity crate | Old key destruction (PFS) |

### Hardware Attestation Flow

```
+----------------+     +------------------+     +------------------+
|   User Device  | --> | HardwareAttest-  | --> | OriginFingerprint|
|                |     | ation.collect()  |     |                  |
+----------------+     +------------------+     +------------------+
        |                      |                        |
        v                      v                        v
+----------------+     +------------------+     +------------------+
| TPM 2.0 (PC)   |     | Verify platform  |     | Bind to 3-       |
| Secure Enclave |     | signature + nonce|     | identity limit   |
| (Apple/Android)|     | + freshness      |     | (Sybil resist)   |
+----------------+     +------------------+     +------------------+

Platform Support:
- Linux/Windows: TPM 2.0 attestation
- macOS/iOS: Secure Enclave attestation
- Android: Hardware-backed Keystore
- Generic: Fallback (lower trust, restricted in production)
```

### Interaction Proof System

```
+------------------+                    +------------------+
|   Party A        |                    |   Party B        |
|  (Initiator)     |                    |  (Recipient)     |
+------------------+                    +------------------+
        |                                       |
        |  1. Generate nonce + timestamp        |
        v                                       |
+------------------+                            |
| InteractionProof |                            |
| - interaction_hash                            |
| - interaction_type                            |
| - timestamp                                   |
| - nonce                                       |
| - from_identity                               |
| - to_identity                                 |
+------------------+                            |
        |                                       |
        |  2. Sign payload (from_signature)     |
        |---------------------------------------->
        |                                       |
        |  3. Counter-sign (to_signature)       |
        |<----------------------------------------
        |                                       |
        v                                       v
+------------------+                    +------------------+
| Complete Proof   |                    | Verify both      |
| (both signatures)|                    | signatures       |
+------------------+                    +------------------+
        |
        v
+------------------+
| ReputationManager|
| - Verify proof   |
| - Check nonce    |
| - Apply score    |
+------------------+

Security Properties:
- Authentication: Both parties sign
- Replay Protection: Unique nonce per proof
- Self-Interaction Prevention: from != to enforced
- Timestamp Binding: Proofs expire after 24 hours
```

---

## Crate Dependency Graph

```
                                 +-------------+
                                 |veritas-core |
                                 +------+------+
                                        |
           +----------------------------+----------------------------+
           |                            |                            |
           v                            v                            v
    +--------------+            +--------------+            +--------------+
    |veritas-net   |            |veritas-chain |            |veritas-store |
    +--------------+            +--------------+            +--------------+
           |                           |                           |
           |                           |                           |
           |      +--------------------+--------------------+      |
           |      |                    |                    |      |
           v      v                    v                    v      v
    +-----------------+         +-----------------+         |      |
    |veritas-protocol |         |veritas-reputation|        |      |
    +--------+--------+         +--------+--------+         |      |
             |                           |                   |      |
             +---------------+-----------+-------------------+      |
                             |                                      |
                             v                                      |
                      +-----------------+                           |
                      |veritas-identity |                           |
                      +--------+--------+                           |
                               |                                    |
                               +------------------+-----------------+
                                                  |
                                                  v
                                           +-------------+
                                           |veritas-crypto|
                                           +-------------+


Bindings (independent):

    +-------------+     +-------------+     +-------------+
    | veritas-ffi |     |veritas-wasm |     | veritas-py  |
    +------+------+     +------+------+     +------+------+
           |                   |                   |
           +-------------------+-------------------+
                               |
                               v
                        +-------------+
                        |veritas-core |
                        +-------------+
```

### Dependency Rules

1. **veritas-crypto**: Foundation - no internal dependencies
2. **veritas-identity**: Depends only on crypto
3. **veritas-protocol**: Depends on crypto and identity
4. **veritas-reputation**: Depends on crypto and identity
5. **veritas-store**: Depends on protocol and crypto
6. **veritas-chain**: Depends on protocol and crypto
7. **veritas-net**: Depends on protocol and reputation
8. **veritas-core**: Orchestrates all crates
9. **Bindings**: Depend only on core

---

## Component Details

### veritas-crypto

Low-level cryptographic primitives.

| Module | Purpose | Library |
|--------|---------|---------|
| `hash` | BLAKE3 hashing | blake3 |
| `symmetric` | ChaCha20-Poly1305 AEAD | chacha20poly1305 |
| `x25519` | Elliptic curve DH | x25519-dalek |
| `mlkem` | Post-quantum KEM | ml-kem |
| `mldsa` | Post-quantum signatures | ml-dsa |

### veritas-identity

Decentralized identity management.

| Module | Purpose |
|--------|---------|
| `identity_hash` | BLAKE3-based identity fingerprints |
| `keypair` | Exchange + signing key pairs |
| `lifecycle` | Key rotation and expiry |
| `limits` | Per-device identity limits |
| `username` | Optional username registration |
| `hardware` | **NEW**: Hardware attestation for Sybil resistance |

### veritas-protocol

Wire protocol and message formats.

| Module | Purpose |
|--------|---------|
| `envelope` | Minimal metadata envelope |
| `encryption` | E2E message encryption |
| `signing` | Message signatures |
| `chunking` | Large message splitting |
| `groups` | Group key management |
| `receipts` | Delivery confirmations |
| `limits` | Protocol constants |

### veritas-net

P2P networking layer.

| Module | Purpose |
|--------|---------|
| `transport` | Transport abstraction |
| `transport_manager` | Multi-transport orchestration |
| `node` | libp2p node implementation |
| `dht` | Kademlia DHT operations |
| `gossip` | GossipSub pub/sub |
| `discovery` | mDNS local discovery |
| `bluetooth` | BLE relay transport |
| `relay` | Store-and-forward |
| `rate_limiter` | **NEW**: Token bucket rate limiting |
| `subnet_limiter` | **NEW**: DHT eclipse attack prevention |

### veritas-chain

Blockchain verification layer.

| Module | Purpose |
|--------|---------|
| `block` | Block structure with signatures |
| `chain` | Chain management + username index |
| `merkle` | Merkle tree proofs |
| `validator` | PoS validator selection |
| `slashing` | Penalty enforcement |
| `sync` | Chain synchronization |

### veritas-store

Encrypted local storage.

| Module | Purpose |
|--------|---------|
| `encrypted_db` | Encrypted key-value store (sled) |
| `keyring` | Identity key storage |
| `message_queue` | **FIXED**: Now uses EncryptedDb |

### veritas-reputation

Reputation and anti-gaming.

| Module | Purpose |
|--------|---------|
| `score` | Reputation scoring |
| `rate_limiter` | Message rate limits |
| `collusion` | Graph-based detection |
| `report` | User reporting |
| `decay` | Time-based decay |
| `effects` | Reputation consequences |
| `proof` | **NEW**: Cryptographic interaction proofs |

### veritas-core

High-level API and orchestration.

| Module | Purpose |
|--------|---------|
| `client` | VeritasClient API |
| `config` | Configuration management |
| `safety_number` | Contact verification |
| `time` | **NEW**: Trusted time validation |

---

## Security Components

### Rate Limiter (`veritas-net/src/rate_limiter.rs`)

Token bucket algorithm for gossip protocol DoS protection.

```rust
// Configuration
pub const DEFAULT_PER_PEER_RATE: u32 = 10;        // Per peer per second
pub const DEFAULT_GLOBAL_RATE: u32 = 1000;        // Global per second
pub const DEFAULT_BURST_MULTIPLIER: u32 = 3;      // Burst capacity
pub const DEFAULT_VIOLATIONS_BEFORE_BAN: u32 = 5; // Ban threshold
pub const DEFAULT_BAN_DURATION_SECS: u64 = 300;   // 5 minute ban
```

**Security Properties**:
- Per-peer isolation prevents single attacker from exhausting global quota
- Global limit prevents coordinated Sybil attacks
- Automatic cleanup of stale peer state (60-second intervals)
- Gradual violation decay for temporary network issues

### Subnet Limiter (`veritas-net/src/subnet_limiter.rs`)

Routing table diversity for DHT eclipse attack prevention.

```rust
pub const MAX_PEERS_PER_SUBNET: usize = 2;   // Per /24 subnet
pub const SUBNET_MASK_V4: u8 = 24;           // IPv4 /24
pub const SUBNET_MASK_V6: u8 = 48;           // IPv6 /48
pub const MIN_TRUSTED_REPUTATION: i64 = 10;  // Trust threshold
```

**Security Properties**:
- Limits attacker's ability to position Sybil nodes near target keys
- Reputation-based peer replacement when subnets are full
- Suspicious behavior tracking with significant reputation penalties
- Diverse peer selection for DHT queries

### Hardware Attestation (`veritas-identity/src/hardware.rs`)

Platform-specific hardware binding for Sybil resistance.

```rust
pub const ATTESTATION_MAX_AGE_SECS: u64 = 300;     // 5 minute freshness
pub const MIN_HARDWARE_ID_LEN: usize = 16;
pub const MAX_HARDWARE_ID_LEN: usize = 256;
pub const MAX_ATTESTATION_SIGNATURE_LEN: usize = 512;
```

**Platform Support**:
| Platform | Method | Trust Level |
|----------|--------|-------------|
| Linux/Windows | TPM 2.0 | Strong |
| macOS/iOS | Secure Enclave | Strong |
| Android | Hardware Keystore | Strong |
| Generic | Software (test only) | Weak |

**Security Properties**:
- Cryptographic proof from secure hardware
- Nonce-based freshness to prevent replay
- Platform-specific signature verification
- Deterministic fingerprint derivation

### Interaction Proofs (`veritas-reputation/src/proof.rs`)

Cryptographic proofs for authenticated reputation interactions.

```rust
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;   // 5 minutes
pub const MAX_PROOF_AGE_SECS: u64 = 86400;  // 24 hours
pub const NONCE_SIZE: usize = 32;
```

**Interaction Types**:
| Type | Base Gain | Counter-Signature Required |
|------|-----------|---------------------------|
| MessageRelay | 3 | Yes |
| MessageStorage | 5 | Yes |
| MessageDelivery | 5 | Yes |
| DhtParticipation | 2 | Yes |
| BlockValidation | 10 | No |

**Security Properties**:
- Both parties must sign (prevents unilateral reputation farming)
- Unique nonce per proof (replay protection)
- Self-interaction explicitly rejected
- Domain-separated signatures per interaction type

### Trusted Time (`veritas-core/src/time.rs`)

Timestamp validation to prevent time manipulation attacks.

```rust
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;        // 5 minutes
pub const MIN_VALID_TIMESTAMP: u64 = 1704067200; // 2024-01-01
pub const MAX_VALID_TIMESTAMP: u64 = 4102444800; // 2100-01-01
```

**Security Properties**:
- Rejects future timestamps (prevents TTL bypass)
- Rejects ancient timestamps (prevents replay)
- Safe fallback on system time errors
- Explicit boundary validation

---

## Data Flow

### Sending a Message (with Security Checks)

```
+-------------+
|  User App   |
+------+------+
       | 1. send_message(recipient, "Hello")
       v
+------------------+
|  VeritasClient   |
|  +------------+  |
|  |  Message   |  |  2. Validate content (300 chars max)
|  |  Service   |  |
|  +-----+------+  |
+--------+---------+
         |
         v
+------------------+     +--------------------------------------+
|    TrustedTime   | --> | 3. validate_timestamp(now())         |
|    Validation    |     |    - Reject if system time invalid   |
+------------------+     +--------------------------------------+
         |
         v
+------------------+
| veritas-protocol |
|                  |
|  +------------+  |     +--------------------------------------+
|  |InnerPayload|<-+-----| sender_id, timestamp, content, sig   |
|  +-----+------+  |     +--------------------------------------+
|        |         |
|        v         |     +--------------------------------------+
|  +------------+  |     | 4. SIZE VALIDATION BEFORE SERIALIZE  |
|  |MinimalEnv  |<-+-----| mailbox_key, ephemeral_pk, nonce,    |
|  |            |  |     | ciphertext (padded to bucket)        |
|  +-----+------+  |     +--------------------------------------+
+--------+---------+
         |
         v
+------------------+
|   veritas-net    |
|  +------------+  |     +--------------------------------------+
|  | Transport  |  |     | 5. Rate limit check (self)           |
|  |  Manager   |  |     |    Priority: Internet > Local > BLE  |
|  +-----+------+  |
|        |         |
|        v         |
|  +------------+  |     +--------------------------------------+
|  |  Gossip    |  |     | 6. Announce via GossipSub            |
|  |  Manager   |  |     |    (rate limited)                    |
|  +-----+------+  |
+--------+---------+
         |
         v
+------------------+
|  veritas-chain   |
|  +------------+  |     +--------------------------------------+
|  |   Block    |  |     | 7. Entry: message_hash, sender,      |
|  |   Entry    |  |     |    recipient (signature verified)    |
|  +------------+  |
+------------------+
```

### Receiving a Message (with Security Checks)

```
+------------------+
|   veritas-net    |
|  +------------+  |     +--------------------------------------+
|  |  Gossip    |  |     | 1. Receive announcement              |
|  |  Manager   |  |
|  +-----+------+  |
+--------+---------+
         |
         v
+------------------+     +--------------------------------------+
|   Rate Limiter   | --> | 2. check(&peer_id)                   |
|                  |     |    - Token bucket per-peer + global  |
|                  |     |    - Reject if limit exceeded        |
|                  |     |    - Track violations, ban if needed |
+------------------+     +--------------------------------------+
         |
         v (if allowed)
+------------------+     +--------------------------------------+
|  Size Validation | --> | 3. bytes.len() <= MAX_ENVELOPE_SIZE  |
|                  |     |    (2048 bytes)                      |
|                  |     |    - BEFORE deserialization          |
+------------------+     +--------------------------------------+
         |
         v (if valid size)
+------------------+
|   veritas-net    |
|  +------------+  |     +--------------------------------------+
|  |    DHT     |  |     | 4. Subnet diversity check            |
|  |  Lookup    |  |     |    - MAX_PEERS_PER_SUBNET = 2        |
|  +-----+------+  |
+--------+---------+
         |
         v
+------------------+
| veritas-protocol |
|  +------------+  |     +--------------------------------------+
|  |MinimalEnv  |  |     | 5. Derive shared secret from         |
|  +-----+------+  |     |    ephemeral_pk                      |
|        |         |
|        v         |
|  +------------+  |     +--------------------------------------+
|  |InnerPayload|  |     | 6. Decrypt and verify signature      |
|  +-----+------+  |
+--------+---------+
         |
         v
+------------------+     +--------------------------------------+
| Timestamp Valid  | --> | 7. validate_timestamp(msg.timestamp) |
|                  |     |    - Reject future timestamps        |
|                  |     |    - Reject ancient timestamps       |
+------------------+     +--------------------------------------+
         |
         v (if valid timestamp)
+------------------+
|  veritas-store   |
|  +------------+  |     +--------------------------------------+
|  |  Message   |  |     | 8. Store in ENCRYPTED inbox          |
|  |   Queue    |  |     |    (EncryptedDb, not plaintext!)     |
|  +------------+  |
+------------------+
         |
         v
+------------------+
|  VeritasClient   |  9. Return ReceivedMessage
+------------------+
```

### Block Validation Flow (with Signature Verification)

```
+------------------+
| Incoming Block   |
+--------+---------+
         |
         v
+------------------+     +--------------------------------------+
|  Size Validation | --> | 1. block.size() <= MAX_BLOCK_SIZE    |
+------------------+     +--------------------------------------+
         |
         v
+------------------+     +--------------------------------------+
|   Header Check   | --> | 2. Verify header structure           |
|                  |     |    - Previous hash matches           |
|                  |     |    - Height is sequential            |
+------------------+     +--------------------------------------+
         |
         v
+------------------+     +--------------------------------------+
|  Timestamp       | --> | 3. Block timestamp validation        |
|  Validation      |     |    - Not too far in future           |
|                  |     |    - Not before parent               |
+------------------+     +--------------------------------------+
         |
         v
+------------------+     +--------------------------------------+
|  SIGNATURE       | --> | 4. verify_signature()                |
|  VERIFICATION    |     |    - Compute signing payload         |
|  (CRITICAL FIX)  |     |    - Verify against validator pubkey |
|                  |     |    - Verify pubkey matches validator |
+------------------+     +--------------------------------------+
         |
         v
+------------------+     +--------------------------------------+
|  Validator       | --> | 5. Check validator is authorized     |
|  Authorization   |     |    - In current validator set        |
|                  |     |    - Correct slot assignment         |
+------------------+     +--------------------------------------+
         |
         v
+------------------+     +--------------------------------------+
|  Merkle Root     | --> | 6. Verify merkle root matches        |
|  Verification    |     |    computed root of entries          |
+------------------+     +--------------------------------------+
         |
         v
+------------------+     +--------------------------------------+
|  Entry           | --> | 7. Process each entry                |
|  Processing      |     |    - Username uniqueness check       |
|                  |     |    - Identity registration           |
|                  |     |    - Reputation changes (with proof) |
+------------------+     +--------------------------------------+
         |
         v
+------------------+
|  Block Accepted  |
+------------------+
```

---

## Network Topology

```
                              +----------------+
                              |   Internet     |
                              +--------+-------+
                                       |
         +-----------------------------+-----------------------------+
         |                             |                             |
         v                             v                             v
    +-----------+                 +-----------+                 +-----------+
    |Bootstrap  |                 |Bootstrap  |                 |Bootstrap  |
    |  Node 1   |                 |  Node 2   |                 |  Node 3   |
    +-----+-----+                 +-----+-----+                 +-----+-----+
          |                             |                             |
          +-----------------------------+-----------------------------+
                                        |
              +-------------------------+-------------------------+
              |                         |                         |
              v                         v                         v
         +-----------+             +-----------+             +-----------+
         |Validator  |<----------->|Validator  |<----------->|Validator  |
         |  Node     |             |  Node     |             |  Node     |
         +-----+-----+             +-----+-----+             +-----+-----+
               |                         |                         |
               |         Gossipsub + Kademlia DHT                  |
               |    (with subnet diversity enforcement)            |
               |                         |                         |
    +----------+---------+---------------+---------------+---------+----------+
    |                    |                               |                    |
    v                    v                               v                    v
+-------+           +-------+                       +-------+           +-------+
| User  |<--------->| User  |                       | User  |<--------->| User  |
| Node  |   mDNS    | Node  |                       | Node  |   BLE     | Node  |
+-------+  (LAN)    +-------+                       +-------+ (relay)   +-------+
```

### Peer Types

| Type | Role | Requirements |
|------|------|--------------|
| Bootstrap | Initial network entry | High availability |
| Validator | Block production | 700+ reputation, 99% uptime |
| User | Send/receive messages | Hardware attestation |

### Discovery Methods

1. **Bootstrap Peers**: Hardcoded known-good nodes
2. **Kademlia DHT**: Distributed peer discovery (subnet-limited)
3. **mDNS**: Local network discovery
4. **Bluetooth**: Direct device discovery

### DHT Eclipse Attack Prevention

```
+------------------+     +------------------+     +------------------+
|  Subnet A        |     |  Subnet B        |     |  Subnet C        |
|  192.168.1.0/24  |     |  192.168.2.0/24  |     |  192.168.3.0/24  |
+------------------+     +------------------+     +------------------+
        |                        |                        |
        v                        v                        v
   +--------+               +--------+               +--------+
   | Peer 1 | (accepted)    | Peer 3 | (accepted)    | Peer 5 | (accepted)
   +--------+               +--------+               +--------+
   | Peer 2 | (accepted)    | Peer 4 | (accepted)    | Peer 6 | (accepted)
   +--------+               +--------+               +--------+
   | Peer X | (REJECTED)
   +--------+
   (MAX_PEERS_PER_SUBNET = 2 exceeded)

Routing Table: Diverse peers from different /24 subnets
- Attacker must control multiple subnets to eclipse
- Reputation-based replacement when at capacity
```

---

## Storage Architecture

```
+------------------------------------------------------------------+
|                          veritas-store                            |
+------------------------------------------------------------------+
|                                                                   |
|  +-------------------------------------------------------------+  |
|  |                       EncryptedDb                            |  |
|  |                                                              |  |
|  |  Storage Key (Argon2id derived from password)                |  |
|  |           |                                                  |  |
|  |           v                                                  |  |
|  |  +----------------------------------------------------+     |  |
|  |  |              sled (embedded database)               |     |  |
|  |  |                                                     |     |  |
|  |  |  +----------+  +----------+  +----------+          |     |  |
|  |  |  | keyring  |  |  inbox   |  |  outbox  |          |     |  |
|  |  |  |  (tree)  |  |  (tree)  |  |  (tree)  |          |     |  |
|  |  |  |ENCRYPTED |  |ENCRYPTED |  |ENCRYPTED | <- FIXED |     |  |
|  |  |  +----------+  +----------+  +----------+          |     |  |
|  |  |                                                     |     |  |
|  |  |  +----------+  +----------+  +----------+          |     |  |
|  |  |  |  blocks  |  | contacts |  |  groups  |          |     |  |
|  |  |  |  (tree)  |  |  (tree)  |  |  (tree)  |          |     |  |
|  |  |  +----------+  +----------+  +----------+          |     |  |
|  |  |                                                     |     |  |
|  |  +----------------------------------------------------+     |  |
|  |                                                              |  |
|  |  All values encrypted with ChaCha20-Poly1305                 |  |
|  |  Random nonce per encryption operation                       |  |
|  |                                                              |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  +---------------+  +---------------+  +---------------+          |
|  |    Keyring    |  | MessageQueue  |  |  BlockCache   |          |
|  |               |  |               |  |               |          |
|  | - Identities  |  | - Inbox       |  | - Headers     |          |
|  | - Private keys|  | - Outbox      |  | - Bodies      |          |
|  | - Metadata    |  | - Status      |  | - Proofs      |          |
|  |               |  | (ENCRYPTED!)  |  |               |          |
|  +---------------+  +---------------+  +---------------+          |
|                                                                   |
+------------------------------------------------------------------+

Data Directory Structure:
~/.local/share/veritas/
+-- db/                 # sled database files (all encrypted)
|   +-- conf
|   +-- db
|   +-- blobs/
+-- cache/              # Temporary cache
+-- logs/               # Application logs
```

### Encryption at Rest

All stored data is encrypted using:

1. **Key Derivation**: Argon2id (64 MiB memory, 3 iterations, 4 parallelism)
2. **Encryption**: ChaCha20-Poly1305 (per-value)
3. **Nonces**: Random per encryption operation

### Key Rotation and Forward Secrecy

```
BEFORE v0.3.0 (VULNERABLE):
+------------------+     +------------------+
| Old Key (Rotated)|     | New Key (Active) |
|                  |     |                  |
| KEPT FOREVER     |     |                  |
| "Historical      |     |                  |
|  decrypt only"   |     |                  |
+------------------+     +------------------+
        |
        v
   Attacker with old DB backup + password
   can decrypt ALL historical messages
   (PFS VIOLATED)


AFTER v0.3.0 (FIXED):
+------------------+     +------------------+
| Old Key          |     | New Key (Active) |
|                  |     |                  |
| DESTROYED        |     |                  |
| (zeroized +      |     |                  |
|  removed from    |     |                  |
|  storage)        |     |                  |
+------------------+     +------------------+
        |
        v
   Attacker with old DB backup
   cannot decrypt messages sent
   after key rotation
   (PFS PRESERVED)
```

---

## Blockchain Integration

```
+------------------------------------------------------------------+
|                         VERITAS Chain                             |
+------------------------------------------------------------------+
|                                                                   |
|  Block Structure:                                                 |
|  +-------------------------------------------------------------+  |
|  |                        BlockHeader                           |  |
|  |  +--------------+--------------+--------------+              |  |
|  |  |  block_hash  | parent_hash  |    height    |              |  |
|  |  +--------------+--------------+--------------+              |  |
|  |  |  timestamp   | merkle_root  |  validator   |              |  |
|  |  +--------------+--------------+--------------+              |  |
|  |  |  signature   | <- NEW: ML-DSA/Ed25519 signature           |  |
|  |  +--------------+                                            |  |
|  +-------------------------------------------------------------+  |
|  +-------------------------------------------------------------+  |
|  |                         BlockBody                            |  |
|  |  +--------------------------------------------------------+  |  |
|  |  |                     ChainEntry[]                        |  |  |
|  |  |  +----------------+  +----------------+                 |  |  |
|  |  |  |IdentityReg    |  |UsernameReg     |                 |  |  |
|  |  |  | - identity    |  | - username     |                 |  |  |
|  |  |  | - public_keys |  | - identity     |                 |  |  |
|  |  |  | - timestamp   |  | - timestamp    |                 |  |  |
|  |  |  | - hw_attest   |  | - UNIQUE CHECK |  <- NEW         |  |  |
|  |  |  +----------------+  +----------------+                 |  |  |
|  |  |  +----------------+  +----------------+                 |  |  |
|  |  |  |MessageProof   |  |ReputationChg   |                 |  |  |
|  |  |  | - msg_hash    |  | - identity     |                 |  |  |
|  |  |  | - sender      |  | - delta        |                 |  |  |
|  |  |  | - recipient   |  | - reason       |                 |  |  |
|  |  |  |               |  | - int_proof    |  <- NEW         |  |  |
|  |  |  +----------------+  +----------------+                 |  |  |
|  |  |  +----------------+  +----------------+                 |  |  |
|  |  |  |ValidatorReg   |  |ValidatorSlash  |                 |  |  |
|  |  |  | - identity    |  | - identity     |                 |  |  |
|  |  |  | - stake       |  | - reason       |                 |  |  |
|  |  |  | - region      |  | - amount       |                 |  |  |
|  |  |  +----------------+  +----------------+                 |  |  |
|  |  +--------------------------------------------------------+  |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  Username Index (NEW):                                            |
|  +-------------------------------------------------------------+  |
|  |  HashMap<String, IdentityHash>                               |  |
|  |                                                              |  |
|  |  "alice" -> IdentityHash([0x1a, 0x2b, ...])                 |  |
|  |  "bob"   -> IdentityHash([0x3c, 0x4d, ...])                 |  |
|  |                                                              |  |
|  |  Enforces: One username per identity (case-insensitive)      |  |
|  +-------------------------------------------------------------+  |
|                                                                   |
|  Merkle Tree:                                                    |
|                        +--------+                                 |
|                        |  Root  |                                 |
|                        +---+----+                                 |
|                    +-------+-------+                              |
|                    v               v                              |
|               +--------+     +--------+                           |
|               | H(A+B) |     | H(C+D) |                           |
|               +---+----+     +---+----+                           |
|               +---+---+      +---+---+                            |
|               v       v      v       v                            |
|            +----+  +----+ +----+  +----+                          |
|            | A  |  | B  | | C  |  | D  |  (Chain Entries)         |
|            +----+  +----+ +----+  +----+                          |
|                                                                   |
+------------------------------------------------------------------+
```

### Validator Selection (PoS)

```
Selection Weight = stake * performance_multiplier * sla_bonus

Where:
  stake = reputation staked (min 700)
  performance_multiplier = 0.5 + (performance_score / 100)  [0.5-1.5]
  sla_bonus = compliant ? (1.0 + streak * 0.05).min(0.5) : 0.7
```

### Slashing Penalties

| Offense | Penalty |
|---------|---------|
| Missed block | 0.1% per block |
| SLA violation | 1% per violation |
| Invalid block | 5% |
| Double sign | 100% + permanent ban |

---

## Transport Selection

### Priority Order

```
+------------------------------------------------------------------+
|                       Transport Selection                         |
+------------------------------------------------------------------+
|                                                                   |
|  1. Check Internet ----------------------> Available? --> USE IT  |
|         |                                      |                  |
|         | No                                   |                  |
|         v                                      |                  |
|  2. Check Local WiFi -------------------> Available? --> USE IT   |
|         |                                      |                  |
|         | No                                   |                  |
|         v                                      |                  |
|  3. Check Bluetooth --------------------> Available? --> USE IT   |
|         |                                      |                  |
|         | No                                   |                  |
|         v                                      |                  |
|  4. Queue Locally ----------------------> Store for later         |
|                                                                   |
+------------------------------------------------------------------+
```

### Transport Characteristics

| Transport | Latency | Reliability | Privacy | Notes |
|-----------|---------|-------------|---------|-------|
| Internet | Low | High | Medium | Primary transport |
| Local WiFi | Low | Medium | High | mDNS discovery |
| Bluetooth | High | Low | Medium | Pure relay, no PIN |
| Queue | N/A | N/A | High | Offline storage |

### Bluetooth Relay Model

```
+------------------------------------------------------------------+
|                       Bluetooth Relay                             |
+------------------------------------------------------------------+
|                                                                   |
|  Offline Device A                    Internet-Connected B         |
|  +-------------+                     +-------------+              |
|  |   VERITAS   |                     |   VERITAS   |              |
|  |   Client    |                     |   Client    |              |
|  +------+------+                     +------+------+              |
|         |                                   |                     |
|         | BLE                               | Internet            |
|         | (encrypted message)               |                     |
|         v                                   |                     |
|  +-------------+                            |                     |
|  |   Relay     | -------------------------->|                     |
|  |   Node      |   Forward to network       |                     |
|  +-------------+                            v                     |
|                                      +-------------+              |
|  Key Points:                         |   Network   |              |
|  - NO PIN verification               +-------------+              |
|  - NO pairing required                                            |
|  - Security from E2E encryption                                   |
|  - Any VERITAS node can relay                                     |
|                                                                   |
+------------------------------------------------------------------+
```

---

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
    pub const MAX_GLOBAL_ANNOUNCEMENTS_PER_SEC: u32 = 1000;

    // Privacy
    pub const PADDING_BUCKETS: &[usize] = &[256, 512, 1024];
    pub const MAX_JITTER_MS: u64 = 3000;

    // Time Validation
    pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
    pub const MIN_VALID_TIMESTAMP: u64 = 1704067200; // 2024-01-01

    // Identity
    pub const MAX_IDENTITIES_PER_ORIGIN: u32 = 3;
    pub const KEY_EXPIRY_SECS: u64 = 30 * 24 * 60 * 60;

    // Hardware Attestation
    pub const ATTESTATION_MAX_AGE_SECS: u64 = 300;

    // Reputation
    pub const MIN_MESSAGE_INTERVAL_SECS: u64 = 60;
    pub const MAX_DAILY_GAIN_PER_PEER: u32 = 30;
    pub const NEGATIVE_REPORT_THRESHOLD: u32 = 3;
    pub const MAX_PROOF_AGE_SECS: u64 = 86400;

    // DHT Eclipse Prevention
    pub const MAX_PEERS_PER_SUBNET: usize = 2;

    // Validators
    pub const MIN_VALIDATOR_STAKE: u32 = 700;
    pub const MAX_VALIDATORS: usize = 21;
    pub const MIN_UPTIME_PERCENT: f32 = 99.0;
}
```

---

## See Also

- [API Documentation](API.md) - Complete API reference
- [Security Guide](SECURITY.md) - Threat model and cryptographic design
- [Setup Guide](SETUP.md) - Installation and configuration
- [Security Audit Report](../SECURITY_AUDIT_REPORT.md) - Comprehensive vulnerability assessment
