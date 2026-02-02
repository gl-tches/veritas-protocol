# VERITAS Protocol

[![Version](https://img.shields.io/badge/version-0.3.1--beta-blue)]()
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)]()
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green)]()
[![Security Audit](https://img.shields.io/badge/security-audited-brightgreen)]()

> **V**erified **E**ncrypted **R**eal-time **I**ntegrity **T**ransmission **A**nd **S**igning

A fully decentralized, post-quantum secure messaging protocol with blockchain-verified message integrity, offline P2P capability, and plug-and-play identity.

## Overview

VERITAS is a Rust library that enables secure, verifiable messaging without central servers. Messages are encrypted with post-quantum cryptography, signed for authentication, and anchored to a purpose-built blockchain for non-repudiation. When internet is unavailable, messages route through local WiFi or Bluetooth mesh networks.

### Key Features

- **Post-Quantum Security** — ML-KEM (Kyber) + ML-DSA (Dilithium) encryption and signatures
- **Blockchain Verification** — Message proofs anchored to VERITAS chain prevent MITM attacks
- **Offline Capability** — Bluetooth and WiFi Direct mesh when internet unavailable
- **Decentralized Identity** — Hash-based DIDs with optional @username aliases
- **Multi-Platform** — Rust core with C FFI, WASM, and Python bindings

## Tech Stack

|Layer               |Technology                |
|--------------------|--------------------------|
|Language            |Rust 2024 (MSRV 1.85)     |
|Key Encapsulation   |ML-KEM-768 (NIST FIPS 203)|
|Signatures          |ML-DSA-65 (NIST FIPS 204) |
|Symmetric Encryption|ChaCha20-Poly1305         |
|Hashing             |BLAKE3                    |
|Hybrid Fallback     |X25519 + AES-256-GCM      |
|P2P Networking      |libp2p                    |
|Bluetooth           |btleplug                  |
|Local Discovery     |mdns-sd                   |
|Storage             |sled (encrypted)          |
|Consensus           |Proof of Authority (PoA)  |

## Security Posture

This project follows security-first principles:

- ✅ OWASP Top 10 addressed
- ✅ NIST post-quantum standards (FIPS 203, 204)
- ✅ Hardened defaults applied
- ✅ No unsafe code without explicit audit

### Security Decisions

|Area           |Decision                                                                    |Rationale                              |
|---------------|----------------------------------------------------------------------------|---------------------------------------|
|Encryption     |ML-KEM-768 + ChaCha20-Poly1305                                              |Post-quantum secure, software-optimized|
|Signatures     |ML-DSA-65                                                                   |NIST standardized, quantum-resistant   |
|Key Storage    |Encrypted sled + Argon2id                                                   |Defense against local attacks          |
|MITM Prevention|5-layer defense (E2E, signatures, blockchain, identity hash, safety numbers)|Defense in depth                       |
|Key Lifecycle  |30-day expiry, rotation support                                             |Limits exposure window                 |
|Metadata       |Minimal envelope, sender hidden                                             |Privacy by design                      |
|Transport      |Network-first, BLE relay fallback                                           |Security from E2E, not transport       |
|Contact        |Require recipient hash                                                      |No spam, no discovery                  |
|Identity Limit |Max 3 per device, wait for expiry                                           |Sybil resistance without PoW           |
|Reputation     |Rate limits + graph analysis                                                |Anti-gaming protection                 |
|Validators     |PoS selection + 99% SLA + slashing                                          |Collusion resistance                   |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          VERITAS PROTOCOL                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                        PUBLIC API (veritas-core)                  │ │
│  │  • send_message()  • receive_messages()  • create_identity()     │ │
│  │  • link_username() • verify_proof()      • sync_offline()        │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                    │                                    │
│         ┌──────────────────────────┼──────────────────────────┐        │
│         ▼                          ▼                          ▼        │
│  ┌─────────────┐          ┌─────────────┐          ┌─────────────┐    │
│  │   veritas   │          │   veritas   │          │   veritas   │    │
│  │   -crypto   │          │   -chain    │          │    -net     │    │
│  ├─────────────┤          ├─────────────┤          ├─────────────┤    │
│  │ ML-KEM      │          │ Block store │          │ libp2p      │    │
│  │ ML-DSA      │          │ Merkle tree │          │ Bluetooth   │    │
│  │ X25519      │          │ Consensus   │          │ WiFi Direct │    │
│  │ ChaCha20    │          │ Sync proto  │          │ mDNS        │    │
│  │ BLAKE3      │          │ DID/Identity│          │ Store+Fwd   │    │
│  └─────────────┘          └─────────────┘          └─────────────┘    │
│         │                          │                          │        │
│         └──────────────────────────┼──────────────────────────┘        │
│                                    ▼                                    │
│  ┌───────────────────────────────────────────────────────────────────┐ │
│  │                      STORAGE (veritas-store)                      │ │
│  │  • Encrypted local database (sled + ChaCha20)                    │ │
│  │  • Message queue • Block cache • Identity keyring                │ │
│  └───────────────────────────────────────────────────────────────────┘ │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  BINDINGS                                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Rust API │  │  C FFI   │  │   WASM   │  │  PyO3    │              │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘              │
└─────────────────────────────────────────────────────────────────────────┘
```

## Crate Structure

```
veritas/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── veritas-crypto/           # Cryptographic primitives
│   ├── veritas-identity/         # DID and username system
│   ├── veritas-protocol/         # Wire protocol and messages
│   ├── veritas-chain/            # Blockchain layer
│   ├── veritas-net/              # P2P networking
│   ├── veritas-store/            # Local encrypted storage
│   ├── veritas-reputation/       # Reputation scoring
│   ├── veritas-core/             # High-level API
│   ├── veritas-ffi/              # C bindings
│   ├── veritas-wasm/             # WASM bindings
│   └── veritas-py/               # Python bindings
├── examples/
└── tests/
```

## Protocol Limits

|Parameter              |Value              |
|-----------------------|-------------------|
|Max message size       |300 characters     |
|Max chunks per message |3 (900 chars total)|
|Message TTL            |7 days             |
|Key expiry             |30 days inactive   |
|Max offline duration   |30 days            |
|Username length        |3-32 characters    |
|Username charset       |`[a-z0-9_]`        |
|Max group size         |100 members        |
|Max groups per identity|50                 |
|Group key rotation     |7 days             |

## Message Delivery

VERITAS uses a hybrid Gossip + DHT delivery model with **network-first** transport selection:

1. **Check Network** — Always attempt internet connectivity first
1. **DHT Storage** — Store encrypted message in distributed hash table
1. **Gossip** — Announce message availability to network
1. **Local Relay** — If no internet, use WiFi/mDNS to find connected peers
1. **Bluetooth Relay** — Last resort, find BLE peers to relay to network
1. **Queue Locally** — No connectivity, store for later transmission

### Transport Priority (Network First)

```
┌─────────────────────────────────────────────────┐
│ 1. Check Internet → Use libp2p/DHT              │
│         ↓ (offline)                             │
│ 2. Check Local WiFi → Relay via mDNS peer      │
│         ↓ (no peers)                            │
│ 3. Scan Bluetooth → Relay via BLE peer         │
│         ↓ (no peers)                            │
│ 4. Queue locally → Send when connected         │
└─────────────────────────────────────────────────┘
```

### Bluetooth as Pure Relay

- **No PIN verification** — BLE is transport only, not a security boundary
- **No pairing required** — Any VERITAS node can relay
- **Security via E2E encryption** — Content protected regardless of transport
- **Relay purpose** — Forward messages to network-connected nodes

### Contact Requirement

**You must know someone’s identity hash to contact them.** There is no user discovery mechanism. This is intentional:

- Prevents spam/unsolicited messages
- No directory to scrape
- Share your hash out-of-band (QR code, in person, etc.)
- Optional @username alias for easier sharing

## Privacy & Minimal Metadata

VERITAS is designed to leak **minimal identifiable metadata**:

### What Relay Nodes See

|Field        |Value            |Linkable?              |
|-------------|-----------------|-----------------------|
|Mailbox Key  |Derived pseudonym|❌ Rotates per epoch    |
|Ephemeral Key|Single-use       |❌ New per message      |
|Nonce        |Random           |❌ No information       |
|Payload Size |Fixed buckets    |❌ Padded (256/512/1024)|

### What’s Hidden (Inside Encrypted Payload)

- **Sender identity** — Only recipient knows who sent it
- **Timestamp** — Only recipient knows when it was sent
- **Content** — Only recipient can read it
- **Signature** — Only recipient can verify it

### Removed Metadata

- ~Sender ID on envelope~ — Hidden inside payload
- ~Timestamp on envelope~ — Hidden inside payload
- ~Delivery hints~ — Removed entirely
- ~True message size~ — Padded to fixed buckets

### Additional Protections

- **Timing jitter** — Random 0-3 second delay before sending
- **Epoch-based mailbox keys** — Unlinkable across time periods
- **Ephemeral key exchange** — No long-term key correlation

## Identity System

- **Identity Hash**: `BLAKE3(ML-DSA_public_key)` — 32-byte unique identifier
- **Username**: Optional `@username` alias, linkable to multiple identity hashes
- **Plug-and-Play**: Same username can point to different keys (key rotation friendly)
- **Decentralized**: No central authority, registered on VERITAS blockchain

### Key Lifecycle

|State   |Description                            |
|--------|---------------------------------------|
|ACTIVE  |Normal operation                       |
|EXPIRING|< 5 days until expiry warning          |
|EXPIRED |30 days inactive, receive-only         |
|ROTATED |Voluntarily replaced, points to new key|
|REVOKED |Manually invalidated (compromised)     |

## Blockchain

VERITAS includes a purpose-built blockchain for message proofs:

- **Consensus**: Proof of Authority (PoA) with rotating validators
- **Content**: Message hashes, delivery receipts, identity registrations (NOT message content)
- **Proofs**: Merkle tree proofs for efficient verification
- **Sync**: Offline nodes catch up via sync protocol

### What’s Stored On-Chain

- Message hash + sender + recipient + timestamp (proof of existence)
- Delivery receipt hashes (proof of delivery)
- Identity registrations and state changes
- Username claims and links
- Group metadata (encrypted)
- Reputation score updates

## Reputation System

Nodes earn reputation for good behavior:

|Action                        |Score Change   |
|------------------------------|---------------|
|Successfully relay message    |+10            |
|Store message for offline peer|+5             |
|Deliver stored message        |+15            |
|DHT participation (per hour)  |+1 (max 24/day)|
|Validate blockchain block     |+20            |
|Drop message without relay    |-20            |
|Invalid/spam messages         |-50            |
|Attempted replay attack       |-200 + ban     |

### Score Effects

|Score|Effect                              |
|-----|------------------------------------|
|800+ |Priority relay, DHT storage priority|
|500+ |Normal operation                    |
|200+ |Deprioritized delivery              |
|< 200|Quarantine                          |
|< 50 |Blacklisted                         |

### Anti-Gaming Measures

VERITAS implements comprehensive anti-gaming protections:

- **Rate Limiting**: 60s minimum between messages to same peer, 30 points/day max per peer, 100 points/day total max
- **Weighted Reports**: Reporter reputation affects impact (rep 500 = 1.0 weight)
- **Report Threshold**: 3 independent reports required before negative action
- **Graph Analysis**: Detect collusion clusters via interaction patterns
- **Cluster Penalties**: Suspicious clusters receive reduced score gains

## Validator System (PoS + SLA)

VERITAS uses Proof-of-Stake style validator selection with strict SLA requirements:

### Becoming a Validator

|Requirement           |Value               |
|----------------------|--------------------|
|Minimum stake         |700 reputation      |
|Stake lock period     |14 epochs (~2 weeks)|
|Cooldown after leaving|7 epochs            |
|Geographic diversity  |Max 5 per region    |

### SLA Requirements

|Metric          |Requirement                    |
|----------------|-------------------------------|
|Uptime          |99% minimum                    |
|Missed blocks   |Max 3 per epoch                |
|Response latency|< 5 seconds                    |
|Block production|Min 10 per epoch when scheduled|

### Validator Selection

- **Stake-weighted random**: Higher reputation = higher selection chance
- **Performance multiplier**: Good performers get 1.5x weight
- **SLA bonus**: Compliant validators get up to 50% bonus
- **Rotation**: 15% (~3 validators) rotate per epoch
- **Worst performers removed first**

### Slashing

|Offense       |Penalty                   |
|--------------|--------------------------|
|Missed block  |0.1% stake per block      |
|SLA violation |1% stake                  |
|Invalid block |5% stake                  |
|Double signing|100% stake + permanent ban|

## Identity Limits

To prevent Sybil attacks, VERITAS limits identity creation:

### Per-Device Limits

|Parameter     |Value                |
|--------------|---------------------|
|Max identities|3 per device         |
|Key expiry    |30 days inactive     |
|Grace period  |24 hours after expiry|
|Slot release  |After grace period   |

### Identity Lifecycle

```
Create → Active (30 days) → Expiring (5 day warning) → Expired → Released
                                                           ↓
                                                    24h grace period
                                                           ↓
                                                    Slot available
```

### Slot Recycling

When at the 3-identity limit:

1. Wait for an existing identity to expire (30 days of inactivity)
1. Wait for 24-hour grace period
1. Slot becomes available for new identity

No proof-of-work required — the time-based limit provides sufficient Sybil resistance.

## API Overview

```rust
use veritas_core::VeritasClient;

// Create identity
let client = VeritasClient::create_identity().await?;

// Set username
client.set_username("alice").await?;

// Send message
let hash = client.send_message(&bob_id, "Hello, Bob!").await?;

// Receive messages
let messages = client.receive_messages().await?;
for msg in messages {
    let content = client.decrypt_message(&msg)?;
    println!("From {}: {}", msg.sender, content.text);
    
    // Send receipt
    client.send_receipt(&msg, ReceiptType::Received).await?;
}

// Verify message proof on blockchain
let proof = client.verify_message_proof(&msg).await?;
println!("Message anchored at block {}", proof.block_height);

// Create group
let group = client.create_group(&[bob_id, carol_id], settings).await?;
client.send_group_message(&group, "Hello everyone!").await?;
```

## Development Setup

```bash
# Clone repository
git clone https://github.com/[user]/veritas.git
cd veritas

# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all crates
cargo build --release

# Run tests
cargo test --all

# Run clippy
cargo clippy --all-targets --all-features

# Build WASM
cd crates/veritas-wasm
wasm-pack build --target web

# Build Python bindings
cd crates/veritas-py
maturin develop
```

## Security Checklist for Implementation

### Before First Commit

- [ ] No secrets in code
- [ ] .env files in .gitignore
- [ ] Unsafe code denied by default

### Before Each PR

- [ ] `cargo clippy` passes with no warnings
- [ ] `cargo test` passes
- [ ] `cargo audit` shows no vulnerabilities
- [ ] Security review for crypto changes

### Before Release

- [ ] Full security audit of crypto layer
- [ ] Fuzz testing on all input parsing
- [ ] Dependency audit
- [ ] OWASP checklist review

## Threat Model

### Assets Protected

- Message content (confidentiality)
- Message integrity (tampering detection)
- Sender authenticity (no spoofing)
- Delivery proof (non-repudiation)
- User identity (privacy)

### Adversaries Considered

- Passive eavesdropper (network sniffer)
- Active attacker (MITM)
- Malicious relay node
- Compromised storage node
- Future quantum computer

### Out of Scope (Flagged for Future)

- Traffic analysis / metadata leakage
- Bluetooth pairing MITM
- Nation-state level attacks
- Side-channel attacks on endpoints

## Contributing

This project uses a strict branch-per-task workflow:

1. **Every task gets its own branch** — `{type}/{id}-{description}`
1. **Every branch gets a PR** — No direct commits to main
1. **Every PR requires approval** — Maintainer reviews and merges
1. **VERSION_HISTORY.md updated** — In every PR

### Branch Types

- `feat/` — New features
- `fix/` — Bug fixes
- `security/` — Security enhancements
- `refactor/` — Code restructuring
- `docs/` — Documentation
- `chore/` — Maintenance

## License

MIT OR Apache-2.0

## Acknowledgments

- NIST for post-quantum cryptography standards (FIPS 203, 204)
- The RustCrypto team for excellent crypto libraries
- libp2p team for the P2P networking stack
- Signal Protocol for inspiration on secure messaging patterns