# VERITAS Protocol

[![Version](https://img.shields.io/badge/version-0.4.0--beta-blue)]()
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
veritas-protocol/
├── Cargo.toml                    # Workspace root
├── crates/
│   ├── veritas-crypto/           # Cryptographic primitives (ML-KEM, ML-DSA, X25519, ChaCha20)
│   ├── veritas-identity/         # DID and username system
│   ├── veritas-protocol/         # Wire protocol v2 and messages
│   ├── veritas-chain/            # Blockchain layer (transactions, epochs, light validators)
│   ├── veritas-net/              # P2P networking (libp2p, gossip, DHT)
│   ├── veritas-store/            # Local encrypted storage (sled)
│   ├── veritas-reputation/       # Reputation scoring and collusion detection
│   ├── veritas-core/             # High-level API
│   ├── veritas-ffi/              # C bindings (cbindgen)
│   ├── veritas-wasm/             # WASM bindings (wasm-pack)
│   ├── veritas-py/               # Python bindings (PyO3)
│   └── veritas-node/             # Standalone node daemon
├── examples/
│   ├── cli-chat/                 # CLI chat example
│   └── web-demo/                 # Browser WASM demo
└── fuzz/                         # Fuzzing targets (8 harnesses)
```

## Protocol Limits

|Parameter              |Value                |
|-----------------------|---------------------|
|Max message size       |300 characters       |
|Max chunks per message |3 (900 chars total)  |
|Max envelope size      |8,192 bytes          |
|Message TTL            |7 days               |
|Epoch duration         |30 days              |
|Key expiry             |30 days inactive     |
|Username length        |3-32 characters      |
|Username charset       |`[a-z0-9_]`          |
|Padding buckets        |1024/2048/4096/8192  |
|Max group size         |100 members          |
|Max groups per identity|50                   |
|Group key rotation     |7 days               |
|ML-DSA-65 public key   |1,952 bytes          |
|ML-DSA-65 signature    |3,309 bytes          |
|Starting reputation    |100                  |

## Message Delivery

VERITAS uses a **chain-as-transport** model — every encrypted message is submitted as a transaction on the VERITAS blockchain. The chain provides ordering, integrity, delivery guarantees, and proof of communication.

### Message Flow

1. **Submit to Trusted Validator** — Client submits message transaction to a trusted validator via internet
2. **Fallback Validators** — If primary validators are unavailable, try trusted peers (3-line trust fallback)
3. **Bluetooth Relay** — Last resort (future, v2.0): BLE mesh hops until a device with internet submits to a validator
4. **Queue Locally** — No connectivity: queue locally, warn user to review validator list

### Transport Priority

```
┌─────────────────────────────────────────────────────┐
│ 1. Trusted Validator → Submit transaction via TCP   │
│         ↓ (unreachable)                             │
│ 2. Fallback Validators → 3-line trust chain         │
│         ↓ (all unreachable)                         │
│ 3. Bluetooth Relay → BLE mesh to chain (future)     │
│         ↓ (no peers)                                │
│ 4. Queue locally → Send when connected              │
└─────────────────────────────────────────────────────┘
```

### Epoch-Based Pruning (30-Day Retention)

Messages live on-chain for one epoch (30 days). After the epoch ends, message bodies and signatures are pruned — only headers remain permanently, verifiable via Merkle proofs against signed block headers. This is a deliberate privacy feature.

### Bluetooth as Pure Relay (Future — v2.0)

- **No PIN verification** — BLE is transport only, not a security boundary
- **No pairing required** — Any VERITAS node can relay
- **Security via E2E encryption** — Content protected regardless of transport
- **Relay purpose** — Get messages back onto the chain, not offline chat

### Contact Requirement

**You must know someone's identity hash to contact them.** There is no user discovery mechanism. This is intentional:

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
|Payload Size |Fixed buckets    |❌ Padded (1024/2048/4096/8192)|

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

VERITAS uses a purpose-built blockchain as the **message transport layer** — every encrypted message is a transaction:

- **Consensus**: Proof of Authority (PoA) with rotating validators
- **Content**: Encrypted message transactions, identity registrations, key rotations, reputation changes
- **Proofs**: Merkle tree proofs for efficient verification
- **Sync**: Header-only sync for light validators, full sync for validators
- **Epoch Pruning**: After 30 days, message bodies + signatures are pruned; headers remain permanently

### What's Stored On-Chain

- **Message transactions**: Encrypted body + ML-DSA signature + header (body/sig pruned after epoch)
- **Permanent headers**: Mailbox key, timestamp bucket, body hash, block height
- Identity registrations and state changes
- Username claims and links
- Key rotations and revocations
- Reputation score updates
- Image transfer proofs (hash + delivery receipt, not the image itself)

### Two Validator Tiers

| Tier | Stores | Purpose |
|------|--------|---------|
| **Full Validator** | Complete blocks (headers + bodies + signatures) | Consensus, block production |
| **Light Validator** | Headers + signatures only (256MB RAM target) | Transaction validation during epoch |

## Reputation System

Nodes earn reputation for good behavior. **Starting score is 100** (Tier 1 / Basic).

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

### Asymmetric Decay

- **Above 500**: Decays toward 500 (baseline)
- **Below 500**: Decays toward 0 (bad actors lose reputation permanently)

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
|Minimum reputation    |700 reputation      |
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
git clone https://github.com/gl-tches/veritas-protocol.git
cd veritas-protocol

# Install Rust (if needed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build all crates
cargo build --release

# Run tests (requires 16MB stack for ML-DSA operations)
RUST_MIN_STACK=16777216 cargo test --all

# Run clippy
cargo clippy --all-targets --all-features

# Build WASM
cd crates/veritas-wasm
wasm-pack build --target web

# Build Python bindings
cd crates/veritas-py
maturin develop
```

**Note**: ML-DSA-65 signing operations require a 16MB minimum stack size. Set `RUST_MIN_STACK=16777216` when running tests or the node binary.

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