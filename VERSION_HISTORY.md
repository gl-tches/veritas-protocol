# VERITAS Version History

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-beta.1] - 2026

### Added

- **Task 035**: Client Interface
  - `VeritasClient` struct - Main entry point for VERITAS protocol
  - `ClientState` enum (Created, Locked, Unlocked, ShuttingDown)
  - `ClientConfig` with comprehensive configuration options:
    - `StorageConfig` - data directory, in-memory mode, encryption
    - `NetworkConfig` - transports, bootstrap peers, timeouts
    - `ReputationConfig` - reputation tracking settings
    - `FeatureConfig` - timing jitter, receipts, queue limits
  - `ClientConfigBuilder` for fluent configuration
  - Lifecycle methods: `new()`, `unlock()`, `lock()`, `shutdown()`
  - Identity management: `identity_hash()`, `public_keys()`, `create_identity()`, `list_identities()`, `set_primary_identity()`
  - Identity slot tracking: `identity_slots()` with max 3 identities per device

- **Task 036**: Messaging API
  - `MessageHash` type alias for message tracking
  - `ReceivedMessage` struct with:
    - Message metadata (id, hash, sender, timestamp)
    - Content access (`text()`, `is_receipt()`, `receipt()`)
    - Verification status (`signature_verified`, `sender_public_keys`)
  - `MessageStatus` enum (Pending, Sending, Sent, Delivered, Read, Failed)
  - `SendOptions` for configuring message delivery:
    - Receipt requests
    - Reply threading
    - Timing jitter control

- **Task 037**: Group API
  - `GroupInfo` struct for group metadata
  - `GroupMessage` struct for group messages
  - Re-exports of `GroupId` and `GroupRole` from veritas-protocol

- **Task 038**: Verification API
  - `MessageProof` struct for blockchain verification:
    - Merkle proof
    - Block height and hash
    - Chain entry
    - `verify_inclusion()` method
  - `SyncStatus` struct for chain sync status:
    - Local and network heights
    - Pending headers/blocks counts
    - Progress percentage
    - `is_synced()`, `blocks_behind()`, `has_pending_work()` methods

- **Task 039**: Safety Numbers
  - `SafetyNumber` struct for identity verification
  - Domain-separated BLAKE3 hashing (`VERITAS-SAFETY-NUMBER-v1`)
  - Symmetric computation (A,B == B,A)
  - Display formats:
    - `to_numeric_string()` - 60 digits in 12 groups of 5
    - `to_qr_string()` - 64-character hex string
  - `Display` and `Debug` trait implementations

- **Internal Services Architecture**
  - `IdentityManager` for identity/keyring coordination
  - `MessageService` placeholder for message handling
  - `ChainService` placeholder for blockchain operations
  - `ReputationService` placeholder for reputation tracking
  - `PersistentIdentityManager` for full encrypted keyring support

### Security

- Safety numbers use domain-separated hashing to prevent cross-protocol attacks
- Keys are sorted consistently for symmetric safety number computation
- All sensitive data implements `Zeroize` and `ZeroizeOnDrop`
- Password handling does not leak information in error messages
- Debug implementations redact all sensitive data
- Services are zeroized when client is locked
- State machine enforces valid operation sequences

### Testing

- 55 integration tests covering:
  - Client lifecycle (13 tests)
  - Identity management (11 tests)
  - Safety numbers (14 tests)
  - Configuration (17 tests)
- Security review: All checks PASS
- Doc tests for public API examples

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-core | 0.1.0-beta.1 | Core API complete |

## [0.1.0-alpha.7] - 2026

### Added

- **Task 028**: Network-First Transport Selection
  - `TransportType` enum (Internet, LocalNetwork, Bluetooth, Queued)
  - `TransportState` for tracking transport availability
  - `TransportStatus` for connection status
  - `TransportCapabilities` describing transport features
  - `Transport` trait with async connectivity methods
  - `TransportSelector` implementing network-first priority:
    1. Internet first (always try direct connectivity)
    2. Local WiFi relay (mDNS-discovered peers)
    3. Bluetooth relay (BLE peers)
    4. Queue locally (store for later)
  - `PeerInfo` for peer tracking with addresses
  - `NetworkAddress` multiaddr wrapper

- **Task 029**: libp2p Integration
  - `NodeConfig` for configuring libp2p node
  - `VeritasNode` wrapping libp2p Swarm with:
    - Noise protocol encryption
    - Kademlia DHT (`/veritas/kad/1.0.0`)
    - Gossipsub pub/sub
    - mDNS local discovery
    - Identify protocol
  - `NodeBehaviour` combining all libp2p behaviours
  - `NodeEvent` enum for external event handling
  - Event loop with channel-based emission
  - Bootstrap peer support
  - Topic subscription management

- **Task 030**: DHT Storage
  - `DhtConfig` with replication, TTL, and query settings
  - `DhtKey` for DHT record keys derived from mailbox keys
  - `DhtRecord` for serialized message storage
  - `DhtRecordSet` for multiple messages per mailbox
  - `DhtStorage` providing:
    - `store_message()` - store envelope by mailbox key
    - `get_messages()` - retrieve messages for mailbox
    - `delete_message()` - remove specific message
    - `has_messages()` - check mailbox status
  - TTL enforcement (7 days per MESSAGE_TTL)
  - Message ID computation from envelope hash

- **Task 031**: Gossip Protocol
  - `GossipConfig` with mesh parameters (heartbeat, size, history)
  - `GossipManager` managing pub/sub messaging
  - Topic constants:
    - `TOPIC_MESSAGES` ("veritas/messages/v1")
    - `TOPIC_BLOCKS` ("veritas/blocks/v1")
    - `TOPIC_RECEIPTS` ("veritas/receipts/v1")
  - `MessageAnnouncement` (privacy-preserving):
    - Uses mailbox key, NOT recipient identity
    - Hourly timestamp buckets to hide exact times
    - Size buckets (256/512/1024) to hide true size
  - `BlockAnnouncement` for new block notifications
  - `ReceiptAnnouncement` for delivery receipts
  - `GossipAnnouncement` enum combining all types

- **Task 032**: Local Discovery (mDNS)
  - `DiscoveryConfig` with TTL and query settings
  - `LocalDiscovery` wrapping mDNS behaviour
  - `DiscoveredPeer` tracking:
    - Peer ID and addresses
    - Discovery and last seen timestamps
  - `DiscoveryEvent` enum (PeerDiscovered, PeerExpired)
  - Automatic peer pruning for stale entries
  - Service name: `_veritas._tcp.local`

- **Task 033**: Bluetooth Relay (Placeholder)
  - `BluetoothConfig` with service UUID, MTU, scan interval
  - `BlePeer` for discovered BLE devices
  - `BluetoothRelay` (placeholder implementation):
    - All methods return `Err(Transport("Bluetooth not implemented"))`
    - API designed for future btleplug integration
  - `BluetoothStats` for relay statistics
  - **CRITICAL**: NO PIN verification, NO pairing required
    - Security from E2E encryption, not transport
    - BLE is pure relay layer

- **Task 034**: Store-and-Forward
  - `RelayConfig` with hop limit, TTL, capacity settings
  - `RelayedMessage` tracking:
    - Envelope data
    - Hop count (max 3 hops)
    - Received timestamp
    - Forward attempts
  - `RelayManager` providing:
    - `store_for_relay()` - hold message for offline peer
    - `get_pending()` - retrieve pending messages
    - `mark_delivered()` - remove delivered message
    - `should_forward()` - check if still valid
    - `increment_hop()` - track forwarding
    - `prune_expired()` - clean old messages
  - `RelayStats` for monitoring
  - Traffic analysis resistance via jitter delay

### Security

- Network-first transport selection prioritizes direct connectivity
- Bluetooth relay requires NO PIN/pairing (security from E2E encryption)
- Mailbox keys derived from recipient + epoch + salt (unlinkable)
- Message announcements use hourly time buckets (temporal privacy)
- Message sizes use fixed padding buckets (traffic analysis resistance)
- Hop limit (3) prevents infinite relay loops
- Message TTL (7 days) prevents indefinite storage

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-net | 0.1.0-alpha.7 | Networking layer complete |

## [0.1.0-alpha.6] - 2026

### Added

- **Task 025**: Reputation Scoring with Rate Limiting
  - `ReputationScore` struct tracking score, gains, losses, timestamps
  - Score range 0-1000 with starting score 500
  - `gain()` and `lose()` methods with capping/flooring
  - `gain_with_multiplier()` for collusion penalty application
  - Status checks: `is_quarantined()`, `is_blacklisted()`, `is_priority()`
  - Permission checks: `can_file_reports()`, `can_be_validator()`
  - `ScoreRateLimiter` with per-peer and total daily limits:
    - 60 seconds minimum between interactions with same peer
    - 30 points maximum gain from any peer per day
    - 100 points maximum total gain per day
  - `PeerInteraction` tracking with automatic daily reset
  - `RateLimitResult` enum for detailed limit feedback
  - 25 unit tests

- **Task 026**: Weighted Negative Reports
  - `ReportReason` enum (Spam, Harassment, Impersonation, Malware, Scam, Other)
  - `NegativeReport` struct with reporter reputation tracking
  - Report weighting formula: `weight = reporter_reputation / 500.0`
  - `ReportAggregator` for collecting and processing reports:
    - Minimum 400 reputation required to file reports
    - Weighted threshold of 3.0 required for penalty
    - Penalty based on most severe reason reported
    - Penalty capped at 200 points per incident
  - Duplicate reporter detection
  - Report cleanup for old reports (30 days)
  - 14 unit tests

- **Task 027**: Collusion Detection
  - `InteractionRecord` tracking interactions between identities
  - `CollusionDetector` with interaction graph analysis:
    - Connected component detection for cluster identification
    - Internal density calculation (edges within cluster)
    - Symmetry scoring (A→B vs B→A balance)
    - External connection ratio tracking
  - `SuspiciousCluster` with suspicion scoring:
    - Flagged when internal density > 70%
    - Flagged when external connections < 30%
    - Flagged when symmetry > 80%
  - `ClusterMember` with per-member suspicion contribution
  - Gain multiplier: `1.0 - suspicion_score` (e.g., 0.8 suspicion = 20% gains)
  - Minimum cluster size of 3 for analysis
  - 8 unit tests

- **Task 027b**: Reputation Decay and Effects
  - `DecayConfig` with configurable decay rate and interval
  - Default: 1% weekly decay toward 500 (baseline)
  - `DecayState` for tracking decay timing per identity
  - `apply_decay()` function with period-based calculation
  - `project_decay()` for decay forecasting
  - `ReputationTier` enum (Blacklisted, Quarantined, Deprioritized, Normal, Priority)
  - `TierEffects` struct with tier-specific restrictions:
    - Messaging permissions
    - Report filing rights (requires 400+ rep)
    - Validator eligibility (requires 700+ rep)
    - Message priority modifiers (-2 to +2)
    - Rate limit multipliers (0.25x to 2.0x)
  - `ReputationManager` coordinating all operations:
    - Score tracking across all identities
    - Rate limiting enforcement
    - Report processing and penalty application
    - Collusion detection integration
    - Decay application
    - Statistics tracking
  - `ReputationStats` for system monitoring
  - 27 unit tests

### Security

- Rate limiting prevents reputation gaming and Sybil attacks
- Reporter reputation weighting reduces low-quality report spam
- Collusion detection via graph analysis flags suspicious clusters
- Gain penalties applied to colluding identities
- Minimum reputation thresholds for privileged actions
- Tier-based access control prevents abuse by low-reputation identities

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-reputation | 0.1.0-alpha.6 | Reputation system complete |

## [0.1.0-alpha.5] - 2026

### Added

- **Task 020**: Block Structure
  - `Block` struct with header and body separation
  - `BlockHeader` with hash, parent_hash, height, timestamp, merkle_root, validator
  - `BlockBody` containing chain entries with merkle root computation
  - `ChainEntry` enum supporting all on-chain entry types:
    - `IdentityRegistration` - identity hash, public keys, timestamp, signature
    - `UsernameRegistration` - username, identity hash, signature
    - `KeyRotation` - old identity, new identity, signatures
    - `MessageProof` - message hash, sender, recipient, timestamp, merkle proof
    - `ReputationChange` - identity hash, change amount, reason, proof
    - `ValidatorRegistration` / `ValidatorExit` / `ValidatorSlash`
  - Genesis block support with `Block::genesis()`
  - Domain-separated hashing (`VERITAS-BLOCK-v1`, `VERITAS-CHAIN-ENTRY-v1`)
  - 32 unit tests

- **Task 021**: Merkle Tree
  - `MerkleTree` struct for tree construction from hash leaves
  - `MerkleProof` for inclusion proofs with sibling hashes and directions
  - `Direction` enum (Left, Right) for proof traversal
  - Domain-separated internal node hashing (`VERITAS-MERKLE-v1`)
  - Handles edge cases: empty, single leaf, power-of-2, non-power-of-2
  - Standalone `verify_proof()` function for efficient verification
  - 29 unit tests including property-based tests

- **Task 022**: Chain Management
  - `Blockchain` struct for full chain storage and management
  - `BlockValidation` with comprehensive validation rules:
    - Height continuity (parent height + 1)
    - Parent hash verification
    - Timestamp ordering (>= parent timestamp)
    - Hash integrity verification
    - Merkle root validation
    - Block producer authorization
  - `ForkChoice` for fork tracking with longest chain rule
  - Deterministic tiebreaker for same-height forks
  - Common ancestor detection for fork analysis
  - Chain iteration (forward and backward from tip/genesis)
  - `ChainState` for persistence/serialization
  - 33 unit tests

- **Task 023**: PoS Validator Selection with SLA
  - `ValidatorStake` struct with performance and SLA tracking
  - `ValidatorSla` requirements (99% uptime, max 3 missed blocks, 5s latency)
  - `ValidatorSet` for managing active validators (max 21)
  - `ValidatorSelection` with deterministic stake-weighted selection:
    - ChaCha20Rng seeded from epoch for determinism
    - Weight formula: `stake * performance_multiplier * sla_bonus`
    - Performance multiplier: 0.5 + (score / 100.0) → 0.5-1.5x
    - SLA bonus: compliant + streak → up to 1.5x; non-compliant → 0.7x
  - Geographic diversity enforcement (max 5 per region)
  - 15% rotation per epoch (worst performers first)
  - Domain-separated selection (`VERITAS-VALIDATOR-SELECTION-v1`)
  - 51 unit tests

- **Task 023b**: Validator Slashing and Penalties
  - `SlashingConfig` with CLAUDE.md-specified percentages:
    - Missed block: 0.1%
    - SLA violation: 1%
    - Invalid block: 5%
    - Double sign: 100% + permanent ban
  - `SlashingOffense` enum for all offense types
  - `SlaViolationType` for SLA violation details
  - `SlashResult` with penalty amount, remaining stake, ban status
  - `SlashingManager` with:
    - `process_offense()` - process and record slashing events
    - `record_block_signature()` - double-sign detection
    - Automatic 100% slash and permanent ban for double-signing
    - Signature pruning for memory management
  - 24 unit tests

- **Task 024**: Chain Sync
  - `SyncMessage` enum for sync protocol:
    - `GetHeaders` / `Headers` - header synchronization
    - `GetBlocks` / `Blocks` - full block synchronization
    - `NewBlock` - new block announcements
    - `GetTip` / `Tip` - chain tip queries
    - `Status` - peer status reporting
  - `SyncState` enum (Synced, SyncingHeaders, SyncingBlocks, Paused)
  - `SyncAction` for sync manager responses
  - `SyncManager` with:
    - Configurable max headers (500) and blocks (100) per request
    - Request timeout tracking (30s default)
    - Progress reporting
    - Pause/resume support
  - `PendingRequest` for tracking in-flight requests
  - 39 unit tests

### Security

- Domain separation applied consistently to all hashing operations
- Constant-time hash comparisons via `Hash256` (uses `subtle::ConstantTimeEq`)
- Input validation at all module boundaries
- Saturating arithmetic prevents overflow/underflow
- Double-sign detection with immediate 100% slash and permanent ban
- Deterministic validator selection prevents gaming
- Fork handling with longest chain rule and deterministic tiebreaker

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-chain | 0.1.0-alpha.5 | Blockchain layer complete |

## [0.1.0-alpha.4] - 2026

### Added

- **Task 017**: Encrypted Database
  - `EncryptedDb` struct wrapping sled with transparent encryption
  - `DbKey` with Argon2id key derivation (64 MiB, 3 iterations, 4 parallelism)
  - XChaCha20-Poly1305 encryption for all stored values
  - Salt stored in database `__meta__` tree, reused on reopen
  - `EncryptedTree` for namespaced/isolated storage within database
  - put/get/delete/contains/iter operations with automatic encrypt/decrypt
  - Zeroize on DbKey drop
  - 27 unit tests

- **Task 018**: Message Queue
  - `MessageQueue` with separate outbox and inbox sled trees
  - `MessageId` 32-byte cryptographically random identifier
  - `QueuedMessage` for outbox with full status tracking
  - `InboxMessage` for received messages with read status
  - `MessageStatus` enum (Pending, Sending, Sent, Delivered, Failed, Read)
  - Exponential backoff retry: 30s, 60s, 120s, 240s, 480s (max 5 retries)
  - Automatic expiry cleanup (7-day MESSAGE_TTL)
  - Pagination support for inbox retrieval
  - `OutboxStats` and `InboxStats` for queue monitoring
  - 32 unit tests

- **Task 019**: Identity Keyring
  - `Keyring` with password-protected identity storage
  - `KeyringEntry` with encrypted keypair, label, timestamps, primary flag
  - Argon2id password key derivation with BLAKE3 domain separation
  - Password verification using constant-time comparison (subtle)
  - Primary identity selection and management
  - `ExportedIdentity` for portable backup and cross-device transfer
  - Export/import with separate export password (different from keyring password)
  - Password change with atomic re-encryption of all entries
  - Secrets redacted in all Debug implementations
  - `KeyringMetadata` with version tracking for future migrations
  - 24 unit tests

### Security

- Argon2id with hardened parameters for all password key derivation
- All secrets implement Zeroize and ZeroizeOnDrop
- Password verification uses constant-time comparison via `subtle`
- No passwords stored - only derived keys and verification hashes
- BLAKE3 domain separation for password key vs export key derivation
- Salt generation using OsRng for cryptographic randomness
- Debug output redacts all sensitive data
- Invalid password returns generic error (no information leakage)

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-store | 0.1.0-alpha.4 | Storage layer complete |

## [0.1.0-alpha.3] - 2025

### Added

- **Task 011**: Minimal Metadata Envelope
  - `MinimalEnvelope` struct hiding all metadata from relays
  - `InnerPayload` with sender_id, timestamp, signature encrypted inside
  - Mailbox key derivation (recipient + epoch + salt) for unlinkability
  - Ephemeral X25519 key generation per message (forward secrecy)
  - Padding to fixed size buckets (256/512/1024 bytes)
  - Timing jitter (0-3 sec random delay) using OsRng
  - `MinimalEnvelopeBuilder` for fluent construction
  - 16 unit tests

- **Task 012**: Message Encryption
  - `encrypt_for_recipient()` - Full E2E encryption pipeline
  - `decrypt_as_recipient()` - Full decryption pipeline
  - Ephemeral X25519 ECDH key exchange (forward secrecy)
  - XChaCha20-Poly1305 AEAD encryption
  - `DecryptionContext` for caching recipient keypair
  - `EncryptedMessage` with serialization support
  - `decrypt_and_verify()` with sender verification
  - 18 unit tests

- **Task 013**: Message Signing (Placeholder)
  - `MessageSignature` struct with version tracking
  - `SignatureVersion` enum (HmacBlake3 placeholder, MlDsa future)
  - `SigningData` with domain-separated hash and Zeroize
  - `sign_message()` placeholder until ML-DSA available
  - `verify_signature()` with constant-time comparison
  - 23 unit tests
  - **Note**: Placeholder HMAC-BLAKE3 scheme until ML-DSA stabilizes

- **Task 014**: Message Chunking
  - `ChunkInfo` struct (chunk_index, total_chunks, message_hash)
  - `MessageChunk` with integrity verification
  - `split_into_chunks()` - Split by character count (max 3 chunks × 300 chars)
  - `ChunkReassembler` with pending message tracking
  - Out-of-order chunk handling and duplicate detection
  - Hash verification after reassembly
  - Expiry cleanup for pending chunks
  - 24 unit tests

- **Task 015**: Delivery Receipts
  - `DeliveryReceipt` struct with signature
  - `ReceiptType` enum (Delivered, Read, Error)
  - `DeliveryError` enum (RecipientNotFound, MessageExpired, Rejected, QuotaExceeded, Other)
  - `DeliveryReceiptData` for embedding in MessageContent
  - Receipt hash computation with domain separation
  - Factory methods: `delivered()`, `read()`, `error()`
  - 26 unit tests

- **Task 016**: Group Messages
  - `GroupId` 32-byte random identifier
  - `GroupRole` enum (Admin, Moderator, Member) with permissions
  - `GroupMember` struct
  - `GroupMetadata` with member management and limits
  - `GroupKey` with Zeroize (symmetric key + generation)
  - `GroupKeyManager` for ECDH-based key distribution
  - `EncryptedGroupKey` per-member encrypted keys
  - `GroupMessageData` for encrypted group messages
  - `KeyRotationManager` (scheduled, manual, compromise triggers)
  - Forward secrecy on member removal
  - MAX_GROUP_SIZE=100, rotation every 7 days
  - 43 unit tests

### Security

- All cryptographic operations use OsRng for randomness
- Secret data (GroupKey, SymmetricKey) implements Zeroize and ZeroizeOnDrop
- Constant-time comparisons for signatures and hashes
- Domain separation in all hashing operations
- Debug output redacts sensitive data
- Metadata protection: sender/timestamp hidden inside encrypted payload
- Mailbox keys derived (not raw recipient ID) for unlinkability
- Message padding to fixed buckets for traffic analysis resistance

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-protocol | 0.1.0-alpha.3 | Protocol layer complete |

## [0.1.0-alpha.2] - 2024

### Added

- **Task 007**: Identity Hash Generation
  - `IdentityHash` type derived from public key using BLAKE3
  - Domain separation (`VERITAS-IDENTITY-HASH-v1`)
  - Constant-time comparison via `subtle`
  - Hex encoding/decoding and Display formatting
  - 23 unit tests + property tests

- **Task 008**: Identity Keypair
  - `IdentityKeyPair` with X25519 keys (ML-DSA placeholder)
  - `IdentityPublicKeys` for shareable public keys
  - Encrypted serialization for secure storage
  - Key exchange and encryption key derivation
  - `Zeroize` on all private keys
  - 16 unit tests

- **Task 009**: Username System
  - `Username` type with validation (3-32 chars, alphanumeric + _-)
  - `UsernameRegistration` linking username to identity
  - Signature-based registration verification
  - Case-insensitive comparison
  - 23 unit tests + property tests

- **Task 010**: Key Lifecycle and Identity Limits
  - `KeyState` enum (Active, Expiring, Expired, Rotated, Revoked)
  - `KeyLifecycle` with 30-day expiry, 5-day warning, 24-hour grace
  - `OriginFingerprint` for privacy-preserving device binding
  - `IdentityLimiter` enforcing max 3 identities per origin
  - `IdentitySlotInfo` for user-facing slot status
  - Slot recycling and rotation support
  - 53 unit tests (36 lifecycle + 17 limits)

### Crates Updated

| Crate | Version | Status |
|-------|---------|--------|
| veritas-identity | 0.1.0-alpha.2 | Identity system complete |

## [0.1.0-alpha.1] - 2024

### Added

- **Task 001**: Project scaffolding
  - Created workspace with 11 crates
  - Set up workspace dependencies
  - Added MIT + Apache-2.0 licenses
  - Created error types for all crates
  - Added protocol limits module

- **Task 002**: BLAKE3 hashing primitives
  - `Hash256` type with 32-byte output
  - Single input hashing
  - Multi-input hashing with domain separation
  - Keyed hashing (MAC)
  - Key derivation
  - Hex encoding/decoding
  - Constant-time comparison via `subtle`
  - `Zeroize` support
  - Unit tests

- **Task 003**: ChaCha20-Poly1305 symmetric encryption
  - `SymmetricKey` type with Zeroize
  - XChaCha20-Poly1305 AEAD encryption/decryption
  - 192-bit random nonce generation
  - Additional authenticated data (AAD) support
  - `EncryptedData` serialization
  - 15 unit tests

- **Task 004**: ML-KEM key encapsulation (PLACEHOLDER)
  - API design for `MlKemKeyPair`, `MlKemPublicKey`, `MlKemPrivateKey`
  - `encapsulate()` and `decapsulate()` function signatures
  - Waiting for ml-kem crate to stabilize (currently 0.3.0-pre.5)
  - Size constants defined (PUBLIC_KEY_SIZE, CIPHERTEXT_SIZE, etc.)

- **Task 005**: ML-DSA digital signatures (PLACEHOLDER)
  - API design for `MlDsaKeyPair`, `MlDsaPublicKey`, `MlDsaPrivateKey`
  - `sign()` and `verify()` method signatures
  - Waiting for ml-dsa crate to stabilize (currently 0.1.0-rc.4)
  - Size constants defined (PUBLIC_KEY_SIZE, SIGNATURE_SIZE, etc.)

- **Task 006**: X25519 key exchange
  - `X25519StaticPrivateKey` for long-term keys
  - `X25519EphemeralKeyPair` for per-message keys
  - `X25519PublicKey` with serialization
  - `SharedSecret` with Zeroize and key derivation
  - Diffie-Hellman key agreement
  - 12 unit tests

### Crates

| Crate | Version | Status |
|-------|---------|--------|
| veritas-crypto | 0.1.0-alpha.1 | Scaffolded |
| veritas-identity | 0.1.0-alpha.1 | Scaffolded |
| veritas-protocol | 0.1.0-alpha.1 | Scaffolded |
| veritas-chain | 0.1.0-alpha.1 | Scaffolded |
| veritas-net | 0.1.0-alpha.1 | Scaffolded |
| veritas-store | 0.1.0-alpha.1 | Scaffolded |
| veritas-reputation | 0.1.0-alpha.1 | Scaffolded |
| veritas-core | 0.1.0-alpha.1 | Scaffolded |
| veritas-ffi | 0.1.0-alpha.1 | Scaffolded |
| veritas-wasm | 0.1.0-alpha.1 | Scaffolded |
| veritas-py | 0.1.0-alpha.1 | Scaffolded |
