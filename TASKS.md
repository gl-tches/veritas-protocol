# VERITAS Implementation Tasks

> Structured task breakdown for Claude Code development sessions

## Phase 1: Foundation (v0.1.0-alpha.1)

### Task 001: Project Scaffolding ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ Create all 11 crate directories with Cargo.toml
- ✅ Set up workspace dependencies
- ✅ Add LICENSE files (MIT + Apache-2.0)
- ✅ Initialize git repository
- ✅ Created error types for all crates
- ✅ Added protocol limits module
  **Version**: 0.1.0-alpha.1
  **Agents**: Lead, Docs

### Task 002: Crypto Primitives — Hashing ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ Implement BLAKE3 wrapper in veritas-crypto
- ✅ Add Hash256 type with serialization
- ✅ Add Zeroize support
- ✅ Unit tests for hash operations (9 tests)
- ✅ Multi-input hashing with domain separation
- ✅ Keyed hashing (MAC) and key derivation
- ✅ Hex encoding/decoding
- ✅ Constant-time comparison via `subtle`
  **Version**: 0.1.0-alpha.1
  **Agents**: Backend, Security, QA

### Task 003: Crypto Primitives — Symmetric Encryption ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ Implement ChaCha20-Poly1305 encrypt/decrypt (XChaCha20-Poly1305 AEAD)
- ✅ Nonce generation (random 192-bit / 24-byte)
- ✅ SymmetricKey type with Zeroize
- ✅ Unit tests + property tests (15 tests)
- ✅ Additional authenticated data (AAD) support
- ✅ EncryptedData serialization
  **Version**: 0.1.0-alpha.1
  **Agents**: Backend, Security, QA

### Task 004: Crypto Primitives — ML-KEM ⏳ PLACEHOLDER

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: API designed, awaiting crate stabilization
**Changes**:

- ✅ API design for MlKemKeyPair, MlKemPublicKey, MlKemPrivateKey
- ✅ encapsulate() and decapsulate() function signatures
- ✅ Size constants defined (PUBLIC_KEY_SIZE, CIPHERTEXT_SIZE, etc.)
- ⏳ Integrate ml-kem crate (waiting for 0.3.0-pre.5 to stabilize)
- ⏳ MlKemKeyPair with generate/encapsulate/decapsulate
- ⏳ Zeroize on private key
- ⏳ Unit tests
  **Version**: 0.1.0-alpha.1
  **Agents**: Backend, Security, QA
  **Note**: ml-kem crate has API compatibility issues in pre-release

### Task 005: Crypto Primitives — ML-DSA ⏳ PLACEHOLDER

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: API designed, awaiting crate stabilization
**Changes**:

- ✅ API design for MlDsaKeyPair, MlDsaPublicKey, MlDsaPrivateKey
- ✅ sign() and verify() method signatures
- ✅ Size constants defined (PUBLIC_KEY_SIZE, SIGNATURE_SIZE, etc.)
- ⏳ Integrate ml-dsa crate (waiting for 0.1.0-rc.4 to stabilize)
- ⏳ MlDsaKeyPair with generate/sign/verify
- ⏳ Zeroize on private key
- ⏳ Unit tests
  **Version**: 0.1.0-alpha.1
  **Agents**: Backend, Security, QA
  **Note**: ml-dsa crate has API compatibility issues in pre-release

### Task 006: Crypto Primitives — X25519 Hybrid ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed (classical key exchange ready, hybrid pending ML-KEM)
**Changes**:

- ✅ Integrate x25519-dalek
- ✅ X25519StaticPrivateKey for long-term identity keys
- ✅ X25519EphemeralKeyPair for per-message encryption
- ✅ X25519PublicKey with serialization
- ✅ SharedSecret with Zeroize and BLAKE3 key derivation
- ✅ Diffie-Hellman key agreement
- ✅ Unit tests (12 tests)
- ⏳ Hybrid key exchange (X25519 + ML-KEM) - pending ML-KEM integration
- ⏳ Combined shared secret derivation - pending ML-KEM integration
  **Version**: 0.1.0-alpha.1
  **Agents**: Backend, Security, QA

-----

## Phase 2: Identity System (v0.1.0-alpha.2)

### Task 007: Identity Hash Generation ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ IdentityHash type (BLAKE3 of public key with domain separation)
- ✅ Serialization/deserialization (serde, bytes, hex)
- ✅ Display formatting (full and short)
- ✅ Constant-time comparison via `subtle`
- ✅ Unit tests (23 tests + property tests)
  **Version**: 0.1.0-alpha.2
  **Agents**: Backend, Security, QA

### Task 008: Identity Keypair ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ Identity struct with X25519 keys (ML-DSA placeholder)
- ✅ Key generation with `generate()`
- ✅ Encrypted serialization for secure storage
- ✅ Key exchange and encryption key derivation
- ✅ Unit tests (16 tests)
  **Version**: 0.1.0-alpha.2
  **Agents**: Backend, Security, QA

### Task 009: Username System ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ Username type with validation (3-32 chars, alphanumeric + _-)
- ✅ UsernameRegistration struct with signing
- ✅ Signature verification support
- ✅ Case-insensitive comparison
- ✅ Unit tests (23 tests + property tests)
  **Version**: 0.1.0-alpha.2
  **Agents**: Backend, Security, QA

### Task 010: Key Lifecycle and Identity Limits ✅ COMPLETED

**Branch**: `claude/review-and-execute-GTVfn`
**Status**: Completed
**Changes**:

- ✅ KeyState enum (Active, Expiring, Expired, Rotated, Revoked)
- ✅ Expiry checking logic (30 days inactive)
- ✅ Rotation with prev_identity linking
- ✅ IdentityLimiter: max 3 identities per origin
- ✅ OriginFingerprint: privacy-preserving device binding
- ✅ 24-hour grace period after expiry
- ✅ Slot recycling when identity expires
- ✅ IdentitySlotInfo for user-facing status
- ✅ Unit tests (53 tests: 36 lifecycle + 17 limits)
  **Version**: 0.1.0-alpha.2
  **Agents**: Backend, Security, QA

-----

## Phase 3: Protocol Layer (v0.1.0-alpha.3)

### Task 011: Minimal Metadata Envelope ✅ COMPLETED

**Branch**: `claude/phase-3-protocol-layer-fhZIO`
**Status**: Completed
**Changes**:

- ✅ MinimalEnvelope struct (mailbox_key, ephemeral_key, nonce, ciphertext)
- ✅ InnerPayload struct (sender_id, timestamp, content, signature inside encryption)
- ✅ Mailbox key derivation (recipient + epoch + salt)
- ✅ Ephemeral key generation per message
- ✅ Padding to fixed size buckets (256/512/1024) with random fill
- ✅ Timing jitter (0-3 sec random delay using OsRng)
- ✅ MinimalEnvelopeBuilder for fluent construction
- ✅ Unit tests (16 tests)
  **Version**: 0.1.0-alpha.3
  **Agents**: Backend, Security, QA

### Task 012: Message Encryption ✅ COMPLETED

**Branch**: `claude/phase-3-protocol-layer-fhZIO`
**Status**: Completed
**Changes**:

- ✅ encrypt_for_recipient() - Full E2E encryption pipeline
- ✅ decrypt_as_recipient() - Full decryption pipeline
- ✅ Ephemeral X25519 key exchange per message (forward secrecy)
- ✅ XChaCha20-Poly1305 AEAD encryption
- ✅ DecryptionContext for caching recipient keypair
- ✅ EncryptedMessage serialization/deserialization
- ✅ decrypt_and_verify() with sender public key verification
- ✅ Unit tests (18 tests)
  **Version**: 0.1.0-alpha.3
  **Agents**: Backend, Security, QA

### Task 013: Message Signing ✅ COMPLETED

**Branch**: `claude/phase-3-protocol-layer-fhZIO`
**Status**: Completed (Placeholder)
**Changes**:

- ✅ MessageSignature struct with version tracking
- ✅ SignatureVersion enum (HmacBlake3 placeholder, MlDsa future)
- ✅ SigningData with domain-separated hash
- ✅ sign_message() - Placeholder HMAC-BLAKE3 until ML-DSA
- ✅ verify_signature() - Signature verification
- ✅ Constant-time comparison using `subtle`
- ✅ Unit tests (23 tests)
  **Version**: 0.1.0-alpha.3
  **Agents**: Backend, Security, QA
  **Note**: Placeholder signature scheme until ML-DSA stabilizes

### Task 014: Message Chunking ✅ COMPLETED

**Branch**: `claude/phase-3-protocol-layer-fhZIO`
**Status**: Completed
**Changes**:

- ✅ ChunkInfo struct (chunk_index, total_chunks, message_hash)
- ✅ MessageChunk with integrity verification
- ✅ split_into_chunks() - Split by character count (max 3, 300 chars each)
- ✅ ChunkReassembler with pending message tracking
- ✅ Out-of-order chunk handling and duplicate detection
- ✅ Hash verification after reassembly
- ✅ Expiry cleanup for pending chunks
- ✅ Unit tests (24 tests)
  **Version**: 0.1.0-alpha.3
  **Agents**: Backend, QA

### Task 015: Delivery Receipts ✅ COMPLETED

**Branch**: `claude/phase-3-protocol-layer-fhZIO`
**Status**: Completed
**Changes**:

- ✅ DeliveryReceipt struct with signature
- ✅ ReceiptType enum (Delivered, Read, Error)
- ✅ DeliveryError enum (RecipientNotFound, MessageExpired, Rejected, QuotaExceeded, Other)
- ✅ DeliveryReceiptData for embedding in MessageContent
- ✅ Receipt hash computation with domain separation
- ✅ Factory methods: delivered(), read(), error()
- ✅ Serialization/deserialization support
- ✅ Unit tests (26 tests)
  **Version**: 0.1.0-alpha.3
  **Agents**: Backend, Security, QA

### Task 016: Group Messages ✅ COMPLETED

**Branch**: `claude/phase-3-protocol-layer-fhZIO`
**Status**: Completed
**Changes**:

- ✅ GroupId (32-byte random identifier)
- ✅ GroupRole enum (Admin, Moderator, Member) with permissions
- ✅ GroupMember struct
- ✅ GroupMetadata with member management
- ✅ GroupKey with Zeroize (symmetric key + generation)
- ✅ GroupKeyManager for ECDH-based key distribution
- ✅ EncryptedGroupKey per-member encrypted keys
- ✅ GroupMessageData for encrypted group messages
- ✅ KeyRotationManager with scheduled/manual/compromise triggers
- ✅ Forward secrecy on member removal
- ✅ MAX_GROUP_SIZE=100, rotation every 7 days
- ✅ Unit tests (43 tests)
  **Version**: 0.1.0-alpha.3
  **Agents**: Backend, Security, QA

-----

## Phase 4: Storage Layer (v0.1.0-alpha.4)

### Task 017: Encrypted Database ✅ COMPLETED

**Branch**: `claude/phase-4-storage-layer-3AenO`
**Status**: Completed
**Changes**:

- ✅ `EncryptedDb` struct wrapping sled with encryption
- ✅ Argon2id key derivation (64 MiB, 3 iterations, 4 parallelism)
- ✅ XChaCha20-Poly1305 encryption for all values
- ✅ `DbKey` with Zeroize support
- ✅ Salt stored in database, reused on reopen
- ✅ `EncryptedTree` for namespaced storage
- ✅ put/get/delete/contains/iter operations
- ✅ Unit tests (27 tests)
  **Version**: 0.1.0-alpha.4
  **Agents**: Backend, Security, QA

### Task 018: Message Queue ✅ COMPLETED

**Branch**: `claude/phase-4-storage-layer-3AenO`
**Status**: Completed
**Changes**:

- ✅ `MessageQueue` with outbox and inbox trees
- ✅ `MessageId` (32-byte random identifier)
- ✅ `QueuedMessage` for outbox with status tracking
- ✅ `InboxMessage` for received messages
- ✅ `MessageStatus` enum (Pending, Sending, Sent, Delivered, Failed, Read)
- ✅ Exponential backoff retry (30s, 60s, 120s, 240s, 480s, max 5 retries)
- ✅ Expiry cleanup (7-day MESSAGE_TTL)
- ✅ Pagination support for inbox
- ✅ OutboxStats and InboxStats for monitoring
- ✅ Unit tests (32 tests)
  **Version**: 0.1.0-alpha.4
  **Agents**: Backend, QA

### Task 019: Identity Keyring ✅ COMPLETED

**Branch**: `claude/phase-4-storage-layer-3AenO`
**Status**: Completed
**Changes**:

- ✅ `Keyring` with password-protected access
- ✅ `KeyringEntry` with identity hash, encrypted keypair, metadata
- ✅ Argon2id password key derivation with domain separation
- ✅ Password verification using constant-time comparison
- ✅ Primary identity selection
- ✅ `ExportedIdentity` for portable backup/transfer
- ✅ Export/import with separate export password
- ✅ Password change with re-encryption of all entries
- ✅ BLAKE3 domain separation for key derivation
- ✅ Secrets redacted in Debug output
- ✅ Unit tests (24 tests)
  **Version**: 0.1.0-alpha.4
  **Agents**: Backend, Security, QA

-----

## Phase 5: Blockchain Layer (v0.1.0-alpha.5)

### Task 020: Block Structure ✅ COMPLETED

**Branch**: `claude/blockchain-layer-phase-5-2I1zZ`
**Status**: Completed
**Changes**:

- ✅ Block struct with header and body separation
- ✅ BlockHeader with hash, parent_hash, height, timestamp, merkle_root, validator
- ✅ BlockBody with chain entries and merkle root computation
- ✅ ChainEntry enum with all entry types (IdentityRegistration, UsernameRegistration, KeyRotation, MessageProof, ReputationChange, ValidatorRegistration/Exit/Slash)
- ✅ Genesis block support with `Block::genesis()`
- ✅ Domain-separated hashing (`VERITAS-BLOCK-v1`, `VERITAS-CHAIN-ENTRY-v1`)
- ✅ Block serialization with serde + bincode
- ✅ Unit tests (32 tests)
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 021: Merkle Tree ✅ COMPLETED

**Branch**: `claude/blockchain-layer-phase-5-2I1zZ`
**Status**: Completed
**Changes**:

- ✅ MerkleTree struct for tree construction
- ✅ MerkleProof with sibling hashes and directions
- ✅ Direction enum (Left, Right) for proof traversal
- ✅ Proof generation via `generate_proof()`
- ✅ Proof verification via `verify_proof()`
- ✅ Domain-separated hashing (`VERITAS-MERKLE-v1`)
- ✅ Edge case handling (empty, single, power-of-2, non-power-of-2)
- ✅ Unit tests (29 tests including property-based)
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 022: Chain Management ✅ COMPLETED

**Branch**: `claude/blockchain-layer-phase-5-2I1zZ`
**Status**: Completed
**Changes**:

- ✅ Blockchain struct for chain storage and management
- ✅ BlockValidation with comprehensive validation rules
- ✅ Height continuity, parent hash, timestamp ordering validation
- ✅ Hash integrity and merkle root validation
- ✅ Block producer authorization validation
- ✅ ForkChoice for fork tracking with longest chain rule
- ✅ Deterministic tiebreaker for same-height forks
- ✅ Common ancestor detection
- ✅ Chain iteration (forward and backward)
- ✅ ChainState for persistence
- ✅ Unit tests (33 tests)
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 023: PoS Validator Selection with SLA ✅ COMPLETED

**Branch**: `claude/blockchain-layer-phase-5-2I1zZ`
**Status**: Completed
**Changes**:

- ✅ ValidatorStake struct with performance tracking
- ✅ ValidatorSla (99% uptime, max 3 missed blocks, 5s latency)
- ✅ ValidatorSet for managing active validators (max 21)
- ✅ Stake-weighted random selection (ChaCha20Rng deterministic)
- ✅ Weight formula: stake × performance_multiplier × sla_bonus
- ✅ Performance multiplier (0.5-1.5x based on score)
- ✅ SLA bonus for compliant validators (up to 1.5x)
- ✅ Geographic diversity enforcement (max 5 per region)
- ✅ 15% rotation per epoch (worst performers first)
- ✅ Domain-separated selection (`VERITAS-VALIDATOR-SELECTION-v1`)
- ✅ Unit tests (51 tests)
  **Version**: 0.1.0-alpha.5
  **Agents**: Architect, Backend, Security, QA

### Task 023b: Validator Slashing and Penalties ✅ COMPLETED

**Branch**: `claude/blockchain-layer-phase-5-2I1zZ`
**Status**: Completed
**Changes**:

- ✅ SlashingConfig with penalty percentages (0.1% missed, 1% SLA, 5% invalid, 100% double-sign)
- ✅ SlashingOffense enum for all offense types
- ✅ SlaViolationType for SLA violation details
- ✅ SlashResult with penalty amount, remaining stake, ban status
- ✅ SlashingManager for offense processing
- ✅ Double-sign detection via `record_block_signature()`
- ✅ Automatic 100% slash and permanent ban for double-signing
- ✅ Signature pruning for memory management
- ✅ Unit tests (24 tests)
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 024: Chain Sync ✅ COMPLETED

**Branch**: `claude/blockchain-layer-phase-5-2I1zZ`
**Status**: Completed
**Changes**:

- ✅ SyncMessage enum for sync protocol (GetHeaders/Headers, GetBlocks/Blocks, NewBlock, GetTip/Tip, Status)
- ✅ SyncState enum (Synced, SyncingHeaders, SyncingBlocks, Paused)
- ✅ SyncAction for sync manager responses
- ✅ SyncManager with configurable limits (500 headers, 100 blocks per request)
- ✅ PendingRequest tracking with 30s timeout
- ✅ Progress reporting and pause/resume support
- ✅ Block request/response handling
- ✅ Catch-up mechanism with batched fetching
- ✅ Unit tests (39 tests)
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, QA

-----

## Phase 6: Reputation System (v0.1.0-alpha.6)

### Task 025: Reputation Scoring with Rate Limiting ✅ COMPLETED

**Branch**: `claude/phase-6-reputation-system-Citik`
**Status**: Completed
**Changes**:

- ✅ `ReputationScore` struct with gain/loss tracking
- ✅ Score range 0-1000 with starting score 500
- ✅ `gain()` and `lose()` methods with capping/flooring
- ✅ `gain_with_multiplier()` for collusion penalty application
- ✅ `ScoreRateLimiter` with rate limiting:
  - 60s min between messages to same peer
  - 30pts max gain from any peer per day
  - 100pts max total gain per day
- ✅ `PeerInteraction` tracking with automatic daily reset
- ✅ `RateLimitResult` enum for detailed limit feedback
- ✅ Unit tests (25 tests)
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, Security, QA

### Task 026: Weighted Negative Reports ✅ COMPLETED

**Branch**: `claude/phase-6-reputation-system-Citik`
**Status**: Completed
**Changes**:

- ✅ `ReportReason` enum (Spam, Harassment, Impersonation, Malware, Scam, Other)
- ✅ `NegativeReport` struct with reporter reputation tracking
- ✅ `ReportAggregator` with weighted counting
- ✅ Report weighting: `weight = reporter_reputation / 500.0`
- ✅ 3-report weighted threshold for penalty
- ✅ Min 400 reputation to file reports
- ✅ Penalty calculation by severity (capped at 200)
- ✅ Duplicate reporter detection
- ✅ Unit tests (14 tests)
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, Security, QA

### Task 027: Collusion Detection ✅ COMPLETED

**Branch**: `claude/phase-6-reputation-system-Citik`
**Status**: Completed
**Changes**:

- ✅ `InteractionRecord` tracking (from, to, count, timestamps)
- ✅ `CollusionDetector` with graph analysis
- ✅ Connected component detection for cluster identification
- ✅ Dense cluster detection (>70% internal density)
- ✅ Symmetry scoring (A→B vs B→A balance)
- ✅ External connection ratio tracking
- ✅ `SuspiciousCluster` with combined suspicion scoring
- ✅ Gain multiplier: `1.0 - suspicion_score`
- ✅ Unit tests (8 tests)
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, Security, QA

### Task 027b: Reputation Decay and Effects ✅ COMPLETED

**Branch**: `claude/phase-6-reputation-system-Citik`
**Status**: Completed
**Changes**:

- ✅ `DecayConfig` with configurable decay rate and interval
- ✅ Weekly decay toward 500 (1%/week default)
- ✅ `DecayState` for tracking decay timing
- ✅ `ReputationTier` enum (Blacklisted, Quarantined, Deprioritized, Normal, Priority)
- ✅ `TierEffects` struct with tier-specific restrictions:
  - Messaging permissions
  - Report filing rights (400+ rep)
  - Validator eligibility (700+ rep)
  - Priority modifiers and rate limit multipliers
- ✅ `ReputationManager` coordinating all operations
- ✅ `ReputationStats` for system monitoring
- ✅ Unit tests (27 tests)
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, QA

-----

## Phase 7: Networking Layer (v0.1.0-alpha.7)

### Task 028: Network-First Transport Selection ✅ COMPLETED

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed
**Changes**:

- ✅ `TransportType` enum (Internet, LocalNetwork, Bluetooth, Queued)
- ✅ `TransportState` for tracking transport availability
- ✅ `TransportStatus` for connection status
- ✅ `TransportCapabilities` describing transport features
- ✅ `Transport` trait with async connectivity methods
- ✅ `TransportSelector` implementing network-first priority
- ✅ `PeerInfo` for peer tracking with addresses
- ✅ `NetworkAddress` multiaddr wrapper
  **Version**: 0.1.0-alpha.7
  **Agents**: Architect, Backend, QA

### Task 029: libp2p Integration ✅ COMPLETED

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed
**Changes**:

- ✅ `NodeConfig` for configuring libp2p node
- ✅ `VeritasNode` wrapping libp2p Swarm
- ✅ Noise protocol encryption
- ✅ Kademlia DHT (`/veritas/kad/1.0.0`)
- ✅ Gossipsub pub/sub integration
- ✅ mDNS local discovery
- ✅ Identify protocol
- ✅ `NodeBehaviour` combining all behaviours
- ✅ `NodeEvent` enum for event handling
- ✅ Event loop with channel-based emission
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, Security, QA

### Task 030: DHT Storage ✅ COMPLETED

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed
**Changes**:

- ✅ `DhtConfig` with replication, TTL, query settings
- ✅ `DhtKey` for DHT record keys from mailbox keys
- ✅ `DhtRecord` for serialized message storage
- ✅ `DhtRecordSet` for multiple messages per mailbox
- ✅ `DhtStorage` with store/get/delete/has methods
- ✅ TTL enforcement (7 days)
- ✅ Message ID computation from envelope hash
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 031: Gossip Protocol ✅ COMPLETED

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed
**Changes**:

- ✅ `GossipConfig` with mesh parameters
- ✅ `GossipManager` for pub/sub messaging
- ✅ Topic constants (messages, blocks, receipts)
- ✅ `MessageAnnouncement` (privacy-preserving)
- ✅ `BlockAnnouncement` for new blocks
- ✅ `ReceiptAnnouncement` for delivery receipts
- ✅ Hourly timestamp buckets for temporal privacy
- ✅ Size buckets for traffic analysis resistance
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 032: Local Discovery (mDNS) ✅ COMPLETED

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed
**Changes**:

- ✅ `DiscoveryConfig` with TTL and query settings
- ✅ `LocalDiscovery` wrapping mDNS behaviour
- ✅ `DiscoveredPeer` with peer ID, addresses, timestamps
- ✅ `DiscoveryEvent` enum (PeerDiscovered, PeerExpired)
- ✅ Automatic peer pruning for stale entries
- ✅ Service name: `_veritas._tcp.local`
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 033: Bluetooth Relay Transport ✅ COMPLETED (Placeholder)

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed (Placeholder)
**Changes**:

- ✅ `BluetoothConfig` with service UUID, MTU, scan interval
- ✅ `BlePeer` for discovered BLE devices
- ✅ `BluetoothRelay` placeholder (all methods return NotImplemented)
- ✅ `BluetoothStats` for relay statistics
- ✅ NO PIN verification (pure relay)
- ✅ NO pairing required (security from E2E encryption)
- ⏳ btleplug integration (pending future implementation)
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA
  **Note**: API designed for future btleplug integration

### Task 034: Store-and-Forward ✅ COMPLETED

**Branch**: `claude/networking-layer-phase-7-IwEch`
**Status**: Completed
**Changes**:

- ✅ `RelayConfig` with hop limit, TTL, capacity settings
- ✅ `RelayedMessage` with envelope, hop count, timestamps
- ✅ `RelayManager` with store/get/mark/forward/prune methods
- ✅ `RelayStats` for monitoring
- ✅ Hop limit (3) prevents infinite loops
- ✅ Traffic analysis resistance via jitter delay
- ✅ 12 unit tests
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

-----

## Phase 8: Core API (v0.1.0-beta.1)

### Task 035: Client Interface

**Branch**: `feat/035-client-interface`
**Changes**:

- VeritasClient struct
- Identity management methods
- Configuration
  **Version**: 0.1.0-beta.1
  **Agents**: Architect, Backend, Docs

### Task 036: Messaging API

**Branch**: `feat/036-messaging-api`
**Changes**:

- send_message()
- receive_messages()
- decrypt_message()
- send_receipt()
  **Version**: 0.1.0-beta.1
  **Agents**: Backend, Docs, QA

### Task 037: Group API

**Branch**: `feat/037-group-api`
**Changes**:

- create_group()
- send_group_message()
- add/remove members
  **Version**: 0.1.0-beta.1
  **Agents**: Backend, Docs, QA

### Task 038: Verification API

**Branch**: `feat/038-verification-api`
**Changes**:

- verify_message_proof()
- verify_receipt_proof()
- lookup_identity()
- resolve_username()
  **Version**: 0.1.0-beta.1
  **Agents**: Backend, Docs, QA

### Task 039: Safety Numbers

**Branch**: `feat/039-safety-numbers`
**Changes**:

- Safety number computation
- Display formatting
- QR code generation (optional)
  **Version**: 0.1.0-beta.1
  **Agents**: Backend, Security, QA

-----

## Phase 9: Bindings (v0.1.0-beta.2)

### Task 040: C FFI

**Branch**: `feat/040-c-ffi`
**Changes**:

- C header generation
- Safe FFI wrappers
- Error codes
- Memory management
  **Version**: 0.1.0-beta.2
  **Agents**: Bindings, Security, QA

### Task 041: WASM Bindings

**Branch**: `feat/041-wasm`
**Changes**:

- wasm-bindgen setup
- Browser-compatible API
- Storage via IndexedDB
- Web Crypto integration (where possible)
  **Version**: 0.1.0-beta.2
  **Agents**: Bindings, Security, QA

### Task 042: Python Bindings

**Branch**: `feat/042-python`
**Changes**:

- PyO3 setup
- Pythonic API wrapper
- Async support
- Type hints
  **Version**: 0.1.0-beta.2
  **Agents**: Bindings, Docs, QA

-----

## Phase 10: Testing & Documentation (v0.1.0-rc.1)

### Task 043: Integration Tests

**Branch**: `test/043-integration`
**Changes**:

- End-to-end messaging tests
- Multi-node tests
- Offline scenario tests
  **Version**: 0.1.0-rc.1
  **Agents**: QA

### Task 044: Property Tests

**Branch**: `test/044-property-tests`
**Changes**:

- Crypto property tests
- Protocol property tests
- Fuzzing setup
  **Version**: 0.1.0-rc.1
  **Agents**: QA, Security

### Task 045: Documentation

**Branch**: `docs/045-documentation`
**Changes**:

- API documentation
- Architecture guide
- Security considerations
- Example code
  **Version**: 0.1.0-rc.1
  **Agents**: Docs

### Task 046: Example Applications

**Branch**: `feat/046-examples`
**Changes**:

- CLI chat example
- Web demo (WASM)
- Mobile bridge example
  **Version**: 0.1.0-rc.1
  **Agents**: Backend, Docs

-----

## Release Checklist (v0.1.0)

- [ ] All tasks completed and merged
- [ ] Security audit of crypto layer
- [ ] Fuzz testing completed
- [ ] Documentation complete
- [ ] Examples working
- [ ] Performance benchmarks meet targets
- [ ] CI/CD pipeline green
- [ ] VERSION_HISTORY.md updated
- [ ] Git tag created
- [ ] Crates published to crates.io (if public)