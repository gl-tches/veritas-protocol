# VERITAS Version History

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
