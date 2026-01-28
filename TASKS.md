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

### Task 017: Encrypted Database

**Branch**: `feat/017-encrypted-store`
**Changes**:

- sled wrapper with encryption
- Argon2id key derivation
- put/get/delete operations
- Unit tests
  **Version**: 0.1.0-alpha.4
  **Agents**: Backend, Security, QA

### Task 018: Message Queue

**Branch**: `feat/018-message-queue`
**Changes**:

- Outbox for pending messages
- Inbox for received messages
- Message status tracking
- Cleanup of expired messages
  **Version**: 0.1.0-alpha.4
  **Agents**: Backend, QA

### Task 019: Identity Keyring

**Branch**: `feat/019-keyring`
**Changes**:

- Secure key storage
- Password-protected access
- Key export/import
- Unit tests
  **Version**: 0.1.0-alpha.4
  **Agents**: Backend, Security, QA

-----

## Phase 5: Blockchain Layer (v0.1.0-alpha.5)

### Task 020: Block Structure

**Branch**: `feat/020-block-struct`
**Changes**:

- Block struct
- ChainEntry enum
- Block serialization
- Unit tests
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 021: Merkle Tree

**Branch**: `feat/021-merkle-tree`
**Changes**:

- Merkle tree construction
- Proof generation
- Proof verification
- Unit tests
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 022: Chain Management

**Branch**: `feat/022-chain-management`
**Changes**:

- Chain storage
- Block validation
- Chain traversal
- Fork handling
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 023: PoS Validator Selection with SLA

**Branch**: `feat/023-pos-validator-selection`
**Changes**:

- ValidatorStake struct with performance tracking
- ValidatorSla (99% uptime, max 3 missed blocks, 5s latency)
- Stake-weighted random selection (ChaCha20Rng)
- Performance multiplier (0.5-1.5x based on score)
- SLA bonus for compliant validators
- Geographic diversity enforcement (max 5 per region)
- 15% rotation per epoch (worst performers first)
- Slashing: 0.1% missed block, 1% SLA, 5% invalid, 100% double-sign
  **Version**: 0.1.0-alpha.5
  **Agents**: Architect, Backend, Security, QA

### Task 023b: Validator Slashing and Penalties

**Branch**: `feat/023b-validator-slashing`
**Changes**:

- SlashingConfig with penalty percentages
- SlashingManager for offense processing
- SlaViolation tracking and severity levels
- Automatic removal for critical violations
- Double-sign detection and permanent ban
- Slash result recording on chain
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, Security, QA

### Task 024: Chain Sync

**Branch**: `feat/024-chain-sync`
**Changes**:

- Sync protocol
- Block request/response
- Catch-up mechanism
- Unit tests
  **Version**: 0.1.0-alpha.5
  **Agents**: Backend, QA

-----

## Phase 6: Reputation System (v0.1.0-alpha.6)

### Task 025: Reputation Scoring with Rate Limiting

**Branch**: `feat/025-reputation-rate-limiting`
**Changes**:

- Score struct with gain/loss tracking
- Rate limiter: 60s between msgs, 30pts/peer/day, 100pts/day total
- ScoreRateLimiter struct
- Daily rotation logic
- Unit tests
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, Security, QA

### Task 026: Weighted Negative Reports

**Branch**: `feat/026-weighted-reports`
**Changes**:

- NegativeReport struct with reporter reputation
- ReportAggregator with weighted counting
- 3-report threshold with rep weighting
- Min 400 reputation to file reports
- Penalty calculation by severity
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, Security, QA

### Task 027: Collusion Detection

**Branch**: `feat/027-collusion-detection`
**Changes**:

- CollusionDetector with graph analysis
- Interaction tracking (from, to, count)
- Dense cluster detection (>70% internal)
- Suspicion scoring (density + symmetry + external)
- Score gain penalties for flagged clusters
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, Security, QA

### Task 027b: Reputation Decay and Effects

**Branch**: `feat/027b-reputation-effects`
**Changes**:

- Weekly decay toward 500 (1%/week)
- Priority levels (800+ priority, 500+ normal, 200+ deprioritized)
- Quarantine logic (<200 reputation)
- Blacklist handling (<50 reputation)
- Integration with network layer
  **Version**: 0.1.0-alpha.6
  **Agents**: Backend, QA

-----

## Phase 7: Networking Layer (v0.1.0-alpha.7)

### Task 028: Network-First Transport Selection

**Branch**: `feat/028-transport-selection`
**Changes**:

- Transport trait abstraction
- TransportManager with priority ordering
- Network connectivity check (always first)
- Fallback chain: Internet → Local WiFi → Bluetooth → Queue
- Transport selection logic
  **Version**: 0.1.0-alpha.7
  **Agents**: Architect, Backend, QA

### Task 029: libp2p Integration

**Branch**: `feat/029-libp2p`
**Changes**:

- libp2p node setup
- Noise encryption
- Peer discovery
- Connection management
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, Security, QA

### Task 030: DHT Storage

**Branch**: `feat/030-dht`
**Changes**:

- Kademlia DHT setup
- Mailbox key derivation
- Message storage/retrieval
- TTL handling
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 031: Gossip Protocol

**Branch**: `feat/031-gossip`
**Changes**:

- Gossipsub setup
- Message announcement
- Topic management
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 032: Local Discovery (mDNS)

**Branch**: `feat/032-mdns`
**Changes**:

- mDNS service advertisement
- Peer discovery on local network
- Integration with transport manager
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 033: Bluetooth Relay Transport

**Branch**: `feat/033-bluetooth-relay`
**Changes**:

- btleplug integration
- BLE service/characteristic setup
- NO PIN verification (pure relay)
- NO pairing required (any VERITAS node can relay)
- Find relay peers, forward to network-connected nodes
- Security from E2E encryption, not transport
  **Version**: 0.1.0-alpha.7
  **Agents**: Backend, QA

### Task 034: Store-and-Forward

**Branch**: `feat/034-store-forward`
**Changes**:

- Relay logic
- Message holding for offline peers
- Delivery on reconnection
- Hop limit handling
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