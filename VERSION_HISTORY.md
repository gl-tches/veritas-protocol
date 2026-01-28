# VERITAS Version History

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
