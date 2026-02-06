# VERITAS Protocol — Comprehensive Codebase Review

**Review Date**: 2026-02-06
**Protocol Version**: v0.3.0-beta
**Scope**: All 12 crates (~45,800 LOC)
**Reviewer**: Claude Code Security Team (parallel agent review)

---

## Executive Summary

This review covers every source file across all 12 crates in the VERITAS protocol. The analysis identified **~95 findings** across the codebase:

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| **Fixes** (security/bugs) | 2 | 14 | 18 | 17 | 2 |
| **Feature Gaps** | — | — | — | — | 42+ |
| **Optimizations** | — | — | — | — | 35+ |

### Top 10 Priority Issues

| # | Severity | Crate | ID | Description |
|---|----------|-------|----|-------------|
| 1 | **CRITICAL** | reputation | REP-FIX-1 | Collusion cluster index mapping broken — detection silently non-functional |
| 2 | **HIGH** | core | CORE-FIX-5 | Non-primary keypairs dropped and lost forever in IdentityManager |
| 3 | **HIGH** | core | CORE-FIX-2 | `set_primary_identity` does not update cached keypair |
| 4 | **HIGH** | ffi | FFI-FIX-1 | New tokio runtime created per FFI call (performance disaster) |
| 5 | **HIGH** | wasm | WASM-FIX-1 | Hardcoded Argon2 salt enables rainbow table attacks |
| 6 | **HIGH** | wasm | WASM-FIX-2 | Installation ID not persisted — Sybil resistance defeated |
| 7 | **HIGH** | protocol | PROTO-FIX-2 | `decrypt_as_recipient` skips ephemeral key validation before ECDH |
| 8 | **HIGH** | protocol | PROTO-FIX-3 | Mailbox salt mismatch — recipient cannot re-derive key |
| 9 | **HIGH** | protocol | PROTO-FIX-9 | Receipt signatures forgeable (hash-only, no signing) |
| 10 | **HIGH** | chain | CHAIN-FIX-1 | Sync header validation missing parent hash linkage |

---

## Table of Contents

1. [veritas-crypto](#1-veritas-crypto)
2. [veritas-identity](#2-veritas-identity)
3. [veritas-protocol](#3-veritas-protocol)
4. [veritas-store](#4-veritas-store)
5. [veritas-chain](#5-veritas-chain)
6. [veritas-reputation](#6-veritas-reputation)
7. [veritas-net](#7-veritas-net)
8. [veritas-node](#8-veritas-node)
9. [veritas-core](#9-veritas-core)
10. [veritas-ffi](#10-veritas-ffi)
11. [veritas-wasm](#11-veritas-wasm)
12. [veritas-py](#12-veritas-py)
13. [Cross-Cutting Concerns](#13-cross-cutting-concerns)

---

## 1. veritas-crypto

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| CRYPTO-FIX-1 | MEDIUM | `mldsa.rs:72-74` | `MlDsaPrivateKey` missing `Zeroize`/`ZeroizeOnDrop` — private key bytes not cleared on drop |
| CRYPTO-FIX-2 | MEDIUM | `mlkem.rs:69-71` | `MlKemPrivateKey` missing `Zeroize`/`ZeroizeOnDrop` — same issue |
| CRYPTO-FIX-3 | LOW | `x25519.rs:152-156` | `X25519StaticPrivateKey` implements `Clone` — violates CLAUDE.md rule "NEVER derive Clone on secret keys" |
| CRYPTO-FIX-4 | LOW | `hash.rs:77` | `Hash256::is_zero()` uses non-constant-time short-circuiting comparison |
| CRYPTO-FIX-5 | LOW | `hash.rs:94-116` | `from_hex()` returns `InvalidHashLength` for parse failures — wrong error variant |
| CRYPTO-FIX-6 | INFO | `mlkem.rs:90-95`, `mldsa.rs:105-110` | Keypair structs expose private keys as `pub` fields |

### Features

| ID | Description |
|----|-------------|
| CRYPTO-FEAT-1 | No maximum size validation in `EncryptedData::from_bytes()` — only checks minimum |
| CRYPTO-FEAT-2 | No Argon2 key derivation API exposed despite dependency — forces downstream to use crate directly |
| CRYPTO-FEAT-3 | No hybrid key exchange combiner (X25519 + ML-KEM) — needed for post-quantum readiness |
| CRYPTO-FEAT-4 | Missing test for all-zero shared secret / low-order point behavior |
| CRYPTO-FEAT-5 | No `Serialize`/`Deserialize` on ML-DSA/ML-KEM types — causes `#[serde(skip)]` downstream |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| CRYPTO-OPT-1 | `hash.rs:81-87` | `to_hex()` allocates via `format!` per byte (32 heap allocs) — use hex crate or lookup table |
| CRYPTO-OPT-2 | `x25519.rs:127-134` | `diffie_hellman()` reconstructs `StaticSecret` each call — acceptable but notable |
| CRYPTO-OPT-3 | `symmetric.rs:151-153` | `is_empty()` semantics misleading — encrypting empty plaintext never returns empty |

---

## 2. veritas-identity

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| IDENT-FIX-1 | **HIGH** | `keypair.rs:339-342` | Decrypted plaintext (`Vec<u8>`) not zeroized in `from_encrypted()` — key material persists in heap |
| IDENT-FIX-2 | MEDIUM | `keypair.rs:379-388` | `Clone` silently drops signing private key (`signing_private: None`) |
| IDENT-FIX-3 | MEDIUM | `keypair.rs:81-84,426-429` | No size validation before `bincode::deserialize` in `from_bytes()` methods |
| IDENT-FIX-4 | MEDIUM | `limits.rs:46-53` | `OriginFingerprint::new()` is public and bypasses hardware attestation requirement |
| IDENT-FIX-5 | LOW | `limits.rs:311-335` | `register_rotation()` doesn't check for duplicate `new_identity` |
| IDENT-FIX-6 | LOW | `lifecycle.rs:220-233` | `update_state()` lacks timestamp validation unlike `is_expired()` |
| IDENT-FIX-7 | LOW | `lifecycle.rs:213` | `touch()` accepts any timestamp without validation |
| IDENT-FIX-8 | LOW | `username.rs:266-278` | `UsernameRegistration::new()` accepts empty signatures |

### Features

| ID | Description |
|----|-------------|
| IDENT-FEAT-1 | No integrated password-based encryption workflow (`to_encrypted_with_password()`) |
| IDENT-FEAT-2 | No validation of deserialized `IdentityPublicKeys` (low-order point check) |
| IDENT-FEAT-3 | No method to list identities pending PFS key destruction |
| IDENT-FEAT-4 | `RESERVED_USERNAMES` list incomplete — missing common attack targets |
| IDENT-FEAT-5 | No `Hash` implementation for `OriginFingerprint` |
| IDENT-FEAT-6 | Missing end-to-end lifecycle integration test (create → use → rotate → destroy) |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| IDENT-OPT-1 | `username.rs:204-206` | `eq_ignore_case()` performs two heap allocations — use `eq_ignore_ascii_case()` |
| IDENT-OPT-2 | `username.rs:146` | `validate()` collects chars into Vec unnecessarily for ASCII-only validation |
| IDENT-OPT-3 | `keypair.rs:73,418` | `to_bytes()` uses `expect()` which panics — should return `Result` |

### Cross-Crate

| ID | Severity | Description |
|----|----------|-------------|
| CROSS-1 | **HIGH** | Post-quantum readiness gap — 7+ coordinated changes needed when ML-DSA/ML-KEM implemented |
| CROSS-2 | MEDIUM | Inconsistent error mapping — deserialization failures mapped to `CryptoError::Decryption` |
| CROSS-3 | LOW | No domain separation in username `compute_signing_payload()` |

---

## 3. veritas-protocol

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| PROTO-FIX-1 | MEDIUM | `minimal.rs:112` | Non-constant-time zero check in ephemeral key validation |
| PROTO-FIX-2 | **HIGH** | `e2e.rs:244-282` | `decrypt_as_recipient` does not call `envelope.validate()` before ECDH — low-order point keys bypass check |
| PROTO-FIX-3 | **HIGH** | `e2e.rs:185-187` | Mailbox salt in `EncryptedMessage` doesn't match salt used in derivation |
| PROTO-FIX-4 | MEDIUM | `inner.rs:221,306` | Silent `unwrap_or_default()` on content serialization produces deterministic wrong hash |
| PROTO-FIX-5 | LOW | `mailbox.rs:253-257` | `epoch_from_timestamp` uses `debug_assert!` for division-by-zero — stripped in release |
| PROTO-FIX-6 | LOW | `inner.rs:67-69` | `GroupMessage` `PartialEq` compares by hash, not value |
| PROTO-FIX-7 | LOW | `rotation.rs:179-182` | Dead code block in `remove_member_and_rotate` |
| PROTO-FIX-8 | MEDIUM | `delivery.rs:436-440` | `DeliveryReceipt::from_bytes` has no pre-deserialization size check |
| PROTO-FIX-9 | **HIGH** | `delivery.rs:343-344,419-421` | Receipt signatures are forgeable — uses hash comparison, not signing module; non-constant-time `==` |
| PROTO-FIX-10 | LOW | `keys.rs:279` | `GroupMessageData::hash()` uses `to_le_bytes()` — inconsistent with rest of protocol (BE) |
| PROTO-FIX-11 | LOW | `rotation.rs:117` | `key_generation` overflow via `saturating_add` — silent stop at `u32::MAX` |

### Features

| ID | Description |
|----|-------------|
| PROTO-FEAT-1 | Add explicit `validate()` call at start of `decrypt_as_recipient` |
| PROTO-FEAT-2 | No `from_bytes` size check for `EncryptedMessage` |
| PROTO-FEAT-3 | Receipt should use signing module instead of hash-based "signatures" |
| PROTO-FEAT-4 | No property test for `GroupMessageData` encrypt/decrypt roundtrip |
| PROTO-FEAT-5 | `InnerPayload::validate()` does not verify signature is non-placeholder |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| PROTO-OPT-1 | `chunk.rs:229` | `split_into_chunks` collects all chars into Vec (3.6KB for max message) |
| PROTO-OPT-2 | `padding.rs:141-143` | `pad_to_bucket` creates intermediate random buffer — write in-place instead |
| PROTO-OPT-3 | `metadata.rs:289-303` | `GroupMetadata` member lookups are O(n) — use HashMap index for O(1) |
| PROTO-OPT-4 | `metadata.rs:61-67` | `GroupId::to_hex` uses per-byte `format!` (32 allocations) |
| PROTO-OPT-5 | `inner.rs:306` | `content_hash()` serializes content on every call — cache bytes or hash |

---

## 4. veritas-store

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| STORE-FIX-1 | LOW | `keyring.rs:193-195` | `PasswordKey::as_symmetric_key()` creates new key each call — weakens zeroization |
| STORE-FIX-2 | LOW | `keyring.rs:741-750` | `export_identity` double-encrypts with same key — redundant and confusing |
| STORE-FIX-3 | MEDIUM | `keyring.rs:165-168` | `ExportedIdentity::from_bytes` — no pre-deserialization size check |
| STORE-FIX-4 | LOW | `keyring.rs:853-887` | `update_metadata`/`update_entry` flush after every operation — expensive |
| STORE-FIX-5 | MEDIUM | `keyring.rs:343-398` | `change_password` is non-atomic — crash causes inconsistent state |

### Features

| ID | Description |
|----|-------------|
| STORE-FEAT-1 | No `Keyring::has_identity()` convenience method — avoids unnecessary decryption |
| STORE-FEAT-2 | No lock/unlock mechanism on Keyring — key stays in memory indefinitely |
| STORE-FEAT-3 | No test for empty password behavior |
| STORE-FEAT-4 | No size limit on label strings — allows arbitrarily large labels |
| STORE-FEAT-5 | `identity_count` metadata can drift out of sync — no `recount()` method |
| STORE-FEAT-6 | No concurrent access tests despite sled supporting it |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| STORE-OPT-1 | `keyring.rs:193-195` | Cache `SymmetricKey` within `PasswordKey` instead of recreating |
| STORE-OPT-2 | `keyring.rs:527-538` | `list_identities()` deserializes all entries — add pagination |
| STORE-OPT-3 | `keyring.rs:648-681` | `set_primary()` performs redundant reads — batch into single transaction |
| STORE-OPT-4 | `keyring.rs:905-937` | Duplicate Argon2 parameter construction — extract shared helper |
| STORE-OPT-5 | `keyring.rs:344` | `change_password` loads all entries to Vec — process streaming |

---

## 5. veritas-chain

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| CHAIN-FIX-1 | **HIGH** | `sync.rs:599-607` | Sync header validation missing parent hash linkage — fabricated chains accepted |
| CHAIN-FIX-2 | **HIGH** | `sync.rs` (multiple) | `pending_headers`/`received_blocks` vectors unbounded — memory exhaustion |
| CHAIN-FIX-3 | MEDIUM | `sync.rs:697` | Pending count uses cumulative received count — premature state transitions |
| CHAIN-FIX-4 | MEDIUM | `pruner.rs:139-146` | `.min()` should be `.max()` — safety margin never takes effect |
| CHAIN-FIX-5 | MEDIUM | `block.rs:892` | `ChainEntry::hash()` produces identical hashes on serialization failure |
| CHAIN-FIX-6 | MEDIUM | `slashing.rs:474-478` | `f32` overflow in penalty calculation for large stakes |
| CHAIN-FIX-7 | LOW | `sled_backend.rs:131` | `cache_capacity` overflows on 32-bit platforms |
| CHAIN-FIX-8 | LOW | `block.rs/chain.rs` | `MerkleTree` built but result discarded — uses flat hash instead |
| CHAIN-FIX-9 | LOW | `slashing.rs:552-575` | `enforce_block_signatures_limit` only removes one entry in fallback |
| CHAIN-FIX-10 | LOW | `pruner.rs:244` | `bytes_freed` uses hardcoded estimate (1000 bytes/block) |
| CHAIN-FIX-11 | LOW | `chain.rs:582` | Fork tiebreaker uses non-standard direction (higher hash wins) |

### Features

| ID | Description |
|----|-------------|
| CHAIN-FEAT-1 | Proper Merkle tree integration in `BlockBody` (Task 021) |
| CHAIN-FEAT-2 | **VERITAS-2026-0004**: Validator consensus uses `f32` — non-deterministic cross-platform (KNOWN) |
| CHAIN-FEAT-3 | No block signature verification during sync |
| CHAIN-FEAT-4 | No size limits on incoming sync messages |
| CHAIN-FEAT-5 | Username index unbounded in `ManagedBlockchain` |
| CHAIN-FEAT-6 | Pin set in `MemoryBudget` unbounded |
| CHAIN-FEAT-7 | Validator state not rebuilt from storage during `rebuild_indexes()` |
| CHAIN-FEAT-8 | No username format validation during registration or rebuild |
| CHAIN-FEAT-9 | Region string uses debug formatting `{:?}` — fragile |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| CHAIN-OPT-1 | `chain.rs:603` | `reorganize_to` uses O(n) scan per ancestor step |
| CHAIN-OPT-2 | `chain.rs:386-395` | `has_fork` uses O(n²) height comparison |
| CHAIN-OPT-3 | `chain.rs:202` | `validate_producer` does linear scan of validators — use HashSet |
| CHAIN-OPT-4 | `memory.rs:210-217` | `estimate_block_size` serializes entire block — use `bincode::serialized_size()` |
| CHAIN-OPT-5 | `managed_chain.rs:489-494` | Prune uses reverse O(n) hash→height lookup per block |
| CHAIN-OPT-6 | `storage.rs:135-141` | `InMemoryBackend` uses two separate RwLocks — non-atomic updates |
| CHAIN-OPT-7 | `sled_backend.rs:472-478` | Atomic counters use `Ordering::Relaxed` — `Release`/`Acquire` preferred |

---

## 6. veritas-reputation

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| REP-FIX-1 | **CRITICAL** | `collusion.rs:334-342` | Cluster index mapping broken — non-suspicious components offset indices, lookups return `None`, detection silently non-functional |
| REP-FIX-2 | **HIGH** | `manager.rs:277-289` | Nonce pruning removes arbitrary nonces via `HashSet::iter().take()` — enables replay attacks |
| REP-FIX-3 | **HIGH** | `manager.rs:220-225` | Signature verification silently skipped when `pubkey_registry` is `None` (the default) |
| REP-FIX-4 | **HIGH** | `proof.rs:160`, `manager.rs:194-306` | Deserialized `InteractionProof` bypasses self-interaction check |
| REP-FIX-5 | MEDIUM | `decay.rs:75-78` | `periods_elapsed` produces huge values on clock skew — negative `i64` cast to `u32` wraps |
| REP-FIX-6 | MEDIUM | `score.rs:135-138` | `set_score` does not update `total_gained`/`total_lost` lifetime counters |
| REP-FIX-7 | MEDIUM | `score.rs:160`, `effects.rs:11`, `report.rs:11` | Threshold `400` hardcoded in 3 separate locations — divergence risk |
| REP-FIX-8 | MEDIUM | `manager.rs:440-458` | `mark_decayed` uses wall-clock time instead of computed `now` — skew accumulates |
| REP-FIX-9 | LOW | `report.rs:72-100` | No self-reporting prevention in `NegativeReport` |
| REP-FIX-10 | LOW | Multiple files | `IdentityHash` type alias defined 4 times independently |

### Features

| ID | Description |
|----|-------------|
| REP-FEAT-1 | No persistence/serialization for `ReputationManager` — state lost on restart |
| REP-FEAT-2 | No event/notification system for reputation state changes |
| REP-FEAT-3 | No rate limiting for reporters filing against different targets |
| REP-FEAT-4 | No collusion detection for coordinated negative reporting |
| REP-FEAT-5 | `evidence_hash` stored but never verified or used |
| REP-FEAT-6 | Unbounded collection growth between cleanup calls |
| REP-FEAT-7 | `ReputationManager` not serializable due to `Arc<dyn PubkeyRegistry>` |
| REP-FEAT-8 | No batch/bulk APIs for querying multiple identities |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| REP-OPT-1 | `decay.rs:111-127` | Decay loop O(n) — use closed-form `(1-rate)^periods` via `powf` |
| REP-OPT-2 | `collusion.rs:129-142` | `get_neighbors` does full linear scan of all edges — use adjacency list index |
| REP-OPT-3 | `collusion.rs:328-343` | `analyze_clusters` rebuilds everything from scratch — incremental would be better |
| REP-OPT-4 | `manager.rs:443` | `apply_decay_to_all` collects all keys into Vec — borrow-checker workaround |
| REP-OPT-5 | `manager.rs:194-305` | Multiple redundant HashMap lookups in `record_positive_interaction` |
| REP-OPT-6 | `manager.rs:56` | Nonce storage should use time-partitioned sets or bloom filter |
| REP-OPT-7 | `collusion.rs:188-212` | Comment says "BFS" but uses `Vec::pop()` (DFS) — misleading |

---

## 7. veritas-net

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| NET-FIX-1 | **HIGH** | `gossip.rs:808-812` | Seen-messages set cleared entirely at 10K — creates replay attack window |
| NET-FIX-2 | MEDIUM | `rate_limiter.rs:288-300` | Global token consumed before per-peer check — misbehaving peer drains global capacity |
| NET-FIX-3 | **HIGH** | `dht.rs:230-233` | DHT record deserialization has no size validation before `bincode::deserialize` |
| NET-FIX-4 | MEDIUM | `gossip.rs:287-392` | Gossip announcement deserialization has no size validation |
| NET-FIX-5 | MEDIUM | `dht.rs:423-424` | `DhtStorage` local store uses unbounded `HashMap` |
| NET-FIX-6 | MEDIUM | `dht.rs:241-244` | `DhtRecordSet` records vector unbounded per mailbox key |
| NET-FIX-7 | LOW | `relay.rs:338` | `seen_hashes` can grow between prune cycles |
| NET-FIX-8 | LOW | `node.rs:1132-1135` | `addresses_of_peer` always returns empty vector |
| NET-FIX-9 | LOW | `transport.rs` / `transport_manager.rs` | Duplicate `TransportType` and `TransportStats` definitions |
| NET-FIX-10 | LOW | `discovery.rs:116-124` | Discovery peer addresses grow without bound |

### Features

| ID | Description |
|----|-------------|
| NET-FEAT-1 | Bluetooth transport entirely stubbed (known P3) |
| NET-FEAT-2 | No address book for peer address tracking |
| NET-FEAT-3 | No connection limits configured in libp2p swarm |
| NET-FEAT-4 | No periodic DHT record republishing |
| NET-FEAT-5 | No QUIC transport (lower latency, better NAT traversal) |
| NET-FEAT-6 | No WebSocket transport despite CLI accepting `--ws-addr` |
| NET-FEAT-7 | No graceful shutdown for `VeritasNode` |
| NET-FEAT-8 | No ban synchronization between rate_limiter and subnet_limiter |
| NET-FEAT-9 | No persistent peer address storage |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| NET-OPT-1 | `transport_manager.rs:443-498` | `select_transport` acquires RwLock up to 3 times — single acquisition better |
| NET-OPT-2 | `relay.rs:616-652` | `increment_hop`/`record_forward_attempt` do O(n) scans — use secondary index |
| NET-OPT-3 | `dht.rs:719` | `has_messages` takes write lock for read-like operation |
| NET-OPT-4 | `gossip.rs:426-458` | `LocalRateLimiter` uses `Vec<Instant>` with linear scan — use VecDeque |
| NET-OPT-5 | `discovery.rs:116-124` | Address dedup uses `Vec::contains` — use HashSet |
| NET-OPT-6 | `relay.rs:662-707` | `prune_expired` iterates messages twice — combine into single pass |

---

## 8. veritas-node

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| NODE-FIX-1 | **HIGH** | `main.rs:218-249` | Node does not actually start P2P event loop — binary is non-functional |
| NODE-FIX-2 | MEDIUM | `main.rs:140-179` | Health check server has no timeout, connection limit, or robust HTTP parsing |
| NODE-FIX-3 | LOW | `Cargo.toml` | Multiple unused dependencies (`veritas-crypto`, `veritas-identity`, etc.) |
| NODE-FIX-4 | LOW | `main.rs:249` | Graceful shutdown commented out — connections dropped abruptly |
| NODE-FIX-5 | LOW | `main.rs:23` | Default data dir `/var/lib/veritas` requires root — use `~/.veritas` |

### Features

| ID | Description |
|----|-------------|
| NODE-FEAT-1 | At least 7 CLI arguments accepted but silently ignored (`listen_addr`, `ws_addr`, `max_connections`, etc.) |

---

## 9. veritas-core

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| CORE-FIX-1 | MEDIUM | `client.rs:512-554` | TOCTOU race in `require_unlocked`/`require_unlocked_mut` — drops state lock before services lock |
| CORE-FIX-2 | **HIGH** | `identity_manager.rs:201-217` | `set_primary_identity` does NOT update `self.primary_identity` cached keypair |
| CORE-FIX-3 | MEDIUM | `identity_manager.rs:164-190` | In-memory `IdentityManager` does not enforce 3-identity slot limit |
| CORE-FIX-4 | LOW | `client.rs:392-394` | Password accepted but silently ignored in in-memory mode |
| CORE-FIX-5 | **HIGH** | `identity_manager.rs:173-188` | Non-primary keypairs immediately dropped — private keys permanently lost |

### Features

| ID | Description |
|----|-------------|
| CORE-FEAT-1 | All messaging, group, and verification methods are stubs (`NotImplemented`) |
| CORE-FEAT-2 | Missing `SafetyNumber::from_bytes()` constructor — forces FFI/WASM to reimplement |
| CORE-FEAT-3 | No RAII pattern for lock lifecycle (auto-lock on drop) |
| CORE-FEAT-4 | `ChainService`, `MessageService`, `ReputationService` are stubs |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| CORE-OPT-1 | `safety.rs:197-245` | `to_numeric_string`/`to_qr_string` use repeated `format!` calls |
| CORE-OPT-2 | `identity_manager.rs:168-171` | `SystemTime` unwrap_or_default silently returns 0 on clock error |
| CORE-OPT-3 | `client.rs:695` | `list_identities()` clones to Vec on every call |

---

## 10. veritas-ffi

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| FFI-FIX-1 | **HIGH** | `client.rs:55-58` (etc.) | New tokio `Runtime::new()` on every FFI call — thread pool creation per API call |
| FFI-FIX-2 | **HIGH** | `types.rs:48-54` | `from_ptr` returns `&mut ClientHandle` — concurrent FFI calls are UB |
| FFI-FIX-3 | MEDIUM | `safety.rs:227-245` | Duplicated safety number formatting logic — divergence risk |
| FFI-FIX-4 | LOW | `error.rs:43` | `BufferTooSmall` maps to `InvalidArgument` — ambiguous error code |
| FFI-FIX-5 | LOW | `error.rs:44-53` | Missing error codes for `AuthenticationFailed`, `Locked`, `NotInitialized`, etc. |
| FFI-FIX-6 | LOW | `client.rs:43-45` | `catch_unwind` closures not checked for `UnwindSafe` |

### Features

| ID | Description |
|----|-------------|
| FFI-FEAT-1 | No `veritas_last_error()` function for retrieving error message strings |
| FFI-FEAT-2 | No `veritas_list_identities` function |
| FFI-FEAT-3 | No `veritas_set_primary_identity` function |
| FFI-FEAT-4 | No `veritas_client_state` function |
| FFI-FEAT-5 | No build-time C header compilation test |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| FFI-OPT-1 | `types.rs:72-98` | `IdentitySlots` struct created then immediately destructured — unnecessary |
| FFI-OPT-2 | `identity.rs:88,200` | Hex string allocation for buffer copy — write hex directly |

---

## 11. veritas-wasm

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| WASM-FIX-1 | **HIGH** | `client.rs:228` | Hardcoded Argon2 salt (`"veritas-wasm-storage-v1"`) — enables rainbow table attacks |
| WASM-FIX-2 | **HIGH** | `client.rs:219-220` | Installation ID regenerated every `new()` — Sybil resistance defeated on page refresh |
| WASM-FIX-3 | MEDIUM | `client.rs:75-78` | `std::sync::Mutex` in WASM — latent deadlock if async methods added |
| WASM-FIX-4 | MEDIUM | `client.rs:276-290` | Nested lock acquisition without documented ordering |
| WASM-FIX-5 | MEDIUM | `safety.rs:90-136` | Reimplemented safety number computation — consistency risk with core |
| WASM-FIX-6 | LOW | `client.rs:145,155` | `.unwrap()` on serialization — should propagate error |

### Features

| ID | Description |
|----|-------------|
| WASM-FEAT-1 | No persistence layer (no IndexedDB integration) — identities lost on refresh |
| WASM-FEAT-2 | No async API despite docs showing `await` examples |
| WASM-FEAT-3 | No `set_primary_identity` method |
| WASM-FEAT-4 | No cross-platform safety number verification test |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| WASM-OPT-1 | `client.rs:225-253` | Argon2 blocks browser main thread — move to Web Worker |

---

## 12. veritas-py

### Fixes

| ID | Severity | File:Line | Description |
|----|----------|-----------|-------------|
| PY-FIX-1 | MEDIUM | `identity.rs:56-64` | `__repr__` slices hash `[..16]` without length check — panic on short hash |
| PY-FIX-2 | LOW | `safety.rs:112-114` | `SafetyNumber` has `__eq__` but not `__hash__` — unhashable in Python |
| PY-FIX-3 | MEDIUM | `client.rs` (all methods) | All operations `block_on` while holding GIL — prevents concurrent Python threads |
| PY-FIX-4 | LOW | `identity.rs:40` | `key_state` uses `Debug` formatting — exposes Rust internals |

### Features

| ID | Description |
|----|-------------|
| PY-FEAT-1 | No async API support (no `pyo3-asyncio` integration) |
| PY-FEAT-2 | No context manager protocol (`__enter__`/`__exit__` for auto-lock) |
| PY-FEAT-3 | No `__str__` on `VeritasClient` |
| PY-FEAT-4 | No `__eq__` on `IdentityInfo` or `IdentitySlots` |

### Optimizations

| ID | File:Line | Description |
|----|-----------|-------------|
| PY-OPT-1 | `client.rs` | Use `py.allow_threads()` around `block_on` calls to release GIL |

---

## 13. Cross-Cutting Concerns

### 13.1 Safety Number Implementation Divergence

Three independent implementations exist:

| Crate | Computation | Formatting |
|-------|-------------|------------|
| `veritas-core` | `SafetyNumber::compute()` | `to_numeric_string()` |
| `veritas-ffi` | Delegates to core | **Reimplemented** `format_safety_number_numeric()` |
| `veritas-wasm` | **Reimplemented** `compute_internal()` | **Reimplemented** `to_numeric_string()` |
| `veritas-py` | Delegates to core | Delegates to core |

**Recommendation**: Add `SafetyNumber::from_bytes([u8; 32])` to core. Have all bindings delegate computation and formatting to core.

### 13.2 API Surface Parity

| Feature | Core | FFI | WASM | Python |
|---------|:----:|:---:|:----:|:------:|
| create client | ✅ | ✅ | ✅ | ✅ |
| unlock/lock | ✅ | ✅ | ✅ | ✅ |
| shutdown | ✅ | ✅ | ✅ | ✅ |
| is_unlocked | ✅ | ❌ | ✅ | ✅ |
| state | ✅ | ❌ | ❌ | ✅ |
| identity_hash | ✅ | ✅ | ✅ | ✅ |
| public_keys | ✅ | ❌ | ✅ | ✅ |
| create_identity | ✅ | ✅ | ✅ | ✅ |
| list_identities | ✅ | ❌ | ✅ | ✅ |
| set_primary | ✅ | ❌ | ❌ | ✅ |
| identity_slots | ✅ | ✅ | ✅ | ✅ |
| safety_number | ✅ | ✅ | ✅ | ✅ |

The FFI binding has the smallest API surface, missing 5 features.

### 13.3 Pre-Deserialization Size Validation

The CLAUDE.md mandates size validation before `bincode::deserialize`. Several locations still violate this:

| File | Missing Check |
|------|---------------|
| `identity/keypair.rs` `IdentityPublicKeys::from_bytes()` | No max size |
| `identity/keypair.rs` `EncryptedIdentityKeyPair::from_bytes()` | No max size |
| `protocol/delivery.rs` `DeliveryReceipt::from_bytes()` | No max size |
| `net/dht.rs` `DhtRecord::from_bytes()` | No max size |
| `net/dht.rs` `DhtRecordSet::from_bytes()` | No max size |
| `net/gossip.rs` `MessageAnnouncement::from_bytes()` | No max size |
| `net/gossip.rs` `BlockAnnouncement::from_bytes()` | No max size |
| `net/gossip.rs` `ReceiptAnnouncement::from_bytes()` | No max size |
| `store/keyring.rs` `ExportedIdentity::from_bytes()` | No max size |

### 13.4 Remaining TASKS.md Items

| Task | Status | Notes |
|------|--------|-------|
| TASK-170: Async closures refactoring | NOT STARTED | P4, optional |
| TASK-171: Remove unnecessary `.clone()` calls | NOT STARTED | P3 |
| VERITAS-2026-0004: Validator consensus | DESIGN NEEDED | Use fixed-point arithmetic, on-chain metrics |
| Hardware attestation | STUBS | TPM/SecureEnclave/AndroidKeystore need native code |
| Bluetooth (btleplug) | STUBBED | P3 |

---

## Recommended Remediation Order

### Phase 1: Critical / Data Loss (Immediate)

1. **REP-FIX-1**: Fix collusion cluster index mapping (collusion detection currently broken)
2. **CORE-FIX-5 + CORE-FIX-2**: Store all keypairs and update cached primary on switch
3. **WASM-FIX-1 + WASM-FIX-2**: Generate random Argon2 salt, persist installation ID
4. **FFI-FIX-1**: Store tokio runtime in `ClientHandle`, reuse across calls
5. **PROTO-FIX-2**: Add `envelope.validate()` at start of `decrypt_as_recipient`

### Phase 2: Security Hardening

6. **PROTO-FIX-3**: Fix mailbox salt mismatch in `encrypt_for_recipient`
7. **PROTO-FIX-9**: Replace hash-based receipt signatures with signing module
8. **REP-FIX-2**: Replace `HashSet` nonce pruning with time-partitioned structure
9. **REP-FIX-3**: Require `PubkeyRegistry` or error loudly when missing
10. **REP-FIX-4**: Add `from != to` check in `record_positive_interaction`
11. **CHAIN-FIX-1 + CHAIN-FIX-2**: Add parent hash validation and bound sync vectors
12. **NET-FIX-1**: Replace gossip `seen_messages.clear()` with LRU cache
13. Add pre-deserialization size checks to all 9 identified locations (§13.3)

### Phase 3: Correctness

14. **IDENT-FIX-1**: Wrap decrypted plaintext in `Zeroizing<Vec<u8>>`
15. **FFI-FIX-2**: Change `from_ptr` to return shared reference
16. **CHAIN-FIX-4**: Fix pruner threshold (`.min()` → `.max()`)
17. **STORE-FIX-5**: Make `change_password` atomic with sled transaction
18. **NODE-FIX-1**: Actually start the P2P event loop

### Phase 4: Features & Optimization

19. Add `SafetyNumber::from_bytes()` to eliminate bindings duplication
20. Implement persistence for `ReputationManager`
21. Add async API to Python bindings (release GIL)
22. Implement QUIC and WebSocket transports
23. Performance optimizations (decay O(1), adjacency list for collusion, etc.)

---

**Report Prepared By**: Claude Code Security Team
**Date**: 2026-02-06
