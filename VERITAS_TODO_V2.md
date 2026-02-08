# VERITAS Protocol — Comprehensive TODO v2

**Generated**: 2026-02-06 (revised)
**Source Documents**: `DESIGN_CRITIQUE.md` (42 findings), `PROTOCOL_REVIEW.md` (~95 findings), owner clarifications
**Current Version**: v0.8.0-beta (Milestone 6 complete) → targeting v1.0 (production)

---

## Architecture Decisions (Owner-Confirmed)

These decisions override any conflicting assumptions in the original review documents.

### AD-1: Chain as Message Transport

The blockchain IS the message exchange layer. Every encrypted message is a transaction. Blocks are batches of message transactions. The chain provides ordering, integrity, delivery guarantees, and proof of communication. Usernames, key rotations, and reputation changes are specific transaction types alongside message transactions.

### AD-2: Epoch-Based Pruning (30-Day Retention)

- **During epoch** (30 days): Full transaction on-chain — ML-DSA signature + encrypted body + header
- **After epoch ends**: Body + signature pruned. Only the header remains permanently
- **Headers are permanent and unsigned** — they serve as historical proof of communication
- **Client-side messages persist independently** — if user hasn't deleted them, they can still read them
- This is a deliberate anonymity feature, not just an optimization

### AD-3: ML-DSA Signing (No Ed25519 Transition)

All signing goes directly to ML-DSA (lattice-based, FIPS 204). No Ed25519 intermediate step. The existing placeholder HMAC-BLAKE3 signing is replaced entirely with ML-DSA. This is a hard cutover — the existing chain is test data with no real signatures to preserve.

Rationale: Cloudflare runs lattice crypto in production. The `ml-dsa` RustCrypto crate (0.1.x, already in Cargo.toml) implements FIPS 204 final and passes NIST test vectors. While not independently audited, the underlying math is NIST-standardized.

**Size implications** (ML-DSA-65):
- Public key: 1,952 bytes (vs Ed25519's 32 bytes)
- Signature: 3,309 bytes (vs Ed25519's 64 bytes)
- These sizes are pruned after epoch end, so long-term storage is unaffected

### AD-4: Two Validator Tiers

- **Full validators**: Hold complete blocks (headers + bodies + signatures). Validate consensus. Produce blocks. Hosted by trusted organizations/individuals.
- **Light validators**: Hold headers + signatures only (no message bodies). Can validate transaction history during the epoch. After epoch, signatures pruned — converge to same state as full validators (headers only).
- More validators = more anonymity (traffic blends across more nodes)
- Users maintain a list of trusted validators with 3 lines of trust as fallback

### AD-5: Bluetooth Last-Mile Relay (Future Milestone)

Bluetooth mesh is NOT offline chat — it's a **last-mile relay to get messages back onto the chain**. Messages hop device-to-device over BLE until one device has internet connectivity to a validator, then that device submits the transaction.

- Native app only (requires BLE permissions)
- Deferred until protocol is solid and working
- If trusted validators are unreachable, user gets a warning to review validator list
- Known metadata risk: relaying device knows approximate location/timing of sender

### AD-6: P2P Image Exchange with On-Chain Proof

- Images are transferred P2P (direct connection), NOT on-chain
- Only a proof/receipt goes on-chain (hash of image, delivery confirmation)
- User gets explicit warning that P2P image transfer can break anonymity (direct connection = IP exposure)
- On-chain proof follows same epoch pruning rules

---

## How to Read This Document

Each item has: **ID** (original finding ID), **Crate(s)**, **Effort**, **Breaking** flag, **Instruction Set** mapping. Items grouped by milestone, ordered by priority within each milestone.

---

## Milestone 1: Critical Code Fixes (v0.3.1-beta) — COMPLETED

> **Goal**: Fix all CRITICAL and HIGH severity code bugs. No architectural changes. No wire format changes. Ship fast.
> **Estimated Effort**: 2–3 instruction sets, ~1 week total
> **Branch Pattern**: `fix/{description}`
>
> **Status**: All 20 fix categories (1.1-1.20) implemented. 44 files changed across 12 crates. ~60 bugs fixed: 1 CRITICAL, 16 HIGH, ~23 MEDIUM, ~20 LOW. All 1,549 tests pass (0 failures). Build succeeds cleanly.

### 1.1 — CRITICAL: Collusion Detection Broken

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | REP-FIX-1 |
| **Crate** | `veritas-reputation` |
| **File** | `collusion.rs:334-342` |
| **Severity** | CRITICAL |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: Cluster index mapping is broken — non-suspicious components offset the indices used to look up suspicious clusters. All lookups return `None`. Collusion detection is **silently non-functional**.

**Fix**: Rebuild the index mapping so that only suspicious cluster indices are used for lookups. The `analyze_clusters` function must return correctly indexed results.

**Tests**: Add test that detects a known collusion pattern (5 nodes with dense mutual interactions) and verify the cluster is flagged.

**Resolution**: Fixed cluster index mapping so only suspicious cluster indices are used for lookups.

---

### 1.2 — HIGH: Non-Primary Keypairs Permanently Lost

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CORE-FIX-5, CORE-FIX-2 |
| **Crate** | `veritas-core` |
| **File** | `identity_manager.rs:173-188, 201-217` |
| **Severity** | HIGH |
| **Effort** | Medium |
| **Breaking** | No |

**Problem**: When creating identities beyond the first, the keypair is immediately dropped — private keys are permanently lost. Additionally, `set_primary_identity` does not update the cached `self.primary_identity` keypair.

**Fix**:
1. Store all keypairs (up to 3 per slot limit) in the identity manager, not just the primary
2. `set_primary_identity` must update `self.primary_identity` to reflect the new selection
3. Enforce the 3-identity slot limit in the in-memory manager (CORE-FIX-3)

**Tests**: Create 3 identities, switch primary, verify all keypairs accessible. Verify 4th creation fails.

**Resolution**: Non-primary keypairs now stored in identity manager. `set_primary_identity` updates cached keypair.

---

### 1.3 — HIGH: Tokio Runtime Per FFI Call

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | FFI-FIX-1 |
| **Crate** | `veritas-ffi` |
| **File** | `client.rs:55-58` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No (internal) |

**Problem**: Every FFI function call creates a new tokio `Runtime`. This spawns a new thread pool per call — massive overhead.

**Fix**: Store a `tokio::runtime::Runtime` inside `ClientHandle`. Create it once in `veritas_client_create()`, reuse for all subsequent calls.

**Resolution**: FFI now uses a single shared runtime created once in `veritas_client_create()`.

---

### 1.4 — HIGH: FFI `from_ptr` Returns `&mut` — UB on Concurrent Calls

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | FFI-FIX-2 |
| **Crate** | `veritas-ffi` |
| **File** | `types.rs:48-54` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No (internal) |

**Problem**: `from_ptr` returns `&mut ClientHandle`, making concurrent FFI calls from multiple threads undefined behavior.

**Fix**: Return `&ClientHandle` (shared reference). If mutation is needed, use interior mutability (`Mutex` or `RwLock` inside `ClientHandle`).

**Resolution**: FFI now uses shared reference (`&ClientHandle`) eliminating UB on concurrent calls.

---

### 1.5 — HIGH: WASM Hardcoded Argon2 Salt

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | WASM-FIX-1, WASM-FIX-2 |
| **Crate** | `veritas-wasm` |
| **File** | `client.rs:219-228` |
| **Severity** | HIGH |
| **Effort** | Medium |
| **Breaking** | Yes (stored keys re-derived) |

**Problem**: Argon2 salt is hardcoded to `"veritas-wasm-storage-v1"` — enables pre-computed rainbow table attacks. Additionally, the installation ID is regenerated on every `new()`, defeating Sybil resistance on page refresh.

**Fix**:
1. Generate a random 16-byte salt per client instance, store it alongside the encrypted data
2. Persist the installation ID to browser storage (localStorage or IndexedDB) so it survives refresh
3. Add migration path for existing stored data (re-encrypt with random salt on first load)

**Resolution**: WASM now uses random Argon2 salt per instance and persists installation ID to browser storage.

---

### 1.6 — HIGH: Ephemeral Key Not Validated Before ECDH

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | PROTO-FIX-2 |
| **Crate** | `veritas-protocol` |
| **File** | `e2e.rs:244-282` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: `decrypt_as_recipient` does not call `envelope.validate()` before performing ECDH. A low-order point ephemeral key bypasses the check and produces a predictable shared secret.

**Fix**: Add `envelope.validate()` as the first operation in `decrypt_as_recipient`. The validate function already checks for low-order points.

**Resolution**: Ephemeral key is now validated before ECDH in `decrypt_as_recipient`.

---

### 1.7 — HIGH: Mailbox Salt Mismatch

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | PROTO-FIX-3 |
| **Crate** | `veritas-protocol` |
| **File** | `e2e.rs:185-187` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | Yes (wire format — salt derivation) |

**Problem**: The salt stored in `EncryptedMessage` doesn't match the salt used during mailbox key derivation. The recipient cannot re-derive the correct mailbox key.

**Fix**: Ensure the salt used for HKDF derivation is the same salt embedded in the message. Verify roundtrip: `encrypt_for_recipient` → `decrypt_as_recipient` with salt consistency.

**Resolution**: Mailbox salt is now consistent between encryption and decryption paths.

---

### 1.8 — HIGH: Receipt Signatures Forgeable

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | PROTO-FIX-9 |
| **Crate** | `veritas-protocol` |
| **File** | `delivery.rs:343-344, 419-421` |
| **Severity** | HIGH |
| **Effort** | Medium |
| **Breaking** | Yes (receipt format) |

**Problem**: Receipt "signatures" are just hash comparisons using non-constant-time `==`. Anyone can forge a receipt by computing the hash.

**Fix**: Replace hash-based receipt signatures with `ConstantTimeEq` as interim measure. Full fix arrives with ML-DSA signing in Milestone 2.

**Resolution**: Receipt signatures now use keyed HMAC-BLAKE3 with `ConstantTimeEq` for verification.

---

### 1.9 — HIGH: Sync Header Validation Missing Parent Hash

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CHAIN-FIX-1 |
| **Crate** | `veritas-chain` |
| **File** | `sync.rs:599-607` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: During chain sync, header validation does not verify parent hash linkage. An attacker can submit fabricated chain segments with correct individual headers but broken parent links.

**Fix**: Verify `header[n].parent_hash == header[n-1].hash()` for every consecutive pair in the sync batch.

**Resolution**: Sync now validates parent hash linkage for every consecutive pair in the sync batch.

---

### 1.10 — HIGH: Sync Vectors Unbounded — Memory Exhaustion

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CHAIN-FIX-2 |
| **Crate** | `veritas-chain` |
| **File** | `sync.rs` (multiple) |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: `pending_headers` and `received_blocks` vectors grow without bound during sync. A malicious peer can exhaust memory.

**Fix**: Cap both vectors at a configurable maximum (e.g., 1000 entries). Reject additional sync data beyond the cap.

**Resolution**: Sync vectors are now bounded with configurable maximums.

---

### 1.11 — HIGH: Reputation Nonce Pruning Enables Replay

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | REP-FIX-2 |
| **Crate** | `veritas-reputation` |
| **File** | `manager.rs:277-289` |
| **Severity** | HIGH |
| **Effort** | Medium |
| **Breaking** | No |

**Problem**: Nonce pruning uses `HashSet::iter().take()` which removes arbitrary nonces. This creates a window where pruned nonces can be replayed.

**Fix**: Replace with time-partitioned nonce sets (buckets by epoch). Prune entire old buckets instead of random entries.

**Resolution**: Time-bucketed nonce tracking replaces random pruning, eliminating replay window.

---

### 1.12 — HIGH: Reputation Signature Verification Silently Skipped

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | REP-FIX-3 |
| **Crate** | `veritas-reputation` |
| **File** | `manager.rs:220-225` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: When `pubkey_registry` is `None` (the default!), signature verification on interaction proofs is silently skipped. Any forged proof is accepted.

**Fix**: Make `pubkey_registry` required — either `require()` it at construction or return an error when verification is attempted without one.

**Resolution**: Signature verification now returns an error when registry is unavailable instead of silently skipping.

---

### 1.13 — HIGH: Self-Interaction Check Bypassed on Deserialization

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | REP-FIX-4 |
| **Crate** | `veritas-reputation` |
| **File** | `proof.rs:160`, `manager.rs:194-306` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: Deserialized `InteractionProof` objects bypass the `from != to` self-interaction check that's enforced during construction.

**Fix**: Add `from != to` validation in `record_positive_interaction` before processing, regardless of how the proof was constructed.

**Resolution**: Self-interaction check now enforced at recording time, not just construction.

---

### 1.14 — HIGH: Gossip Seen-Messages Set Creates Replay Window

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | NET-FIX-1 |
| **Crate** | `veritas-net` |
| **File** | `gossip.rs:808-812` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: The `seen_messages` set is cleared entirely when it reaches 10K entries. After clearing, all previously seen messages can be replayed.

**Fix**: Replace with an LRU cache (e.g., `lru` crate). Old entries are evicted one at a time as new entries arrive.

**Resolution**: LRU-style seen-messages cache replaces clear-all approach, preventing replay window.

---

### 1.15 — HIGH: DHT Record Deserialization Unbounded

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | NET-FIX-3 |
| **Crate** | `veritas-net` |
| **File** | `dht.rs:230-233` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: `DhtRecord::from_bytes` has no pre-deserialization size check. Crafted input can cause excessive memory allocation during deserialization.

**Fix**: Add size validation before `bincode::deserialize` — reject inputs exceeding `MAX_DHT_RECORD_SIZE`.

**Resolution**: Pre-deserialization size checks added on DHT records.

---

### 1.16 — HIGH: Decrypted Plaintext Not Zeroized

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | IDENT-FIX-1 |
| **Crate** | `veritas-identity` |
| **File** | `keypair.rs:339-342` |
| **Severity** | HIGH |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: In `from_encrypted()`, the decrypted plaintext (`Vec<u8>`) containing key material is not zeroized — it persists in heap memory after the function returns.

**Fix**: Wrap decrypted plaintext in `Zeroizing<Vec<u8>>` from the `zeroize` crate.

**Resolution**: Decrypted plaintext now wrapped in `Zeroizing<Vec<u8>>` for automatic zeroization.

---

### 1.17 — HIGH: Node Binary Non-Functional

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | NODE-FIX-1 |
| **Crate** | `veritas-node` |
| **File** | `main.rs:218-249` |
| **Severity** | HIGH |
| **Effort** | Medium |
| **Breaking** | No |

**Problem**: The node binary does not actually start the P2P event loop. The binary compiles and runs but does nothing.

**Fix**: Wire up the `VeritasNode` event loop in `main()`. Actually start listening, connect to bootstrap nodes, and begin gossip/DHT operations.

**Resolution**: Node binary wired up with event loop for P2P operations.

---

### 1.18 — MEDIUM: Pre-Deserialization Size Checks (9 locations)

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | PROTO-FIX-8, IDENT-FIX-3, STORE-FIX-3, NET-FIX-4, Cross-§13.3 |
| **Crates** | `veritas-identity`, `veritas-protocol`, `veritas-net`, `veritas-store` |
| **Severity** | MEDIUM |
| **Effort** | Low |
| **Breaking** | No |

**Problem**: 9 `from_bytes()` methods across 4 crates lack pre-deserialization size validation, violating CLAUDE.md rules.

**Locations**:
1. `identity/keypair.rs` — `IdentityPublicKeys::from_bytes()`
2. `identity/keypair.rs` — `EncryptedIdentityKeyPair::from_bytes()`
3. `protocol/delivery.rs` — `DeliveryReceipt::from_bytes()`
4. `net/dht.rs` — `DhtRecord::from_bytes()` (covered by 1.15)
5. `net/dht.rs` — `DhtRecordSet::from_bytes()`
6. `net/gossip.rs` — `MessageAnnouncement::from_bytes()`
7. `net/gossip.rs` — `BlockAnnouncement::from_bytes()`
8. `net/gossip.rs` — `ReceiptAnnouncement::from_bytes()`
9. `store/keyring.rs` — `ExportedIdentity::from_bytes()`

**Fix**: Add `if bytes.len() > MAX_*_SIZE { return Err(...) }` before every `bincode::deserialize` call.

**Resolution**: Pre-deserialization size checks added on all 9 `from_bytes` locations across 4 crates.

---

### 1.19 — MEDIUM: Remaining Medium-Severity Code Fixes

**Status**: Completed (23 fixes across crypto, chain, net, store, FFI, WASM, Python)

| ID | Crate | Description | Status |
|----|-------|-------------|--------|
| CRYPTO-FIX-1 | `veritas-crypto` | `MlDsaPrivateKey` missing `Zeroize`/`ZeroizeOnDrop` | Fixed |
| CRYPTO-FIX-2 | `veritas-crypto` | `MlKemPrivateKey` missing `Zeroize`/`ZeroizeOnDrop` | Fixed |
| IDENT-FIX-2 | `veritas-identity` | `Clone` silently drops signing private key | Fixed |
| IDENT-FIX-4 | `veritas-identity` | `OriginFingerprint::new()` bypasses attestation | Fixed |
| PROTO-FIX-1 | `veritas-protocol` | Non-constant-time zero check in ephemeral key validation | Fixed |
| PROTO-FIX-4 | `veritas-protocol` | Silent `unwrap_or_default()` produces wrong hash | Fixed |
| CHAIN-FIX-3 | `veritas-chain` | Pending count uses cumulative received — premature state transitions | Fixed |
| CHAIN-FIX-4 | `veritas-chain` | Pruner threshold `.min()` → `.max()` | Fixed |
| CHAIN-FIX-5 | `veritas-chain` | `ChainEntry::hash()` identical on serialization failure | Fixed |
| CHAIN-FIX-6 | `veritas-chain` | `f32` overflow in slashing penalty for large stakes | Fixed |
| REP-FIX-5 | `veritas-reputation` | `periods_elapsed` wraps on clock skew | Fixed |
| REP-FIX-6 | `veritas-reputation` | `set_score` doesn't update lifetime counters | Fixed |
| REP-FIX-7 | `veritas-reputation` | Threshold `400` hardcoded in 3 separate locations | Fixed |
| REP-FIX-8 | `veritas-reputation` | `mark_decayed` uses wall-clock instead of computed `now` | Fixed |
| NET-FIX-2 | `veritas-net` | Global token consumed before per-peer check | Fixed |
| NET-FIX-5 | `veritas-net` | `DhtStorage` local store unbounded HashMap | Fixed |
| NET-FIX-6 | `veritas-net` | `DhtRecordSet` records vector unbounded | Fixed |
| STORE-FIX-5 | `veritas-store` | `change_password` non-atomic | Fixed |
| NODE-FIX-2 | `veritas-node` | Health check server has no timeout/limit | Fixed |
| WASM-FIX-3 | `veritas-wasm` | `std::sync::Mutex` in WASM | Fixed |
| WASM-FIX-4 | `veritas-wasm` | Nested lock acquisition without ordering | Fixed |
| WASM-FIX-5 | `veritas-wasm` | Reimplemented safety number — divergence risk | Fixed |
| PY-FIX-1 | `veritas-py` | `__repr__` slices hash without length check | Fixed |
| PY-FIX-3 | `veritas-py` | All operations `block_on` while holding GIL | Fixed |
| FFI-FIX-3 | `veritas-ffi` | Duplicated safety number formatting | Fixed |

---

### 1.20 — LOW: Low-Severity Code Fixes

**Status**: Completed (33 fixes across all crates)

| ID | Crate | Description | Status |
|----|-------|-------------|--------|
| CRYPTO-FIX-3 | `veritas-crypto` | `X25519StaticPrivateKey` implements `Clone` | Fixed |
| CRYPTO-FIX-4 | `veritas-crypto` | `Hash256::is_zero()` non-constant-time | Fixed |
| CRYPTO-FIX-5 | `veritas-crypto` | `from_hex()` returns wrong error variant | Fixed |
| IDENT-FIX-5 | `veritas-identity` | `register_rotation()` no duplicate check | Fixed |
| IDENT-FIX-6 | `veritas-identity` | `update_state()` lacks timestamp validation | Fixed |
| IDENT-FIX-7 | `veritas-identity` | `touch()` accepts any timestamp | Fixed |
| IDENT-FIX-8 | `veritas-identity` | `UsernameRegistration::new()` accepts empty signatures | Fixed |
| PROTO-FIX-5 | `veritas-protocol` | `epoch_from_timestamp` uses `debug_assert!` | Fixed |
| PROTO-FIX-6 | `veritas-protocol` | `GroupMessage` `PartialEq` compares by hash | Fixed |
| PROTO-FIX-7 | `veritas-protocol` | Dead code in `remove_member_and_rotate` | Fixed |
| PROTO-FIX-10 | `veritas-protocol` | `GroupMessageData::hash()` uses LE, rest uses BE | Fixed |
| PROTO-FIX-11 | `veritas-protocol` | `key_generation` overflow via `saturating_add` | Fixed |
| CHAIN-FIX-7 | `veritas-chain` | `cache_capacity` overflows on 32-bit | Fixed |
| CHAIN-FIX-8 | `veritas-chain` | MerkleTree built but result discarded | Fixed |
| CHAIN-FIX-9 | `veritas-chain` | `enforce_block_signatures_limit` only removes one entry | Fixed |
| CHAIN-FIX-10 | `veritas-chain` | `bytes_freed` uses hardcoded 1000 bytes | Fixed |
| CHAIN-FIX-11 | `veritas-chain` | Fork tiebreaker non-standard direction | Fixed |
| REP-FIX-9 | `veritas-reputation` | No self-reporting prevention | Fixed |
| REP-FIX-10 | `veritas-reputation` | `IdentityHash` type alias defined 4 times | Fixed |
| NET-FIX-7 | `veritas-net` | `seen_hashes` can grow between prune cycles | Fixed |
| NET-FIX-8 | `veritas-net` | `addresses_of_peer` always returns empty | Fixed |
| NET-FIX-9 | `veritas-net` | Duplicate `TransportType`/`TransportStats` | Fixed |
| NET-FIX-10 | `veritas-net` | Discovery peer addresses grow without bound | Fixed |
| STORE-FIX-1 | `veritas-store` | `PasswordKey::as_symmetric_key()` recreates each call | Fixed |
| STORE-FIX-2 | `veritas-store` | `export_identity` double-encrypts with same key | Fixed |
| STORE-FIX-4 | `veritas-store` | Metadata flush after every operation | Fixed |
| NODE-FIX-3 | `veritas-node` | Unused dependencies | Fixed |
| NODE-FIX-4 | `veritas-node` | Graceful shutdown commented out | Fixed |
| NODE-FIX-5 | `veritas-node` | Default data dir requires root | Fixed |
| WASM-FIX-6 | `veritas-wasm` | `.unwrap()` on serialization | Fixed |
| PY-FIX-2 | `veritas-py` | `SafetyNumber` has `__eq__` but not `__hash__` | Fixed |
| PY-FIX-4 | `veritas-py` | `key_state` uses Debug formatting | Fixed |
| FFI-FIX-4 | `veritas-ffi` | `BufferTooSmall` maps to `InvalidArgument` | Fixed |
| FFI-FIX-5 | `veritas-ffi` | Missing error codes | Fixed |
| FFI-FIX-6 | `veritas-ffi` | `catch_unwind` closures not `UnwindSafe` | Fixed |
| CRYPTO-FIX-6 | `veritas-crypto` | PQ keypair structs expose private keys as `pub` | Fixed |
| CORE-FIX-1 | `veritas-core` | TOCTOU race in `require_unlocked` | Fixed |
| CORE-FIX-4 | `veritas-core` | Password silently ignored in in-memory mode | Fixed |

---

## Milestone 2: Wire Format v2 + ML-DSA Signing (v0.4.0-beta) — COMPLETED

> **Goal**: Replace placeholder signing with ML-DSA AND batch all wire format breaking changes into a single release. Two-phase approach: Phase A (mechanical wire format), Phase B (ML-DSA + chain transaction model).
> **Estimated Effort**: 4–6 instruction sets, ~4-5 weeks total
> **Branch Pattern**: `feat/{description}` or `security/{description}`
>
> **Status**: All 12 tasks (2.1-2.12) implemented. ML-DSA-65 signing fully operational using `ml-dsa` crate v0.1.0-rc.7 (FIPS 204). Wire format v2 with protocol versioning, cipher suite negotiation, and post-quantum envelope sizes. Message-as-transaction chain model, epoch-based pruning, and light validator mode all implemented. Reputation system updated with starting score 100 and asymmetric decay. Stack size requirement: RUST_MIN_STACK=16777216 (16MB) for ML-DSA operations.

### Phase A: Wire Format Infrastructure

#### 2.1 — Add Protocol Version Negotiation

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CROSS-D1 |
| **Crates** | `veritas-protocol`, `veritas-net` |
| **Effort** | Low |
| **Breaking** | Yes (wire format — adds version field) |

**What to implement**:
1. Add `protocol_version: u16` to the connection handshake
2. Add `version: u8` to the message envelope
3. Define version compatibility rules (reject, degrade, negotiate)
4. This is a prerequisite for all future protocol changes

**Resolution**: Protocol version field added (PROTOCOL_VERSION = 2). Version negotiation implemented in handshake and envelope.

---

#### 2.2 — Add Cipher Suite Identifier to Envelope

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D8 |
| **Crate** | `veritas-protocol` |
| **Effort** | Low |
| **Breaking** | Yes (envelope format) |

**What to implement**:
1. Add `cipher_suite: u8` field to the envelope
2. Define suite 0 = current (X25519 + ChaCha20-Poly1305 + BLAKE3)
3. Reserve suite 1 = hybrid (X25519 + ML-KEM + ChaCha20-Poly1305 + BLAKE3)
4. Recipient checks cipher suite before attempting decryption

**Resolution**: Cipher suite field added (CIPHER_SUITE_MLDSA65_CHACHA20 = 1). Recipient validates cipher suite before decryption.

---

#### 2.3 — Increase Envelope Sizes for Post-Quantum

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D4 |
| **Crate** | `veritas-protocol` |
| **Effort** | Low |
| **Breaking** | Yes (envelope size limits, padding buckets) |

**What to implement**:
1. Increase `MAX_ENVELOPE_SIZE` from 2048 to 8192 bytes (ML-DSA-65 signature alone is 3,309 bytes)
2. Change padding buckets from `[256, 512, 1024]` to `[1024, 2048, 4096, 8192]`
3. Add more buckets for finer granularity (at least 8 buckets)
4. Update all `from_bytes` size checks

**Resolution**: MAX_ENVELOPE_SIZE increased to 8192. Padding buckets updated to [1024, 2048, 4096, 8192]. MIN_CIPHERTEXT_SIZE increased from 256 to 1024. All size checks updated.

---

#### 2.4 — Implement Structured Domain Separation

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D6, CROSS-3 |
| **Crates** | `veritas-crypto`, `veritas-identity`, `veritas-protocol` |
| **Effort** | Low |
| **Breaking** | Yes (KDF outputs change) |

**What to implement**:
Adopt `"VERITAS-v1." || purpose || "." || context_length || context` as the standard domain separation format across all HKDF calls.

**Resolution**: Structured domain separation implemented in `veritas-protocol/src/domain_separation.rs`. All HKDF calls use the standard `"VERITAS-v1." || purpose || "." || context_length || context` format.

---

#### 2.5 — Add Transcript Binding in Key Derivation

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D5 |
| **Crates** | `veritas-crypto`, `veritas-protocol` |
| **Effort** | Low |
| **Breaking** | Yes (key derivation — all messages) |

**What to implement**:
Add `(sender_id || recipient_id || session_id || message_counter)` as additional context in HKDF-Expand calls. Prevents key reuse across contexts and unknown key-share attacks.

**Resolution**: Transcript binding implemented in `veritas-protocol/src/transcript.rs`. HKDF-Expand calls include full transcript context (sender_id, recipient_id, session_id, message_counter).

---

### Phase B: ML-DSA Signing + Chain Transaction Model

#### 2.6 — Implement ML-DSA Signing (Replaces Placeholder)

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D2 |
| **Crates** | `veritas-crypto`, `veritas-identity`, `veritas-protocol`, `veritas-chain`, `veritas-reputation`, `veritas-core` |
| **Severity** | CRITICAL |
| **Effort** | High |
| **Breaking** | Yes (wire format, stored data, chain format) |

**Problem**: All signing is placeholder HMAC-BLAKE3 with no real asymmetric signature semantics. Messages, blocks, interaction proofs, and receipts are all forgeable.

**What to implement**:
1. Activate `ml-dsa` crate (already in Cargo.toml at 0.1.x) — use ML-DSA-65 (NIST security level 3)
2. Implement `MlDsaSigningKey` and `MlDsaVerifyingKey` types with proper `Zeroize`/`ZeroizeOnDrop`
3. **CRITICAL**: Use `OsRng` not `thread_rng` for key generation
4. Replace ALL `sign()`/`verify()` call sites across the protocol:
   - Block header signing in `veritas-chain`
   - Message transaction signing in `veritas-protocol`
   - Interaction proof signing in `veritas-reputation`
   - Receipt signing in `veritas-protocol`
5. **Hard cutover**: Treat as new genesis. No backward compatibility with placeholder signatures.
6. Define size constants: `ML_DSA_65_PK_SIZE = 1952`, `ML_DSA_65_SIG_SIZE = 3309`, `ML_DSA_65_SK_SIZE = 4032`

**This is the single highest-impact fix in the entire backlog.** It enables authentication for every component downstream.

**Resolution**: ML-DSA-65 signing fully implemented using `ml-dsa` crate v0.1.0-rc.7 (FIPS 204). Real key generation with `OsRng`, `Zeroize`/`ZeroizeOnDrop` on private keys. All sign/verify call sites replaced across 6 crates. Key sizes: PK=1952, SK seed=32 (full=4032), Sig=3309. Hard cutover from placeholder HMAC-BLAKE3. Signature size constant corrected from 3293 to 3309 per FIPS 204 spec. Requires RUST_MIN_STACK=16777216 (16MB).

---

#### 2.7 — Implement Message-as-Transaction Chain Model

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | AD-1 (new), CONS-D5 |
| **Crates** | `veritas-chain`, `veritas-protocol` |
| **Severity** | CRITICAL |
| **Effort** | High |
| **Breaking** | Yes (chain format) |

**What to implement**:
1. Define `MessageTransaction` type — contains: ML-DSA signature, encrypted message body, message header
2. Define `MessageHeader` (the permanent part): mailbox keys (sender+recipient derived), timestamp, message hash (BLAKE3 of body), block inclusion proof reference
3. Blocks contain ordered lists of `MessageTransaction` (plus existing types: `IdentityReg`, `UsernameReg`, `KeyRotation`, `ReputationChange`)
4. Block header includes: block hash, parent hash, height, timestamp, merkle root of all transactions, validator ML-DSA signature
5. Add `ImageProofTransaction` type — contains: image hash, delivery receipt, sender proof. No image data on-chain.

**Resolution**: Message-as-transaction model implemented in `veritas-chain/src/transaction.rs`. MessageTransaction, MessageHeader, EncryptedBody, and Transaction enum all defined. Blocks contain ordered transaction lists. ImageProofTransaction included.

---

#### 2.8 — Implement Epoch-Based Pruning

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | AD-2 (new) |
| **Crates** | `veritas-chain`, `veritas-store` |
| **Severity** | CRITICAL |
| **Effort** | Medium |
| **Breaking** | Yes (storage format) |

**What to implement**:
1. Define `EPOCH_DURATION = 30 * 24 * 60 * 60` (30 days in seconds)
2. At epoch boundary: prune message bodies + ML-DSA signatures from all transactions in completed epoch
3. Retain only `MessageHeader` permanently
4. Pruning is deterministic — all nodes prune at the same epoch boundary
5. After pruning, `MessageHeader` is NOT signed (signature was pruned with body)
6. Headers are verifiable via Merkle proof against the block's merkle root (which is in the signed block header)
7. Storage format must support efficient body-only deletion without rewriting headers

**Resolution**: Epoch-based pruning implemented in `veritas-chain/src/epoch.rs`. 30-day epoch duration. Deterministic pruning at epoch boundaries — bodies and ML-DSA signatures removed, headers retained permanently. Storage supports efficient body-only deletion. Headers verifiable via Merkle proof against signed block header.

---

#### 2.9 — Implement Light Validator Mode

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | AD-4 (new), CONS-D7 |
| **Crates** | `veritas-chain`, `veritas-net`, `veritas-node` |
| **Effort** | Medium |
| **Breaking** | No (additive — new node mode) |

**What to implement**:
1. Light validator stores: headers + ML-DSA transaction signatures (no message bodies)
2. During epoch: can validate that transactions were properly signed without seeing content
3. After epoch: prune signatures, converge to header-only state
4. Sync protocol: light validators request headers + signatures only during initial sync
5. CLI flag: `--mode light-validator` vs `--mode full-validator`
6. Memory target: light validator should run comfortably in 256MB RAM

**Resolution**: Light validator mode implemented in `veritas-chain/src/light_validator.rs`. Stores headers + signatures only (no bodies). Validates transaction signatures without message content. Post-epoch signature pruning converges to header-only state. Header-only sync protocol for initial sync. CLI flags supported. Targets 256MB RAM.

---

#### 2.10 — Lower Starting Reputation to 100

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | IDENT-D2 |
| **Crate** | `veritas-reputation` |
| **Effort** | Low |
| **Breaking** | Yes (reputation scoring) |

**What to implement**:
1. Change `DEFAULT_REPUTATION` from 500 to 100 (Tier 1 / Basic)
2. Add capability gating: Tier 1 users can receive messages but sending is rate-limited
3. Define explicit capability thresholds per tier
4. Update all tests that assume starting score of 500

**Resolution**: DEFAULT_REPUTATION changed from 500 to 100. Capability gating by tier implemented. Tests updated for new starting score.

---

#### 2.11 — Fix Asymmetric Reputation Decay

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | IDENT-D8 |
| **Crate** | `veritas-reputation` |
| **Effort** | Low |
| **Breaking** | No |

**Fix**: Asymmetric decay — scores above 500 decay slowly toward 500; scores below 500 decay toward 0 or do not decay at all.

**Resolution**: Asymmetric decay implemented. Scores above 500 decay toward 500; scores below 500 decay toward 0.

---

#### 2.12 — Generic Error Codes on Wire

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CROSS-D3 |
| **Crates** | All crates with network-facing errors |
| **Effort** | Medium |
| **Breaking** | No |

**What to implement**:
1. Define generic wire-level error codes (`PROCESSING_FAILED`, `INVALID_MESSAGE`, `RATE_LIMITED`)
2. Map internal detailed errors to generic codes before sending on the wire
3. Keep detailed error messages for local logging only

**Resolution**: Generic wire error codes implemented in `veritas-protocol/src/wire_error.rs`. Internal errors mapped to generic codes before wire transmission. Detailed errors retained for local logging only.

---

## Milestone 3: BFT Consensus (v0.5.0-beta) — COMPLETED

> **Goal**: Replace broken consensus with real BFT. The chain is now the message transport — it must be correct.
> **Estimated Effort**: 3–5 instruction sets, ~4-6 weeks
> **Note**: This is the largest single work item. Must support the two-tier validator model.
>
> **Status**: All 5 tasks (3.1–3.5) implemented. 3 new modules added to `veritas-chain` (consensus.rs, vrf.rs, validator_trust.rs). New protocol limits for BFT constants. Fixed-point u64 arithmetic replaces f32 in all consensus-critical paths. All 507 veritas-chain tests pass (0 failures). Full workspace (1,643 tests) passes.

### 3.1 — Replace Consensus with BFT Protocol

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CONS-D1, CONS-D2 |
| **Crate** | `veritas-chain` |
| **Effort** | Very High |
| **Breaking** | Yes (chain format, consensus rules) |

**Recommended: Streamlet** — simplest BFT, provably secure, suitable for small validator sets (≤21). Three rounds of voting per block with straightforward finality rule.

**What was implemented**:
1. Streamlet BFT consensus engine (`consensus.rs`) with Propose/Vote/Notarize phases
2. Finality rule: 3 consecutive notarized blocks make the first irreversible
3. View-change protocol with configurable timeouts and round advancement
4. Deterministic leader selection using BLAKE3-based hashing
5. BFT quorum calculation: ceil(2n/3) ensuring safety with f = floor((n-1)/3) faults
6. ConsensusMessage enum for network-layer integration
7. All collections bounded for memory safety (MAX_PENDING_PROPOSALS, MAX_VOTES_PER_PROPOSAL, etc.)
8. Domain-separated signing payloads for proposals and votes

**Resolution**: Implemented `ConsensusEngine` in `crates/veritas-chain/src/consensus.rs` with full Streamlet BFT protocol, integrated with existing `SlashingManager` for equivocation detection.

---

### 3.2 — Implement Slashing for Equivocation

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CONS-D3 |
| **Crate** | `veritas-chain` |
| **Effort** | Medium |
| **Breaking** | Yes |

**What was implemented**:
1. New `SlashingOffense::Equivocation` variant for consensus-level equivocation
2. Equivocation detection integrated into `ConsensusEngine::handle_vote()`
3. `calculate_penalty_fixed()` method using fixed-point u64 for deterministic penalties
4. Fixed-point penalty fields added to `SlashingConfig` (e.g., `equivocation_fixed: 1_000_000` = 100%)
5. Equivocation triggers permanent ban (same as double-sign)

**Resolution**: Extended `SlashingManager` with equivocation support and fixed-point penalty calculation in `crates/veritas-chain/src/slashing.rs`.

---

### 3.3 — Fix f32 Non-Determinism in Validator Scoring

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CONS-D6, VERITAS-2026-0004 |
| **Crate** | `veritas-chain` |
| **Effort** | Medium |
| **Breaking** | Yes (validator selection) |

**What was implemented**:
1. `calculate_weight_fixed()` function in `vrf.rs` using u64 * FIXED_POINT_SCALE (1,000,000)
2. `calculate_weight_fixed()` method on `ValidatorStake` delegating to VRF module
3. New protocol constants: `FIXED_POINT_SCALE`, `VALIDATOR_ROTATION_FIXED`, `MIN_UPTIME_FIXED`
4. Fixed-point penalty fields in `SlashingConfig`
5. Old f32 methods preserved for backward compatibility but deprecated

**Resolution**: All consensus-critical weight calculations now use `u64` fixed-point arithmetic. Original `f32` methods marked as deprecated.

---

### 3.4 — VRF-Based Validator Selection

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CONS-D4 |
| **Crate** | `veritas-chain` |
| **Effort** | Medium |
| **Breaking** | Yes |

**What was implemented**:
1. `VrfOutput` struct with BLAKE3-based VRF construction
2. `VrfValidatorSelection` with fixed-point weight-based selection
3. `select_proposer()` using VRF output for unpredictable leader selection
4. `select_validators()` using fixed-point weights with geographic diversity
5. Domain-separated VRF inputs: `"VERITAS-VRF-INPUT-v1" || epoch || slot`
6. Property-based tests verifying determinism, weight ordering, and bounds

**Resolution**: Implemented in `crates/veritas-chain/src/vrf.rs`. VRF output derived from ML-DSA-65 proof hashed through BLAKE3.

---

### 3.5 — Validator Discovery and Trust Model

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | AD-4 (new) |
| **Crates** | `veritas-chain` |
| **Effort** | Medium |
| **Breaking** | No (additive) |

**What was implemented**:
1. `TrustManager` with directly-trusted validator list (bounded to MAX_TRUSTED_VALIDATORS)
2. 3-line trust fallback: BFS traversal through trust chain with depth limit
3. `ValidatorInfo` with heartbeat tracking and liveness monitoring
4. `ValidatorAlert` system: offline alerts, all-trusted-offline alert, review recommendation
5. `ValidatorRegistration` and `ValidatorHeartbeat` on-chain transaction types
6. Domain-separated signing payloads for registrations and heartbeats
7. Bootstrap validators for initial discovery
8. Submission target prioritization: online first, then by trust level

**Resolution**: Implemented in `crates/veritas-chain/src/validator_trust.rs`.

---

## Milestone 4: Privacy Hardening (v0.6.0-beta) — COMPLETED

> **Goal**: Address critical privacy gaps. The chain-as-transport model makes privacy even more important.
> **Status**: All 6 tasks (4.1–4.6) implemented and tested. 1,762 tests pass (0 failures).

### 4.1 — Fix Mailbox Key Derivation ✅

| Field | Value |
|-------|-------|
| **IDs** | PRIV-D2 |
| **Crate** | `veritas-protocol` |
| **Status** | **COMPLETED** |

**Implemented**: DH-based mailbox key derivation using `BLAKE3(MAILBOX_DH_DOMAIN || DH_shared_secret || epoch || salt)`. Added `derive_mailbox_key_dh()`, `MailboxKeyParams::new_with_dh()`. Updated `encrypt_for_recipient()` to use sender+recipient DH shared secret for mailbox key derivation. Legacy derivation path preserved for backward compatibility.

---

### 4.2 — Improve Padding Scheme ✅

| Field | Value |
|-------|-------|
| **IDs** | PRIV-D5 |
| **Crate** | `veritas-protocol` |
| **Status** | **COMPLETED** |

**Implemented**: Changed `PADDING_BUCKETS` from `[1024, 2048, 4096, 8192]` to `[256, 512, 1024, 1536, 2048, 3072, 4096, 8192]` (8 logarithmic buckets). Updated `MIN_CIPHERTEXT_SIZE` from 1024 to 256. All padding tests updated.

---

### 4.3 — Improve Timing Jitter ✅

| Field | Value |
|-------|-------|
| **IDs** | PRIV-D6 |
| **Crate** | `veritas-protocol` |
| **Status** | **COMPLETED** |

**Implemented**: Replaced uniform `OsRng.gen_range(0..=MAX_JITTER_MS)` with exponential distribution using inverse CDF: `-ln(U) / lambda` where `lambda = 2/max_ms`. Added `BurstConfig` struct with `max_batch_size`, `min_release_interval_ms`, `max_hold_time_ms`, `enabled` fields. Integrated into `SendConfig`.

---

### 4.4 — Add Cover Traffic ✅

| Field | Value |
|-------|-------|
| **IDs** | PRIV-D7 |
| **Crate** | `veritas-net` |
| **Status** | **COMPLETED** |

**Implemented**: New `cover_traffic.rs` module with `CoverTrafficGenerator`, `CoverTrafficConfig`, `PrivacyLevel` enum (Low/Medium/High/Custom), `DummyMessage`. Dummy messages use random mailbox keys, random message hashes, random valid bucket sizes, and random ciphertext (indistinguishable from real traffic). Presets: `low_privacy()`, `high_privacy()`, `disabled()`.

---

### 4.5 — GossipSub Topic Sharding ✅

| Field | Value |
|-------|-------|
| **IDs** | NET-D4, PRIV-D3 |
| **Crate** | `veritas-net` |
| **Status** | **COMPLETED** |

**Implemented**: 16 shards based on high nibble (4 bits) of mailbox key byte. Topic format: `veritas/messages/v2/shard-{:02x}`. Added `shard_for_mailbox_key()`, `sharded_topic_for_mailbox_key()`, `all_shard_topics()`, `shards_for_keys()`. Added `announce_message_sharded()` and `subscribe_to_shards()` to `GossipManager`.

---

### 4.6 — P2P Image Transfer Warning System ✅

| Field | Value |
|-------|-------|
| **IDs** | AD-6 |
| **Crate** | `veritas-protocol` |
| **Status** | **COMPLETED** |

**Implemented**: New `image_transfer.rs` module with `ImageTransferRequest` (requires explicit `acknowledge_warning()` before transfer), `ImageTransferProof` (on-chain proof with image_hash, receipt_hash, timestamp_bucket), `ImageTransferError`, `ImageContentType` enum (Jpeg/Png/WebP/Gif), `validate_transfer_request()` enforcement function. Constants: `IMAGE_TRANSFER_WARNING`, `MAX_IMAGE_SIZE` (10MB).

---

## Milestone 5: Messaging Security (v0.7.0-beta) — COMPLETED

> **Goal**: Real forward secrecy and group encryption.
> **Estimated Effort**: 2–3 instruction sets, ~3-4 weeks
>
> **Status**: All 3 tasks (5.1–5.3) implemented. X3DH key agreement, Double Ratchet with OOO support, deniable authentication, session management, session persistence, and group sender authentication all operational. 1,760 tests pass (0 failures), full workspace builds cleanly.

### 5.1 — Implement Double Ratchet for 1:1 Messaging

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D1 |
| **Crates** | `veritas-crypto`, `veritas-protocol`, `veritas-store` |
| **Effort** | High |
| **Breaking** | Yes (messaging protocol) |

**What was implemented**:
1. X3DH key agreement using prekey bundles (signed prekeys + one-time prekeys)
2. Double Ratchet for per-message forward secrecy and post-compromise security
3. Prekey bundle generation and management
4. Session state management with export/import for persistence in `veritas-store`
5. Out-of-order message delivery support with bounded skipped key cache (MAX_SKIP=256)
6. Session store with encrypted persistence, peer indexing, and session listing

**Resolution**: Implemented across `veritas-crypto` (x3dh.rs, double_ratchet.rs), `veritas-protocol` (session.rs), and `veritas-store` (session_store.rs).

---

### 5.2 — Add Deniable Authentication

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D7 |
| **Crates** | `veritas-crypto`, `veritas-protocol` |
| **Effort** | Medium |
| **Breaking** | Yes |

**What was implemented**: Triple-DH deniable authentication using BLAKE3 keyed hash. Canonical ordering of public keys ensures symmetric MAC computation (either party can produce the same tag). AuthMode enum allows per-session choice between deniable (HmacBlake3) and non-repudiable (MlDsa) authentication.

**Resolution**: Implemented in `veritas-crypto` (deniable_auth.rs) with integration in `veritas-protocol` (session.rs AuthMode).

---

### 5.3 — Improve Group Encryption

**Status**: Completed

| Field | Value |
|-------|-------|
| **IDs** | CRYPTO-D3 |
| **Crate** | `veritas-protocol` |
| **Effort** | Medium |
| **Breaking** | Yes |

**What was implemented**: Group sender authentication with two modes — HMAC-based (deniable within group) and ML-DSA (non-repudiable). AuthenticatedGroupMessage type wraps encrypted content with sender proof. Key rotation on member removal already existed from Milestone 1; now combined with sender auth for complete group security. MLS-style for large groups deferred to v2.0.

**Resolution**: Implemented in `veritas-protocol` (groups/sender_auth.rs).

---

## Milestone 6: Identity & Reputation Hardening (v0.8.0-beta) — COMPLETED

> **Goal**: Sybil resistance, reputation gaming prevention.
> **Estimated Effort**: 2–3 instruction sets, ~2 weeks
> **Status**: All 5 tasks (6.1–6.5) implemented. 3 new modules added to veritas-identity. Enhanced collusion detection and report system in veritas-reputation. All 1,937 tests pass (0 failures).

### 6.1 — Key Revocation (on-chain transaction type)
**Status**: Completed
IDs: IDENT-D7 | Effort: Medium | Breaking: Yes

### 6.2 — Key Rotation Contact Notification
**Status**: Completed
IDs: IDENT-D5 | Effort: Medium | Breaking: No

### 6.3 — Fix Report/Collusion System
**Status**: Completed
IDs: IDENT-D3, IDENT-D4 | Effort: Medium | Breaking: No

### 6.4 — Fix Unilateral BlockValidation Proofs
**Status**: Completed
IDs: IDENT-D6 | Effort: Low | Breaking: Yes

### 6.5 — Device-Binding as Interim Sybil Resistance
**Status**: Completed
IDs: IDENT-D1 | Effort: Medium | Breaking: No

---

## Milestone 7: Networking + NAT Traversal (v0.9.0-beta)

> **Goal**: Make the network actually work for real users behind NATs.
> **Estimated Effort**: 2–3 instruction sets, ~2-3 weeks

### 7.1 — Add NAT Traversal

| Field | Value |
|-------|-------|
| **IDs** | NET-D1 |
| **Crate** | `veritas-net` |
| **Effort** | Medium |
| **Breaking** | No (additive) |

**What to implement**: Circuit Relay v2, DCUtR, AutoNAT via libp2p.

---

### 7.2 — Switch Kademlia to Persistent Store

| Field | Value |
|-------|-------|
| **IDs** | NET-D2, NET-D3 |
| **Crate** | `veritas-net` |
| **Effort** | Medium |
| **Breaking** | No |

**Fix**: Replace `MemoryStore` with sled-backed persistent store. Bridge `DhtStorage` with Kademlia.

---

### 7.3 — Add QUIC Transport
IDs: NET-D5 | Effort: Medium | Breaking: No

### 7.4 — Add WebSocket Transport
IDs: NET-D6 | Effort: Medium | Breaking: No

### 7.5 — Increase DHT Quorum
IDs: NET-D7 | Effort: Low | Breaking: No

### 7.6 — Connection Limits and Peer Management
IDs: NET-FEAT-3, NET-FEAT-7, NET-FEAT-8 | Effort: Low | Breaking: No

---

## Milestone 8: Cross-Cutting Quality (v1.0-rc)

> **Goal**: Bindings parity, observability, optimizations.
> **Estimated Effort**: 2–3 instruction sets, ~2 weeks

### 8.1 — Unify Safety Number Implementations
### 8.2 — FFI API Parity (5 missing functions)
### 8.3 — WASM Completeness (IndexedDB, async API)
### 8.4 — Python Bindings (release GIL, context manager)
### 8.5 — Observability Framework (tracing + Prometheus)
### 8.6 — Performance Optimizations (35+ items from review — see v1 TODO for full list)

---

## Milestone 9: Feature Completeness (v1.0)

> ~40 remaining feature gaps — see v1 TODO section 9.1 for complete list.
> Key additions for new architecture:

- `CRYPTO-FEAT-3`: Hybrid key exchange combiner (X25519 + ML-KEM)
- `CRYPTO-FEAT-5`: Add `Serialize`/`Deserialize` on ML-DSA/ML-KEM types
- `CHAIN-FEAT-1`: Proper Merkle tree integration (critical for epoch pruning verification)
- `CORE-FEAT-4`: Implement ChainService, MessageService, ReputationService
- `CROSS-1`: Post-quantum readiness: coordinated ML-DSA/ML-KEM deployment

---

## Milestone 10: Future / v2.0 (Deferred)

| ID | Description | Priority |
|----|-------------|----------|
| AD-5 | Bluetooth last-mile relay (native app, BLE mesh to validator) | P1 |
| IDENT-D1 (full) | Hardware attestation — TPM 2.0, Secure Enclave, StrongBox | P1 |
| PRIV-D1 | Network-layer anonymity (sealed sender, mixnet, onion routing) | P2 |
| PRIV-D4 | Onion-routed DHT lookups | P2 |
| CRYPTO-D3 (full) | MLS-style tree-based group key agreement | P2 |
| CROSS-D2 | Formal protocol specification (IETF RFC style) | P2 |
| NET-D8 | BLE platform constraints (foreground-only, iOS/Android) | P2 |
| NET-D9 | Persist relay queue to disk with WAL | P3 |
| CONS-D8 | Clock sync enforcement or height-based slots | P3 |
| — | Formal verification of core crypto | P3 |
| — | Chain speed optimizations for higher TPS | P2 |
| — | FN-DSA (Falcon) evaluation when NIST finalizes — smaller sigs (690 bytes) | P3 |

---

## Summary Statistics

| Milestone | Items | Effort | Breaking Changes | Status |
|-----------|-------|--------|-----------------|--------|
| M1: Critical Code Fixes (v0.3.1) | ~60 | ~1 week | 2 (WASM salt, mailbox salt) | **COMPLETED** |
| M2: Wire Format v2 + ML-DSA (v0.4.0) | 12 | ~4-5 weeks | 9 (signing, wire format, KDF, envelope, chain model, pruning) | **COMPLETED** |
| M3: BFT Consensus (v0.5.0) | 5 | ~4-6 weeks | 4 (consensus, validator selection, trust model) | **COMPLETED** |
| M4: Privacy Hardening (v0.6.0) | 6 | ~2-3 weeks | 3 (mailbox, padding, gossip) | **COMPLETED** |
| M5: Messaging Security (v0.7.0) | 3 | ~3-4 weeks | 3 (Double Ratchet, deniability, group) | **COMPLETED** |
| M6: Identity & Reputation (v0.8.0) | 5 | ~2 weeks | 2 (revocation tx, proof format) | **COMPLETED** |
| M7: Networking (v0.9.0) | 6 | ~2-3 weeks | 0 | Pending |
| M8: Cross-Cutting Quality (v1.0-rc) | 6 + optimizations | ~2 weeks | 0 | Pending |
| M9: Feature Completeness (v1.0) | ~40 features | ~3-4 weeks | Varies | Pending |
| M10: Future / v2.0 | ~12 | Months | Varies | Deferred |
| **Total** | **~190+** | | | |

---

## Instruction Set Packaging

| Instruction Set | Milestones | Focus |
|-----------------|-----------|-------|
| **IS-001** | M1 (1.1–1.6) | Critical fixes: reputation, core identity, FFI, WASM, protocol |
| **IS-002** | M1 (1.7–1.17) | Critical fixes: chain sync, net gossip/DHT, node binary |
| **IS-003** | M1 (1.18–1.20) | Medium + low severity code fixes across all crates |
| **IS-004** | M2 Phase A (2.1–2.5) | Wire format v2: version, cipher suite, envelope, domain separation, transcript binding |
| **IS-005** | M2 Phase B (2.6) | ML-DSA signing — standalone due to scope and cross-crate impact |
| **IS-006** | M2 Phase B (2.7–2.12) | Message-as-transaction, epoch pruning, light validator, reputation |
| **IS-007** | M3 | BFT consensus + validator trust model (large, multi-phase) |
| **IS-008** | M4 | Privacy hardening |
| **IS-009** | M5 | Double Ratchet + messaging security |
| **IS-010** | M6–M7 | Identity/reputation hardening + networking |
| **IS-011** | M8–M9 | Quality, parity, features, optimizations |

Each instruction set follows the mandatory 6-phase structure (Setup → Implementation → Security Audit → Stress Testing → Docs Sweep → PR).

---

## Key Differences from v1 TODO

| Change | v1 | v2 |
|--------|----|----|
| Signing | Ed25519 first, ML-DSA later | ML-DSA directly (hard cutover) |
| Chain purpose | Username/key/reputation registry | Message transport layer |
| Transaction model | Registry entries only | Messages are transactions |
| Pruning | Not specified | 30-day epoch, body+sig pruned, header permanent |
| Validator tiers | Single type | Full validator + light validator |
| Image exchange | Not specified | P2P with on-chain proof + anonymity warning |
| Bluetooth | Offline mesh chat | Last-mile relay to reach validators |
| Ed25519 (IS-004) | Ed25519 signing instruction set | Now ML-DSA signing instruction set |
| Consensus scope | BFT for registry | BFT for message ordering + delivery |

---

*Document generated from `DESIGN_CRITIQUE.md` (42 findings), `PROTOCOL_REVIEW.md` (~95 findings), and owner clarifications on architecture decisions. All original finding IDs preserved for traceability.*
