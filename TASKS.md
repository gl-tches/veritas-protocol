# TASKS.md — VERITAS Protocol

> Task tracking for development, security remediation, and Rust 2024 migration

-----

## Current Sprint: Rust 2024 Edition Migration

**Branch**: `chore/rust-2024-edition-upgrade`  
**Target**: Upgrade all crates from Rust 2021 to Rust 2024 edition  
**MSRV Change**: 1.75 → 1.85  
**Estimated Effort**: 2-3 days

### Pre-Migration Checklist

- [x] **TASK-100**: Ensure all security audit fixes are merged to `main`
- [x] **TASK-101**: Run full test suite on `main` branch (baseline) — 1,289 tests passed
- [x] **TASK-102**: Create migration branch `chore/rust-2024-edition-upgrade`
- [x] **TASK-103**: Verify all dependencies build with Rust 1.85 — all 13 crates compile clean
- [x] **TASK-104**: Document current `static mut` usage across codebase — none found

-----

### Phase 1: Leaf Crates (No Internal Dependencies)

#### TASK-110: Migrate veritas-crypto to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Review `unsafe` blocks — crate uses `#![deny(unsafe_code)]`, no unsafe present
- [x] Verify no `static mut` usage — confirmed clean
- [x] Run `cargo test -p veritas-crypto` — 68 tests passed
- [x] Run `cargo clippy -p veritas-crypto` — no warnings

**Result**:

- Migration completed with no code changes required
- All 68 unit tests pass
- Clippy clean

-----

#### TASK-111: Migrate veritas-identity to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-110

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Review `hardware.rs` for any unsafe patterns — crate uses `#![deny(unsafe_code)]`
- [x] Check `limits.rs` for `static mut` — none found
- [x] Run `cargo test -p veritas-identity` — 179 tests passed
- [x] Run `cargo clippy -p veritas-identity` — no warnings

**Result**:

- Migration completed with no code changes required
- All 179 unit tests pass
- Clippy clean

-----

#### TASK-112: Migrate veritas-reputation to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Review rate limiter for any timing-sensitive code — crate uses `#![deny(unsafe_code)]`
- [x] Run `cargo test -p veritas-reputation` — 100 tests passed
- [x] Run `cargo clippy -p veritas-reputation` — no warnings

**Result**:

- Migration completed with no code changes required
- All 100 unit tests pass
- Clippy clean

-----

### Phase 2: Protocol & Storage Crates

#### TASK-120: Migrate veritas-protocol to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-110, TASK-111

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] **Review macros** — no `expr` fragment specifier issues found
- [x] Review RPIT lifetime changes — no changes needed
- [x] Check envelope deserialization — crate uses `#![deny(unsafe_code)]`
- [x] Run `cargo test -p veritas-protocol` — 84 tests passed
- [x] Run `cargo clippy -p veritas-protocol` — clean (1 fix applied)

**Result**:

- Fixed clippy warning: `manual_range_contains` in `inner.rs:395`
- All 84 unit tests pass
- Clippy clean

-----

#### TASK-121: Migrate veritas-store to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-110, TASK-120

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] **CRITICAL**: Review all `Mutex`/`RwLock` usage — NO locks found in crate
- [x] **CRITICAL**: Review tail expression scoping — `cargo fix` auto-fixed 1 pattern
- [x] Check `encrypted_db.rs` for lock patterns — none found
- [x] Check `message_queue.rs` for lock patterns — none found
- [x] Verify no `static mut` usage — confirmed clean
- [x] Run `cargo test -p veritas-store` — 70 tests passed
- [x] Run `cargo clippy -p veritas-store` — clean (1 fix applied)

**Result**:

- Fixed clippy warning: `unnecessary_map_or` → `is_none_or` in `message_queue.rs:197`
- Drop order warning in `keyring.rs:243` was harmless (Arc drops, not locks)
- All 70 unit tests pass
- Clippy clean

-----

#### TASK-122: Migrate veritas-chain to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-110, TASK-120

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Review validator set locking patterns — NO locks found (uses HashMap/BTreeMap directly)
- [x] Review block storage lock patterns — NO locks found
- [x] Check sync protocol for unsafe — crate uses `#![deny(unsafe_code)]`
- [x] Run `cargo test -p veritas-chain` — 234 tests passed
- [x] Run `cargo clippy -p veritas-chain` — no warnings

**Result**:

- Migration completed with no code changes required
- All 234 unit tests pass
- Clippy clean

-----

### Phase 3: Networking Crate

#### TASK-130: Migrate veritas-net to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-120, TASK-112

**Checklist**:

- [x] Run `cargo fix --edition` on crate
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] **OPPORTUNITY**: Reviewed — no async closure refactoring opportunities found
- [x] Review gossip.rs for async patterns — 8 lock operations, all safe
- [x] Review dht.rs for async patterns — 6 lock operations, all safe
- [x] Review transport_manager.rs for lock patterns — 19 lock operations, all safe
- [x] Check rate_limiter.rs — no async locks, uses `#![deny(unsafe_code)]`
- [x] Run `cargo test -p veritas-net` — 44 tests passed
- [x] Run `cargo clippy -p veritas-net` — clean (3 fixes applied)

**Result**:

- Fixed clippy warnings:
  - `bluetooth.rs:214`: `map_or` → `is_none_or`
  - `dht.rs:221`: manual arithmetic → `saturating_sub`
  - `transport.rs:215`: clone on Copy → dereference
- Lock pattern audit: 33 operations reviewed, all safe for Rust 2024
- Crate uses `#![deny(unsafe_code)]`
- All 44 unit tests pass
- Clippy clean

-----

### Phase 4: High-Level API

#### TASK-140: Migrate veritas-core to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-121, TASK-122, TASK-130

**Checklist**:

- [x] Run `cargo fix --edition` on crate — 1 auto-fix applied
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Review public API for RPIT changes — no `-> impl Trait` patterns found
- [x] Ensure no breaking API changes introduced — confirmed
- [x] Run `cargo test -p veritas-core` — 261 unit + 170 integration tests passed
- [x] Run `cargo clippy -p veritas-core` — no warnings

**Result**:

- `cargo fix` auto-fixed 1 drop order pattern in `identity_manager.rs:387`
- Drop order warning is harmless (Arc drops, not locks)
- Lock patterns already use explicit `drop()` calls — best practice
- Crate uses `#![deny(unsafe_code)]`
- All tests pass
- Clippy clean

-----

### Phase 5: FFI & Bindings (Most Work)

#### TASK-150: Migrate veritas-ffi to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-140

**Checklist**:

- [x] Run `cargo fix --edition` on crate — 35 auto-fixes applied
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] **REQUIRED**: No bare `extern` blocks found (all functions use `extern "C"`)
- [x] **REQUIRED**: All 12 `#[no_mangle]` → `#[unsafe(no_mangle)]` (auto-fixed)
- [x] **REQUIRED**: No `#[export_name]` found
- [x] Review all FFI functions — no `static mut` usage
- [x] Verify C header compatibility — updated cbindgen to 0.29 for Rust 2024 support
- [x] Run `cargo test -p veritas-ffi` — 14 tests passed
- [x] Run `cargo clippy -p veritas-ffi` — no warnings

**Result**:

- cargo fix auto-converted all 12 `#[no_mangle]` to `#[unsafe(no_mangle)]`
- Updated cbindgen from 0.26 → 0.29 for Rust 2024 syntax support
- All 14 FFI tests pass
- C header generation works correctly
- Clippy clean

-----

#### TASK-151: Migrate veritas-wasm to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-140

**Checklist**:

- [x] Run `cargo fix --edition` on crate — no changes needed
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Update `#[wasm_bindgen]` exports — no `#[no_mangle]` used
- [x] Review JS interop — crate uses `#![deny(unsafe_code)]`
- [x] Run `cargo test -p veritas-wasm` — 11 tests passed
- [x] Run `cargo clippy -p veritas-wasm` — no warnings

**Result**:

- wasm_bindgen handles all FFI internally — no code changes needed
- Crate uses `#![deny(unsafe_code)]` for safety
- All 11 tests pass
- Clippy clean

-----

#### TASK-152: Migrate veritas-py to Rust 2024

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Depends On**: TASK-140

**Checklist**:

- [x] Run `cargo fix --edition` on crate — completed
- [x] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [x] Review PyO3 macros — updated PyO3 0.20 → 0.23 for Rust 2024 support
- [x] Update module API for PyO3 0.23 (`&PyModule` → `&Bound<'_, PyModule>`)
- [x] Run `cargo test -p veritas-py` — 1 test passed
- [x] Run `cargo clippy -p veritas-py` — no warnings

**Result**:

- Updated PyO3 from 0.20 → 0.23 for Rust 2024 compatibility
- Updated lib.rs: module signature to use `Bound<'_, PyModule>`
- Updated error.rs: register_error signature for new API
- All tests pass
- Clippy clean

-----

### Phase 6: Workspace & Documentation

#### TASK-160: Update Workspace Cargo.toml

**Priority**: P1
**Status**: ✅ COMPLETED
**Depends On**: TASK-150, TASK-151, TASK-152

**Checklist**:

- [x] Update workspace `edition = "2024"`, `rust-version = "1.85"`
- [x] Verify resolver version compatibility — resolver = "2" works
- [x] Run `cargo build --all --release` — all 13 crates compile
- [x] Run `cargo test --all` — all tests pass
- [x] Run `cargo clippy --all-targets` — clean after fixes

**Result**:

- Updated workspace Cargo.toml to edition 2024 and rust-version 1.85
- All crates now inherit from workspace or override with 2024
- Release build successful

-----

#### TASK-161: Update Documentation

**Priority**: P2
**Status**: ✅ COMPLETED
**Depends On**: TASK-160

**Checklist**:

- [x] Update README.md MSRV to 1.85 — "Rust 2024 (MSRV 1.85)"
- [x] Update documentation/README.md — MSRV 1.85
- [x] Update Dockerfile — rust:1.85-bookworm
- [x] No CI/CD workflows found to update

**Result**:

- README.md: Updated tech stack table
- documentation/README.md: Updated version info
- Dockerfile: Updated base image to rust:1.85-bookworm

-----

#### TASK-162: Final Validation & PR

**Priority**: P1
**Status**: ✅ COMPLETED
**Depends On**: TASK-160, TASK-161

**Checklist**:

- [x] Run full test suite: `cargo test --all` — all tests pass
- [x] Run `cargo clippy --all-targets -- -D warnings` — clean
- [x] Run `cargo build --all --release` — successful
- [x] Fixed 13 new clippy warnings for Rust 2024 stricter lints

**Clippy Fixes Applied**:

- Removed duplicated `#![cfg(test)]` attributes in 3 proptests modules
- Fixed `repeat().take()` → `repeat_n()` patterns
- Fixed manual `RangeInclusive::contains` implementations
- Fixed assertions on constants with `const { }` blocks
- Fixed unused field and function warnings
- Fixed borrowed expression patterns

**Result**:

- All 11 crates migrated to Rust 2024 edition
- Full test suite passes
- Clippy clean with -D warnings
- Release build successful

-----

## Post-Migration Tasks (Optional Refactoring)

### TASK-170: Refactor veritas-net with Async Closures

**Priority**: P3  
**Status**: NOT STARTED  
**Depends On**: TASK-130

**Description**: Take advantage of Rust 2024 async closures to simplify networking code.

**Scope**:

- [ ] gossip.rs — message broadcasting
- [ ] dht.rs — parallel DHT queries
- [ ] relay.rs — multi-peer forwarding
- [ ] transport_manager.rs — connection management

**Note**: This is optional cleanup. The protocol works without it.

-----

### TASK-171: Remove Unnecessary .clone() Calls

**Priority**: P3  
**Status**: NOT STARTED  
**Depends On**: TASK-170

**Description**: Async closures capture by reference — remove clones that were only needed for `async move` blocks.

-----

## Feature: Lightweight Node Profiles

### TASK-200: Implement Lightweight Node Profiles for Resource-Constrained Devices

**Priority**: P1
**Status**: ✅ COMPLETED
**Assignee**: Claude Code
**Branch**: `feat/lightweight-node-profiles`
**Version**: 0.3.0-beta → 0.3.1-beta

**Description**: Reduce memory requirements for VERITAS nodes to enable deployment on resource-constrained hardware (Raspberry Pi, mobile, embedded):
- Relay nodes: 2 GB → 256 MB RAM
- Full nodes: 4 GB → 512 MB RAM
- Validators: 4 GB → 1 GB RAM

**Implementation**:

- [x] **Workstream A**: SledBackend — persistent block storage with sled 0.34.7
  - Height-indexed block retrieval (BE u64 keys)
  - Username index persistence with Blake3 integrity verification
  - Optional zstd compression support
  - Configurable cache size via `sled_cache_mb`

- [x] **Workstream B**: ManagedBlockchain — tiered storage architecture
  - Hot cache (MemoryBudget LRU) for recent/active blocks
  - Cold storage (StorageBackend) for older blocks
  - Genesis and tip blocks pinned (never evicted)
  - Automatic cache miss recovery from cold storage

- [x] **Workstream C**: NodeRole enum and profile constructors
  - Five node roles: Relay, FullNode, Validator, Bootstrap, Archive
  - Pre-configured memory budgets per role
  - Profile constructors: `BlockchainConfig::relay()`, `full_node()`, etc.

**Files Changed**:

- `Cargo.toml` (workspace): version 0.3.1-beta, sled = "0.34.7"
- `crates/veritas-chain/Cargo.toml`: sled-storage feature flag
- `crates/veritas-wasm/Cargo.toml`: `default-features = false` for WASM compatibility
- `crates/veritas-chain/src/config.rs`: NodeRole enum, profile constructors
- `crates/veritas-chain/src/memory.rs`: pin/unpin support in MemoryBudget
- `crates/veritas-chain/src/sled_backend.rs`: NEW — SledBackend implementation
- `crates/veritas-chain/src/managed_chain.rs`: NEW — ManagedBlockchain
- `crates/veritas-chain/src/lib.rs`: exports for new modules

**Test Results**:

- All 411 unit tests pass
- All 15 doc tests pass (6 ignored)
- Clippy clean with `-D warnings`

-----

## Milestone 1: Critical Code Fixes (Completed — v0.3.1-beta)

**Branch**: `fix/milestone-1-code-fixes`
**Status**: COMPLETED
**Date**: 2026-02-06
**Tracking**: See VERITAS_TODO_V2.md sections 1.1–1.20

### Summary

All ~60 bugs from the comprehensive code review have been fixed:
- **1 CRITICAL**: Collusion detection cluster index mapping (REP-FIX-1)
- **16 HIGH**: Identity keypair loss, FFI UB, WASM salt, ephemeral key validation, mailbox salt, receipt forgery, sync validation, nonce replay, signature skip, self-interaction bypass, gossip replay, DHT unbounded, plaintext zeroization, node binary
- **~23 MEDIUM**: Zeroize/ZeroizeOnDrop on PQ keys, constant-time checks, chain state fixes, reputation fixes, rate limiter ordering, bounded collections, WASM mutex/lock fixes, Python/FFI fixes
- **~20 LOW**: Clone on secret types, error variants, timestamp validation, dead code, overflow fixes, shutdown handling, formatting fixes

### Scope

- **44 files changed** across 12 crates
- **All 20 fix categories** (1.1–1.20) implemented
- **All 1,549 tests pass** (0 failures)
- **Build succeeds cleanly**

### Key Fixes by Category

| Task | Category | Description |
|------|----------|-------------|
| 1.1 | CRITICAL | Collusion detection cluster index mapping fixed |
| 1.2 | HIGH | Non-primary keypairs now stored in identity manager |
| 1.3+1.4 | HIGH | FFI uses single runtime + shared reference (no UB) |
| 1.5 | HIGH | WASM uses random Argon2 salt + persisted installation ID |
| 1.6+1.7 | HIGH | Ephemeral key validated before ECDH, mailbox salt consistent |
| 1.8 | HIGH | Receipt signatures use keyed HMAC-BLAKE3 + ConstantTimeEq |
| 1.9+1.10 | HIGH | Sync validates parent hash linkage + bounded vectors |
| 1.11 | HIGH | Time-bucketed nonce tracking replaces random pruning |
| 1.12 | HIGH | Signature verification returns error when registry unavailable |
| 1.13 | HIGH | Self-interaction check at recording time (not just construction) |
| 1.14 | HIGH | LRU-style seen-messages replaces clear-all approach |
| 1.15 | HIGH | Pre-deserialization size checks on DHT records |
| 1.16 | HIGH | Decrypted plaintext wrapped in Zeroizing<Vec<u8>> |
| 1.17 | HIGH | Node binary wired up with event loop |
| 1.18 | MEDIUM | Pre-deserialization size checks on all 9 from_bytes locations |
| 1.19 | MEDIUM | 23 medium-severity fixes across crypto, chain, net, store, FFI, WASM, Python |
| 1.20 | LOW | 33 low-severity fixes across all crates |

-----

## Milestone 2: Wire Format v2 + ML-DSA Signing (Completed — v0.4.0-beta)

**Branch**: `feat/milestone-2-wire-format-mldsa`
**Status**: COMPLETED
**Date**: 2026-02-07
**Tracking**: See VERITAS_TODO_V2.md sections 2.1–2.12

### Summary

All 12 tasks from Milestone 2 have been implemented. ML-DSA-65 signing is fully operational, replacing the placeholder HMAC-BLAKE3 signing. Wire format v2 deployed with post-quantum envelope sizes. Message-as-transaction chain model, epoch-based pruning, and light validator mode all implemented.

**Stack requirement**: ML-DSA operations require RUST_MIN_STACK=16777216 (16MB).

### Key Changes

| Task | Category | Description |
|------|----------|-------------|
| 2.1 | Wire Format | Protocol version negotiation added (PROTOCOL_VERSION = 2) |
| 2.2 | Wire Format | Cipher suite identifier added (CIPHER_SUITE_MLDSA65_CHACHA20 = 1) |
| 2.3 | Wire Format | Envelope sizes increased: MAX_ENVELOPE_SIZE 2048→8192, padding buckets [256,512,1024]→[1024,2048,4096,8192], MIN_CIPHERTEXT_SIZE 256→1024 |
| 2.4 | Crypto | Structured domain separation in `veritas-protocol/src/domain_separation.rs` |
| 2.5 | Crypto | Transcript binding for HKDF in `veritas-protocol/src/transcript.rs` |
| 2.6 | CRITICAL | ML-DSA-65 signing (FIPS 204) via `ml-dsa` crate v0.1.0-rc.7 — replaces all placeholder HMAC-BLAKE3 signing across 6 crates. Key sizes: PK=1952, SK seed=32 (full=4032), Sig=3309. Signature size constant corrected 3293→3309. |
| 2.7 | Chain | Message-as-transaction model in `veritas-chain/src/transaction.rs` |
| 2.8 | Chain | Epoch-based 30-day pruning in `veritas-chain/src/epoch.rs` |
| 2.9 | Chain | Light validator mode in `veritas-chain/src/light_validator.rs` (256MB RAM target) |
| 2.10 | Reputation | Starting score lowered from 500 to 100, capability gating by tier |
| 2.11 | Reputation | Asymmetric decay: above 500 → decay toward 500; below 500 → decay toward 0 |
| 2.12 | Wire Format | Generic wire error codes in `veritas-protocol/src/wire_error.rs` |

### New Files Added

- `crates/veritas-protocol/src/domain_separation.rs` — Structured domain separation
- `crates/veritas-protocol/src/transcript.rs` — Transcript binding for HKDF
- `crates/veritas-protocol/src/wire_error.rs` — Generic wire error codes
- `crates/veritas-chain/src/transaction.rs` — Message-as-transaction model
- `crates/veritas-chain/src/epoch.rs` — Epoch-based 30-day pruning
- `crates/veritas-chain/src/light_validator.rs` — Light validator mode

-----

## Completed Tasks

### Security Remediation (Completed)

- [x] **TASK-001**: Fix VERITAS-2026-0001 — Sybil fingerprint bypass
- [x] **TASK-002**: Fix VERITAS-2026-0002 — Missing block signatures
- [x] **TASK-003**: Fix VERITAS-2026-0003 — Unbounded deserialization DoS
- [x] **TASK-004**: Fix VERITAS-2026-0004 — Validator consensus divergence
- [x] **TASK-005**: Fix VERITAS-2026-0005 — Message queue metadata leak
- [x] **TASK-006**: Fix VERITAS-2026-0006 — DHT eclipse attack
- [x] **TASK-007**: Fix VERITAS-2026-0007 — Gossip protocol flooding
- [x] **TASK-008**: Fix VERITAS-2026-0008 — Time manipulation (identity)
- [x] **TASK-009**: Fix VERITAS-2026-0009 — Time manipulation (TTL)
- [x] **TASK-010**: Fix VERITAS-2026-0010 — Reputation interaction auth
- [x] **TASK-011-022**: Remaining critical fixes
- [x] **TASK-023-053**: High severity fixes
- [x] **TASK-054-079**: Medium severity fixes
- [x] **TASK-080-090**: Low severity fixes

-----

## Task ID Reference

|Range  |Category                   |
|-------|---------------------------|
|001-099|Security Remediation       |
|100-109|Migration Pre-work         |
|110-119|Phase 1: Leaf Crates       |
|120-129|Phase 2: Protocol & Storage|
|130-139|Phase 3: Networking        |
|140-149|Phase 4: High-Level API    |
|150-159|Phase 5: FFI & Bindings    |
|160-169|Phase 6: Workspace & Docs  |
|170-179|Post-Migration Refactoring |
|200-299|Future Features            |
|300-399|M1: Critical Code Fixes    |
|400-499|M2: Wire Format v2 + ML-DSA|

-----

## Notes

### Branch Strategy

```
main (stable)
  └── chore/rust-2024-edition-upgrade (this work)
        ├── Crate-by-crate commits
        └── Merge after full test + security review
```

### Commit Format

```
chore(crate-name): migrate to Rust 2024 edition

- Updated edition to 2024
- Updated rust-version to 1.85
- [specific changes made]

Task-ID: TASK-1XX
```

### Rollback Plan

If issues discovered after merge:

1. Revert merge commit
1. Fix issues on migration branch
1. Re-run full test suite
1. Re-merge

Edition changes are isolated per-crate, so partial rollback is possible if needed.

-----

## Milestone 3: BFT Consensus (v0.5.0-beta) — COMPLETED

**Branch**: `claude/implement-bft-consensus-p8xy7`
**Target**: Implement BFT consensus, fixed-point arithmetic, VRF selection, validator trust model
**Version**: v0.4.0-beta → v0.5.0-beta

### Summary

All 5 tasks completed. 3 new modules added to `veritas-chain`. Protocol limits extended with BFT constants.

| Task | Description | Status |
|------|-------------|--------|
| 3.1 | Streamlet BFT consensus engine | Completed |
| 3.2 | Slashing for equivocation | Completed |
| 3.3 | Fixed-point u64 validator scoring | Completed |
| 3.4 | VRF-based validator selection | Completed |
| 3.5 | Validator discovery and trust model | Completed |

### New Files

- `crates/veritas-chain/src/consensus.rs` — Streamlet BFT consensus engine
- `crates/veritas-chain/src/vrf.rs` — VRF-based validator selection, fixed-point arithmetic
- `crates/veritas-chain/src/validator_trust.rs` — Trusted validator list, 3-line fallback

### Modified Files

- `crates/veritas-chain/src/lib.rs` — New module declarations and exports
- `crates/veritas-chain/src/error.rs` — New error variants (Consensus, Equivocation, etc.)
- `crates/veritas-chain/src/validator.rs` — Added `calculate_weight_fixed()` method
- `crates/veritas-chain/src/slashing.rs` — Added Equivocation offense, fixed-point penalties
- `crates/veritas-protocol/src/limits.rs` — New BFT/VRF/trust model constants

### Test Results

- veritas-chain: 507 tests passed (0 failed)
- Full workspace: 1,643 tests passed (0 failed)
- Clippy: 0 warnings from new code