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
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-121, TASK-122, TASK-130

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Review public API for RPIT changes
- [ ] Ensure no breaking API changes introduced
- [ ] Run `cargo test -p veritas-core`
- [ ] Run `cargo clippy -p veritas-core`

**Expected Changes**:

- Minimal — mostly wraps other crates

-----

### Phase 5: FFI & Bindings (Most Work)

#### TASK-150: Migrate veritas-ffi to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-140

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] **REQUIRED**: Add `unsafe` to all `extern` blocks
- [ ] **REQUIRED**: Update `#[no_mangle]` → `#[unsafe(no_mangle)]`
- [ ] **REQUIRED**: Update `#[export_name]` → `#[unsafe(export_name)]`
- [ ] Review all FFI functions for `static mut` usage
- [ ] Verify C header compatibility unchanged
- [ ] Run `cargo test -p veritas-ffi`
- [ ] Run `cargo clippy -p veritas-ffi`

**Required Changes**:

```rust
// Before (2021)
#[no_mangle]
pub extern "C" fn veritas_create_identity() -> *mut Identity { ... }

extern "C" {
    fn platform_entropy(buf: *mut u8, len: usize);
}

// After (2024)
#[unsafe(no_mangle)]
pub extern "C" fn veritas_create_identity() -> *mut Identity { ... }

unsafe extern "C" {
    fn platform_entropy(buf: *mut u8, len: usize);
}
```

-----

#### TASK-151: Migrate veritas-wasm to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-140

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Update `#[wasm_bindgen]` exports if any use `#[no_mangle]`
- [ ] Review JS interop for any unsafe patterns
- [ ] Test WASM build: `wasm-pack build --target web`
- [ ] Test WASM build: `wasm-pack build --target nodejs`
- [ ] Run `cargo test -p veritas-wasm`

**Expected Changes**:

- `wasm_bindgen` handles most FFI — should be minimal

-----

#### TASK-152: Migrate veritas-py to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-140

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Review PyO3 macros for any unsafe patterns
- [ ] Test Python build: `maturin develop`
- [ ] Run Python test suite
- [ ] Run `cargo test -p veritas-py`

**Expected Changes**:

- PyO3 handles most FFI — should be minimal

-----

### Phase 6: Workspace & Documentation

#### TASK-160: Update Workspace Cargo.toml

**Priority**: P1  
**Status**: NOT STARTED  
**Depends On**: TASK-150, TASK-151, TASK-152

**Checklist**:

- [ ] Update workspace `rust-version = "1.85"` if specified
- [ ] Verify resolver version compatibility
- [ ] Run `cargo build --all --release`
- [ ] Run `cargo test --all`
- [ ] Run `cargo clippy --all-targets --all-features`

-----

#### TASK-161: Update Documentation

**Priority**: P2  
**Status**: NOT STARTED  
**Depends On**: TASK-160

**Checklist**:

- [ ] Update README.md MSRV to 1.85
- [ ] Update CLAUDE.md with 2024 edition notes
- [ ] Update any CI/CD workflows for Rust 1.85
- [ ] Add entry to VERSION_HISTORY.md
- [ ] Update Dockerfile if present

-----

#### TASK-162: Final Validation & PR

**Priority**: P1  
**Status**: NOT STARTED  
**Depends On**: TASK-160, TASK-161

**Checklist**:

- [ ] Run full test suite: `cargo test --all --all-features`
- [ ] Run security tests: `cargo test security --all`
- [ ] Run fuzz tests (if configured)
- [ ] Run `cargo audit`
- [ ] Run `cargo deny check`
- [ ] Compare binary sizes (optional)
- [ ] Create PR to `main`
- [ ] Request security review of unsafe changes

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
|200+   |Future Features            |

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