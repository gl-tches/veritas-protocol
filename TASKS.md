# TASKS.md — VERITAS Protocol

> Task tracking for development, security remediation, and Rust 2024 migration

-----

## Current Sprint: Rust 2024 Edition Migration

**Branch**: `chore/rust-2024-edition-upgrade`  
**Target**: Upgrade all crates from Rust 2021 to Rust 2024 edition  
**MSRV Change**: 1.75 → 1.85  
**Estimated Effort**: 2-3 days

### Pre-Migration Checklist

- [ ] **TASK-100**: Ensure all security audit fixes are merged to `main`
- [ ] **TASK-101**: Run full test suite on `main` branch (baseline)
- [ ] **TASK-102**: Create migration branch `chore/rust-2024-edition-upgrade`
- [ ] **TASK-103**: Verify all dependencies build with Rust 1.85
- [ ] **TASK-104**: Document current `static mut` usage across codebase

-----

### Phase 1: Leaf Crates (No Internal Dependencies)

#### TASK-110: Migrate veritas-crypto to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Review `unsafe` blocks — add explicit `unsafe {}` inside unsafe fns
- [ ] Verify no `static mut` usage (should be clean)
- [ ] Run `cargo test -p veritas-crypto`
- [ ] Run `cargo clippy -p veritas-crypto`

**Expected Changes**:

- `unsafe_op_in_unsafe_fn` — May need explicit blocks in low-level crypto
- No FFI in this crate — should be straightforward

-----

#### TASK-111: Migrate veritas-identity to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-110

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Review `hardware.rs` for any unsafe patterns
- [ ] Check `limits.rs` for `static mut` (installation ID storage)
- [ ] Run `cargo test -p veritas-identity`
- [ ] Run `cargo clippy -p veritas-identity`

**Expected Changes**:

- Minimal — mostly safe Rust code

-----

#### TASK-112: Migrate veritas-reputation to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Review rate limiter for any timing-sensitive code
- [ ] Run `cargo test -p veritas-reputation`
- [ ] Run `cargo clippy -p veritas-reputation`

**Expected Changes**:

- Minimal — pure business logic

-----

### Phase 2: Protocol & Storage Crates

#### TASK-120: Migrate veritas-protocol to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-110, TASK-111

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] **Review macros** — check for `expr` fragment specifiers
- [ ] Review RPIT lifetime changes in iterator code
- [ ] Check envelope deserialization for any unsafe
- [ ] Run `cargo test -p veritas-protocol`
- [ ] Run `cargo clippy -p veritas-protocol`

**Expected Changes**:

- Macro fragment specifiers may need `expr_2021` if issues arise
- RPIT lifetime capture — `cargo fix` handles automatically

-----

#### TASK-121: Migrate veritas-store to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-110, TASK-120

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] **CRITICAL**: Review all `Mutex`/`RwLock` usage in `if let` expressions
- [ ] **CRITICAL**: Review tail expression temporary scoping with locks
- [ ] Check `encrypted_db.rs` for lock patterns
- [ ] Check `message_queue.rs` for lock patterns
- [ ] Verify no `static mut` usage
- [ ] Run `cargo test -p veritas-store`
- [ ] Run `cargo clippy -p veritas-store`

**Expected Changes**:

- Lock scoping may change behavior — **test thoroughly**
- `cargo fix` will add explicit blocks to preserve old behavior if needed

**Review Focus**:

```rust
// These patterns need manual review:
if let Some(x) = mutex.lock().unwrap().get(&key) { ... }
mutex.lock().unwrap().get(&key).cloned()  // tail expression
```

-----

#### TASK-122: Migrate veritas-chain to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-110, TASK-120

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] Review validator set locking patterns
- [ ] Review block storage lock patterns
- [ ] Check sync protocol for any unsafe
- [ ] Run `cargo test -p veritas-chain`
- [ ] Run `cargo clippy -p veritas-chain`

**Expected Changes**:

- Lock scoping changes — review consensus-critical code carefully

-----

### Phase 3: Networking Crate

#### TASK-130: Migrate veritas-net to Rust 2024

**Priority**: P1  
**Status**: NOT STARTED  
**Assignee**: Claude Code  
**Depends On**: TASK-120, TASK-112

**Checklist**:

- [ ] Run `cargo fix --edition` on crate
- [ ] Update `Cargo.toml`: `edition = "2024"`, `rust-version = "1.85"`
- [ ] **OPPORTUNITY**: Refactor to use async closures where beneficial
- [ ] Review gossip.rs for async patterns
- [ ] Review dht.rs for async patterns
- [ ] Review transport_manager.rs for lock patterns
- [ ] Check rate_limiter.rs (new file from security fixes)
- [ ] Run `cargo test -p veritas-net`
- [ ] Run `cargo clippy -p veritas-net`

**Expected Changes**:

- **Async closures** — Can simplify many patterns (optional refactor)
- Lock scoping in connection management

**Refactor Opportunity** (optional):

```rust
// Before (2021)
peers.iter().map(|p| {
    let p = p.clone();
    async move { send_to(&p).await }
})

// After (2024) — cleaner
peers.iter().map(async |p| { send_to(p).await })
```

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