# VERITAS-2026-0090 Remediation Plan

## Username Uniqueness Enforcement

**Vulnerability**: Username Uniqueness Not Enforced at Blockchain Level
**Severity**: CRITICAL (CVSS 9.3)
**Date**: 2026-01-31
**Author**: Claude Code Security Team

---

## Executive Summary

The VERITAS Protocol currently allows multiple users to register the same `@username` with different DIDs (Decentralized Identifiers). This creates a social engineering attack vector where attackers can impersonate legitimate users by registering their username.

This document provides a comprehensive remediation plan with:
1. Root cause analysis
2. Proposed code changes
3. Test requirements
4. Migration considerations

---

## Root Cause Analysis

### Current State

1. **`ChainEntry::UsernameRegistration`** stores username as raw `String`:
   ```rust
   // crates/veritas-chain/src/block.rs:795-804
   UsernameRegistration {
       username: String,           // NOT validated Username type
       identity_hash: IdentityHash,
       signature: Vec<u8>,
       timestamp: u64,
   }
   ```

2. **No uniqueness validation** in `Blockchain::add_block()`:
   ```rust
   // crates/veritas-chain/src/chain.rs
   // No code checks if username already exists
   ```

3. **Error type defined but unused**:
   ```rust
   // crates/veritas-identity/src/error.rs:28-29
   #[error("Username already taken: {0}")]
   UsernameTaken(String),  // NEVER returned anywhere
   ```

4. **No username index** in `Blockchain` struct:
   ```rust
   // No HashMap<String, IdentityHash> for lookups
   ```

---

## Proposed Changes

### Phase 1: Chain-Level Changes (veritas-chain)

#### 1.1 Add ChainError Variant

```rust
// crates/veritas-chain/src/error.rs

#[derive(Error, Debug)]
pub enum ChainError {
    // ... existing variants ...

    /// Username already registered to a different identity.
    #[error("Username already registered: {username} (owned by {owner})")]
    UsernameTaken {
        username: String,
        owner: String,  // Hex-encoded IdentityHash
    },

    /// Invalid username format.
    #[error("Invalid username: {0}")]
    InvalidUsername(String),
}
```

#### 1.2 Add Username Index to Blockchain

```rust
// crates/veritas-chain/src/chain.rs

use std::collections::HashMap;
use veritas_identity::{IdentityHash, Username};

pub struct Blockchain {
    // ... existing fields ...

    /// Username index mapping normalized usernames to their owners.
    /// Key: lowercase username, Value: owner's IdentityHash
    username_index: HashMap<String, IdentityHash>,
}

impl Blockchain {
    /// Look up the owner of a username.
    ///
    /// Usernames are case-insensitive; lookups are normalized to lowercase.
    pub fn lookup_username(&self, username: &str) -> Option<&IdentityHash> {
        let normalized = username.to_ascii_lowercase();
        self.username_index.get(&normalized)
    }

    /// Check if a username is available for registration.
    pub fn is_username_available(&self, username: &str) -> bool {
        self.lookup_username(username).is_none()
    }

    /// Get all registered usernames (for enumeration protection, consider rate limiting).
    pub fn username_count(&self) -> usize {
        self.username_index.len()
    }
}
```

#### 1.3 Add Username Validation in Block Processing

```rust
// crates/veritas-chain/src/chain.rs

impl Blockchain {
    /// Process chain entries when adding a block.
    fn process_entries(&mut self, entries: &[ChainEntry]) -> Result<()> {
        for entry in entries {
            match entry {
                ChainEntry::UsernameRegistration {
                    username,
                    identity_hash,
                    signature,
                    timestamp
                } => {
                    self.process_username_registration(
                        username,
                        identity_hash,
                        signature,
                        *timestamp
                    )?;
                }
                // ... handle other entry types ...
                _ => {}
            }
        }
        Ok(())
    }

    /// Validate and process a username registration.
    fn process_username_registration(
        &mut self,
        username: &str,
        identity: &IdentityHash,
        signature: &[u8],
        timestamp: u64,
    ) -> Result<()> {
        // Step 1: Validate username format using the Username type
        let validated = Username::new(username)
            .map_err(|e| ChainError::InvalidUsername(e.to_string()))?;

        // Step 2: Get normalized (lowercase) form for uniqueness check
        let normalized = validated.normalized();

        // Step 3: Check for existing registration
        if let Some(existing_owner) = self.username_index.get(&normalized) {
            // Allow re-registration by the same identity (e.g., for updates)
            if existing_owner != identity {
                return Err(ChainError::UsernameTaken {
                    username: username.to_string(),
                    owner: existing_owner.to_hex(),
                });
            }
            // Same owner - allow update (e.g., timestamp refresh)
        }

        // Step 4: Verify signature
        // TODO: Integrate with signature verification system
        // This should verify that the identity_hash owns this registration

        // Step 5: Register the username
        self.username_index.insert(normalized, identity.clone());

        Ok(())
    }

    /// Integrate entry processing with add_block.
    pub fn add_block(&mut self, block: Block) -> Result<()> {
        // ... existing validation ...

        // Process entries BEFORE adding to storage
        self.process_entries(block.entries())?;

        // ... existing block addition logic ...
    }
}
```

#### 1.4 Initialization and Serialization

```rust
// crates/veritas-chain/src/chain.rs

impl Blockchain {
    pub fn new() -> Result<Self> {
        // ... existing code ...
        Ok(Self {
            // ... existing fields ...
            username_index: HashMap::new(),
        })
    }

    /// Rebuild username index from existing blocks.
    /// Call this when loading a blockchain from storage.
    pub fn rebuild_username_index(&mut self) -> Result<()> {
        self.username_index.clear();

        // Iterate through all blocks and rebuild index
        for height in 0..=self.height {
            if let Some(block) = self.get_block_at_height(height) {
                for entry in block.entries() {
                    if let ChainEntry::UsernameRegistration {
                        username,
                        identity_hash,
                        ..
                    } = entry {
                        let normalized = username.to_ascii_lowercase();
                        // Later registrations override earlier ones
                        // (this handles chain reorganization correctly)
                        self.username_index.insert(normalized, identity_hash.clone());
                    }
                }
            }
        }

        Ok(())
    }
}

// Update ChainState to include username_index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    pub blocks: Vec<Block>,
    pub tip_hash: Hash256,
    pub genesis_hash: Hash256,
    pub username_index: HashMap<String, IdentityHash>,  // ADD
}
```

### Phase 2: Identity-Level Changes (veritas-identity)

#### 2.1 Use Username Type in ChainEntry

```rust
// crates/veritas-chain/src/block.rs

use veritas_identity::Username;

pub enum ChainEntry {
    UsernameRegistration {
        username: Username,  // CHANGE: Use validated type
        identity_hash: IdentityHash,
        signature: Vec<u8>,
        timestamp: u64,
    },
    // ...
}
```

#### 2.2 Add Reserved Username Check

```rust
// crates/veritas-identity/src/username.rs

/// Reserved usernames that cannot be registered.
const RESERVED_USERNAMES: &[&str] = &[
    "admin",
    "administrator",
    "system",
    "veritas",
    "support",
    "help",
    "root",
    "moderator",
    "mod",
    "official",
    "verified",
    "security",
];

impl Username {
    pub fn new(username: &str) -> Result<Self> {
        Self::validate(username)?;
        Self::check_reserved(username)?;
        Ok(Self(username.to_string()))
    }

    fn check_reserved(username: &str) -> Result<()> {
        let normalized = username.to_ascii_lowercase();
        if RESERVED_USERNAMES.contains(&normalized.as_str()) {
            return Err(IdentityError::InvalidUsername {
                reason: format!("'{}' is a reserved username", username),
            });
        }
        Ok(())
    }
}
```

### Phase 3: Fork Handling

```rust
// crates/veritas-chain/src/chain.rs

impl Blockchain {
    /// Handle chain reorganization for usernames.
    fn reorganize_to(&mut self, new_tip: &Hash256) -> Result<()> {
        // ... existing reorg logic ...

        // After reorg, rebuild username index
        // This ensures correct state even with competing registrations
        self.rebuild_username_index()?;

        Ok(())
    }
}
```

---

## Test Requirements

### Unit Tests

```rust
#[cfg(test)]
mod username_uniqueness_tests {
    use super::*;

    #[test]
    fn test_first_registration_succeeds() {
        let mut chain = Blockchain::new().unwrap();
        let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();

        let result = chain.register_username("alice", &alice);
        assert!(result.is_ok());

        assert_eq!(chain.lookup_username("alice"), Some(&alice));
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let mut chain = Blockchain::new().unwrap();
        let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let attacker = IdentityHash::from_bytes(&[2u8; 32]).unwrap();

        chain.register_username("alice", &alice).unwrap();

        let result = chain.register_username("alice", &attacker);
        assert!(matches!(result, Err(ChainError::UsernameTaken { .. })));
    }

    #[test]
    fn test_case_insensitive_collision() {
        let mut chain = Blockchain::new().unwrap();
        let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
        let attacker = IdentityHash::from_bytes(&[2u8; 32]).unwrap();

        chain.register_username("alice", &alice).unwrap();

        // All case variants should fail
        assert!(chain.register_username("Alice", &attacker).is_err());
        assert!(chain.register_username("ALICE", &attacker).is_err());
        assert!(chain.register_username("aLiCe", &attacker).is_err());
    }

    #[test]
    fn test_same_owner_can_update() {
        let mut chain = Blockchain::new().unwrap();
        let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();

        chain.register_username("alice", &alice).unwrap();

        // Same owner re-registering should succeed (timestamp update)
        let result = chain.register_username("alice", &alice);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reserved_usernames_blocked() {
        let mut chain = Blockchain::new().unwrap();
        let user = IdentityHash::from_bytes(&[1u8; 32]).unwrap();

        assert!(chain.register_username("admin", &user).is_err());
        assert!(chain.register_username("system", &user).is_err());
        assert!(chain.register_username("veritas", &user).is_err());
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let mut chain = Blockchain::new().unwrap();
        let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();

        chain.register_username("Alice", &alice).unwrap();

        // All case variants should find the same owner
        assert_eq!(chain.lookup_username("alice"), Some(&alice));
        assert_eq!(chain.lookup_username("ALICE"), Some(&alice));
        assert_eq!(chain.lookup_username("aLiCe"), Some(&alice));
    }

    #[test]
    fn test_username_index_survives_reorg() {
        let mut chain = Blockchain::new().unwrap();
        let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();

        // Register and verify
        chain.register_username("alice", &alice).unwrap();

        // Simulate reorganization
        chain.rebuild_username_index().unwrap();

        // Index should still be correct
        assert_eq!(chain.lookup_username("alice"), Some(&alice));
    }
}
```

### Property Tests

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_no_duplicate_usernames_possible(
        username in "[a-z][a-z0-9]{2,10}",
        id1 in prop::array::uniform32(any::<u8>()),
        id2 in prop::array::uniform32(any::<u8>())
    ) {
        prop_assume!(id1 != id2);

        let mut chain = Blockchain::new().unwrap();
        let owner1 = IdentityHash::from_bytes(&id1).unwrap();
        let owner2 = IdentityHash::from_bytes(&id2).unwrap();

        // First registration succeeds
        prop_assert!(chain.register_username(&username, &owner1).is_ok());

        // Second registration fails
        prop_assert!(chain.register_username(&username, &owner2).is_err());

        // Lookup returns first owner
        prop_assert_eq!(chain.lookup_username(&username), Some(&owner1));
    }

    #[test]
    fn prop_case_variants_collide(
        base in "[a-z][a-z0-9]{2,10}",
        id1 in prop::array::uniform32(any::<u8>()),
        id2 in prop::array::uniform32(any::<u8>())
    ) {
        prop_assume!(id1 != id2);

        let mut chain = Blockchain::new().unwrap();
        let owner1 = IdentityHash::from_bytes(&id1).unwrap();
        let owner2 = IdentityHash::from_bytes(&id2).unwrap();

        // Register lowercase
        prop_assert!(chain.register_username(&base, &owner1).is_ok());

        // Uppercase should collide
        let upper = base.to_uppercase();
        prop_assert!(chain.register_username(&upper, &owner2).is_err());
    }
}
```

### Integration Tests

```rust
#[test]
fn test_username_registration_in_block() {
    let mut chain = Blockchain::new().unwrap();
    let genesis = chain.genesis().clone();

    let alice = IdentityHash::from_bytes(&[1u8; 32]).unwrap();
    let attacker = IdentityHash::from_bytes(&[2u8; 32]).unwrap();

    // Block 1: Alice registers username
    let block1 = Block::new(
        genesis.hash().clone(),
        1,
        1001,
        vec![ChainEntry::UsernameRegistration {
            username: Username::new("alice").unwrap(),
            identity_hash: alice.clone(),
            signature: vec![],  // TODO: proper signature
            timestamp: 1001,
        }],
        alice.clone(),
    );
    chain.add_block(block1).unwrap();

    assert_eq!(chain.lookup_username("alice"), Some(&alice));

    // Block 2: Attacker tries to squat
    let block2 = Block::new(
        chain.tip().hash().clone(),
        2,
        1002,
        vec![ChainEntry::UsernameRegistration {
            username: Username::new("alice").unwrap(),
            identity_hash: attacker.clone(),
            signature: vec![],
            timestamp: 1002,
        }],
        attacker.clone(),
    );

    // Should fail
    let result = chain.add_block(block2);
    assert!(result.is_err());

    // Alice still owns the username
    assert_eq!(chain.lookup_username("alice"), Some(&alice));
}
```

---

## Migration Considerations

### Backward Compatibility

1. **Existing registrations**: When upgrading, scan existing blocks to build the username index
2. **First-come-first-served**: The first registration in block order wins
3. **Conflicting registrations**: Log warnings for duplicate registrations found in historical data

### Upgrade Path

```rust
impl Blockchain {
    /// Upgrade the blockchain to enforce username uniqueness.
    ///
    /// Call this once during upgrade to build the initial username index.
    /// Logs warnings for any duplicate registrations found.
    pub fn upgrade_username_enforcement(&mut self) -> Result<UpgradeReport> {
        let mut report = UpgradeReport::default();

        for height in 0..=self.height {
            if let Some(block) = self.get_block_at_height(height) {
                for entry in block.entries() {
                    if let ChainEntry::UsernameRegistration {
                        username,
                        identity_hash,
                        ..
                    } = entry {
                        let normalized = username.to_ascii_lowercase();

                        if let Some(existing) = self.username_index.get(&normalized) {
                            if existing != identity_hash {
                                report.conflicts.push(UsernameConflict {
                                    username: username.clone(),
                                    first_owner: existing.clone(),
                                    second_owner: identity_hash.clone(),
                                    block_height: height,
                                });
                            }
                        } else {
                            self.username_index.insert(normalized, identity_hash.clone());
                            report.registered += 1;
                        }
                    }
                }
            }
        }

        Ok(report)
    }
}
```

---

## Security Checklist

- [ ] ChainError::UsernameTaken error variant added
- [ ] Username index (HashMap) added to Blockchain struct
- [ ] lookup_username() function implemented
- [ ] Uniqueness validation in add_block()
- [ ] Case-insensitive comparison using normalized()
- [ ] Reserved username list implemented
- [ ] Unit tests for duplicate rejection (10+ tests)
- [ ] Property tests for uniqueness invariant
- [ ] Integration tests for block-level enforcement
- [ ] Fork/reorg handling tested
- [ ] ChainState serialization updated
- [ ] Migration/upgrade path documented
- [ ] Security review by 🔒 Security Agent
- [ ] Full test suite passes

---

## Timeline

| Task | Effort | Dependencies |
|------|--------|--------------|
| Add ChainError::UsernameTaken | Low | None |
| Add username_index to Blockchain | Low | Error type |
| Implement lookup_username() | Low | Index |
| Add validation in add_block() | Medium | Lookup |
| Reserved username list | Low | Validation |
| Unit tests | Medium | Implementation |
| Property tests | Medium | Implementation |
| Integration tests | Medium | Implementation |
| Fork handling tests | Medium | Implementation |
| Documentation update | Low | All |
| **Total** | **Medium** | |

---

## References

- VERITAS-2026-0090: Username Uniqueness Not Enforced at Blockchain Level
- VERITAS-2026-0047: Username case squatting vulnerability
- VERITAS-2026-0028: Username registration replay attack
- VERITAS-2026-0081: No Unicode normalization for usernames

---

**Document Prepared By**: Claude Code Security Team
**Session**: https://claude.ai/code/session_014QKiSThRWboAM5SuMgQPYA
**Date**: 2026-01-31
