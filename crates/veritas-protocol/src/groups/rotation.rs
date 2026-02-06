//! Group key rotation management.
//!
//! Handles scheduled and on-demand key rotation for groups.
//! Key rotation ensures forward secrecy when members are removed.

use serde::{Deserialize, Serialize};

use veritas_identity::{IdentityHash, IdentityKeyPair, IdentityPublicKeys};

use crate::error::{ProtocolError, Result};
use crate::groups::keys::{EncryptedGroupKey, GroupKey, GroupKeyManager};
use crate::groups::metadata::GroupMetadata;
use crate::limits::GROUP_KEY_ROTATION_SECS;

/// Reason for key rotation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationTrigger {
    /// A member was removed from the group.
    /// Contains the identity hash of the removed member.
    MemberRemoved(IdentityHash),
    /// Scheduled rotation (e.g., 7 days elapsed).
    Scheduled,
    /// Manual rotation requested by admin.
    Manual,
    /// Key compromise suspected or detected.
    Compromise,
}

impl std::fmt::Display for RotationTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RotationTrigger::MemberRemoved(id) => write!(f, "MemberRemoved({})", id.short()),
            RotationTrigger::Scheduled => write!(f, "Scheduled"),
            RotationTrigger::Manual => write!(f, "Manual"),
            RotationTrigger::Compromise => write!(f, "Compromise"),
        }
    }
}

/// Result of a key rotation operation.
#[derive(Debug)]
pub struct RotationResult {
    /// The new group key.
    pub new_key: GroupKey,
    /// Encrypted copies of the new key for each member.
    pub encrypted_keys: Vec<EncryptedGroupKey>,
    /// What triggered this rotation.
    pub trigger: RotationTrigger,
    /// The previous key generation number.
    pub previous_generation: u32,
}

impl RotationResult {
    /// Get the new key generation number.
    pub fn new_generation(&self) -> u32 {
        self.new_key.generation()
    }

    /// Get the number of members who received the new key.
    pub fn member_count(&self) -> usize {
        self.encrypted_keys.len()
    }
}

/// Manager for group key rotation operations.
///
/// Stateless utility for managing key rotation.
pub struct KeyRotationManager;

impl KeyRotationManager {
    /// Check if scheduled rotation is needed.
    ///
    /// # Arguments
    ///
    /// * `last_rotation` - Unix timestamp of the last rotation
    /// * `current_time` - Current Unix timestamp
    ///
    /// # Returns
    ///
    /// `true` if enough time has passed since the last rotation.
    pub fn needs_scheduled_rotation(last_rotation: u64, current_time: u64) -> bool {
        current_time.saturating_sub(last_rotation) >= GROUP_KEY_ROTATION_SECS
    }

    /// Rotate the group key.
    ///
    /// Generates a new key and encrypts it for all current members.
    ///
    /// # Arguments
    ///
    /// * `group` - The group metadata
    /// * `rotator` - The identity performing the rotation (must be admin)
    /// * `member_keys` - Public keys for each member
    /// * `trigger` - What triggered this rotation
    ///
    /// # Returns
    ///
    /// The rotation result with the new key and encrypted copies.
    ///
    /// # Errors
    ///
    /// Returns an error if the rotator is not authorized.
    pub fn rotate(
        group: &GroupMetadata,
        rotator: &IdentityKeyPair,
        member_keys: &[(IdentityHash, IdentityPublicKeys)],
        trigger: RotationTrigger,
    ) -> Result<RotationResult> {
        // Verify rotator is an admin
        if !group.is_admin(rotator.identity_hash()) {
            return Err(ProtocolError::NotAuthorized(
                "Only admins can rotate group keys".to_string(),
            ));
        }

        let previous_generation = group.key_generation();
        let new_generation = previous_generation.saturating_add(1);

        // Generate new key
        let new_key = GroupKey::generate(new_generation);

        // Encrypt for all current members
        let encrypted_keys = GroupKeyManager::encrypt_for_members(&new_key, rotator, member_keys)?;

        Ok(RotationResult {
            new_key,
            encrypted_keys,
            trigger,
            previous_generation,
        })
    }

    /// Remove a member and rotate the key.
    ///
    /// This is the primary way to remove members while maintaining
    /// forward secrecy. The removed member will not receive the new key.
    ///
    /// # Arguments
    ///
    /// * `group` - The group metadata (will be modified)
    /// * `member_to_remove` - The identity to remove
    /// * `admin` - The admin performing the operation
    /// * `remaining_member_keys` - Public keys for members AFTER removal
    ///
    /// # Returns
    ///
    /// The rotation result with the new key encrypted for remaining members.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The admin is not authorized
    /// - The member is not in the group
    /// - Cannot remove the last admin
    ///
    /// # Security
    ///
    /// The key rotation ensures the removed member cannot decrypt any
    /// messages sent after their removal (forward secrecy).
    pub fn remove_member_and_rotate(
        group: &mut GroupMetadata,
        member_to_remove: &IdentityHash,
        admin: &IdentityKeyPair,
        remaining_member_keys: &[(IdentityHash, IdentityPublicKeys)],
    ) -> Result<RotationResult> {
        // Verify admin authorization
        if !group.is_admin(admin.identity_hash()) {
            return Err(ProtocolError::NotAuthorized(
                "Only admins can remove members".to_string(),
            ));
        }

        // Verify member exists before removal
        let _member = group
            .get_member(member_to_remove)
            .ok_or(ProtocolError::MemberNotInGroup)?;

        // PROTO-FIX-7: Removed empty check for admin removal - already
        // handled by group.remove_member() authorization logic.

        // Remove the member
        group.remove_member(member_to_remove, admin.identity_hash())?;

        // Perform rotation with the removed member excluded
        let result = Self::rotate(
            group,
            admin,
            remaining_member_keys,
            RotationTrigger::MemberRemoved(member_to_remove.clone()),
        )?;

        // Update group metadata with new key info
        group.increment_key_generation(result.new_key.hash())?;

        Ok(result)
    }

    /// Perform a scheduled rotation.
    ///
    /// Convenience method that uses `RotationTrigger::Scheduled`.
    pub fn scheduled_rotation(
        group: &mut GroupMetadata,
        admin: &IdentityKeyPair,
        member_keys: &[(IdentityHash, IdentityPublicKeys)],
    ) -> Result<RotationResult> {
        let result = Self::rotate(group, admin, member_keys, RotationTrigger::Scheduled)?;

        // Update group metadata with new key info
        group.increment_key_generation(result.new_key.hash())?;

        Ok(result)
    }

    /// Perform a manual rotation.
    ///
    /// Convenience method that uses `RotationTrigger::Manual`.
    pub fn manual_rotation(
        group: &mut GroupMetadata,
        admin: &IdentityKeyPair,
        member_keys: &[(IdentityHash, IdentityPublicKeys)],
    ) -> Result<RotationResult> {
        let result = Self::rotate(group, admin, member_keys, RotationTrigger::Manual)?;

        // Update group metadata with new key info
        group.increment_key_generation(result.new_key.hash())?;

        Ok(result)
    }

    /// Perform a compromise rotation.
    ///
    /// Convenience method that uses `RotationTrigger::Compromise`.
    /// Should be used when a key compromise is suspected.
    pub fn compromise_rotation(
        group: &mut GroupMetadata,
        admin: &IdentityKeyPair,
        member_keys: &[(IdentityHash, IdentityPublicKeys)],
    ) -> Result<RotationResult> {
        let result = Self::rotate(group, admin, member_keys, RotationTrigger::Compromise)?;

        // Update group metadata with new key info
        group.increment_key_generation(result.new_key.hash())?;

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groups::metadata::GroupRole;

    fn create_test_identity(seed: &[u8]) -> IdentityHash {
        IdentityHash::from_public_key(seed)
    }

    fn create_test_group_with_members(
        admin: &IdentityKeyPair,
        member_count: usize,
    ) -> (GroupMetadata, Vec<IdentityKeyPair>) {
        let mut group =
            GroupMetadata::create(admin.identity_hash(), Some("Test Group".to_string()));

        let mut members = Vec::with_capacity(member_count);
        for _ in 0..member_count {
            let member = IdentityKeyPair::generate();
            group
                .add_member(
                    member.identity_hash(),
                    GroupRole::Member,
                    admin.identity_hash(),
                )
                .unwrap();
            members.push(member);
        }

        (group, members)
    }

    fn get_member_keys(
        admin: &IdentityKeyPair,
        members: &[IdentityKeyPair],
    ) -> Vec<(IdentityHash, IdentityPublicKeys)> {
        let mut keys = vec![(admin.identity_hash().clone(), admin.public_keys().clone())];
        for m in members {
            keys.push((m.identity_hash().clone(), m.public_keys().clone()));
        }
        keys
    }

    #[test]
    fn test_needs_scheduled_rotation() {
        let last_rotation = 0;
        let current_time = GROUP_KEY_ROTATION_SECS - 1;
        assert!(!KeyRotationManager::needs_scheduled_rotation(
            last_rotation,
            current_time
        ));

        let current_time = GROUP_KEY_ROTATION_SECS;
        assert!(KeyRotationManager::needs_scheduled_rotation(
            last_rotation,
            current_time
        ));

        let current_time = GROUP_KEY_ROTATION_SECS + 1;
        assert!(KeyRotationManager::needs_scheduled_rotation(
            last_rotation,
            current_time
        ));
    }

    #[test]
    fn test_rotate_basic() {
        let admin = IdentityKeyPair::generate();
        let (group, members) = create_test_group_with_members(&admin, 2);
        let member_keys = get_member_keys(&admin, &members);

        let result =
            KeyRotationManager::rotate(&group, &admin, &member_keys, RotationTrigger::Manual)
                .unwrap();

        assert_eq!(result.new_key.generation(), 1);
        assert_eq!(result.previous_generation, 0);
        assert_eq!(result.encrypted_keys.len(), 3); // admin + 2 members
        assert!(matches!(result.trigger, RotationTrigger::Manual));
    }

    #[test]
    fn test_rotate_unauthorized() {
        let admin = IdentityKeyPair::generate();
        let (group, members) = create_test_group_with_members(&admin, 1);

        // Try to rotate as non-admin member
        let member_keys = get_member_keys(&admin, &members);
        let result =
            KeyRotationManager::rotate(&group, &members[0], &member_keys, RotationTrigger::Manual);

        assert!(matches!(result, Err(ProtocolError::NotAuthorized(_))));
    }

    #[test]
    fn test_remove_member_and_rotate() {
        let admin = IdentityKeyPair::generate();
        let (mut group, members) = create_test_group_with_members(&admin, 2);

        // Get keys for remaining members (admin + member[1])
        let remaining_keys = vec![
            (admin.identity_hash().clone(), admin.public_keys().clone()),
            (
                members[1].identity_hash().clone(),
                members[1].public_keys().clone(),
            ),
        ];

        let result = KeyRotationManager::remove_member_and_rotate(
            &mut group,
            members[0].identity_hash(),
            &admin,
            &remaining_keys,
        )
        .unwrap();

        // Member was removed
        assert_eq!(group.member_count(), 2); // admin + member[1]
        assert!(!group.is_member(members[0].identity_hash()));

        // Key was rotated
        assert_eq!(result.new_key.generation(), 1);
        assert_eq!(result.encrypted_keys.len(), 2); // Only remaining members get the key
        assert!(matches!(result.trigger, RotationTrigger::MemberRemoved(_)));

        // Group metadata updated
        assert_eq!(group.key_generation(), 1);
    }

    #[test]
    fn test_forward_secrecy() {
        let admin = IdentityKeyPair::generate();
        let (mut group, members) = create_test_group_with_members(&admin, 2);

        // Get keys for remaining members after removing member[0]
        let remaining_keys = vec![
            (admin.identity_hash().clone(), admin.public_keys().clone()),
            (
                members[1].identity_hash().clone(),
                members[1].public_keys().clone(),
            ),
        ];

        let result = KeyRotationManager::remove_member_and_rotate(
            &mut group,
            members[0].identity_hash(),
            &admin,
            &remaining_keys,
        )
        .unwrap();

        // Verify removed member is not in encrypted keys
        let removed_member_id = members[0].identity_hash();
        let has_removed_member_key = result
            .encrypted_keys
            .iter()
            .any(|k| &k.member_id == removed_member_id);

        assert!(
            !has_removed_member_key,
            "Removed member should not receive new key"
        );

        // Verify remaining members can decrypt
        for encrypted_key in &result.encrypted_keys {
            if &encrypted_key.member_id == admin.identity_hash() {
                let decrypted =
                    GroupKeyManager::decrypt_for_member(encrypted_key, &admin, admin.public_keys())
                        .unwrap();
                assert_eq!(decrypted.as_bytes(), result.new_key.as_bytes());
            } else if &encrypted_key.member_id == members[1].identity_hash() {
                let decrypted = GroupKeyManager::decrypt_for_member(
                    encrypted_key,
                    &members[1],
                    admin.public_keys(),
                )
                .unwrap();
                assert_eq!(decrypted.as_bytes(), result.new_key.as_bytes());
            }
        }
    }

    #[test]
    fn test_scheduled_rotation() {
        let admin = IdentityKeyPair::generate();
        let (mut group, members) = create_test_group_with_members(&admin, 1);
        let member_keys = get_member_keys(&admin, &members);

        let result =
            KeyRotationManager::scheduled_rotation(&mut group, &admin, &member_keys).unwrap();

        assert!(matches!(result.trigger, RotationTrigger::Scheduled));
        assert_eq!(group.key_generation(), 1);
    }

    #[test]
    fn test_manual_rotation() {
        let admin = IdentityKeyPair::generate();
        let (mut group, members) = create_test_group_with_members(&admin, 1);
        let member_keys = get_member_keys(&admin, &members);

        let result = KeyRotationManager::manual_rotation(&mut group, &admin, &member_keys).unwrap();

        assert!(matches!(result.trigger, RotationTrigger::Manual));
        assert_eq!(group.key_generation(), 1);
    }

    #[test]
    fn test_compromise_rotation() {
        let admin = IdentityKeyPair::generate();
        let (mut group, members) = create_test_group_with_members(&admin, 1);
        let member_keys = get_member_keys(&admin, &members);

        let result =
            KeyRotationManager::compromise_rotation(&mut group, &admin, &member_keys).unwrap();

        assert!(matches!(result.trigger, RotationTrigger::Compromise));
        assert_eq!(group.key_generation(), 1);
    }

    #[test]
    fn test_multiple_rotations() {
        let admin = IdentityKeyPair::generate();
        let (mut group, members) = create_test_group_with_members(&admin, 1);
        let member_keys = get_member_keys(&admin, &members);

        // Perform multiple rotations
        for i in 1..=5 {
            let result =
                KeyRotationManager::manual_rotation(&mut group, &admin, &member_keys).unwrap();
            assert_eq!(result.new_key.generation(), i);
            assert_eq!(group.key_generation(), i);
        }
    }

    #[test]
    fn test_rotation_result_helper_methods() {
        let admin = IdentityKeyPair::generate();
        let (group, members) = create_test_group_with_members(&admin, 3);
        let member_keys = get_member_keys(&admin, &members);

        let result =
            KeyRotationManager::rotate(&group, &admin, &member_keys, RotationTrigger::Manual)
                .unwrap();

        assert_eq!(result.new_generation(), 1);
        assert_eq!(result.member_count(), 4); // admin + 3 members
    }

    #[test]
    fn test_rotation_trigger_display() {
        let id = create_test_identity(b"test");

        assert_eq!(
            format!("{}", RotationTrigger::MemberRemoved(id)),
            format!(
                "MemberRemoved({})",
                IdentityHash::from_public_key(b"test").short()
            )
        );
        assert_eq!(format!("{}", RotationTrigger::Scheduled), "Scheduled");
        assert_eq!(format!("{}", RotationTrigger::Manual), "Manual");
        assert_eq!(format!("{}", RotationTrigger::Compromise), "Compromise");
    }

    #[test]
    fn test_cannot_remove_nonexistent_member() {
        let admin = IdentityKeyPair::generate();
        let (mut group, _) = create_test_group_with_members(&admin, 1);

        let nonexistent = IdentityKeyPair::generate();
        let remaining_keys = vec![(admin.identity_hash().clone(), admin.public_keys().clone())];

        let result = KeyRotationManager::remove_member_and_rotate(
            &mut group,
            nonexistent.identity_hash(),
            &admin,
            &remaining_keys,
        );

        assert!(matches!(result, Err(ProtocolError::MemberNotInGroup)));
    }
}
