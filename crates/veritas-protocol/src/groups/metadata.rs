//! Group metadata structures.
//!
//! Provides group identification, membership tracking, and role management.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::error::{ProtocolError, Result};
use crate::limits::MAX_GROUP_SIZE;

/// Size of group ID in bytes.
pub const GROUP_ID_SIZE: usize = 32;

/// A unique identifier for a group.
///
/// Generated randomly when a group is created.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId([u8; GROUP_ID_SIZE]);

impl GroupId {
    /// Generate a new random group ID.
    pub fn generate() -> Self {
        let mut bytes = [0u8; GROUP_ID_SIZE];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create a GroupId from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not exactly 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != GROUP_ID_SIZE {
            return Err(ProtocolError::InvalidEnvelope(format!(
                "Invalid group ID length: expected {}, got {}",
                GROUP_ID_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; GROUP_ID_SIZE];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    /// Get the group ID as a byte slice.
    pub fn as_bytes(&self) -> &[u8; GROUP_ID_SIZE] {
        &self.0
    }

    /// Convert to owned byte array.
    pub fn to_bytes(&self) -> [u8; GROUP_ID_SIZE] {
        self.0
    }

    /// Format as hex string.
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for byte in &self.0 {
            s.push_str(&format!("{:02x}", byte));
        }
        s
    }

    /// Parse from hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is not a valid 64-character hex string.
    pub fn from_hex(s: &str) -> Result<Self> {
        if s.len() != 64 {
            return Err(ProtocolError::InvalidEnvelope(format!(
                "Invalid group ID hex length: expected 64, got {}",
                s.len()
            )));
        }
        let mut bytes = [0u8; GROUP_ID_SIZE];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk)
                .map_err(|_| ProtocolError::InvalidEnvelope("Invalid hex encoding".to_string()))?;
            bytes[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|_| ProtocolError::InvalidEnvelope("Invalid hex character".to_string()))?;
        }
        Ok(Self(bytes))
    }

    /// Get a truncated representation for display.
    pub fn short(&self) -> String {
        let hex = self.to_hex();
        format!("{}...", &hex[..16])
    }
}

impl std::fmt::Debug for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GroupId({})", self.short())
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl AsRef<[u8]> for GroupId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Role of a member within a group.
///
/// Roles determine what operations a member can perform.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum GroupRole {
    /// Administrator with full control.
    /// Can: add/remove members, change roles, rotate keys, delete group.
    Admin = 1,
    /// Moderator with limited admin capabilities.
    /// Can: add members (not admins), remove regular members.
    Moderator = 2,
    /// Regular member.
    /// Can: send/receive messages.
    Member = 3,
}

impl GroupRole {
    /// Check if this role can add new members.
    pub fn can_add_members(&self) -> bool {
        matches!(self, GroupRole::Admin | GroupRole::Moderator)
    }

    /// Check if this role can remove members.
    pub fn can_remove_members(&self) -> bool {
        matches!(self, GroupRole::Admin | GroupRole::Moderator)
    }

    /// Check if this role can remove a member with the given role.
    pub fn can_remove(&self, target_role: GroupRole) -> bool {
        match self {
            GroupRole::Admin => true, // Admins can remove anyone
            GroupRole::Moderator => target_role == GroupRole::Member, // Mods can only remove members
            GroupRole::Member => false, // Members cannot remove anyone
        }
    }

    /// Check if this role can rotate group keys.
    pub fn can_rotate_keys(&self) -> bool {
        matches!(self, GroupRole::Admin)
    }

    /// Check if this role can change member roles.
    pub fn can_change_roles(&self) -> bool {
        matches!(self, GroupRole::Admin)
    }
}

/// A member of a group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupMember {
    /// The member's identity hash.
    pub identity: IdentityHash,
    /// The member's role in the group.
    pub role: GroupRole,
    /// Unix timestamp when the member joined.
    pub joined_at: u64,
    /// Identity hash of who added this member.
    pub added_by: IdentityHash,
}

impl GroupMember {
    /// Create a new group member.
    pub fn new(
        identity: IdentityHash,
        role: GroupRole,
        joined_at: u64,
        added_by: IdentityHash,
    ) -> Self {
        Self {
            identity,
            role,
            joined_at,
            added_by,
        }
    }
}

/// Metadata for a group.
///
/// Contains group identification, membership list, and key generation info.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupMetadata {
    /// Unique group identifier.
    group_id: GroupId,
    /// Optional human-readable name.
    name: Option<String>,
    /// List of group members.
    members: Vec<GroupMember>,
    /// Unix timestamp when the group was created.
    created_at: u64,
    /// Identity hash of the group creator.
    created_by: IdentityHash,
    /// Current key generation number (increments on rotation).
    key_generation: u32,
    /// Hash of the current group key for verification.
    key_hash: Hash256,
}

impl GroupMetadata {
    /// Create a new group.
    ///
    /// The creator becomes the first admin.
    ///
    /// # Arguments
    ///
    /// * `creator` - The identity creating the group
    /// * `name` - Optional human-readable name
    pub fn create(creator: &IdentityHash, name: Option<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let creator_member = GroupMember {
            identity: creator.clone(),
            role: GroupRole::Admin,
            joined_at: now,
            added_by: creator.clone(),
        };

        Self {
            group_id: GroupId::generate(),
            name,
            members: vec![creator_member],
            created_at: now,
            created_by: creator.clone(),
            key_generation: 0,
            key_hash: Hash256::default(),
        }
    }

    /// Get the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Get the group name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Set the group name.
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the creator's identity hash.
    pub fn created_by(&self) -> &IdentityHash {
        &self.created_by
    }

    /// Get the current key generation.
    pub fn key_generation(&self) -> u32 {
        self.key_generation
    }

    /// Get the current key hash.
    pub fn key_hash(&self) -> &Hash256 {
        &self.key_hash
    }

    /// Get all members.
    pub fn members(&self) -> &[GroupMember] {
        &self.members
    }

    /// Get a member by identity.
    pub fn get_member(&self, identity: &IdentityHash) -> Option<&GroupMember> {
        self.members.iter().find(|m| &m.identity == identity)
    }

    /// Check if an identity is a member of the group.
    pub fn is_member(&self, identity: &IdentityHash) -> bool {
        self.members.iter().any(|m| &m.identity == identity)
    }

    /// Check if an identity is an admin.
    pub fn is_admin(&self, identity: &IdentityHash) -> bool {
        self.members
            .iter()
            .any(|m| &m.identity == identity && m.role == GroupRole::Admin)
    }

    /// Check if an identity can add members.
    pub fn can_add_members(&self, identity: &IdentityHash) -> bool {
        self.members
            .iter()
            .find(|m| &m.identity == identity)
            .map(|m| m.role.can_add_members())
            .unwrap_or(false)
    }

    /// Check if an identity can remove members.
    pub fn can_remove_members(&self, identity: &IdentityHash) -> bool {
        self.members
            .iter()
            .find(|m| &m.identity == identity)
            .map(|m| m.role.can_remove_members())
            .unwrap_or(false)
    }

    /// Get the number of members.
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// Count members with a specific role.
    pub fn count_role(&self, role: GroupRole) -> usize {
        self.members.iter().filter(|m| m.role == role).count()
    }

    /// Add a member to the group.
    ///
    /// # Arguments
    ///
    /// * `member_id` - The identity to add
    /// * `role` - The role to assign
    /// * `added_by` - The identity performing the add
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The group is full
    /// - The member is already in the group
    /// - The adder doesn't have permission
    pub fn add_member(
        &mut self,
        member_id: &IdentityHash,
        role: GroupRole,
        added_by: &IdentityHash,
    ) -> Result<()> {
        // Check if group is full
        if self.members.len() >= MAX_GROUP_SIZE {
            return Err(ProtocolError::GroupFull {
                max: MAX_GROUP_SIZE,
            });
        }

        // Check if already a member
        if self.is_member(member_id) {
            return Err(ProtocolError::MemberAlreadyInGroup);
        }

        // Check authorization
        let adder = self
            .get_member(added_by)
            .ok_or_else(|| ProtocolError::NotAuthorized("Not a group member".to_string()))?;

        if !adder.role.can_add_members() {
            return Err(ProtocolError::NotAuthorized(
                "Role cannot add members".to_string(),
            ));
        }

        // Moderators cannot add admins
        if adder.role == GroupRole::Moderator && role == GroupRole::Admin {
            return Err(ProtocolError::NotAuthorized(
                "Moderators cannot add admins".to_string(),
            ));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        let new_member = GroupMember {
            identity: member_id.clone(),
            role,
            joined_at: now,
            added_by: added_by.clone(),
        };

        self.members.push(new_member);
        Ok(())
    }

    /// Remove a member from the group.
    ///
    /// # Arguments
    ///
    /// * `member_id` - The identity to remove
    /// * `removed_by` - The identity performing the removal
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The member is not in the group
    /// - The remover doesn't have permission
    /// - Trying to remove the last admin
    pub fn remove_member(
        &mut self,
        member_id: &IdentityHash,
        removed_by: &IdentityHash,
    ) -> Result<()> {
        // Find the member to remove
        let member_index = self
            .members
            .iter()
            .position(|m| &m.identity == member_id)
            .ok_or(ProtocolError::MemberNotInGroup)?;

        let target_role = self.members[member_index].role;

        // Self-removal is always allowed
        if member_id != removed_by {
            // Check authorization
            let remover = self
                .get_member(removed_by)
                .ok_or_else(|| ProtocolError::NotAuthorized("Not a group member".to_string()))?;

            if !remover.role.can_remove(target_role) {
                return Err(ProtocolError::NotAuthorized(format!(
                    "{:?} cannot remove {:?}",
                    remover.role, target_role
                )));
            }
        }

        // Cannot remove last admin
        if target_role == GroupRole::Admin && self.count_role(GroupRole::Admin) == 1 {
            return Err(ProtocolError::CannotRemoveLastAdmin);
        }

        self.members.remove(member_index);
        Ok(())
    }

    /// Change a member's role.
    ///
    /// # Arguments
    ///
    /// * `member_id` - The identity whose role to change
    /// * `new_role` - The new role
    /// * `changed_by` - The identity performing the change
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The member is not in the group
    /// - The changer doesn't have permission
    /// - Trying to demote the last admin
    pub fn change_role(
        &mut self,
        member_id: &IdentityHash,
        new_role: GroupRole,
        changed_by: &IdentityHash,
    ) -> Result<()> {
        // Check authorization
        let changer = self
            .get_member(changed_by)
            .ok_or_else(|| ProtocolError::NotAuthorized("Not a group member".to_string()))?;

        if !changer.role.can_change_roles() {
            return Err(ProtocolError::NotAuthorized(
                "Only admins can change roles".to_string(),
            ));
        }

        // Count admins first (before mutable borrow)
        let admin_count = self.count_role(GroupRole::Admin);

        // Find the member
        let member = self
            .members
            .iter_mut()
            .find(|m| &m.identity == member_id)
            .ok_or(ProtocolError::MemberNotInGroup)?;

        // Cannot demote last admin
        if member.role == GroupRole::Admin && new_role != GroupRole::Admin && admin_count == 1 {
            return Err(ProtocolError::CannotRemoveLastAdmin);
        }

        member.role = new_role;
        Ok(())
    }

    /// Increment the key generation and update the key hash.
    ///
    /// Called when group key is rotated.
    ///
    /// # Errors
    ///
    /// PROTO-FIX-11: Returns an error if the key generation counter would overflow,
    /// rather than silently saturating. A saturated counter would mean two different
    /// keys share the same generation number, which is a security issue.
    pub fn increment_key_generation(&mut self, new_key_hash: Hash256) -> Result<()> {
        self.key_generation = self.key_generation.checked_add(1).ok_or_else(|| {
            ProtocolError::InvalidEnvelope(
                "key generation overflow: cannot rotate keys further".to_string(),
            )
        })?;
        self.key_hash = new_key_hash;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_identity(seed: &[u8]) -> IdentityHash {
        IdentityHash::from_public_key(seed)
    }

    #[test]
    fn test_group_id_generation() {
        let id1 = GroupId::generate();
        let id2 = GroupId::generate();

        // Should be different
        assert_ne!(id1, id2);
        assert_eq!(id1.as_bytes().len(), GROUP_ID_SIZE);
    }

    #[test]
    fn test_group_id_hex_roundtrip() {
        let id = GroupId::generate();
        let hex = id.to_hex();
        let restored = GroupId::from_hex(&hex).unwrap();

        assert_eq!(id, restored);
    }

    #[test]
    fn test_group_id_bytes_roundtrip() {
        let id = GroupId::generate();
        let bytes = id.to_bytes();
        let restored = GroupId::from_bytes(&bytes).unwrap();

        assert_eq!(id, restored);
    }

    #[test]
    fn test_group_role_ordering() {
        assert!(GroupRole::Admin < GroupRole::Moderator);
        assert!(GroupRole::Moderator < GroupRole::Member);
    }

    #[test]
    fn test_group_role_permissions() {
        assert!(GroupRole::Admin.can_add_members());
        assert!(GroupRole::Moderator.can_add_members());
        assert!(!GroupRole::Member.can_add_members());

        assert!(GroupRole::Admin.can_rotate_keys());
        assert!(!GroupRole::Moderator.can_rotate_keys());
        assert!(!GroupRole::Member.can_rotate_keys());

        assert!(GroupRole::Admin.can_remove(GroupRole::Admin));
        assert!(GroupRole::Admin.can_remove(GroupRole::Member));
        assert!(!GroupRole::Moderator.can_remove(GroupRole::Admin));
        assert!(GroupRole::Moderator.can_remove(GroupRole::Member));
    }

    #[test]
    fn test_group_creation() {
        let creator = create_test_identity(b"creator");
        let group = GroupMetadata::create(&creator, Some("Test Group".to_string()));

        assert_eq!(group.name(), Some("Test Group"));
        assert_eq!(group.member_count(), 1);
        assert!(group.is_member(&creator));
        assert!(group.is_admin(&creator));
        assert_eq!(group.key_generation(), 0);
    }

    #[test]
    fn test_add_member() {
        let creator = create_test_identity(b"creator");
        let member = create_test_identity(b"member");

        let mut group = GroupMetadata::create(&creator, None);
        group
            .add_member(&member, GroupRole::Member, &creator)
            .unwrap();

        assert_eq!(group.member_count(), 2);
        assert!(group.is_member(&member));
        assert!(!group.is_admin(&member));
    }

    #[test]
    fn test_add_member_group_full() {
        let creator = create_test_identity(b"creator");
        let mut group = GroupMetadata::create(&creator, None);

        // Fill up the group
        for i in 0..MAX_GROUP_SIZE - 1 {
            let member = create_test_identity(format!("member-{}", i).as_bytes());
            group
                .add_member(&member, GroupRole::Member, &creator)
                .unwrap();
        }

        // Try to add one more
        let extra = create_test_identity(b"extra");
        let result = group.add_member(&extra, GroupRole::Member, &creator);

        assert!(matches!(result, Err(ProtocolError::GroupFull { .. })));
    }

    #[test]
    fn test_add_member_already_exists() {
        let creator = create_test_identity(b"creator");
        let member = create_test_identity(b"member");

        let mut group = GroupMetadata::create(&creator, None);
        group
            .add_member(&member, GroupRole::Member, &creator)
            .unwrap();

        let result = group.add_member(&member, GroupRole::Member, &creator);
        assert!(matches!(result, Err(ProtocolError::MemberAlreadyInGroup)));
    }

    #[test]
    fn test_add_member_unauthorized() {
        let creator = create_test_identity(b"creator");
        let member = create_test_identity(b"member");
        let other = create_test_identity(b"other");

        let mut group = GroupMetadata::create(&creator, None);
        group
            .add_member(&member, GroupRole::Member, &creator)
            .unwrap();

        // Member cannot add others
        let new_member = create_test_identity(b"new");
        let result = group.add_member(&new_member, GroupRole::Member, &member);

        assert!(matches!(result, Err(ProtocolError::NotAuthorized(_))));

        // Non-member cannot add
        let result = group.add_member(&new_member, GroupRole::Member, &other);
        assert!(matches!(result, Err(ProtocolError::NotAuthorized(_))));
    }

    #[test]
    fn test_moderator_cannot_add_admin() {
        let creator = create_test_identity(b"creator");
        let moderator = create_test_identity(b"moderator");
        let new_member = create_test_identity(b"new");

        let mut group = GroupMetadata::create(&creator, None);
        group
            .add_member(&moderator, GroupRole::Moderator, &creator)
            .unwrap();

        // Moderator can add members
        let result = group.add_member(&new_member, GroupRole::Member, &moderator);
        assert!(result.is_ok());

        // But not admins
        let another = create_test_identity(b"another");
        let result = group.add_member(&another, GroupRole::Admin, &moderator);
        assert!(matches!(result, Err(ProtocolError::NotAuthorized(_))));
    }

    #[test]
    fn test_remove_member() {
        let creator = create_test_identity(b"creator");
        let member = create_test_identity(b"member");

        let mut group = GroupMetadata::create(&creator, None);
        group
            .add_member(&member, GroupRole::Member, &creator)
            .unwrap();

        group.remove_member(&member, &creator).unwrap();
        assert_eq!(group.member_count(), 1);
        assert!(!group.is_member(&member));
    }

    #[test]
    fn test_self_removal() {
        let creator = create_test_identity(b"creator");
        let member = create_test_identity(b"member");

        let mut group = GroupMetadata::create(&creator, None);
        group
            .add_member(&member, GroupRole::Member, &creator)
            .unwrap();

        // Member can remove themselves
        group.remove_member(&member, &member).unwrap();
        assert!(!group.is_member(&member));
    }

    #[test]
    fn test_cannot_remove_last_admin() {
        let creator = create_test_identity(b"creator");
        let mut group = GroupMetadata::create(&creator, None);

        let result = group.remove_member(&creator, &creator);
        assert!(matches!(result, Err(ProtocolError::CannotRemoveLastAdmin)));
    }

    #[test]
    fn test_moderator_cannot_remove_admin() {
        let admin = create_test_identity(b"admin");
        let moderator = create_test_identity(b"moderator");

        let mut group = GroupMetadata::create(&admin, None);
        group
            .add_member(&moderator, GroupRole::Moderator, &admin)
            .unwrap();

        let result = group.remove_member(&admin, &moderator);
        assert!(matches!(result, Err(ProtocolError::NotAuthorized(_))));
    }

    #[test]
    fn test_change_role() {
        let admin = create_test_identity(b"admin");
        let member = create_test_identity(b"member");

        let mut group = GroupMetadata::create(&admin, None);
        group
            .add_member(&member, GroupRole::Member, &admin)
            .unwrap();

        // Promote to moderator
        group
            .change_role(&member, GroupRole::Moderator, &admin)
            .unwrap();
        assert_eq!(
            group.get_member(&member).unwrap().role,
            GroupRole::Moderator
        );

        // Promote to admin
        group
            .change_role(&member, GroupRole::Admin, &admin)
            .unwrap();
        assert!(group.is_admin(&member));
    }

    #[test]
    fn test_cannot_demote_last_admin() {
        let admin = create_test_identity(b"admin");
        let mut group = GroupMetadata::create(&admin, None);

        let result = group.change_role(&admin, GroupRole::Member, &admin);
        assert!(matches!(result, Err(ProtocolError::CannotRemoveLastAdmin)));
    }

    #[test]
    fn test_increment_key_generation() {
        let creator = create_test_identity(b"creator");
        let mut group = GroupMetadata::create(&creator, None);

        assert_eq!(group.key_generation(), 0);

        let new_hash = Hash256::hash(b"new key");
        group.increment_key_generation(new_hash.clone()).unwrap();

        assert_eq!(group.key_generation(), 1);
        assert_eq!(group.key_hash(), &new_hash);
    }
}
