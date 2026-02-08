//! Group messaging for VERITAS protocol.
//!
//! Provides:
//! - Group metadata management (members, roles, creation)
//! - Group key management with forward secrecy
//! - Key rotation on member removal or schedule
//! - Encrypted group messages
//!
//! ## Security Properties
//!
//! - **Forward Secrecy**: Removed members cannot decrypt new messages
//! - **Key Rotation**: Keys rotate on member removal and periodically
//! - **Role-Based Access**: Only admins/moderators can add members
//! - **Zeroization**: All keys are zeroized on drop
//!
//! ## Group Limits
//!
//! - Maximum 100 members per group
//! - Maximum 50 groups per identity
//! - Keys rotate every 7 days or on member removal
//!
//! ## Example
//!
//! ```ignore
//! use veritas_protocol::groups::{GroupMetadata, GroupKey, GroupRole};
//! use veritas_identity::IdentityHash;
//!
//! // Create a new group
//! let creator = IdentityHash::from_public_key(b"creator-key");
//! let mut group = GroupMetadata::create(&creator, Some("My Group".to_string()));
//!
//! // Add a member
//! let member = IdentityHash::from_public_key(b"member-key");
//! group.add_member(&member, GroupRole::Member, &creator)?;
//!
//! // Generate group key
//! let group_key = GroupKey::generate(group.key_generation());
//!
//! // Encrypt a message
//! let encrypted = GroupMessageData::encrypt(
//!     group.group_id(),
//!     &group_key,
//!     "Hello group!",
//! )?;
//! ```

pub mod keys;
pub mod metadata;
pub mod rotation;
pub mod sender_auth;

pub use keys::{EncryptedGroupKey, GroupKey, GroupKeyManager, GroupMessageData};
pub use metadata::{GroupId, GroupMember, GroupMetadata, GroupRole};
pub use rotation::{KeyRotationManager, RotationResult, RotationTrigger};
pub use sender_auth::{
    AuthenticatedGroupMessage, GroupAuthMode, GroupSenderAuth, GROUP_SENDER_AUTH_TAG_SIZE,
    compute_group_sender_auth, compute_group_sender_auth_mldsa, verify_group_sender_auth,
};
