//! Group types for the high-level VERITAS API.
//!
//! This module provides user-friendly types for working with groups in VERITAS.
//! These types wrap or simplify the lower-level protocol types for easier
//! integration with application code.
//!
//! ## Types
//!
//! - [`GroupInfo`]: Summary information about a group the user belongs to
//! - [`GroupMessage`]: A decrypted message received in a group chat
//!
//! ## Re-exports
//!
//! For convenience, this module re-exports commonly used types:
//! - [`GroupId`]: Unique identifier for a group
//! - [`GroupRole`]: Member role within a group (Admin, Moderator, Member)
//!
//! ## Example
//!
//! ```ignore
//! use veritas_core::groups::{GroupInfo, GroupMessage, GroupRole};
//!
//! // Get info about groups the user belongs to
//! let groups: Vec<GroupInfo> = client.list_groups().await?;
//! for group in groups {
//!     println!("Group: {:?}", group.name);
//!     println!("My role: {:?}", group.my_role);
//!     println!("Members: {}", group.member_count);
//! }
//!
//! // Receive messages from a group
//! let messages: Vec<GroupMessage> = client.get_group_messages(&group_id).await?;
//! for msg in messages {
//!     println!("[{}]: {}", msg.sender, msg.text);
//! }
//! ```

use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;
use veritas_store::MessageId;

// Re-export commonly used types from veritas_protocol::groups
pub use veritas_protocol::groups::{GroupId, GroupRole};

/// Summary information about a group.
///
/// This struct provides a high-level view of a group suitable for
/// displaying in a group list or group details screen. It contains
/// the essential metadata needed for UI presentation.
///
/// ## Fields
///
/// - `id`: The unique identifier for this group
/// - `name`: Optional human-readable name for the group
/// - `member_count`: Number of members currently in the group
/// - `my_role`: The current user's role within the group
/// - `created_at`: Unix timestamp when the group was created
/// - `key_generation`: Current key generation number (increments on key rotation)
///
/// ## Key Generation
///
/// The `key_generation` field is useful for detecting when group keys
/// have been rotated. Applications may want to notify users when key
/// rotation occurs (e.g., after a member is removed).
#[derive(Clone, Debug)]
pub struct GroupInfo {
    /// The unique identifier for this group.
    pub id: GroupId,

    /// Optional human-readable name for the group.
    ///
    /// Groups may be created without a name, in which case applications
    /// typically display a placeholder or derive a name from members.
    pub name: Option<String>,

    /// Number of members currently in the group.
    ///
    /// This count includes all roles (admins, moderators, and members).
    /// Maximum group size is 100 members as per protocol limits.
    pub member_count: usize,

    /// The current user's role within this group.
    ///
    /// This determines what actions the user can perform:
    /// - `Admin`: Full control (add/remove members, change roles, rotate keys)
    /// - `Moderator`: Can add members and remove regular members
    /// - `Member`: Can send and receive messages only
    pub my_role: GroupRole,

    /// Unix timestamp (seconds since epoch) when the group was created.
    pub created_at: u64,

    /// Current key generation number.
    ///
    /// This value starts at 0 and increments each time the group key
    /// is rotated. Key rotation occurs automatically when members are
    /// removed (for forward secrecy) and periodically per the rotation
    /// schedule (every 7 days by default).
    pub key_generation: u32,
}

/// A decrypted group message.
///
/// This struct represents a message that has been received from a group
/// and successfully decrypted. It contains both the message content and
/// metadata needed for display and tracking.
///
/// ## Security Note
///
/// This struct only contains decrypted content. The original encrypted
/// payload is not retained after decryption to minimize exposure of
/// sensitive data in memory.
///
/// ## Timestamps
///
/// The struct contains two timestamp fields:
/// - `timestamp`: When the sender created the message (from the signed payload)
/// - `received_at`: When our node received the message from the network
///
/// These may differ due to network latency, offline delivery, or clock skew.
/// Applications should generally display `timestamp` to users but may use
/// `received_at` for sorting recent messages.
#[derive(Clone, Debug)]
pub struct GroupMessage {
    /// Local storage identifier for this message.
    ///
    /// This ID is used to reference the message in local storage operations
    /// (mark as read, delete, etc.). It is generated locally and not shared
    /// across the network.
    pub id: MessageId,

    /// Cryptographic hash of the message (BLAKE3).
    ///
    /// This hash uniquely identifies the message content and is used for:
    /// - Deduplication (detecting if we've already received this message)
    /// - Blockchain anchoring (proving message existence at a point in time)
    /// - Message references (replying to or quoting messages)
    pub message_hash: Hash256,

    /// The group this message belongs to.
    pub group_id: GroupId,

    /// Identity hash of the message sender.
    ///
    /// This is extracted from the encrypted payload and verified against
    /// the message signature. Only group members can send messages, so
    /// this identity is guaranteed to be (or have been) a group member.
    pub sender: IdentityHash,

    /// The decrypted message text content.
    ///
    /// Message length is limited to 300 characters per chunk, with a
    /// maximum of 3 chunks (900 characters total) per protocol limits.
    pub text: String,

    /// Unix timestamp (seconds) when the message was created by the sender.
    ///
    /// This value comes from the signed message payload and represents
    /// when the sender composed the message. Note that this timestamp
    /// is self-reported by the sender and may be subject to clock skew.
    pub timestamp: u64,

    /// Unix timestamp (seconds) when this message was received locally.
    ///
    /// This is the time our node received and stored the message from
    /// the network. For messages received while offline, this will be
    /// the sync time rather than the original send time.
    pub received_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_info_clone() {
        let info = GroupInfo {
            id: GroupId::generate(),
            name: Some("Test Group".to_string()),
            member_count: 5,
            my_role: GroupRole::Admin,
            created_at: 1700000000,
            key_generation: 2,
        };

        let cloned = info.clone();
        assert_eq!(cloned.name, Some("Test Group".to_string()));
        assert_eq!(cloned.member_count, 5);
        assert_eq!(cloned.my_role, GroupRole::Admin);
        assert_eq!(cloned.created_at, 1700000000);
        assert_eq!(cloned.key_generation, 2);
    }

    #[test]
    fn test_group_info_debug() {
        let info = GroupInfo {
            id: GroupId::generate(),
            name: None,
            member_count: 3,
            my_role: GroupRole::Member,
            created_at: 1700000000,
            key_generation: 0,
        };

        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("GroupInfo"));
        assert!(debug_str.contains("member_count: 3"));
        assert!(debug_str.contains("Member"));
    }

    #[test]
    fn test_group_message_clone() {
        let msg = GroupMessage {
            id: MessageId::generate(),
            message_hash: Hash256::hash(b"test message"),
            group_id: GroupId::generate(),
            sender: IdentityHash::from_public_key(b"sender-key"),
            text: "Hello, group!".to_string(),
            timestamp: 1700000000,
            received_at: 1700000001,
        };

        let cloned = msg.clone();
        assert_eq!(cloned.text, "Hello, group!");
        assert_eq!(cloned.timestamp, 1700000000);
        assert_eq!(cloned.received_at, 1700000001);
    }

    #[test]
    fn test_group_message_debug() {
        let msg = GroupMessage {
            id: MessageId::generate(),
            message_hash: Hash256::hash(b"test"),
            group_id: GroupId::generate(),
            sender: IdentityHash::from_public_key(b"sender"),
            text: "Test message".to_string(),
            timestamp: 1700000000,
            received_at: 1700000001,
        };

        let debug_str = format!("{:?}", msg);
        assert!(debug_str.contains("GroupMessage"));
        assert!(debug_str.contains("Test message"));
    }

    #[test]
    fn test_group_role_reexport() {
        // Verify re-exports work correctly
        assert!(GroupRole::Admin.can_add_members());
        assert!(GroupRole::Moderator.can_add_members());
        assert!(!GroupRole::Member.can_add_members());
    }

    #[test]
    fn test_group_id_reexport() {
        // Verify GroupId re-export works
        let id = GroupId::generate();
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
    }
}
