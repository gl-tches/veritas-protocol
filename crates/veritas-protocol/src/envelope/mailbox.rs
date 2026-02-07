//! Mailbox key derivation for privacy-preserving message routing.
//!
//! Mailbox keys are derived identifiers that change over time, preventing
//! recipients from being tracked across messages. Instead of using the
//! recipient's identity hash directly, we derive a mailbox key from:
//!
//! - Recipient identity hash
//! - Current epoch (rotates daily)
//! - Random per-message salt
//!
//! This ensures that:
//! - Messages to the same recipient have different mailbox keys
//! - Mailbox keys are unlinkable across epochs
//! - Relays cannot correlate recipient identities
//!
//! ## Security Properties
//!
//! - **Unlinkability**: Different salts produce different mailbox keys
//! - **Forward Privacy**: Old epochs cannot be correlated with new ones
//! - **Recipient Privacy**: Mailbox key reveals nothing about recipient identity

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::limits::EPOCH_DURATION_SECS;

/// Domain separator for mailbox key derivation.
///
/// This prefix ensures mailbox keys cannot be confused with other
/// types of keys in the VERITAS protocol.
const MAILBOX_KEY_DOMAIN: &[u8] = b"VERITAS-MAILBOX-KEY-v1";

/// Size of mailbox key in bytes.
pub const MAILBOX_KEY_SIZE: usize = 32;

/// Size of mailbox salt in bytes.
pub const MAILBOX_SALT_SIZE: usize = 16;

/// A derived mailbox key for privacy-preserving message routing.
///
/// This is NOT the recipient's identity hash - it's a derived value
/// that changes with each epoch and salt combination.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxKey([u8; MAILBOX_KEY_SIZE]);

impl MailboxKey {
    /// Create a mailbox key from raw bytes.
    pub fn from_bytes(bytes: [u8; MAILBOX_KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Get the mailbox key as a byte slice.
    pub fn as_bytes(&self) -> &[u8; MAILBOX_KEY_SIZE] {
        &self.0
    }

    /// Convert to owned byte array.
    pub fn to_bytes(&self) -> [u8; MAILBOX_KEY_SIZE] {
        self.0
    }
}

impl std::fmt::Debug for MailboxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MailboxKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

impl AsRef<[u8]> for MailboxKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Parameters for deriving a mailbox key.
///
/// Contains all inputs needed to derive a mailbox key for a message.
#[derive(Clone, Serialize, Deserialize)]
pub struct MailboxKeyParams {
    /// Recipient's identity hash (kept private, used only for derivation).
    recipient_id: IdentityHash,
    /// Current epoch (based on timestamp / epoch duration).
    epoch: u64,
    /// Random salt for this specific message.
    salt: [u8; MAILBOX_SALT_SIZE],
}

impl MailboxKeyParams {
    /// Create new mailbox key parameters for the current epoch.
    ///
    /// Generates a random salt and computes the current epoch based
    /// on the system time.
    ///
    /// # Arguments
    ///
    /// * `recipient_id` - The recipient's identity hash
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_protocol::envelope::mailbox::MailboxKeyParams;
    /// use veritas_identity::IdentityHash;
    ///
    /// let recipient = IdentityHash::from_public_key(b"public-key");
    /// let params = MailboxKeyParams::new_current(&recipient);
    /// let mailbox_key = params.derive();
    /// ```
    pub fn new_current(recipient_id: &IdentityHash) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time before UNIX epoch")
            .as_secs();

        let epoch = epoch_from_timestamp(now, EPOCH_DURATION_SECS);
        let salt = generate_mailbox_salt();

        Self {
            recipient_id: recipient_id.clone(),
            epoch,
            salt,
        }
    }

    /// Create mailbox key parameters with explicit values.
    ///
    /// Use this for testing or when you need specific epoch/salt values.
    ///
    /// # Arguments
    ///
    /// * `recipient_id` - The recipient's identity hash
    /// * `epoch` - The epoch number
    /// * `salt` - The random salt
    pub fn new(recipient_id: &IdentityHash, epoch: u64, salt: [u8; MAILBOX_SALT_SIZE]) -> Self {
        Self {
            recipient_id: recipient_id.clone(),
            epoch,
            salt,
        }
    }

    /// Get the epoch number.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get the salt.
    pub fn salt(&self) -> &[u8; MAILBOX_SALT_SIZE] {
        &self.salt
    }

    /// Derive the mailbox key from these parameters.
    ///
    /// The mailbox key is derived as:
    /// ```text
    /// BLAKE3(DOMAIN || recipient_id || epoch || salt)
    /// ```
    ///
    /// # Returns
    ///
    /// A 32-byte mailbox key that is unlinkable to the recipient's identity.
    pub fn derive(&self) -> MailboxKey {
        let key = derive_mailbox_key(&self.recipient_id, self.epoch, &self.salt);
        MailboxKey(key)
    }
}

impl std::fmt::Debug for MailboxKeyParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MailboxKeyParams")
            .field("recipient_id", &self.recipient_id)
            .field("epoch", &self.epoch)
            .field(
                "salt",
                &format!("{:02x}{:02x}...", self.salt[0], self.salt[1]),
            )
            .finish()
    }
}

/// Derive a mailbox key from recipient identity, epoch, and salt.
///
/// This is the core derivation function. The mailbox key changes when
/// any of the inputs change, providing unlinkability.
///
/// # Arguments
///
/// * `recipient_id` - The recipient's identity hash
/// * `epoch` - Current epoch number (changes daily)
/// * `salt` - Random 16-byte salt (unique per message)
///
/// # Returns
///
/// A 32-byte derived mailbox key.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::envelope::mailbox::derive_mailbox_key;
/// use veritas_identity::IdentityHash;
///
/// let recipient = IdentityHash::from_public_key(b"public-key");
/// let epoch = 12345;
/// let salt = [0u8; 16];
///
/// let mailbox_key = derive_mailbox_key(&recipient, epoch, &salt);
/// ```
pub fn derive_mailbox_key(
    recipient_id: &IdentityHash,
    epoch: u64,
    salt: &[u8; MAILBOX_SALT_SIZE],
) -> [u8; MAILBOX_KEY_SIZE] {
    Hash256::hash_many(&[
        MAILBOX_KEY_DOMAIN,
        recipient_id.as_bytes(),
        &epoch.to_be_bytes(),
        salt,
    ])
    .to_bytes()
}

/// Calculate epoch number from a Unix timestamp.
///
/// Epochs are used to rotate mailbox keys periodically, preventing
/// long-term correlation of recipients.
///
/// # Arguments
///
/// * `timestamp_secs` - Unix timestamp in seconds
/// * `epoch_duration_secs` - Duration of each epoch in seconds
///
/// # Returns
///
/// The epoch number for the given timestamp.
///
/// # Example
///
/// ```ignore
/// use veritas_protocol::envelope::mailbox::epoch_from_timestamp;
/// use veritas_protocol::limits::EPOCH_DURATION_SECS;
///
/// // Day 0
/// let epoch0 = epoch_from_timestamp(0, EPOCH_DURATION_SECS);
/// assert_eq!(epoch0, 0);
///
/// // Day 1
/// let epoch1 = epoch_from_timestamp(86400, EPOCH_DURATION_SECS);
/// assert_eq!(epoch1, 1);
/// ```
pub fn epoch_from_timestamp(timestamp_secs: u64, epoch_duration_secs: u64) -> u64 {
    // PROTO-FIX-5: Replace debug_assert! with runtime check to prevent
    // division by zero in release builds (debug_assert is stripped in release).
    if epoch_duration_secs == 0 {
        return 0;
    }
    timestamp_secs / epoch_duration_secs
}

/// Get the current epoch number.
///
/// Uses the system clock and the default epoch duration.
pub fn current_epoch() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs();

    epoch_from_timestamp(now, EPOCH_DURATION_SECS)
}

/// Generate a random mailbox salt.
///
/// Uses the system's cryptographic RNG (OsRng) to generate a
/// 16-byte random salt for mailbox key derivation.
///
/// # Returns
///
/// A 16-byte random salt.
pub fn generate_mailbox_salt() -> [u8; MAILBOX_SALT_SIZE] {
    let mut salt = [0u8; MAILBOX_SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_recipient() -> IdentityHash {
        IdentityHash::from_public_key(b"test-recipient-public-key")
    }

    #[test]
    fn test_derive_mailbox_key_deterministic() {
        let recipient = test_recipient();
        let epoch = 12345u64;
        let salt = [0x42u8; MAILBOX_SALT_SIZE];

        let key1 = derive_mailbox_key(&recipient, epoch, &salt);
        let key2 = derive_mailbox_key(&recipient, epoch, &salt);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_recipients_different_keys() {
        let recipient1 = IdentityHash::from_public_key(b"recipient-1");
        let recipient2 = IdentityHash::from_public_key(b"recipient-2");
        let epoch = 12345u64;
        let salt = [0x42u8; MAILBOX_SALT_SIZE];

        let key1 = derive_mailbox_key(&recipient1, epoch, &salt);
        let key2 = derive_mailbox_key(&recipient2, epoch, &salt);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_epochs_different_keys() {
        let recipient = test_recipient();
        let salt = [0x42u8; MAILBOX_SALT_SIZE];

        let key1 = derive_mailbox_key(&recipient, 100, &salt);
        let key2 = derive_mailbox_key(&recipient, 101, &salt);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_salts_different_keys() {
        let recipient = test_recipient();
        let epoch = 12345u64;

        let salt1 = [0x11u8; MAILBOX_SALT_SIZE];
        let salt2 = [0x22u8; MAILBOX_SALT_SIZE];

        let key1 = derive_mailbox_key(&recipient, epoch, &salt1);
        let key2 = derive_mailbox_key(&recipient, epoch, &salt2);

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_epoch_from_timestamp() {
        let day_secs = 24 * 60 * 60;

        // Day 0
        assert_eq!(epoch_from_timestamp(0, day_secs), 0);
        assert_eq!(epoch_from_timestamp(day_secs - 1, day_secs), 0);

        // Day 1
        assert_eq!(epoch_from_timestamp(day_secs, day_secs), 1);
        assert_eq!(epoch_from_timestamp(day_secs * 2 - 1, day_secs), 1);

        // Day 365
        assert_eq!(epoch_from_timestamp(day_secs * 365, day_secs), 365);
    }

    #[test]
    fn test_generate_mailbox_salt_random() {
        let salt1 = generate_mailbox_salt();
        let salt2 = generate_mailbox_salt();

        // Should be different with overwhelming probability
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_mailbox_key_params_derive() {
        let recipient = test_recipient();
        let epoch = 12345u64;
        let salt = [0x42u8; MAILBOX_SALT_SIZE];

        let params = MailboxKeyParams::new(&recipient, epoch, salt);
        let derived = params.derive();

        let expected = derive_mailbox_key(&recipient, epoch, &salt);
        assert_eq!(derived.as_bytes(), &expected);
    }

    #[test]
    fn test_mailbox_key_params_accessors() {
        let recipient = test_recipient();
        let epoch = 12345u64;
        let salt = [0x42u8; MAILBOX_SALT_SIZE];

        let params = MailboxKeyParams::new(&recipient, epoch, salt);

        assert_eq!(params.epoch(), epoch);
        assert_eq!(params.salt(), &salt);
    }

    #[test]
    fn test_mailbox_key_from_bytes() {
        let bytes = [0x42u8; MAILBOX_KEY_SIZE];
        let key = MailboxKey::from_bytes(bytes);

        assert_eq!(key.as_bytes(), &bytes);
        assert_eq!(key.to_bytes(), bytes);
    }

    #[test]
    fn test_mailbox_key_debug() {
        let bytes = [
            0x12u8, 0x34u8, 0x56u8, 0x78u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
            0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        ];
        let key = MailboxKey::from_bytes(bytes);
        let debug = format!("{:?}", key);

        assert!(debug.contains("MailboxKey"));
        assert!(debug.contains("1234"));
    }

    #[test]
    fn test_current_epoch_reasonable() {
        let epoch = current_epoch();
        // Should be non-zero (we're past 1970)
        // and reasonable (less than year 3000)
        assert!(epoch > 0);
        assert!(epoch < 100_000); // ~274 years of daily epochs
    }

    #[test]
    fn test_mailbox_key_serialization() {
        let bytes = [0x42u8; MAILBOX_KEY_SIZE];
        let key = MailboxKey::from_bytes(bytes);

        let serialized = bincode::serialize(&key).unwrap();
        let deserialized: MailboxKey = bincode::deserialize(&serialized).unwrap();

        assert_eq!(key, deserialized);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn mailbox_key_deterministic(
            pubkey: Vec<u8>,
            epoch: u64,
            salt in any::<[u8; MAILBOX_SALT_SIZE]>()
        ) {
            let recipient = IdentityHash::from_public_key(&pubkey);

            let key1 = derive_mailbox_key(&recipient, epoch, &salt);
            let key2 = derive_mailbox_key(&recipient, epoch, &salt);

            prop_assert_eq!(key1, key2);
        }

        #[test]
        fn different_salts_produce_different_keys(
            pubkey: Vec<u8>,
            epoch: u64,
            salt1 in any::<[u8; MAILBOX_SALT_SIZE]>(),
            salt2 in any::<[u8; MAILBOX_SALT_SIZE]>()
        ) {
            prop_assume!(salt1 != salt2);

            let recipient = IdentityHash::from_public_key(&pubkey);

            let key1 = derive_mailbox_key(&recipient, epoch, &salt1);
            let key2 = derive_mailbox_key(&recipient, epoch, &salt2);

            prop_assert_ne!(key1, key2);
        }

        #[test]
        fn epoch_calculation_consistent(timestamp: u64, duration in 1u64..=86400u64) {
            let epoch = epoch_from_timestamp(timestamp, duration);

            // Verify the epoch covers the right range
            let epoch_start = epoch * duration;
            let epoch_end = epoch_start + duration;

            prop_assert!(timestamp >= epoch_start);
            prop_assert!(timestamp < epoch_end);
        }
    }
}
