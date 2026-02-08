//! Session management for 1:1 messaging with Double Ratchet.
//!
//! Integrates the X3DH key agreement and Double Ratchet algorithm
//! from `veritas-crypto` into the VERITAS protocol layer.
//!
//! ## Session Lifecycle
//!
//! 1. **Bundle publication**: User generates and publishes a prekey bundle
//! 2. **Session initiation**: Initiator fetches bundle, performs X3DH, creates session
//! 3. **Message exchange**: Messages encrypted/decrypted via Double Ratchet
//! 4. **Session persistence**: State saved to `veritas-store` between messages
//!
//! ## Security Properties
//!
//! - **Forward secrecy**: Per-message keys via symmetric ratchet
//! - **Post-compromise security**: DH ratchet recovers after key compromise
//! - **Deniable authentication**: Optional deniable auth tags instead of ML-DSA
//! - **Out-of-order delivery**: Skipped message keys cached (bounded)

use serde::{Deserialize, Serialize};

use veritas_crypto::{
    DeniableAuthTag, DoubleRatchetSession, Hash256, PreKeyBundle, RatchetMessage,
    SessionState, X3DHInitialMessage, X25519PublicKey, X25519StaticPrivateKey,
    compute_deniable_auth, verify_deniable_auth, x3dh_initiate, x3dh_respond,
};
use veritas_identity::IdentityHash;

use crate::error::{ProtocolError, Result};

/// A unique session identifier derived from the X3DH exchange.
pub type SessionId = [u8; 32];

/// Authentication mode for messages in a session.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthMode {
    /// Non-repudiable ML-DSA-65 signature (default for on-chain messages).
    MlDsa,
    /// Deniable authentication via shared-secret MAC.
    /// Only the two parties can verify; neither can prove authorship to a third party.
    Deniable,
}

/// Metadata about a messaging session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub session_id: SessionId,
    /// Our identity hash.
    pub our_identity: IdentityHash,
    /// Peer's identity hash.
    pub peer_identity: IdentityHash,
    /// Our X25519 identity public key (for DH-based operations).
    pub our_identity_key: X25519PublicKey,
    /// Peer's X25519 identity public key.
    pub peer_identity_key: X25519PublicKey,
    /// Authentication mode for this session.
    pub auth_mode: AuthMode,
    /// Timestamp when this session was created.
    pub created_at: u64,
    /// Timestamp of the last message in this session.
    pub last_activity: u64,
    /// Total messages sent in this session.
    pub messages_sent: u64,
    /// Total messages received in this session.
    pub messages_received: u64,
}

/// A complete persisted session (metadata + ratchet state).
#[derive(Serialize, Deserialize)]
pub struct PersistedSession {
    /// Session metadata.
    pub info: SessionInfo,
    /// Double Ratchet state.
    pub ratchet_state: SessionState,
}

/// An encrypted message produced by a session, ready for transport.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionMessage {
    /// The session identifier.
    pub session_id: SessionId,
    /// The ratchet-encrypted message.
    pub ratchet_message: RatchetMessage,
    /// Optional deniable authentication tag (if auth_mode is Deniable).
    pub deniable_auth: Option<DeniableAuthTag>,
    /// Content hash for integrity verification.
    pub content_hash: [u8; 32],
}

/// An initial session message (sent with X3DH initial message).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitialSessionMessage {
    /// The X3DH initial message for the responder.
    pub x3dh_initial: X3DHInitialMessage,
    /// The first ratchet-encrypted message.
    pub session_message: SessionMessage,
}

/// Manages a single messaging session with Double Ratchet.
pub struct Session {
    /// Session metadata.
    info: SessionInfo,
    /// The Double Ratchet instance.
    ratchet: DoubleRatchetSession,
    /// Our X25519 identity private key (for deniable auth).
    our_identity_private: X25519StaticPrivateKey,
}

impl Session {
    /// Create a new session as the initiator (Alice).
    ///
    /// Performs X3DH key agreement with the peer's prekey bundle and
    /// initializes the Double Ratchet.
    ///
    /// # Arguments
    ///
    /// * `our_identity_private` - Our X25519 identity private key
    /// * `our_identity_hash` - Our identity hash
    /// * `peer_identity_hash` - Peer's identity hash
    /// * `peer_bundle` - Peer's published prekey bundle
    /// * `auth_mode` - Authentication mode for this session
    pub fn initiate(
        our_identity_private: X25519StaticPrivateKey,
        our_identity_hash: IdentityHash,
        peer_identity_hash: IdentityHash,
        peer_bundle: &PreKeyBundle,
        auth_mode: AuthMode,
    ) -> Result<(Self, X3DHInitialMessage)> {
        // Perform X3DH
        let (shared_secret, initial_message) =
            x3dh_initiate(&our_identity_private, peer_bundle)?;

        // Derive session ID from the shared secret
        let session_id = blake3::derive_key(
            "VERITAS-v1.SESSION.session-id",
            shared_secret.as_bytes(),
        );

        let now = current_timestamp();

        // Initialize Double Ratchet as Alice
        let ratchet = DoubleRatchetSession::init_alice(
            shared_secret.as_bytes(),
            &peer_bundle.signed_prekey.public_key,
        );

        let info = SessionInfo {
            session_id,
            our_identity: our_identity_hash,
            peer_identity: peer_identity_hash,
            our_identity_key: our_identity_private.public_key(),
            peer_identity_key: peer_bundle.identity_key.clone(),
            auth_mode,
            created_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
        };

        let session = Session {
            info,
            ratchet,
            our_identity_private,
        };

        Ok((session, initial_message))
    }

    /// Create a new session as the responder (Bob).
    ///
    /// Processes the X3DH initial message and initializes the Double Ratchet.
    ///
    /// # Arguments
    ///
    /// * `our_identity_private` - Our X25519 identity private key
    /// * `our_identity_hash` - Our identity hash
    /// * `peer_identity_hash` - Peer's identity hash
    /// * `signed_prekey_private` - Our signed prekey private that was used
    /// * `one_time_prekey_private` - Our one-time prekey private (if used)
    /// * `initial_message` - The X3DH initial message from the initiator
    /// * `auth_mode` - Authentication mode for this session
    pub fn respond(
        our_identity_private: X25519StaticPrivateKey,
        our_identity_hash: IdentityHash,
        peer_identity_hash: IdentityHash,
        signed_prekey_private: X25519StaticPrivateKey,
        one_time_prekey_private: Option<&X25519StaticPrivateKey>,
        initial_message: &X3DHInitialMessage,
        auth_mode: AuthMode,
    ) -> Result<Self> {
        // Perform X3DH response
        let shared_secret = x3dh_respond(
            &our_identity_private,
            &signed_prekey_private,
            one_time_prekey_private,
            initial_message,
        )?;

        let session_id = blake3::derive_key(
            "VERITAS-v1.SESSION.session-id",
            shared_secret.as_bytes(),
        );

        let now = current_timestamp();

        // Initialize Double Ratchet as Bob
        let ratchet = DoubleRatchetSession::init_bob(
            shared_secret.as_bytes(),
            signed_prekey_private,
        );

        let info = SessionInfo {
            session_id,
            our_identity: our_identity_hash,
            peer_identity: peer_identity_hash,
            our_identity_key: our_identity_private.public_key(),
            peer_identity_key: initial_message.identity_key.clone(),
            auth_mode,
            created_at: now,
            last_activity: now,
            messages_sent: 0,
            messages_received: 0,
        };

        Ok(Session {
            info,
            ratchet,
            our_identity_private,
        })
    }

    /// Encrypt a message in this session.
    ///
    /// Uses the Double Ratchet to encrypt the plaintext and optionally
    /// adds a deniable authentication tag.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<SessionMessage> {
        let ad = self.build_associated_data();

        let ratchet_message = self.ratchet.encrypt(plaintext, &ad)?;

        // Compute content hash
        let content_hash = *Hash256::hash(plaintext).as_bytes();

        // Compute deniable auth if enabled
        let deniable_auth = if self.info.auth_mode == AuthMode::Deniable {
            Some(compute_deniable_auth(
                &self.our_identity_private,
                &self.info.peer_identity_key,
                &content_hash,
                &self.info.session_id,
            ))
        } else {
            None
        };

        self.info.messages_sent += 1;
        self.info.last_activity = current_timestamp();

        Ok(SessionMessage {
            session_id: self.info.session_id,
            ratchet_message,
            deniable_auth,
            content_hash,
        })
    }

    /// Decrypt a message in this session.
    ///
    /// Uses the Double Ratchet to decrypt and optionally verifies
    /// the deniable authentication tag.
    pub fn decrypt_message(&mut self, message: &SessionMessage) -> Result<Vec<u8>> {
        // Verify session ID matches
        if message.session_id != self.info.session_id {
            return Err(ProtocolError::InvalidEnvelope(
                "Session ID mismatch".to_string(),
            ));
        }

        let ad = self.build_associated_data();
        let plaintext = self.ratchet.decrypt(&message.ratchet_message, &ad)?;

        // Verify content hash
        let content_hash = *Hash256::hash(&plaintext).as_bytes();
        if content_hash != message.content_hash {
            return Err(ProtocolError::InvalidEnvelope(
                "Content hash mismatch".to_string(),
            ));
        }

        // Verify deniable auth if present
        if let Some(ref auth_tag) = message.deniable_auth {
            let valid = verify_deniable_auth(
                &self.our_identity_private,
                &self.info.peer_identity_key,
                &content_hash,
                &self.info.session_id,
                auth_tag,
            );
            if !valid {
                return Err(ProtocolError::InvalidSignature);
            }
        }

        self.info.messages_received += 1;
        self.info.last_activity = current_timestamp();

        Ok(plaintext)
    }

    /// Get session information.
    pub fn info(&self) -> &SessionInfo {
        &self.info
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.info.session_id
    }

    /// Get the peer's identity hash.
    pub fn peer_identity(&self) -> &IdentityHash {
        &self.info.peer_identity
    }

    /// Export the session for persistence.
    pub fn export(&self) -> PersistedSession {
        PersistedSession {
            info: self.info.clone(),
            ratchet_state: self.ratchet.export_state(),
        }
    }

    /// Restore a session from persisted state.
    pub fn restore(
        persisted: PersistedSession,
        our_identity_private: X25519StaticPrivateKey,
    ) -> Result<Self> {
        let ratchet = DoubleRatchetSession::from_state(persisted.ratchet_state)?;

        Ok(Session {
            info: persisted.info,
            ratchet,
            our_identity_private,
        })
    }

    /// Build associated data for AEAD.
    /// AD = min(identity_a, identity_b) || max(identity_a, identity_b) || session_id
    /// Uses canonical ordering so both parties produce the same AD.
    fn build_associated_data(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(32 + 32 + 32);
        let a = self.info.our_identity.as_bytes();
        let b = self.info.peer_identity.as_bytes();
        if a <= b {
            ad.extend_from_slice(a);
            ad.extend_from_slice(b);
        } else {
            ad.extend_from_slice(b);
            ad.extend_from_slice(a);
        }
        ad.extend_from_slice(&self.info.session_id);
        ad
    }
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &hex_prefix(&self.info.session_id))
            .field("peer", &self.info.peer_identity)
            .field("auth_mode", &self.info.auth_mode)
            .field("messages_sent", &self.info.messages_sent)
            .field("messages_received", &self.info.messages_received)
            .finish()
    }
}

fn hex_prefix(bytes: &[u8; 32]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}..", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_crypto::{generate_signed_prekey, generate_one_time_prekeys};

    fn make_identity() -> (X25519StaticPrivateKey, IdentityHash) {
        let private = X25519StaticPrivateKey::generate();
        let hash = IdentityHash::from_bytes(&Hash256::hash(private.public_key().as_bytes()).as_bytes()[..]).unwrap();
        (private, hash)
    }

    #[test]
    fn test_session_initiate_and_respond() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        // Bob creates prekey bundle
        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: None,
        };

        // Alice initiates session
        let (mut alice_session, initial_msg) = Session::initiate(
            alice_private,
            alice_hash.clone(),
            bob_hash.clone(),
            &bob_bundle,
            AuthMode::Deniable,
        )
        .unwrap();

        // Bob responds
        let mut bob_session = Session::respond(
            bob_private,
            bob_hash,
            alice_hash,
            bob_spk_private,
            None,
            &initial_msg,
            AuthMode::Deniable,
        )
        .unwrap();

        // Alice sends message
        let encrypted = alice_session.encrypt_message(b"Hello Bob!").unwrap();
        let plaintext = bob_session.decrypt_message(&encrypted).unwrap();
        assert_eq!(plaintext, b"Hello Bob!");

        // Bob responds
        let encrypted = bob_session.encrypt_message(b"Hello Alice!").unwrap();
        let plaintext = alice_session.decrypt_message(&encrypted).unwrap();
        assert_eq!(plaintext, b"Hello Alice!");
    }

    #[test]
    fn test_session_with_one_time_prekey() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_otpk_pairs = generate_one_time_prekeys(1, 100);
        let (bob_otpk_private, bob_otpk_public) = &bob_otpk_pairs[0];

        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: Some(bob_otpk_public.clone()),
        };

        let (mut alice_session, initial_msg) = Session::initiate(
            alice_private,
            alice_hash.clone(),
            bob_hash.clone(),
            &bob_bundle,
            AuthMode::MlDsa,
        )
        .unwrap();

        let mut bob_session = Session::respond(
            bob_private,
            bob_hash,
            alice_hash,
            bob_spk_private,
            Some(bob_otpk_private),
            &initial_msg,
            AuthMode::MlDsa,
        )
        .unwrap();

        let encrypted = alice_session.encrypt_message(b"With OTP key!").unwrap();
        let plaintext = bob_session.decrypt_message(&encrypted).unwrap();
        assert_eq!(plaintext, b"With OTP key!");
    }

    #[test]
    fn test_session_multiple_messages() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: None,
        };

        let (mut alice_session, initial_msg) = Session::initiate(
            alice_private,
            alice_hash.clone(),
            bob_hash.clone(),
            &bob_bundle,
            AuthMode::Deniable,
        )
        .unwrap();

        let mut bob_session = Session::respond(
            bob_private,
            bob_hash,
            alice_hash,
            bob_spk_private,
            None,
            &initial_msg,
            AuthMode::Deniable,
        )
        .unwrap();

        // Alternating messages
        for i in 0..10 {
            if i % 2 == 0 {
                let msg = alice_session
                    .encrypt_message(format!("Alice msg {i}").as_bytes())
                    .unwrap();
                let pt = bob_session.decrypt_message(&msg).unwrap();
                assert_eq!(pt, format!("Alice msg {i}").as_bytes());
            } else {
                let msg = bob_session
                    .encrypt_message(format!("Bob msg {i}").as_bytes())
                    .unwrap();
                let pt = alice_session.decrypt_message(&msg).unwrap();
                assert_eq!(pt, format!("Bob msg {i}").as_bytes());
            }
        }

        assert_eq!(alice_session.info().messages_sent, 5);
        assert_eq!(alice_session.info().messages_received, 5);
    }

    #[test]
    fn test_session_export_restore() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: None,
        };

        let alice_private_clone_bytes = *alice_private.as_bytes();

        let (mut alice_session, initial_msg) = Session::initiate(
            alice_private,
            alice_hash.clone(),
            bob_hash.clone(),
            &bob_bundle,
            AuthMode::Deniable,
        )
        .unwrap();

        let mut bob_session = Session::respond(
            bob_private,
            bob_hash,
            alice_hash,
            bob_spk_private,
            None,
            &initial_msg,
            AuthMode::Deniable,
        )
        .unwrap();

        // Exchange a message
        let msg = alice_session.encrypt_message(b"Before restore").unwrap();
        bob_session.decrypt_message(&msg).unwrap();

        // Export and restore Alice's session
        let persisted = alice_session.export();
        let alice_private_restored =
            X25519StaticPrivateKey::from_bytes(&alice_private_clone_bytes).unwrap();
        let mut alice_restored = Session::restore(persisted, alice_private_restored).unwrap();

        // Continue conversation
        let msg = alice_restored.encrypt_message(b"After restore").unwrap();
        let pt = bob_session.decrypt_message(&msg).unwrap();
        assert_eq!(pt, b"After restore");
    }

    #[test]
    fn test_session_id_mismatch_rejected() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: None,
        };

        let (mut alice_session, initial_msg) = Session::initiate(
            alice_private,
            alice_hash.clone(),
            bob_hash.clone(),
            &bob_bundle,
            AuthMode::Deniable,
        )
        .unwrap();

        let mut bob_session = Session::respond(
            bob_private,
            bob_hash,
            alice_hash,
            bob_spk_private,
            None,
            &initial_msg,
            AuthMode::Deniable,
        )
        .unwrap();

        let mut msg = alice_session.encrypt_message(b"Test").unwrap();
        // Tamper with session ID
        msg.session_id = [0xFF; 32];

        let result = bob_session.decrypt_message(&msg);
        assert!(result.is_err());
    }

    #[test]
    fn test_deniable_auth_mode() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: None,
        };

        let (mut alice_session, initial_msg) = Session::initiate(
            alice_private,
            alice_hash.clone(),
            bob_hash.clone(),
            &bob_bundle,
            AuthMode::Deniable,
        )
        .unwrap();

        let msg = alice_session.encrypt_message(b"Deniable").unwrap();
        assert!(msg.deniable_auth.is_some());
    }

    #[test]
    fn test_mldsa_auth_mode() {
        let (alice_private, alice_hash) = make_identity();
        let (bob_private, bob_hash) = make_identity();

        let (bob_spk_private, bob_signed_prekey) = generate_signed_prekey(&bob_private, 1);
        let bob_bundle = PreKeyBundle {
            identity_key: bob_private.public_key(),
            signed_prekey: bob_signed_prekey,
            one_time_prekey: None,
        };

        let (mut alice_session, _) = Session::initiate(
            alice_private,
            alice_hash,
            bob_hash,
            &bob_bundle,
            AuthMode::MlDsa,
        )
        .unwrap();

        let msg = alice_session.encrypt_message(b"MlDsa mode").unwrap();
        assert!(msg.deniable_auth.is_none());
    }
}
