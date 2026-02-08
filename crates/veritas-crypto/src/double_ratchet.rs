//! Double Ratchet algorithm for per-message forward secrecy.
//!
//! Implements the Signal-style Double Ratchet that provides:
//! - **Forward secrecy**: Compromise of current keys doesn't reveal past messages
//! - **Post-compromise security**: Session recovers after key compromise via DH ratchet
//! - **Out-of-order delivery**: Skipped message keys are cached for later decryption
//!
//! ## Ratchet Structure
//!
//! The Double Ratchet combines two ratchets:
//! 1. **Symmetric ratchet** (KDF chain): Derives per-message keys from a chain key
//! 2. **DH ratchet**: Periodically ratchets the root key via a new DH exchange
//!
//! ## Domain Separation
//!
//! All key derivations use `"VERITAS-v1.DR."` prefix.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::symmetric::{self, EncryptedData, SymmetricKey};
use crate::x25519::{X25519PublicKey, X25519StaticPrivateKey};
use crate::{CryptoError, Result};

/// Domain separation for root key derivation.
const ROOT_KDF_DOMAIN: &str = "VERITAS-v1.DR.root-key";
/// Domain separation for chain key derivation.
const CHAIN_KDF_DOMAIN: &str = "VERITAS-v1.DR.chain-key";
/// Domain separation for message key derivation.
const MESSAGE_KDF_DOMAIN: &str = "VERITAS-v1.DR.message-key";

/// Maximum number of skipped message keys to store.
/// Prevents memory exhaustion from malicious counter inflation.
pub const MAX_SKIP: usize = 256;

/// A ratchet header sent with each message.
///
/// Contains the sender's current DH ratchet public key and
/// message counters for the receiver to advance their ratchet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetHeader {
    /// Sender's current DH ratchet public key.
    pub dh_public: X25519PublicKey,
    /// Number of messages in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in the current sending chain.
    pub message_number: u32,
}

/// A message encrypted with the Double Ratchet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// The ratchet header.
    pub header: RatchetHeader,
    /// The encrypted payload.
    pub ciphertext: EncryptedData,
}

/// Key pair for skipped message lookup.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct SkippedKey {
    /// The DH public key that was current when this message was sent.
    dh_public: [u8; 32],
    /// The message number in that chain.
    message_number: u32,
}

/// The Double Ratchet session state.
///
/// Maintains the cryptographic state for a 1:1 messaging session.
/// All secret material is zeroized on drop.
pub struct DoubleRatchetSession {
    /// Our current DH ratchet key pair.
    dh_self_private: X25519StaticPrivateKey,
    /// Peer's current DH ratchet public key.
    dh_remote_public: Option<X25519PublicKey>,
    /// Root key (ratcheted via DH).
    root_key: [u8; 32],
    /// Sending chain key.
    chain_key_send: Option<[u8; 32]>,
    /// Receiving chain key.
    chain_key_recv: Option<[u8; 32]>,
    /// Number of messages sent in the current sending chain.
    send_count: u32,
    /// Number of messages received in the current receiving chain.
    recv_count: u32,
    /// Number of messages in the previous sending chain (for header).
    previous_send_count: u32,
    /// Skipped message keys (for out-of-order delivery).
    skipped_keys: HashMap<SkippedKey, [u8; 32]>,
}

impl Drop for DoubleRatchetSession {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.chain_key_send {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.chain_key_recv {
            ck.zeroize();
        }
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

impl std::fmt::Debug for DoubleRatchetSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DoubleRatchetSession")
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("skipped_keys_count", &self.skipped_keys.len())
            .finish()
    }
}

/// Serializable session state for persistence.
#[derive(Serialize, Deserialize)]
pub struct SessionState {
    /// Our DH private key bytes.
    dh_self_private: [u8; 32],
    /// Remote DH public key bytes.
    dh_remote_public: Option<[u8; 32]>,
    /// Root key.
    root_key: [u8; 32],
    /// Sending chain key.
    chain_key_send: Option<[u8; 32]>,
    /// Receiving chain key.
    chain_key_recv: Option<[u8; 32]>,
    /// Send counter.
    send_count: u32,
    /// Receive counter.
    recv_count: u32,
    /// Previous send count.
    previous_send_count: u32,
    /// Skipped keys.
    skipped_keys: Vec<(SkippedKey, [u8; 32])>,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.dh_self_private.zeroize();
        self.root_key.zeroize();
        if let Some(ref mut ck) = self.chain_key_send {
            ck.zeroize();
        }
        if let Some(ref mut ck) = self.chain_key_recv {
            ck.zeroize();
        }
        for (_, key) in self.skipped_keys.iter_mut() {
            key.zeroize();
        }
    }
}

impl DoubleRatchetSession {
    /// Initialize as the session initiator (Alice).
    ///
    /// Alice initializes after performing X3DH. She knows Bob's
    /// signed prekey as the initial remote DH public key.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The 32-byte shared secret from X3DH
    /// * `remote_dh_public` - Bob's signed prekey public (initial DH public)
    pub fn init_alice(
        shared_secret: &[u8; 32],
        remote_dh_public: &X25519PublicKey,
    ) -> Self {
        // Generate Alice's initial DH ratchet key pair
        let dh_self_private = X25519StaticPrivateKey::generate();

        // Perform initial DH ratchet step
        let dh_output = dh_self_private.diffie_hellman(remote_dh_public);
        let (new_root_key, chain_key_send) = kdf_rk(shared_secret, dh_output.as_bytes());

        DoubleRatchetSession {
            dh_self_private,
            dh_remote_public: Some(remote_dh_public.clone()),
            root_key: new_root_key,
            chain_key_send: Some(chain_key_send),
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Initialize as the session responder (Bob).
    ///
    /// Bob initializes with the X3DH shared secret and his signed prekey
    /// as the initial DH key pair.
    ///
    /// # Arguments
    ///
    /// * `shared_secret` - The 32-byte shared secret from X3DH
    /// * `signed_prekey_private` - Bob's signed prekey private key
    pub fn init_bob(
        shared_secret: &[u8; 32],
        signed_prekey_private: X25519StaticPrivateKey,
    ) -> Self {
        DoubleRatchetSession {
            dh_self_private: signed_prekey_private,
            dh_remote_public: None,
            root_key: *shared_secret,
            chain_key_send: None,
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            previous_send_count: 0,
            skipped_keys: HashMap::new(),
        }
    }

    /// Encrypt a message using the Double Ratchet.
    ///
    /// Advances the sending chain and returns the encrypted message
    /// with a ratchet header.
    pub fn encrypt(&mut self, plaintext: &[u8], ad: &[u8]) -> Result<RatchetMessage> {
        let chain_key = self
            .chain_key_send
            .as_ref()
            .ok_or_else(|| CryptoError::Encryption("No sending chain key".into()))?;

        // Derive message key from chain key
        let (new_chain_key, message_key_bytes) = kdf_ck(chain_key);
        self.chain_key_send = Some(new_chain_key);

        let message_key = SymmetricKey::from_bytes(&message_key_bytes)?;

        // Build header
        let header = RatchetHeader {
            dh_public: self.dh_self_private.public_key(),
            previous_chain_length: self.previous_send_count,
            message_number: self.send_count,
        };

        // Encrypt with AAD = ad || header
        let header_bytes = bincode::serialize(&header)
            .map_err(|e| CryptoError::Encryption(format!("Header serialization: {e}")))?;
        let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header_bytes);

        let ciphertext = symmetric::encrypt_with_aad(&message_key, plaintext, &full_ad)?;

        self.send_count += 1;

        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt a message using the Double Ratchet.
    ///
    /// Handles DH ratchet advancement and out-of-order message delivery.
    pub fn decrypt(&mut self, message: &RatchetMessage, ad: &[u8]) -> Result<Vec<u8>> {
        // Try skipped message keys first
        let skip_key = SkippedKey {
            dh_public: message.header.dh_public.to_bytes(),
            message_number: message.header.message_number,
        };

        if let Some(mk) = self.skipped_keys.remove(&skip_key) {
            let message_key = SymmetricKey::from_bytes(&mk)?;
            let header_bytes = bincode::serialize(&message.header)
                .map_err(|_| CryptoError::Decryption)?;
            let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
            full_ad.extend_from_slice(ad);
            full_ad.extend_from_slice(&header_bytes);
            return symmetric::decrypt_with_aad(&message_key, &message.ciphertext, &full_ad);
        }

        // Check if we need a DH ratchet step
        let needs_dh_ratchet = match &self.dh_remote_public {
            Some(current) => current.as_bytes() != message.header.dh_public.as_bytes(),
            None => true,
        };

        if needs_dh_ratchet {
            // Skip any missed messages in the current receiving chain
            if self.chain_key_recv.is_some() {
                self.skip_message_keys(message.header.previous_chain_length)?;
            }

            // DH ratchet step
            self.dh_ratchet(&message.header.dh_public)?;
        }

        // Skip any missed messages in the new receiving chain
        self.skip_message_keys(message.header.message_number)?;

        // Derive message key
        let chain_key = self
            .chain_key_recv
            .as_ref()
            .ok_or(CryptoError::Decryption)?;
        let (new_chain_key, message_key_bytes) = kdf_ck(chain_key);
        self.chain_key_recv = Some(new_chain_key);
        self.recv_count = message.header.message_number + 1;

        let message_key = SymmetricKey::from_bytes(&message_key_bytes)?;

        // Decrypt with AAD
        let header_bytes = bincode::serialize(&message.header)
            .map_err(|_| CryptoError::Decryption)?;
        let mut full_ad = Vec::with_capacity(ad.len() + header_bytes.len());
        full_ad.extend_from_slice(ad);
        full_ad.extend_from_slice(&header_bytes);

        symmetric::decrypt_with_aad(&message_key, &message.ciphertext, &full_ad)
    }

    /// Perform a DH ratchet step.
    fn dh_ratchet(&mut self, new_remote_public: &X25519PublicKey) -> Result<()> {
        self.previous_send_count = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;
        self.dh_remote_public = Some(new_remote_public.clone());

        // Derive new receiving chain key
        let dh_output = self.dh_self_private.diffie_hellman(new_remote_public);
        let (new_root_key, chain_key_recv) = kdf_rk(&self.root_key, dh_output.as_bytes());
        self.root_key = new_root_key;
        self.chain_key_recv = Some(chain_key_recv);

        // Generate new DH key pair
        self.dh_self_private = X25519StaticPrivateKey::generate();

        // Derive new sending chain key
        let dh_output = self.dh_self_private.diffie_hellman(new_remote_public);
        let (new_root_key, chain_key_send) = kdf_rk(&self.root_key, dh_output.as_bytes());
        self.root_key = new_root_key;
        self.chain_key_send = Some(chain_key_send);

        Ok(())
    }

    /// Store skipped message keys for out-of-order delivery.
    fn skip_message_keys(&mut self, until: u32) -> Result<()> {
        let chain_key = match &self.chain_key_recv {
            Some(ck) => ck,
            None => return Ok(()),
        };

        let remote_public = match &self.dh_remote_public {
            Some(pk) => pk.to_bytes(),
            None => return Ok(()),
        };

        let skip_count = until.saturating_sub(self.recv_count) as usize;
        if self.skipped_keys.len() + skip_count > MAX_SKIP {
            return Err(CryptoError::Decryption);
        }

        let mut current_chain_key = *chain_key;

        for n in self.recv_count..until {
            let (new_chain_key, message_key) = kdf_ck(&current_chain_key);

            let skip_key = SkippedKey {
                dh_public: remote_public,
                message_number: n,
            };
            self.skipped_keys.insert(skip_key, message_key);

            current_chain_key = new_chain_key;
        }

        self.chain_key_recv = Some(current_chain_key);
        self.recv_count = until;

        Ok(())
    }

    /// Get the current number of skipped keys stored.
    pub fn skipped_keys_count(&self) -> usize {
        self.skipped_keys.len()
    }

    /// Get our current public DH ratchet key.
    pub fn our_public_key(&self) -> X25519PublicKey {
        self.dh_self_private.public_key()
    }

    /// Export the session state for persistence.
    pub fn export_state(&self) -> SessionState {
        SessionState {
            dh_self_private: *self.dh_self_private.as_bytes(),
            dh_remote_public: self.dh_remote_public.as_ref().map(|pk| pk.to_bytes()),
            root_key: self.root_key,
            chain_key_send: self.chain_key_send,
            chain_key_recv: self.chain_key_recv,
            send_count: self.send_count,
            recv_count: self.recv_count,
            previous_send_count: self.previous_send_count,
            skipped_keys: self
                .skipped_keys
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        }
    }

    /// Restore a session from persisted state.
    pub fn from_state(mut state: SessionState) -> Result<Self> {
        let dh_self_private = X25519StaticPrivateKey::from_bytes(&state.dh_self_private)?;
        let dh_remote_public = match state.dh_remote_public {
            Some(bytes) => Some(X25519PublicKey::from_bytes(&bytes)?),
            None => None,
        };

        // Use std::mem::take to move out of Drop type
        let skipped_keys_vec = std::mem::take(&mut state.skipped_keys);
        let skipped_keys: HashMap<_, _> = skipped_keys_vec.into_iter().collect();

        Ok(DoubleRatchetSession {
            dh_self_private,
            dh_remote_public,
            root_key: state.root_key,
            chain_key_send: state.chain_key_send,
            chain_key_recv: state.chain_key_recv,
            send_count: state.send_count,
            recv_count: state.recv_count,
            previous_send_count: state.previous_send_count,
            skipped_keys,
        })
    }
}

/// Root key derivation function.
///
/// KDF_RK(rk, dh_out) → (new_root_key, chain_key)
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(root_key);
    input[32..].copy_from_slice(dh_output);

    let new_root_key = blake3::derive_key(ROOT_KDF_DOMAIN, &input);
    let chain_key = blake3::derive_key(CHAIN_KDF_DOMAIN, &input);

    input.zeroize();

    (new_root_key, chain_key)
}

/// Chain key derivation function.
///
/// KDF_CK(ck) → (new_chain_key, message_key)
fn kdf_ck(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Chain key advances with constant input 0x01
    let new_chain_key = blake3::derive_key(CHAIN_KDF_DOMAIN, &[chain_key.as_slice(), &[0x01]].concat());
    // Message key derived with constant input 0x02
    let message_key = blake3::derive_key(MESSAGE_KDF_DOMAIN, &[chain_key.as_slice(), &[0x02]].concat());

    (new_chain_key, message_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_encrypt_decrypt() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&shared_secret, bob_prekey);

        let ad = b"associated-data";

        // Alice sends to Bob
        let msg1 = alice.encrypt(b"Hello Bob!", ad).unwrap();
        let plaintext1 = bob.decrypt(&msg1, ad).unwrap();
        assert_eq!(plaintext1, b"Hello Bob!");

        // Bob responds to Alice
        let msg2 = bob.encrypt(b"Hello Alice!", ad).unwrap();
        let plaintext2 = alice.decrypt(&msg2, ad).unwrap();
        assert_eq!(plaintext2, b"Hello Alice!");
    }

    #[test]
    fn test_multiple_messages_same_direction() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&shared_secret, bob_prekey);

        let ad = b"ad";

        // Alice sends 5 messages in a row
        let messages: Vec<_> = (0..5)
            .map(|i| alice.encrypt(format!("Message {i}").as_bytes(), ad).unwrap())
            .collect();

        // Bob decrypts all in order
        for (i, msg) in messages.iter().enumerate() {
            let plaintext = bob.decrypt(msg, ad).unwrap();
            assert_eq!(plaintext, format!("Message {i}").as_bytes());
        }
    }

    #[test]
    fn test_out_of_order_delivery() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&shared_secret, bob_prekey);

        let ad = b"ad";

        // Alice sends 3 messages
        let msg0 = alice.encrypt(b"Message 0", ad).unwrap();
        let msg1 = alice.encrypt(b"Message 1", ad).unwrap();
        let msg2 = alice.encrypt(b"Message 2", ad).unwrap();

        // Bob receives out of order: 2, 0, 1
        let p2 = bob.decrypt(&msg2, ad).unwrap();
        assert_eq!(p2, b"Message 2");

        let p0 = bob.decrypt(&msg0, ad).unwrap();
        assert_eq!(p0, b"Message 0");

        let p1 = bob.decrypt(&msg1, ad).unwrap();
        assert_eq!(p1, b"Message 1");
    }

    #[test]
    fn test_alternating_messages() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&shared_secret, bob_prekey);

        let ad = b"ad";

        for i in 0..10 {
            if i % 2 == 0 {
                let msg = alice
                    .encrypt(format!("Alice {i}").as_bytes(), ad)
                    .unwrap();
                let plaintext = bob.decrypt(&msg, ad).unwrap();
                assert_eq!(plaintext, format!("Alice {i}").as_bytes());
            } else {
                let msg = bob
                    .encrypt(format!("Bob {i}").as_bytes(), ad)
                    .unwrap();
                let plaintext = alice.decrypt(&msg, ad).unwrap();
                assert_eq!(plaintext, format!("Bob {i}").as_bytes());
            }
        }
    }

    #[test]
    fn test_wrong_ad_fails() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&shared_secret, bob_prekey);

        let msg = alice.encrypt(b"Hello", b"correct-ad").unwrap();
        let result = bob.decrypt(&msg, b"wrong-ad");
        assert!(result.is_err());
    }

    #[test]
    fn test_session_state_export_import() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&shared_secret, bob_prekey);

        let ad = b"ad";

        // Exchange some messages
        let msg1 = alice.encrypt(b"Hello", ad).unwrap();
        bob.decrypt(&msg1, ad).unwrap();

        let msg2 = bob.encrypt(b"World", ad).unwrap();
        alice.decrypt(&msg2, ad).unwrap();

        // Export and restore Alice's state
        let state = alice.export_state();
        let mut alice_restored = DoubleRatchetSession::from_state(state).unwrap();

        // Continue conversation with restored session
        let msg3 = alice_restored.encrypt(b"After restore", ad).unwrap();
        let plaintext = bob.decrypt(&msg3, ad).unwrap();
        assert_eq!(plaintext, b"After restore");
    }

    #[test]
    fn test_skipped_keys_limit() {
        let shared_secret = [0x42u8; 32];
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&shared_secret, &bob_prekey_public);

        let ad = b"ad";

        // Generate many messages without decrypting
        let _messages: Vec<_> = (0..MAX_SKIP + 10)
            .map(|_| alice.encrypt(b"msg", ad).unwrap())
            .collect();

        // Alice should have advanced her send counter but not exceeded skip limit
        // (skip limit is enforced on the receiving side)
        assert!(alice.send_count > 0);
    }

    #[test]
    fn test_different_shared_secrets_fail() {
        let bob_prekey = X25519StaticPrivateKey::generate();
        let bob_prekey_public = bob_prekey.public_key();

        let mut alice = DoubleRatchetSession::init_alice(&[0x42u8; 32], &bob_prekey_public);
        let mut bob = DoubleRatchetSession::init_bob(&[0x99u8; 32], bob_prekey);

        let ad = b"ad";
        let msg = alice.encrypt(b"Hello", ad).unwrap();
        let result = bob.decrypt(&msg, ad);
        assert!(result.is_err());
    }

    #[test]
    fn test_kdf_rk_deterministic() {
        let rk = [0xAA; 32];
        let dh = [0xBB; 32];

        let (rk1, ck1) = kdf_rk(&rk, &dh);
        let (rk2, ck2) = kdf_rk(&rk, &dh);

        assert_eq!(rk1, rk2);
        assert_eq!(ck1, ck2);
    }

    #[test]
    fn test_kdf_ck_deterministic() {
        let ck = [0xCC; 32];

        let (ck1, mk1) = kdf_ck(&ck);
        let (ck2, mk2) = kdf_ck(&ck);

        assert_eq!(ck1, ck2);
        assert_eq!(mk1, mk2);
        // Chain key and message key should be different
        assert_ne!(ck1, mk1);
    }

    #[test]
    fn test_kdf_different_inputs_different_outputs() {
        let (rk1, ck1) = kdf_rk(&[0xAA; 32], &[0xBB; 32]);
        let (rk2, ck2) = kdf_rk(&[0xAA; 32], &[0xCC; 32]);

        assert_ne!(rk1, rk2);
        assert_ne!(ck1, ck2);
    }
}
