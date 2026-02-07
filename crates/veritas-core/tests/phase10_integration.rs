//! Phase 10 Integration Tests for VERITAS Protocol.
//!
//! These tests verify end-to-end messaging, multi-node scenarios,
//! and offline message handling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use veritas_core::{ClientConfigBuilder, ClientState, CoreError, VeritasClient};
use veritas_crypto::Hash256;
use veritas_identity::{IdentityKeyPair, IdentityPublicKeys};
use veritas_net::{
    RelayConfig, RelayManager,
    gossip::{GossipConfig, GossipManager, TOPIC_MESSAGES},
};
use veritas_protocol::{
    chunking::{ChunkReassembler, split_into_chunks},
    encryption::{
        DecryptionContext, EncryptedMessage, add_timing_jitter, decrypt_and_verify,
        decrypt_as_recipient, encrypt_for_recipient,
    },
    envelope::{
        InnerPayload, MailboxKey, MailboxKeyParams, MessageContent, MinimalEnvelope,
        derive_mailbox_key, generate_mailbox_salt,
    },
    limits::{EPOCH_DURATION_SECS, MAX_MESSAGE_CHARS, MAX_TOTAL_MESSAGE_CHARS, PADDING_BUCKETS},
    receipts::{DeliveryError, DeliveryReceipt, DeliveryReceiptData, ReceiptType},
};
use veritas_store::{MessageQueue, MessageStatus};

// ============================================================================
// Test Utilities
// ============================================================================

/// Test network node for simulating multi-node scenarios.
struct TestNode {
    identity: IdentityKeyPair,
    inbox: Vec<MinimalEnvelope>,
    _relay: RelayManager,
}

impl TestNode {
    fn new() -> Self {
        Self {
            identity: IdentityKeyPair::generate(),
            inbox: Vec::new(),
            _relay: RelayManager::with_defaults(),
        }
    }

    fn public_keys(&self) -> &IdentityPublicKeys {
        self.identity.public_keys()
    }

    fn receive(&mut self, envelope: MinimalEnvelope) {
        self.inbox.push(envelope);
    }

    fn decrypt_latest(&self) -> Option<InnerPayload> {
        self.inbox
            .last()
            .and_then(|env| decrypt_as_recipient(&self.identity, env).ok())
    }
}

/// Simple in-memory network for testing message routing.
struct TestNetwork {
    nodes: HashMap<String, Arc<RwLock<TestNode>>>,
}

impl TestNetwork {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    async fn add_node(&mut self, name: &str) -> Arc<RwLock<TestNode>> {
        let node = Arc::new(RwLock::new(TestNode::new()));
        self.nodes.insert(name.to_string(), node.clone());
        node
    }
}

// ============================================================================
// End-to-End Messaging Tests
// ============================================================================

mod e2e_messaging {
    use super::*;

    /// Test basic message encryption and decryption roundtrip.
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("Hello, Bob!").unwrap();
        let encrypted =
            encrypt_for_recipient(&alice, bob.public_keys(), content.clone(), None).unwrap();

        // Verify envelope structure
        assert!(encrypted.envelope.validate().is_ok());

        // Decrypt as Bob
        let payload = decrypt_as_recipient(&bob, &encrypted.envelope).unwrap();

        // Verify content
        assert_eq!(payload.content(), &content);
        assert_eq!(payload.sender_id(), alice.identity_hash());
        assert!(payload.reply_to().is_none());
    }

    /// Test message with reply-to field.
    #[test]
    fn test_message_with_reply() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let original_message_hash = Hash256::hash(b"original-message");
        let content = MessageContent::text("This is a reply").unwrap();

        let encrypted = encrypt_for_recipient(
            &alice,
            bob.public_keys(),
            content.clone(),
            Some(original_message_hash.clone()),
        )
        .unwrap();

        let payload = decrypt_as_recipient(&bob, &encrypted.envelope).unwrap();

        assert_eq!(payload.content(), &content);
        assert_eq!(payload.reply_to(), Some(&original_message_hash));
    }

    /// Test signature verification with known sender.
    #[test]
    fn test_signature_verification() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("Signed message").unwrap();
        let encrypted =
            encrypt_for_recipient(&alice, bob.public_keys(), content.clone(), None).unwrap();

        // Decrypt and verify with known sender keys
        let payload = decrypt_and_verify(&bob, &encrypted.envelope, alice.public_keys()).unwrap();

        assert_eq!(payload.content(), &content);
        assert_eq!(payload.sender_id(), alice.identity_hash());
    }

    /// Test that wrong recipient cannot decrypt.
    #[test]
    fn test_wrong_recipient_fails() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let eve = IdentityKeyPair::generate();

        let content = MessageContent::text("Secret for Bob only").unwrap();
        let encrypted = encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap();

        // Eve should not be able to decrypt
        let result = decrypt_as_recipient(&eve, &encrypted.envelope);
        assert!(result.is_err());
    }

    /// Test that impersonation is detected.
    #[test]
    fn test_impersonation_detected() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let mallory = IdentityKeyPair::generate();

        let content = MessageContent::text("From Mallory pretending to be Alice").unwrap();
        let encrypted = encrypt_for_recipient(&mallory, bob.public_keys(), content, None).unwrap();

        // Bob tries to verify as if it's from Alice
        let result = decrypt_and_verify(&bob, &encrypted.envelope, alice.public_keys());

        // Should fail because signature doesn't match Alice's keys
        assert!(result.is_err());
    }

    /// Test decryption context for batch processing.
    #[test]
    fn test_decryption_context() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let ctx = DecryptionContext::new(bob.clone());

        // Encrypt multiple messages
        let messages: Vec<EncryptedMessage> = (0..5)
            .map(|i| {
                let content = MessageContent::text(&format!("Message {}", i)).unwrap();
                encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap()
            })
            .collect();

        // Decrypt all using context
        for (i, encrypted) in messages.iter().enumerate() {
            let payload = ctx.decrypt(&encrypted.envelope).unwrap();
            let expected = MessageContent::text(&format!("Message {}", i)).unwrap();
            assert_eq!(payload.content(), &expected);
        }
    }

    /// Test timing jitter range.
    #[test]
    fn test_timing_jitter() {
        // Generate many jitter values and verify they're in range
        for _ in 0..100 {
            let jitter = add_timing_jitter();
            assert!(jitter <= Duration::from_millis(3000));
        }

        // Verify jitter values are not all the same (randomness)
        let jitters: Vec<Duration> = (0..10).map(|_| add_timing_jitter()).collect();
        let all_same = jitters.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Jitter should vary");
    }

    /// Test empty message encryption.
    #[test]
    fn test_empty_message() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("").unwrap();
        let encrypted =
            encrypt_for_recipient(&alice, bob.public_keys(), content.clone(), None).unwrap();

        let payload = decrypt_as_recipient(&bob, &encrypted.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    /// Test maximum length single message.
    #[test]
    fn test_max_length_message() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let text = "x".repeat(MAX_MESSAGE_CHARS);
        let content = MessageContent::text(&text).unwrap();
        let encrypted =
            encrypt_for_recipient(&alice, bob.public_keys(), content.clone(), None).unwrap();

        let payload = decrypt_as_recipient(&bob, &encrypted.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    /// Test that messages are padded to bucket sizes.
    #[test]
    fn test_message_padding() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Test various message sizes
        let size_100 = "a".repeat(100);
        let size_250 = "b".repeat(250);
        let test_sizes = vec!["", "Hi", "Hello, World!", &size_100, &size_250];

        for text in test_sizes {
            let content = MessageContent::text(text).unwrap();
            let encrypted =
                encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap();

            // Ciphertext size should be >= smallest bucket (due to padding)
            assert!(encrypted.envelope.ciphertext().len() >= PADDING_BUCKETS[0]);
        }
    }

    /// Test encrypted message serialization roundtrip.
    #[test]
    fn test_encrypted_message_serialization() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("Serialize me").unwrap();
        let encrypted =
            encrypt_for_recipient(&alice, bob.public_keys(), content.clone(), None).unwrap();

        // Serialize and deserialize
        let bytes = encrypted.to_bytes().unwrap();
        let restored = EncryptedMessage::from_bytes(&bytes).unwrap();

        // Should still decrypt correctly
        let payload = decrypt_as_recipient(&bob, &restored.envelope).unwrap();
        assert_eq!(payload.content(), &content);
    }

    /// Test unique envelope hashes for different messages.
    #[test]
    fn test_envelope_hash_uniqueness() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let encrypted1 = encrypt_for_recipient(
            &alice,
            bob.public_keys(),
            MessageContent::text("Message 1").unwrap(),
            None,
        )
        .unwrap();

        let encrypted2 = encrypt_for_recipient(
            &alice,
            bob.public_keys(),
            MessageContent::text("Message 2").unwrap(),
            None,
        )
        .unwrap();

        // Hashes should be different
        assert_ne!(encrypted1.envelope_hash(), encrypted2.envelope_hash());
    }

    /// Test that same message encrypted twice has different envelopes.
    #[test]
    fn test_ephemeral_key_uniqueness() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("Same content").unwrap();

        let encrypted1 =
            encrypt_for_recipient(&alice, bob.public_keys(), content.clone(), None).unwrap();

        let encrypted2 = encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap();

        // Ephemeral keys should differ (forward secrecy)
        assert_ne!(
            encrypted1.envelope.ephemeral_public(),
            encrypted2.envelope.ephemeral_public()
        );

        // Nonces should differ
        assert_ne!(encrypted1.envelope.nonce(), encrypted2.envelope.nonce());

        // Ciphertext should differ
        assert_ne!(
            encrypted1.envelope.ciphertext(),
            encrypted2.envelope.ciphertext()
        );
    }
}

// ============================================================================
// Message Chunking Tests
// ============================================================================

mod chunking {
    use super::*;

    /// Test short message requires no chunking.
    #[test]
    fn test_short_message_no_chunking() {
        let message = "Hello, world!";
        let chunks = split_into_chunks(message).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].info().chunk_index(), 0);
        assert_eq!(chunks[0].info().total_chunks(), 1);
    }

    /// Test message at exactly MAX_MESSAGE_CHARS.
    #[test]
    fn test_max_single_chunk_message() {
        let message: String = "a".repeat(MAX_MESSAGE_CHARS);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content(), message);
    }

    /// Test message requiring two chunks.
    #[test]
    fn test_two_chunk_message() {
        let message: String = "a".repeat(MAX_MESSAGE_CHARS + 1);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].info().total_chunks(), 2);
        assert_eq!(chunks[0].info().chunk_index(), 0);
        assert_eq!(chunks[1].info().chunk_index(), 1);

        // Combined content should equal original
        let combined: String = chunks.iter().map(|c| c.content()).collect();
        assert_eq!(combined, message);
    }

    /// Test message requiring maximum three chunks.
    #[test]
    fn test_three_chunk_message() {
        let message: String = "a".repeat(MAX_MESSAGE_CHARS * 2 + 1);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 3);

        // Verify all chunks have correct metadata
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.info().chunk_index() as usize, i);
            assert_eq!(chunk.info().total_chunks(), 3);
        }

        // Combined content should equal original
        let combined: String = chunks.iter().map(|c| c.content()).collect();
        assert_eq!(combined, message);
    }

    /// Test message at maximum total length.
    #[test]
    fn test_maximum_message_length() {
        let message: String = "a".repeat(MAX_TOTAL_MESSAGE_CHARS);
        let chunks = split_into_chunks(&message).unwrap();

        assert_eq!(chunks.len(), 3);

        let combined: String = chunks.iter().map(|c| c.content()).collect();
        assert_eq!(combined, message);
    }

    /// Test message exceeding maximum length fails.
    #[test]
    fn test_exceeding_max_length_fails() {
        let message: String = "a".repeat(MAX_TOTAL_MESSAGE_CHARS + 1);
        let result = split_into_chunks(&message);

        assert!(result.is_err());
    }

    /// Test chunk reassembly in order.
    #[test]
    fn test_chunk_reassembly_in_order() {
        let message: String = "a".repeat(600);
        let chunks = split_into_chunks(&message).unwrap();

        let mut reassembler = ChunkReassembler::new(300);
        let current_time = 1000u64;

        // Add chunks in order
        let result1 = reassembler
            .add_chunk(chunks[0].clone(), current_time)
            .unwrap();
        assert!(result1.is_none()); // Not complete yet

        let result2 = reassembler
            .add_chunk(chunks[1].clone(), current_time)
            .unwrap();
        assert_eq!(result2, Some(message));
    }

    /// Test chunk reassembly out of order.
    #[test]
    fn test_chunk_reassembly_out_of_order() {
        let message: String = "b".repeat(600);
        let chunks = split_into_chunks(&message).unwrap();

        let mut reassembler = ChunkReassembler::new(300);
        let current_time = 1000u64;

        // Add chunks in reverse order
        let result2 = reassembler
            .add_chunk(chunks[1].clone(), current_time)
            .unwrap();
        assert!(result2.is_none());

        let result1 = reassembler
            .add_chunk(chunks[0].clone(), current_time)
            .unwrap();
        assert_eq!(result1, Some(message));
    }

    /// Test chunk info encoding/decoding.
    #[test]
    fn test_chunk_info() {
        let message = "Test message";
        let chunks = split_into_chunks(message).unwrap();

        let info = chunks[0].info();
        assert_eq!(info.chunk_index(), 0);
        assert_eq!(info.total_chunks(), 1);
    }

    /// Test Unicode message chunking.
    #[test]
    fn test_unicode_chunking() {
        // Unicode characters - each emoji is multiple bytes but 1 character
        let emoji_message: String = "\u{1F600}".repeat(MAX_MESSAGE_CHARS); // grinning face

        let chunks = split_into_chunks(&emoji_message).unwrap();
        assert_eq!(chunks.len(), 1);

        let combined: String = chunks.iter().map(|c| c.content()).collect();
        assert_eq!(combined, emoji_message);
    }

    /// Test mixed content chunking.
    #[test]
    fn test_mixed_content_chunking() {
        let mixed = format!(
            "{}{}{}",
            "Hello ".repeat(50),
            "\u{1F600}".repeat(10),
            " World".repeat(50)
        );

        // Should chunk based on character count, not bytes
        if mixed.chars().count() <= MAX_MESSAGE_CHARS {
            let chunks = split_into_chunks(&mixed).unwrap();
            assert_eq!(chunks.len(), 1);
        } else {
            let chunks = split_into_chunks(&mixed).unwrap();
            assert!(chunks.len() > 1);
        }
    }
}

// ============================================================================
// Delivery Receipt Tests
// ============================================================================

mod receipts {
    use super::*;

    /// Test delivery receipt creation.
    #[test]
    fn test_delivery_receipt_creation() {
        let bob = IdentityKeyPair::generate();
        let message_hash = Hash256::hash(b"original-message");

        let receipt = DeliveryReceipt::delivered(&message_hash, &bob).unwrap();

        assert!(receipt.is_for_message(&message_hash));
        assert!(receipt.is_delivered());
        assert!(!receipt.is_error());
    }

    /// Test read receipt creation.
    #[test]
    fn test_read_receipt_creation() {
        let bob = IdentityKeyPair::generate();
        let message_hash = Hash256::hash(b"read-message");

        let receipt = DeliveryReceipt::read(&message_hash, &bob).unwrap();

        assert!(receipt.is_for_message(&message_hash));
        assert!(receipt.is_read());
        assert!(!receipt.is_delivered());
    }

    /// Test error receipt creation.
    #[test]
    fn test_error_receipt_creation() {
        let bob = IdentityKeyPair::generate();
        let message_hash = Hash256::hash(b"failed-message");

        let receipt =
            DeliveryReceipt::error(&message_hash, &bob, DeliveryError::RecipientNotFound).unwrap();

        assert!(receipt.is_for_message(&message_hash));
        assert!(receipt.is_error());
        assert!(receipt.delivery_error().is_some());
    }

    /// Test receipt can be sent as message content.
    #[test]
    fn test_receipt_as_message_content() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let message_hash = Hash256::hash(b"original-message");
        let receipt_data = DeliveryReceiptData::new(message_hash.clone(), ReceiptType::Delivered);
        let content = MessageContent::receipt(receipt_data);

        // Bob sends receipt to Alice
        let encrypted =
            encrypt_for_recipient(&bob, alice.public_keys(), content.clone(), None).unwrap();

        // Alice decrypts and verifies receipt
        let payload = decrypt_as_recipient(&alice, &encrypted.envelope).unwrap();

        assert!(payload.content().is_receipt());
        let received_receipt = payload.content().as_receipt().unwrap();
        assert_eq!(received_receipt.message_id, message_hash);
        assert_eq!(received_receipt.receipt_type, ReceiptType::Delivered);
    }

    /// Test receipt hash is deterministic.
    #[test]
    fn test_receipt_hash_deterministic() {
        let bob = IdentityKeyPair::generate();
        let message_hash = Hash256::hash(b"deterministic-test");

        let receipt = DeliveryReceipt::delivered(&message_hash, &bob).unwrap();

        // Receipt hash should be deterministic for same receipt
        let hash1 = receipt.receipt_hash();
        let hash2 = receipt.receipt_hash();
        assert_eq!(hash1, hash2);
    }

    /// Test different receipts have different hashes.
    #[test]
    fn test_different_receipts_different_hashes() {
        let bob = IdentityKeyPair::generate();
        let message1 = Hash256::hash(b"message-1");
        let message2 = Hash256::hash(b"message-2");

        let receipt1 = DeliveryReceipt::delivered(&message1, &bob).unwrap();
        let receipt2 = DeliveryReceipt::delivered(&message2, &bob).unwrap();

        assert_ne!(receipt1.receipt_hash(), receipt2.receipt_hash());
    }
}

// ============================================================================
// Multi-Node Tests
// ============================================================================

mod multi_node {
    use super::*;

    /// Test message routing between two nodes.
    #[tokio::test]
    async fn test_two_node_message_exchange() {
        let mut network = TestNetwork::new();

        let alice_node = network.add_node("alice").await;
        let bob_node = network.add_node("bob").await;

        // Get public keys
        let bob_public = bob_node.read().await.public_keys().clone();
        let alice_identity = alice_node.read().await.identity.clone();

        // Alice creates message for Bob
        let content = MessageContent::text("Hello from Alice!").unwrap();
        let encrypted =
            encrypt_for_recipient(&alice_identity, &bob_public, content.clone(), None).unwrap();

        // Simulate network delivery
        bob_node.write().await.receive(encrypted.envelope.clone());

        // Bob decrypts
        let payload = bob_node.read().await.decrypt_latest().unwrap();
        assert_eq!(payload.content(), &content);
        assert_eq!(payload.sender_id(), alice_identity.identity_hash());
    }

    /// Test bidirectional message exchange.
    #[tokio::test]
    async fn test_bidirectional_exchange() {
        let mut network = TestNetwork::new();

        let alice_node = network.add_node("alice").await;
        let bob_node = network.add_node("bob").await;

        let alice = alice_node.read().await.identity.clone();
        let bob = bob_node.read().await.identity.clone();

        // Alice sends to Bob
        let msg1 = MessageContent::text("Hi Bob!").unwrap();
        let encrypted1 =
            encrypt_for_recipient(&alice, bob.public_keys(), msg1.clone(), None).unwrap();
        bob_node.write().await.receive(encrypted1.envelope);

        // Bob sends to Alice
        let msg2 = MessageContent::text("Hi Alice!").unwrap();
        let encrypted2 =
            encrypt_for_recipient(&bob, alice.public_keys(), msg2.clone(), None).unwrap();
        alice_node.write().await.receive(encrypted2.envelope);

        // Verify both received correctly
        let bob_received = bob_node.read().await.decrypt_latest().unwrap();
        assert_eq!(bob_received.content(), &msg1);

        let alice_received = alice_node.read().await.decrypt_latest().unwrap();
        assert_eq!(alice_received.content(), &msg2);
    }

    /// Test multiple clients with unique identities.
    #[tokio::test]
    async fn test_multiple_clients() {
        let clients: Vec<VeritasClient> = futures::future::join_all(
            (0..3).map(|_| async { VeritasClient::in_memory().await.unwrap() }),
        )
        .await;

        // Unlock all clients
        for client in &clients {
            client.unlock(b"test_password").await.unwrap();
        }

        // Create identities
        let mut hashes = Vec::new();
        for (i, client) in clients.iter().enumerate() {
            let hash = client
                .create_identity(Some(&format!("Client {}", i)))
                .await
                .unwrap();
            hashes.push(hash);
        }

        // Verify all hashes are unique
        for i in 0..hashes.len() {
            for j in (i + 1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j]);
            }
        }

        // Verify all clients are functional
        for client in &clients {
            assert_eq!(client.state().await, ClientState::Unlocked);
            let identities = client.list_identities().await.unwrap();
            assert_eq!(identities.len(), 1);
        }
    }

    /// Test concurrent message processing.
    #[tokio::test]
    async fn test_concurrent_message_processing() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        // Create many messages concurrently
        let messages: Vec<EncryptedMessage> = futures::future::join_all((0..20).map(|i| {
            let alice = alice.clone();
            let bob_public = bob.public_keys().clone();
            async move {
                let content = MessageContent::text(&format!("Message {}", i)).unwrap();
                encrypt_for_recipient(&alice, &bob_public, content, None).unwrap()
            }
        }))
        .await;

        // Decrypt all concurrently
        let payloads: Vec<InnerPayload> =
            futures::future::join_all(messages.iter().map(|encrypted| {
                let bob = bob.clone();
                async move {
                    let ctx = DecryptionContext::new(bob);
                    ctx.decrypt(&encrypted.envelope).unwrap()
                }
            }))
            .await;

        // Verify all decrypted correctly
        assert_eq!(payloads.len(), 20);
        for payload in &payloads {
            assert_eq!(payload.sender_id(), alice.identity_hash());
        }
    }
}

// ============================================================================
// Gossip Protocol Tests
// ============================================================================

mod gossip {
    use super::*;
    use veritas_net::gossip::{BlockAnnouncement, MessageAnnouncement, ReceiptAnnouncement};

    /// Test message announcement creation.
    #[test]
    fn test_message_announcement() {
        let mailbox_key = MailboxKey::from_bytes([1u8; 32]);
        let message_hash = Hash256::hash(b"test-message");

        let announcement =
            MessageAnnouncement::new_now(mailbox_key.clone(), message_hash.clone(), 1024).unwrap();

        assert_eq!(announcement.mailbox_key, mailbox_key);
        assert_eq!(announcement.message_hash, message_hash);
        assert_eq!(announcement.size_bucket, 1024);
    }

    /// Test announcement serialization.
    #[test]
    fn test_announcement_serialization() {
        let mailbox_key = MailboxKey::from_bytes([2u8; 32]);
        let message_hash = Hash256::hash(b"serialize-me");

        let announcement =
            MessageAnnouncement::new_now(mailbox_key.clone(), message_hash.clone(), 2048).unwrap();

        let bytes = announcement.to_bytes().unwrap();
        let restored = MessageAnnouncement::from_bytes(&bytes).unwrap();

        assert_eq!(restored.mailbox_key, mailbox_key);
        assert_eq!(restored.message_hash, message_hash);
        assert_eq!(restored.size_bucket, 2048);
    }

    /// Test block announcement.
    #[test]
    fn test_block_announcement() {
        let block_hash = Hash256::hash(b"block-data");
        let height = 12345u64;

        let announcement = BlockAnnouncement::new_now(block_hash.clone(), height);

        assert_eq!(announcement.block_hash, block_hash);
        assert_eq!(announcement.height, height);

        // Serialization roundtrip
        let bytes = announcement.to_bytes().unwrap();
        let restored = BlockAnnouncement::from_bytes(&bytes).unwrap();
        assert_eq!(restored.height, height);
    }

    /// Test receipt announcement.
    #[test]
    fn test_receipt_announcement() {
        let message_hash = Hash256::hash(b"original");
        let receipt_hash = Hash256::hash(b"receipt");

        let announcement = ReceiptAnnouncement::new_now(message_hash.clone(), receipt_hash.clone());

        assert_eq!(announcement.message_hash, message_hash);
        assert_eq!(announcement.receipt_hash, receipt_hash);

        // Serialization roundtrip
        let bytes = announcement.to_bytes().unwrap();
        let restored = ReceiptAnnouncement::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_hash, message_hash);
    }

    /// Test timestamp bucketing.
    #[test]
    fn test_timestamp_bucketing() {
        let mailbox_key = MailboxKey::from_bytes([3u8; 32]);
        let message_hash = Hash256::hash(b"bucket-test");

        // Create announcements at different times within same hour
        let ts1 = 3600 * 10 + 100; // 10th hour + 100 seconds
        let ts2 = 3600 * 10 + 3500; // 10th hour + 3500 seconds

        let ann1 =
            MessageAnnouncement::new(mailbox_key.clone(), message_hash.clone(), ts1, 1024).unwrap();
        let ann2 =
            MessageAnnouncement::new(mailbox_key.clone(), message_hash.clone(), ts2, 1024).unwrap();

        // Should be in same bucket
        assert_eq!(ann1.timestamp_bucket, ann2.timestamp_bucket);
        assert_eq!(ann1.timestamp_bucket, 10);
    }

    /// Test invalid size bucket rejected.
    #[test]
    fn test_invalid_size_bucket() {
        let mailbox_key = MailboxKey::from_bytes([4u8; 32]);
        let message_hash = Hash256::hash(b"invalid-size");

        // 300 is not a valid padding bucket (valid: 1024, 2048, 4096, 8192)
        let result = MessageAnnouncement::new_now(mailbox_key, message_hash, 300);
        assert!(result.is_err());
    }

    /// Test gossip manager configuration.
    #[test]
    fn test_gossip_config() {
        let config = GossipConfig::default();

        assert_eq!(config.mesh_n, 6);
        assert_eq!(config.mesh_n_low, 4);
        assert_eq!(config.mesh_n_high, 12);
        assert_eq!(config.max_transmit_size, 65536);
    }

    /// Test gossip manager subscriptions.
    #[tokio::test]
    async fn test_gossip_subscriptions() {
        let manager = GossipManager::with_defaults();

        // Initially not subscribed
        assert!(!manager.is_subscribed(TOPIC_MESSAGES).await);

        // Subscribe (note: without behaviour set, this just updates internal state)
        // In a real test with a swarm, we'd set the behaviour first
        let subscribed = manager.subscribed_topics().await;
        assert!(subscribed.is_empty());
    }
}

// ============================================================================
// Offline Scenario Tests
// ============================================================================

mod offline {
    use super::*;

    /// Create a test message queue backed by a temp directory with encryption.
    fn create_test_queue() -> (tempfile::TempDir, veritas_store::EncryptedDb, MessageQueue) {
        use veritas_store::EncryptedDb;
        let dir = tempfile::TempDir::new().expect("Failed to create temp dir");
        let db = EncryptedDb::open(dir.path(), b"test-password").expect("Failed to open test db");
        let queue = MessageQueue::new(&db).expect("Failed to create queue");
        (dir, db, queue)
    }

    /// Test message queuing when offline.
    #[test]
    fn test_message_queuing() {
        let (_dir, _db, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let payload = b"encrypted-message".to_vec();

        let id = queue.queue_outgoing(&recipient, payload.clone()).unwrap();

        // Should be retrievable
        let message = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(message.id, id);
        assert_eq!(message.recipient, recipient);
        assert_eq!(message.encrypted_payload, payload);
        assert_eq!(message.status, MessageStatus::Pending);
        assert_eq!(message.retry_count, 0);
    }

    /// Test pending message retrieval.
    #[test]
    fn test_get_pending_messages() {
        let (_dir, _db, queue) = create_test_queue();

        let recipient = [1u8; 32];

        // Queue multiple messages
        let _id1 = queue.queue_outgoing(&recipient, b"msg1".to_vec()).unwrap();
        let _id2 = queue.queue_outgoing(&recipient, b"msg2".to_vec()).unwrap();

        // Both should be pending
        let pending = queue.get_pending().unwrap();
        assert_eq!(pending.len(), 2);
    }

    /// Test status transitions.
    #[test]
    fn test_status_transitions() {
        let (_dir, _db, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let id = queue.queue_outgoing(&recipient, b"msg".to_vec()).unwrap();

        // Pending -> Sent
        queue.mark_sent(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Sent);

        // Sent -> Delivered
        queue.mark_delivered(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Delivered);
        assert!(msg.status.is_terminal());
    }

    /// Test retry scheduling with exponential backoff.
    #[test]
    fn test_retry_scheduling() {
        let (_dir, _db, queue) = create_test_queue();

        let recipient = [1u8; 32];
        let id = queue
            .queue_outgoing(&recipient, b"retry-me".to_vec())
            .unwrap();

        // First failure
        queue.mark_failed(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Pending);
        assert_eq!(msg.retry_count, 1);
        assert!(msg.next_retry_at.is_some());

        // Second failure
        queue.mark_failed(&id).unwrap();
        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.retry_count, 2);

        // Continue failing until permanent failure
        for _ in 0..3 {
            queue.mark_failed(&id).unwrap();
        }

        let msg = queue.get_outbox_message(&id).unwrap().unwrap();
        assert_eq!(msg.status, MessageStatus::Failed);
        assert!(msg.status.is_terminal());
    }

    /// Test inbox message storage.
    #[test]
    fn test_inbox_storage() {
        let (_dir, _db, queue) = create_test_queue();

        let payload = b"incoming-message".to_vec();
        let id = queue.store_incoming(payload.clone()).unwrap();

        let message = queue.get_inbox_message(&id).unwrap().unwrap();
        assert_eq!(message.id, id);
        assert_eq!(message.encrypted_payload, payload);
        assert!(!message.read);
    }

    /// Test unread message retrieval.
    #[test]
    fn test_unread_messages() {
        let (_dir, _db, queue) = create_test_queue();

        let id1 = queue.store_incoming(b"msg1".to_vec()).unwrap();
        let id2 = queue.store_incoming(b"msg2".to_vec()).unwrap();

        // Both unread
        let unread = queue.get_unread().unwrap();
        assert_eq!(unread.len(), 2);

        // Mark one as read
        queue.mark_read(&id1).unwrap();

        // Only one unread
        let unread = queue.get_unread().unwrap();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].id, id2);
    }

    /// Test inbox statistics.
    #[test]
    fn test_inbox_stats() {
        let (_dir, _db, queue) = create_test_queue();

        let id1 = queue.store_incoming(b"msg1".to_vec()).unwrap();
        let _id2 = queue.store_incoming(b"msg2".to_vec()).unwrap();
        let _id3 = queue.store_incoming(b"msg3".to_vec()).unwrap();

        queue.mark_read(&id1).unwrap();

        let stats = queue.inbox_count().unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.read, 1);
        assert_eq!(stats.unread, 2);
    }

    /// Test outbox statistics.
    #[test]
    fn test_outbox_stats() {
        let (_dir, _db, queue) = create_test_queue();

        let recipient = [1u8; 32];

        let id1 = queue.queue_outgoing(&recipient, b"msg1".to_vec()).unwrap();
        let id2 = queue.queue_outgoing(&recipient, b"msg2".to_vec()).unwrap();
        let _id3 = queue.queue_outgoing(&recipient, b"msg3".to_vec()).unwrap();

        queue.mark_sent(&id1).unwrap();
        queue.mark_sent(&id2).unwrap();
        queue.mark_delivered(&id2).unwrap();

        let stats = queue.outbox_count().unwrap();
        assert_eq!(stats.total, 3);
        assert_eq!(stats.pending, 1);
        assert_eq!(stats.sent, 1);
        assert_eq!(stats.delivered, 1);
    }

    /// Test message deletion.
    #[test]
    fn test_message_deletion() {
        let (_dir, _db, queue) = create_test_queue();

        let id = queue.store_incoming(b"delete-me".to_vec()).unwrap();

        // Should exist
        assert!(queue.get_inbox_message(&id).unwrap().is_some());

        // Delete
        queue.delete_inbox_message(&id).unwrap();

        // Should not exist
        assert!(queue.get_inbox_message(&id).unwrap().is_none());

        // Double delete should fail
        assert!(queue.delete_inbox_message(&id).is_err());
    }

    /// Test pagination.
    #[test]
    fn test_inbox_pagination() {
        let (_dir, _db, queue) = create_test_queue();

        // Store 5 messages
        for i in 0..5 {
            queue
                .store_incoming(format!("msg{}", i).into_bytes())
                .unwrap();
        }

        // Get first page
        let page1 = queue.get_inbox(2, 0).unwrap();
        assert_eq!(page1.len(), 2);

        // Get second page
        let page2 = queue.get_inbox(2, 2).unwrap();
        assert_eq!(page2.len(), 2);

        // Get third page
        let page3 = queue.get_inbox(2, 4).unwrap();
        assert_eq!(page3.len(), 1);

        // Beyond end
        let empty = queue.get_inbox(2, 10).unwrap();
        assert!(empty.is_empty());
    }
}

// ============================================================================
// Store-and-Forward Relay Tests
// ============================================================================

mod relay {
    use super::*;

    /// Create a minimal test envelope.
    fn create_test_envelope() -> MinimalEnvelope {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let content = MessageContent::text("Relay me").unwrap();
        let encrypted = encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap();
        encrypted.envelope
    }

    /// Test relay storage.
    #[test]
    fn test_relay_storage() {
        let mut relay = RelayManager::with_defaults();
        let mailbox_key = MailboxKey::from_bytes([1u8; 32]);
        let envelope = create_test_envelope();

        relay.store_for_relay(&mailbox_key, envelope).unwrap();

        assert_eq!(relay.message_count(), 1);
        assert!(relay.has_pending(&mailbox_key));
        assert_eq!(relay.pending_count(&mailbox_key), 1);
    }

    /// Test relay retrieval.
    #[test]
    fn test_relay_retrieval() {
        let mut relay = RelayManager::with_defaults();
        let mailbox_key = MailboxKey::from_bytes([2u8; 32]);
        let envelope = create_test_envelope();
        let expected_hash = envelope.envelope_hash();

        relay.store_for_relay(&mailbox_key, envelope).unwrap();

        let pending = relay.get_pending(&mailbox_key);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message_hash(), &expected_hash);
        assert_eq!(pending[0].hop_count(), 0);
    }

    /// Test delivery marking.
    #[test]
    fn test_mark_delivered() {
        let mut relay = RelayManager::with_defaults();
        let mailbox_key = MailboxKey::from_bytes([3u8; 32]);
        let envelope = create_test_envelope();
        let message_hash = envelope.envelope_hash();

        relay.store_for_relay(&mailbox_key, envelope).unwrap();
        assert_eq!(relay.message_count(), 1);

        relay.mark_delivered(&mailbox_key, &message_hash).unwrap();

        assert_eq!(relay.message_count(), 0);
        assert!(!relay.has_pending(&mailbox_key));
    }

    /// Test hop count limits.
    #[test]
    fn test_hop_count_limit() {
        let config = RelayConfig {
            max_hop_count: 3,
            ..RelayConfig::default()
        };
        let mut relay = RelayManager::new(config);
        let mailbox_key = MailboxKey::from_bytes([4u8; 32]);
        let envelope = create_test_envelope();

        // Should reject message that's already at max hops
        let result = relay.store_for_relay_with_hop(&mailbox_key, envelope, 3);
        assert!(result.is_err());
    }

    /// Test hop count incrementing.
    #[test]
    fn test_hop_increment() {
        let mut relay = RelayManager::with_defaults();
        let mailbox_key = MailboxKey::from_bytes([5u8; 32]);
        let envelope = create_test_envelope();
        let message_hash = envelope.envelope_hash();

        relay.store_for_relay(&mailbox_key, envelope).unwrap();

        // Initial hop count
        let pending = relay.get_pending(&mailbox_key);
        assert_eq!(pending[0].hop_count(), 0);

        // Increment
        let new_hop = relay.increment_hop(&message_hash).unwrap();
        assert_eq!(new_hop, 1);

        // Verify persisted
        let pending = relay.get_pending(&mailbox_key);
        assert_eq!(pending[0].hop_count(), 1);
    }

    /// Test message size limit.
    #[test]
    fn test_size_limit() {
        let config = RelayConfig {
            max_message_size: 100, // Very small for testing
            ..RelayConfig::default()
        };
        let mut relay = RelayManager::new(config);
        let mailbox_key = MailboxKey::from_bytes([6u8; 32]);
        let envelope = create_test_envelope(); // Will be larger than 100 bytes

        let result = relay.store_for_relay(&mailbox_key, envelope);
        assert!(result.is_err());
    }

    /// Test duplicate rejection.
    #[test]
    fn test_duplicate_rejection() {
        let mut relay = RelayManager::with_defaults();
        let mailbox_key = MailboxKey::from_bytes([7u8; 32]);
        let envelope = create_test_envelope();

        // First store succeeds
        relay
            .store_for_relay(&mailbox_key, envelope.clone())
            .unwrap();

        // Duplicate should fail
        let result = relay.store_for_relay(&mailbox_key, envelope);
        assert!(result.is_err());
    }

    /// Test relay statistics.
    #[test]
    fn test_relay_stats() {
        let mut relay = RelayManager::with_defaults();

        let stats_initial = relay.stats();
        assert_eq!(stats_initial.messages_stored, 0);
        assert_eq!(stats_initial.active_mailboxes, 0);

        // Add messages to different mailboxes
        let mailbox1 = MailboxKey::from_bytes([8u8; 32]);
        let mailbox2 = MailboxKey::from_bytes([9u8; 32]);

        relay
            .store_for_relay(&mailbox1, create_test_envelope())
            .unwrap();
        relay
            .store_for_relay(&mailbox1, create_test_envelope())
            .unwrap();
        relay
            .store_for_relay(&mailbox2, create_test_envelope())
            .unwrap();

        let stats = relay.stats();
        assert_eq!(stats.messages_stored, 3);
        assert_eq!(stats.active_mailboxes, 2);
        assert!(stats.bytes_stored > 0);
    }

    /// Test forward delay generation.
    #[test]
    fn test_forward_delay() {
        let config = RelayConfig {
            forward_delay: Duration::from_millis(500),
            ..RelayConfig::default()
        };
        let relay = RelayManager::new(config);

        // Generate multiple delays
        let delays: Vec<Duration> = (0..100).map(|_| relay.get_forward_delay()).collect();

        // All should be within range
        for delay in &delays {
            assert!(*delay <= Duration::from_millis(500));
        }

        // Should have some variation
        let all_same = delays.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "Forward delays should vary");
    }

    /// Test relay clear.
    #[test]
    fn test_relay_clear() {
        let mut relay = RelayManager::with_defaults();
        let mailbox = MailboxKey::from_bytes([10u8; 32]);

        relay
            .store_for_relay(&mailbox, create_test_envelope())
            .unwrap();
        relay
            .store_for_relay(&mailbox, create_test_envelope())
            .unwrap();

        assert_eq!(relay.message_count(), 2);

        relay.clear();

        assert_eq!(relay.message_count(), 0);
        assert!(!relay.has_pending(&mailbox));
    }

    /// Test pending mailboxes listing.
    #[test]
    fn test_pending_mailboxes() {
        let mut relay = RelayManager::with_defaults();

        let mailbox1 = MailboxKey::from_bytes([11u8; 32]);
        let mailbox2 = MailboxKey::from_bytes([12u8; 32]);
        let mailbox3 = MailboxKey::from_bytes([13u8; 32]);

        relay
            .store_for_relay(&mailbox1, create_test_envelope())
            .unwrap();
        relay
            .store_for_relay(&mailbox2, create_test_envelope())
            .unwrap();
        relay
            .store_for_relay(&mailbox3, create_test_envelope())
            .unwrap();

        let pending = relay.pending_mailboxes();
        assert_eq!(pending.len(), 3);
    }

    /// Test mailbox removal.
    #[test]
    fn test_remove_mailbox() {
        let mut relay = RelayManager::with_defaults();
        let mailbox = MailboxKey::from_bytes([14u8; 32]);

        relay
            .store_for_relay(&mailbox, create_test_envelope())
            .unwrap();
        relay
            .store_for_relay(&mailbox, create_test_envelope())
            .unwrap();

        assert_eq!(relay.pending_count(&mailbox), 2);

        let removed = relay.remove_mailbox(&mailbox);
        assert_eq!(removed, 2);
        assert_eq!(relay.pending_count(&mailbox), 0);
    }

    /// Test configuration validation.
    #[test]
    fn test_config_validation() {
        // Valid config
        let valid = RelayConfig::default();
        assert!(valid.validate().is_ok());

        // Invalid: zero hop count
        let invalid1 = RelayConfig {
            max_hop_count: 0,
            ..RelayConfig::default()
        };
        assert!(invalid1.validate().is_err());

        // Invalid: zero TTL
        let invalid2 = RelayConfig {
            message_ttl: Duration::ZERO,
            ..RelayConfig::default()
        };
        assert!(invalid2.validate().is_err());

        // Invalid: too small message size
        let invalid3 = RelayConfig {
            max_message_size: 100,
            ..RelayConfig::default()
        };
        assert!(invalid3.validate().is_err());
    }

    /// Test low resource configuration preset.
    #[test]
    fn test_low_resource_config() {
        let config = RelayConfig::low_resource();
        assert_eq!(config.max_hop_count, 2);
        assert_eq!(config.max_stored_messages, 10_000);
        assert!(config.validate().is_ok());
    }

    /// Test high throughput configuration preset.
    #[test]
    fn test_high_throughput_config() {
        let config = RelayConfig::high_throughput();
        assert_eq!(config.max_hop_count, 5);
        assert_eq!(config.max_stored_messages, 1_000_000);
        assert!(config.validate().is_ok());
    }
}

// ============================================================================
// Mailbox Key Derivation Tests
// ============================================================================

mod mailbox {
    use super::*;
    use veritas_protocol::envelope::{current_epoch, epoch_from_timestamp};

    /// Test mailbox key derivation is deterministic.
    #[test]
    fn test_mailbox_key_deterministic() {
        let recipient = IdentityKeyPair::generate();
        let recipient_hash = recipient.identity_hash();
        let salt = [1u8; 16];
        let epoch = 1000u64;

        let key1 = derive_mailbox_key(recipient_hash, epoch, &salt);
        let key2 = derive_mailbox_key(recipient_hash, epoch, &salt);

        assert_eq!(key1, key2);
    }

    /// Test different epochs produce different keys.
    #[test]
    fn test_mailbox_key_epoch_separation() {
        let recipient = IdentityKeyPair::generate();
        let recipient_hash = recipient.identity_hash();
        let salt = [2u8; 16];

        let key_epoch1 = derive_mailbox_key(recipient_hash, 1000, &salt);
        let key_epoch2 = derive_mailbox_key(recipient_hash, 1001, &salt);

        assert_ne!(key_epoch1, key_epoch2);
    }

    /// Test different salts produce different keys.
    #[test]
    fn test_mailbox_key_salt_separation() {
        let recipient = IdentityKeyPair::generate();
        let recipient_hash = recipient.identity_hash();
        let epoch = 1000u64;

        let key_salt1 = derive_mailbox_key(recipient_hash, epoch, &[1u8; 16]);
        let key_salt2 = derive_mailbox_key(recipient_hash, epoch, &[2u8; 16]);

        assert_ne!(key_salt1, key_salt2);
    }

    /// Test different recipients produce different keys.
    #[test]
    fn test_mailbox_key_recipient_separation() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let salt = [3u8; 16];
        let epoch = 1000u64;

        let key_alice = derive_mailbox_key(alice.identity_hash(), epoch, &salt);
        let key_bob = derive_mailbox_key(bob.identity_hash(), epoch, &salt);

        assert_ne!(key_alice, key_bob);
    }

    /// Test epoch calculation from timestamp.
    #[test]
    fn test_epoch_calculation() {
        // Epoch duration is 24 hours = 86400 seconds
        let epoch_duration_secs = EPOCH_DURATION_SECS;

        let ts1 = epoch_duration_secs * 100; // Start of epoch 100
        let ts2 = epoch_duration_secs * 100 + 1000; // Still epoch 100
        let ts3 = epoch_duration_secs * 101; // Start of epoch 101

        assert_eq!(epoch_from_timestamp(ts1, epoch_duration_secs), 100);
        assert_eq!(epoch_from_timestamp(ts2, epoch_duration_secs), 100);
        assert_eq!(epoch_from_timestamp(ts3, epoch_duration_secs), 101);
    }

    /// Test mailbox salt generation is random.
    #[test]
    fn test_mailbox_salt_randomness() {
        let salt1 = generate_mailbox_salt();
        let salt2 = generate_mailbox_salt();
        let salt3 = generate_mailbox_salt();

        // All should be different (with overwhelming probability)
        assert_ne!(salt1, salt2);
        assert_ne!(salt2, salt3);
        assert_ne!(salt1, salt3);
    }

    /// Test MailboxKeyParams convenience methods.
    #[test]
    fn test_mailbox_key_params() {
        let recipient = IdentityKeyPair::generate();
        let params = MailboxKeyParams::new_current(recipient.identity_hash());

        let key = params.derive();

        // Key should not be all zeros
        assert!(!key.as_bytes().iter().all(|&b| b == 0));
    }

    /// Test current_epoch returns reasonable value.
    #[test]
    fn test_current_epoch_reasonable() {
        let epoch = current_epoch();
        // Should be non-zero (we're well past 1970)
        assert!(epoch > 0);
        // Should be reasonable (less than 100 years of daily epochs)
        assert!(epoch < 40000);
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod errors {
    use super::*;

    /// Test decryption with corrupted ciphertext fails.
    #[test]
    fn test_corrupted_ciphertext() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("Corrupt me").unwrap();
        let encrypted = encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap();

        // Corrupt the ciphertext
        let ciphertext = encrypted.envelope.ciphertext().to_vec();
        let mut corrupted = ciphertext.clone();
        if !corrupted.is_empty() {
            corrupted[0] ^= 0xFF;
        }

        // Create new envelope with corrupted data
        let corrupted_envelope = MinimalEnvelope::new(
            encrypted.envelope.mailbox_key_typed(),
            encrypted.envelope.ephemeral_public().clone(),
            *encrypted.envelope.nonce(),
            corrupted,
        );

        // Decryption should fail
        let result = decrypt_as_recipient(&bob, &corrupted_envelope);
        assert!(result.is_err());
    }

    /// Test decryption with corrupted nonce fails.
    #[test]
    fn test_corrupted_nonce() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let content = MessageContent::text("Nonce test").unwrap();
        let encrypted = encrypt_for_recipient(&alice, bob.public_keys(), content, None).unwrap();

        // Corrupt the nonce
        let mut corrupted_nonce = *encrypted.envelope.nonce();
        corrupted_nonce[0] ^= 0xFF;

        let corrupted_envelope = MinimalEnvelope::new(
            encrypted.envelope.mailbox_key_typed(),
            encrypted.envelope.ephemeral_public().clone(),
            corrupted_nonce,
            encrypted.envelope.ciphertext().to_vec(),
        );

        // Decryption should fail
        let result = decrypt_as_recipient(&bob, &corrupted_envelope);
        assert!(result.is_err());
    }

    /// Test message too long error.
    #[test]
    fn test_message_too_long() {
        let too_long = "x".repeat(MAX_MESSAGE_CHARS + 1);
        let result = MessageContent::text(&too_long);
        assert!(result.is_err());
    }

    /// Test chunking too long message error.
    #[test]
    fn test_chunking_too_long() {
        let too_long = "x".repeat(MAX_TOTAL_MESSAGE_CHARS + 1);
        let result = split_into_chunks(&too_long);
        assert!(result.is_err());
    }
}

// ============================================================================
// Client Integration Tests
// ============================================================================

mod client {
    use super::*;

    /// Helper to create an unlocked test client.
    async fn unlocked_client() -> VeritasClient {
        let client = VeritasClient::in_memory().await.unwrap();
        client.unlock(b"test_password").await.unwrap();
        client
    }

    /// Test client lifecycle with messaging state.
    #[tokio::test]
    async fn test_client_messaging_state() {
        let client = unlocked_client().await;

        // Create identity
        let hash = client.create_identity(Some("Alice")).await.unwrap();

        // Get public keys
        let keys = client.public_keys().await.unwrap();
        assert_eq!(keys.identity_hash(), hash);

        // Lock should clear state
        client.lock().await.unwrap();
        assert_eq!(client.state().await, ClientState::Locked);

        // Operations should fail when locked
        let result = client.public_keys().await;
        assert!(matches!(result, Err(CoreError::Locked)));
    }

    /// Test multiple identities for messaging.
    #[tokio::test]
    async fn test_multiple_identities() {
        let client = unlocked_client().await;

        let id1 = client.create_identity(Some("Personal")).await.unwrap();
        let id2 = client.create_identity(Some("Work")).await.unwrap();
        let id3 = client.create_identity(Some("Anonymous")).await.unwrap();

        // All should be unique
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);

        // Should not be able to create more
        let slots = client.identity_slots().await.unwrap();
        assert!(!slots.can_create());
    }

    /// Test primary identity switching.
    #[tokio::test]
    async fn test_primary_identity_switch() {
        let client = unlocked_client().await;

        let id1 = client.create_identity(Some("First")).await.unwrap();
        let id2 = client.create_identity(Some("Second")).await.unwrap();

        // Verify both identities were created
        let identities = client.list_identities().await.unwrap();
        assert_eq!(identities.len(), 2);

        // Set primary to id1 explicitly
        client.set_primary_identity(&id1).await.unwrap();

        // Verify via list_identities that id1 is now primary
        let identities = client.list_identities().await.unwrap();
        let id1_entry = identities.iter().find(|i| i.hash == id1).unwrap();
        assert!(
            id1_entry.is_primary,
            "id1 should be primary after set_primary_identity"
        );

        // Switch to id2
        client.set_primary_identity(&id2).await.unwrap();

        // Verify via list_identities that id2 is now primary
        let identities = client.list_identities().await.unwrap();
        let id2_entry = identities.iter().find(|i| i.hash == id2).unwrap();
        assert!(
            id2_entry.is_primary,
            "id2 should be primary after set_primary_identity"
        );
        let id1_entry = identities.iter().find(|i| i.hash == id1).unwrap();
        assert!(
            !id1_entry.is_primary,
            "id1 should not be primary after switching to id2"
        );
    }

    /// Test concurrent client access.
    #[tokio::test]
    async fn test_concurrent_client_access() {
        let client = Arc::new(unlocked_client().await);
        client.create_identity(Some("Test")).await.unwrap();

        let mut handles = vec![];

        // Spawn multiple tasks accessing the client
        for i in 0..10 {
            let client_clone = client.clone();
            handles.push(tokio::spawn(async move {
                let state = client_clone.state().await;
                assert_eq!(state, ClientState::Unlocked);

                let hash = client_clone.identity_hash().await.unwrap();
                let keys = client_clone.public_keys().await.unwrap();
                assert_eq!(keys.identity_hash(), hash);

                i
            }));
        }

        // All should complete successfully
        for handle in handles {
            handle.await.unwrap();
        }
    }

    /// Test client configuration for testing.
    #[test]
    fn test_client_config_for_testing() {
        let config = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .disable_bluetooth()
            .disable_local_discovery()
            .disable_timing_jitter()
            .with_max_queued_messages(100)
            .build();

        assert!(config.storage.in_memory);
        assert!(!config.network.enable_bluetooth);
        assert!(!config.network.enable_local_discovery);
        assert!(!config.features.timing_jitter);
        assert_eq!(config.features.max_queued_messages, 100);
    }
}
