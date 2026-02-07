//! Integration tests for veritas-core Phase 8 implementation.
//!
//! These tests verify the high-level API behavior of the VeritasClient,
//! including lifecycle management, identity operations, safety numbers,
//! and configuration.

use std::time::Duration;

use veritas_core::{
    ClientConfig, ClientConfigBuilder, ClientState, CoreError, SafetyNumber, VeritasClient,
};
use veritas_identity::IdentityKeyPair;

// ============================================================================
// Client Lifecycle Tests
// ============================================================================

mod lifecycle {
    use super::*;

    /// Helper to create a test client with in-memory storage.
    async fn test_client() -> VeritasClient {
        VeritasClient::in_memory()
            .await
            .expect("Failed to create in-memory client")
    }

    #[tokio::test]
    async fn test_create_unlock_lock_unlock_cycle() {
        // Test the full lifecycle: create -> unlock -> lock -> unlock
        let client = test_client().await;

        // Initial state is Created
        assert_eq!(client.state().await, ClientState::Created);
        assert!(!client.is_unlocked().await);

        // Unlock transitions to Unlocked
        client.unlock(b"test_password").await.unwrap();
        assert_eq!(client.state().await, ClientState::Unlocked);
        assert!(client.is_unlocked().await);

        // Lock transitions to Locked
        client.lock().await.unwrap();
        assert_eq!(client.state().await, ClientState::Locked);
        assert!(!client.is_unlocked().await);

        // Unlock again works
        client.unlock(b"test_password").await.unwrap();
        assert_eq!(client.state().await, ClientState::Unlocked);
        assert!(client.is_unlocked().await);
    }

    #[tokio::test]
    async fn test_create_unlock_shutdown() {
        // Test: create -> unlock -> shutdown
        let client = test_client().await;

        // Start in Created state
        assert_eq!(client.state().await, ClientState::Created);

        // Unlock
        client.unlock(b"password").await.unwrap();
        assert_eq!(client.state().await, ClientState::Unlocked);

        // Shutdown
        client.shutdown().await.unwrap();
        assert_eq!(client.state().await, ClientState::ShuttingDown);
    }

    #[tokio::test]
    async fn test_operations_fail_when_locked() {
        let client = test_client().await;

        // Unlock first, create identity, then lock
        client.unlock(b"password").await.unwrap();
        client.create_identity(Some("Test")).await.unwrap();
        client.lock().await.unwrap();

        // Operations should fail when locked
        let identity_hash_result = client.identity_hash().await;
        assert!(matches!(identity_hash_result, Err(CoreError::Locked)));

        let public_keys_result = client.public_keys().await;
        assert!(matches!(public_keys_result, Err(CoreError::Locked)));

        let list_result = client.list_identities().await;
        assert!(matches!(list_result, Err(CoreError::Locked)));

        let slots_result = client.identity_slots().await;
        assert!(matches!(slots_result, Err(CoreError::Locked)));

        let create_result = client.create_identity(None).await;
        assert!(matches!(create_result, Err(CoreError::Locked)));
    }

    #[tokio::test]
    async fn test_operations_fail_after_shutdown() {
        let client = test_client().await;

        // Unlock first
        client.unlock(b"password").await.unwrap();

        // Shutdown
        client.shutdown().await.unwrap();

        // Unlock should fail after shutdown
        let unlock_result = client.unlock(b"password").await;
        assert!(matches!(unlock_result, Err(CoreError::ShuttingDown)));

        // Lock should fail after shutdown
        let lock_result = client.lock().await;
        assert!(matches!(lock_result, Err(CoreError::ShuttingDown)));

        // Identity operations should fail
        let identity_result = client.identity_hash().await;
        assert!(matches!(identity_result, Err(CoreError::ShuttingDown)));

        let create_result = client.create_identity(None).await;
        assert!(matches!(create_result, Err(CoreError::ShuttingDown)));
    }

    #[tokio::test]
    async fn test_operations_fail_when_not_initialized() {
        let client = test_client().await;

        // Client is in Created state (not unlocked yet)
        assert_eq!(client.state().await, ClientState::Created);

        // All operations should fail with NotInitialized
        let identity_hash_result = client.identity_hash().await;
        assert!(matches!(
            identity_hash_result,
            Err(CoreError::NotInitialized)
        ));

        let public_keys_result = client.public_keys().await;
        assert!(matches!(public_keys_result, Err(CoreError::NotInitialized)));

        let list_result = client.list_identities().await;
        assert!(matches!(list_result, Err(CoreError::NotInitialized)));

        let slots_result = client.identity_slots().await;
        assert!(matches!(slots_result, Err(CoreError::NotInitialized)));

        let create_result = client.create_identity(None).await;
        assert!(matches!(create_result, Err(CoreError::NotInitialized)));
    }

    #[tokio::test]
    async fn test_unlock_idempotent() {
        // Unlocking an already unlocked client should succeed (idempotent)
        let client = test_client().await;

        client.unlock(b"password").await.unwrap();
        assert_eq!(client.state().await, ClientState::Unlocked);

        // Second unlock should also succeed
        let result = client.unlock(b"password").await;
        assert!(result.is_ok());
        assert_eq!(client.state().await, ClientState::Unlocked);
    }

    #[tokio::test]
    async fn test_lock_idempotent() {
        // Locking an already locked client should succeed (idempotent)
        let client = test_client().await;

        // Lock from Created state
        let result = client.lock().await;
        assert!(result.is_ok());

        // Lock again
        let result = client.lock().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_shutdown_idempotent() {
        // Multiple shutdowns should succeed
        let client = test_client().await;

        client.shutdown().await.unwrap();
        assert_eq!(client.state().await, ClientState::ShuttingDown);

        // Second shutdown should also succeed
        let result = client.shutdown().await;
        assert!(result.is_ok());
        assert_eq!(client.state().await, ClientState::ShuttingDown);
    }

    #[tokio::test]
    async fn test_unlock_with_empty_password_fails() {
        let client = test_client().await;

        let result = client.unlock(b"").await;
        assert!(matches!(result, Err(CoreError::AuthenticationFailed)));
        assert_eq!(client.state().await, ClientState::Created);
    }

    #[tokio::test]
    async fn test_multiple_lock_unlock_cycles() {
        let client = test_client().await;

        for _ in 0..5 {
            client.unlock(b"password").await.unwrap();
            assert!(client.is_unlocked().await);

            client.lock().await.unwrap();
            assert!(!client.is_unlocked().await);
        }
    }

    #[tokio::test]
    async fn test_state_descriptions() {
        // Verify state descriptions are non-empty
        assert!(!ClientState::Created.description().is_empty());
        assert!(!ClientState::Locked.description().is_empty());
        assert!(!ClientState::Unlocked.description().is_empty());
        assert!(!ClientState::ShuttingDown.description().is_empty());

        // Display trait should work
        let display = format!("{}", ClientState::Unlocked);
        assert!(!display.is_empty());
    }

    #[tokio::test]
    async fn test_state_is_ready() {
        assert!(!ClientState::Created.is_ready());
        assert!(!ClientState::Locked.is_ready());
        assert!(ClientState::Unlocked.is_ready());
        assert!(!ClientState::ShuttingDown.is_ready());
    }
}

// ============================================================================
// Identity Management Tests
// ============================================================================

mod identity {
    use super::*;

    async fn test_client() -> VeritasClient {
        VeritasClient::in_memory()
            .await
            .expect("Failed to create in-memory client")
    }

    #[tokio::test]
    async fn test_unlock_starts_with_no_identity() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // Initially no identities
        let identities = client.list_identities().await.unwrap();
        assert!(identities.is_empty());

        // No primary identity
        let result = client.identity_hash().await;
        assert!(matches!(result, Err(CoreError::NoPrimaryIdentity)));
    }

    #[tokio::test]
    async fn test_create_identity_sets_primary() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // Create first identity
        let hash = client.create_identity(Some("Primary")).await.unwrap();

        // Should be set as primary automatically
        let primary = client.identity_hash().await.unwrap();
        assert_eq!(primary, hash);

        // Verify in list
        let identities = client.list_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert!(identities[0].is_primary);
        assert_eq!(identities[0].label, Some("Primary".to_string()));
    }

    #[tokio::test]
    async fn test_create_multiple_identities_up_to_three() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // Create 3 identities (the maximum)
        let hash1 = client.create_identity(Some("First")).await.unwrap();
        let hash2 = client.create_identity(Some("Second")).await.unwrap();
        let hash3 = client.create_identity(Some("Third")).await.unwrap();

        // All hashes should be unique
        assert_ne!(hash1, hash2);
        assert_ne!(hash2, hash3);
        assert_ne!(hash1, hash3);

        // Should have 3 identities
        let identities = client.list_identities().await.unwrap();
        assert_eq!(identities.len(), 3);

        // First should still be primary
        let primary = client.identity_hash().await.unwrap();
        assert_eq!(primary, hash1);
    }

    #[tokio::test]
    async fn test_list_identities_returns_all() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // Create identities with different labels
        let hash1 = client.create_identity(Some("Personal")).await.unwrap();
        let hash2 = client.create_identity(Some("Work")).await.unwrap();
        let hash3 = client.create_identity(None).await.unwrap();

        let identities = client.list_identities().await.unwrap();
        assert_eq!(identities.len(), 3);

        // Verify all are present
        let hashes: Vec<_> = identities.iter().map(|i| &i.hash).collect();
        assert!(hashes.contains(&&hash1));
        assert!(hashes.contains(&&hash2));
        assert!(hashes.contains(&&hash3));

        // Verify labels
        let personal = identities.iter().find(|i| i.hash == hash1).unwrap();
        assert_eq!(personal.label, Some("Personal".to_string()));

        let work = identities.iter().find(|i| i.hash == hash2).unwrap();
        assert_eq!(work.label, Some("Work".to_string()));

        let unlabeled = identities.iter().find(|i| i.hash == hash3).unwrap();
        assert_eq!(unlabeled.label, None);
    }

    #[tokio::test]
    async fn test_set_primary_identity() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let hash1 = client.create_identity(Some("First")).await.unwrap();
        let hash2 = client.create_identity(Some("Second")).await.unwrap();

        // First is primary initially
        let primary = client.identity_hash().await.unwrap();
        assert_eq!(primary, hash1);

        // Set second as primary
        client.set_primary_identity(&hash2).await.unwrap();

        // Verify through list (is_primary flags)
        let identities = client.list_identities().await.unwrap();
        let first = identities.iter().find(|i| i.hash == hash1).unwrap();
        let second = identities.iter().find(|i| i.hash == hash2).unwrap();

        assert!(!first.is_primary);
        assert!(second.is_primary);
    }

    #[tokio::test]
    async fn test_set_primary_identity_not_found() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        client.create_identity(Some("Real")).await.unwrap();

        // Try to set a non-existent identity as primary
        let fake_hash = veritas_identity::IdentityHash::from_public_key(b"nonexistent");
        let result = client.set_primary_identity(&fake_hash).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_identity_slots_info_accurate() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // Initially: 0 used, 3 available
        let slots = client.identity_slots().await.unwrap();
        assert_eq!(slots.used, 0);
        assert_eq!(slots.max, 3);
        assert_eq!(slots.available, 3);
        assert!(slots.can_create());

        // Create one: 1 used, 2 available
        client.create_identity(None).await.unwrap();
        let slots = client.identity_slots().await.unwrap();
        assert_eq!(slots.used, 1);
        assert_eq!(slots.available, 2);
        assert!(slots.can_create());

        // Create second: 2 used, 1 available
        client.create_identity(None).await.unwrap();
        let slots = client.identity_slots().await.unwrap();
        assert_eq!(slots.used, 2);
        assert_eq!(slots.available, 1);
        assert!(slots.can_create());

        // Create third: 3 used, 0 available
        client.create_identity(None).await.unwrap();
        let slots = client.identity_slots().await.unwrap();
        assert_eq!(slots.used, 3);
        assert_eq!(slots.available, 0);
        assert!(!slots.can_create());
    }

    #[tokio::test]
    async fn test_public_keys_accessible() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        client.create_identity(None).await.unwrap();

        // Should be able to get public keys
        let keys = client.public_keys().await.unwrap();

        // Verify the public keys have non-empty exchange key
        assert!(!keys.exchange.as_bytes().is_empty());

        // Identity hash should match
        let hash = client.identity_hash().await.unwrap();
        assert_eq!(keys.identity_hash(), hash);
    }

    #[tokio::test]
    async fn test_identity_info_is_usable() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        client.create_identity(Some("Test")).await.unwrap();

        let identities = client.list_identities().await.unwrap();
        let identity = &identities[0];

        // New identity should be usable
        assert!(identity.is_usable());
        assert!(!identity.is_expiring());
    }

    #[tokio::test]
    async fn test_create_identity_without_label() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let hash = client.create_identity(None).await.unwrap();

        let identities = client.list_identities().await.unwrap();
        let identity = identities.iter().find(|i| i.hash == hash).unwrap();

        assert!(identity.label.is_none());
    }
}

// ============================================================================
// Safety Number Tests
// ============================================================================

mod safety_numbers {
    use super::*;

    #[test]
    fn test_symmetric_computation() {
        // Safety number A->B should equal B->A
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_computes = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let bob_computes = SafetyNumber::compute(bob.public_keys(), alice.public_keys());

        assert_eq!(alice_computes, bob_computes);
        assert_eq!(alice_computes.as_bytes(), bob_computes.as_bytes());
        assert_eq!(
            alice_computes.to_numeric_string(),
            bob_computes.to_numeric_string()
        );
        assert_eq!(alice_computes.to_qr_string(), bob_computes.to_qr_string());
    }

    #[test]
    fn test_different_keys_produce_different_numbers() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();
        let charlie = IdentityKeyPair::generate();

        let alice_bob = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let alice_charlie = SafetyNumber::compute(alice.public_keys(), charlie.public_keys());
        let bob_charlie = SafetyNumber::compute(bob.public_keys(), charlie.public_keys());

        // All pairs should produce different safety numbers
        assert_ne!(alice_bob, alice_charlie);
        assert_ne!(alice_bob, bob_charlie);
        assert_ne!(alice_charlie, bob_charlie);
    }

    #[test]
    fn test_numeric_string_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let numeric = safety.to_numeric_string();

        // Should be 60 digits + 11 spaces = 71 characters
        assert_eq!(numeric.len(), 71);

        // Should have 11 spaces separating 12 groups
        let space_count = numeric.chars().filter(|c| *c == ' ').count();
        assert_eq!(space_count, 11);

        // Split into groups and verify each
        let groups: Vec<&str> = numeric.split(' ').collect();
        assert_eq!(groups.len(), 12);

        for group in groups {
            // Each group should be 5 digits
            assert_eq!(group.len(), 5);
            // All characters should be digits
            assert!(group.chars().all(|c| c.is_ascii_digit()));
        }

        // Total digits (excluding spaces) should be 60
        let digit_count = numeric.chars().filter(|c| c.is_ascii_digit()).count();
        assert_eq!(digit_count, 60);
    }

    #[test]
    fn test_qr_string_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let qr = safety.to_qr_string();

        // Should be 64 hex characters (32 bytes * 2)
        assert_eq!(qr.len(), 64);

        // All characters should be lowercase hex
        assert!(
            qr.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_qr_string_matches_bytes() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let qr = safety.to_qr_string();
        let bytes = safety.as_bytes();

        // Verify QR string correctly encodes the bytes
        for (i, byte) in bytes.iter().enumerate() {
            let hex_pair = &qr[i * 2..i * 2 + 2];
            let parsed = u8::from_str_radix(hex_pair, 16).unwrap();
            assert_eq!(*byte, parsed);
        }
    }

    #[test]
    fn test_deterministic_computation() {
        // Same keys should always produce the same safety number
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let first = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let second = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let third = SafetyNumber::compute(alice.public_keys(), bob.public_keys());

        assert_eq!(first, second);
        assert_eq!(second, third);
    }

    #[test]
    fn test_same_identity_both_sides() {
        // Computing safety number with same identity on both sides should work
        let alice = IdentityKeyPair::generate();

        let result = SafetyNumber::compute(alice.public_keys(), alice.public_keys());

        // Should produce a valid (non-zero) safety number
        assert!(!result.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_display_uses_numeric_string() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());

        let display = format!("{}", safety);
        let numeric = safety.to_numeric_string();

        assert_eq!(display, numeric);
    }

    #[test]
    fn test_debug_format() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let debug = format!("{:?}", safety);

        // Debug should show truncated hex
        assert!(debug.starts_with("SafetyNumber("));
        assert!(debug.ends_with("...)"));
        // Should contain first 16 chars of QR string
        assert!(debug.contains(&safety.to_qr_string()[..16]));
    }

    #[test]
    fn test_clone_equality() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let cloned = safety.clone();

        assert_eq!(safety, cloned);
        assert_eq!(safety.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn test_as_bytes_length() {
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let bytes = safety.as_bytes();

        // Safety number is 32 bytes (256 bits)
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_numeric_digits_bounded() {
        // Each pair of digits should be in range 00-99
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let safety = SafetyNumber::compute(alice.public_keys(), bob.public_keys());
        let numeric = safety.to_numeric_string();

        // Remove spaces and check each 2-digit group
        let digits_only: String = numeric.chars().filter(|c| c.is_ascii_digit()).collect();
        assert_eq!(digits_only.len(), 60);

        // Check each pair is < 100
        for chunk in digits_only.as_bytes().chunks(2) {
            let value: u32 = std::str::from_utf8(chunk).unwrap().parse().unwrap();
            assert!(value < 100);
        }
    }
}

// ============================================================================
// Config Tests
// ============================================================================

mod config {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClientConfig::default();

        // Storage defaults
        assert!(!config.storage.in_memory);
        assert!(config.storage.encrypt_database);

        // Network defaults
        assert!(config.network.enable_internet);
        assert!(config.network.enable_local_discovery);
        assert!(config.network.enable_bluetooth);
        assert!(config.network.bootstrap_peers.is_empty());
        assert!(config.network.listen_addresses.is_empty());
        assert_eq!(config.network.connection_timeout, Duration::from_secs(30));

        // Reputation defaults
        assert!(config.reputation.enabled);
        assert!(config.reputation.enable_collusion_detection);
        assert!((config.reputation.decay_rate_percent - 1.0).abs() < f32::EPSILON);

        // Feature defaults
        assert!(config.features.timing_jitter);
        assert!(config.features.auto_queue_offline);
        assert_eq!(config.features.max_queued_messages, 1000);
        assert!(config.features.delivery_receipts);
        assert!(!config.features.read_receipts);
    }

    #[test]
    fn test_builder_pattern() {
        let config = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .disable_bluetooth()
            .disable_local_discovery()
            .with_connection_timeout(Duration::from_secs(60))
            .with_bootstrap_peer("/dns4/peer1.example.com/tcp/4001".into())
            .with_bootstrap_peer("/dns4/peer2.example.com/tcp/4001".into())
            .with_listen_address("/ip4/0.0.0.0/tcp/4001".into())
            .disable_collusion_detection()
            .with_decay_rate(2.5)
            .disable_timing_jitter()
            .with_max_queued_messages(500)
            .enable_read_receipts()
            .build();

        // Verify all settings
        assert!(config.storage.in_memory);
        assert!(!config.network.enable_bluetooth);
        assert!(!config.network.enable_local_discovery);
        assert!(config.network.enable_internet); // Still enabled
        assert_eq!(config.network.connection_timeout, Duration::from_secs(60));
        assert_eq!(config.network.bootstrap_peers.len(), 2);
        assert_eq!(config.network.listen_addresses.len(), 1);
        assert!(!config.reputation.enable_collusion_detection);
        assert!((config.reputation.decay_rate_percent - 2.5).abs() < f32::EPSILON);
        assert!(!config.features.timing_jitter);
        assert_eq!(config.features.max_queued_messages, 500);
        assert!(config.features.read_receipts);
    }

    #[test]
    fn test_in_memory_config() {
        let config = ClientConfig::in_memory();
        assert!(config.storage.in_memory);
    }

    #[test]
    fn test_config_validation_valid() {
        let config = ClientConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_decay_rate_negative() {
        let config = ClientConfigBuilder::new().with_decay_rate(-1.0).build();

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_invalid_decay_rate_over_100() {
        let config = ClientConfigBuilder::new().with_decay_rate(101.0).build();

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_zero_timeout() {
        let config = ClientConfigBuilder::new()
            .with_connection_timeout(Duration::from_secs(0))
            .build();

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_zero_queued_messages() {
        let config = ClientConfigBuilder::new()
            .with_max_queued_messages(0)
            .build();

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validation_in_memory_with_empty_path() {
        // In-memory storage with empty path should be valid
        let config = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .with_data_dir(std::path::PathBuf::new())
            .build();

        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_build_validated_success() {
        let result = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .build_validated();

        assert!(result.is_ok());
    }

    #[test]
    fn test_build_validated_failure() {
        let result = ClientConfigBuilder::new()
            .with_decay_rate(-5.0)
            .build_validated();

        assert!(result.is_err());
    }

    #[test]
    fn test_builder_replace_peers() {
        let config = ClientConfigBuilder::new()
            .with_bootstrap_peer("peer1".into())
            .with_bootstrap_peer("peer2".into())
            .with_bootstrap_peers(vec!["peer3".into()])
            .build();

        // with_bootstrap_peers should replace all previous peers
        assert_eq!(config.network.bootstrap_peers, vec!["peer3"]);
    }

    #[test]
    fn test_builder_replace_addresses() {
        let config = ClientConfigBuilder::new()
            .with_listen_address("addr1".into())
            .with_listen_address("addr2".into())
            .with_listen_addresses(vec!["addr3".into()])
            .build();

        // with_listen_addresses should replace all previous addresses
        assert_eq!(config.network.listen_addresses, vec!["addr3"]);
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let original = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .disable_bluetooth()
            .with_bootstrap_peer("/dns4/example.com/tcp/4001".into())
            .with_decay_rate(1.5)
            .with_max_queued_messages(2000)
            .build();

        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ClientConfig = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(original.storage.in_memory, deserialized.storage.in_memory);
        assert_eq!(
            original.network.enable_bluetooth,
            deserialized.network.enable_bluetooth
        );
        assert_eq!(
            original.network.bootstrap_peers,
            deserialized.network.bootstrap_peers
        );
        assert!(
            (original.reputation.decay_rate_percent - deserialized.reputation.decay_rate_percent)
                .abs()
                < f32::EPSILON
        );
        assert_eq!(
            original.features.max_queued_messages,
            deserialized.features.max_queued_messages
        );
    }

    #[test]
    fn test_builder_enable_disable_toggles() {
        // Test all enable/disable toggle methods
        let config = ClientConfigBuilder::new()
            // Storage
            .with_disk_storage()
            .with_in_memory_storage()
            .with_encrypted_database()
            .with_unencrypted_database()
            // Network
            .enable_internet()
            .disable_internet()
            .enable_local_discovery()
            .disable_local_discovery()
            .enable_bluetooth()
            .disable_bluetooth()
            // Reputation
            .enable_reputation()
            .disable_reputation()
            .enable_collusion_detection()
            .disable_collusion_detection()
            // Features
            .enable_timing_jitter()
            .disable_timing_jitter()
            .enable_auto_queue()
            .disable_auto_queue()
            .enable_delivery_receipts()
            .disable_delivery_receipts()
            .enable_read_receipts()
            .disable_read_receipts()
            .build();

        // Final state after all toggles (last call wins)
        assert!(config.storage.in_memory);
        assert!(!config.storage.encrypt_database);
        assert!(!config.network.enable_internet);
        assert!(!config.network.enable_local_discovery);
        assert!(!config.network.enable_bluetooth);
        assert!(!config.reputation.enabled);
        assert!(!config.reputation.enable_collusion_detection);
        assert!(!config.features.timing_jitter);
        assert!(!config.features.auto_queue_offline);
        assert!(!config.features.delivery_receipts);
        assert!(!config.features.read_receipts);
    }

    #[tokio::test]
    async fn test_client_with_custom_config() {
        let config = ClientConfigBuilder::new()
            .with_in_memory_storage()
            .disable_bluetooth()
            .with_max_queued_messages(100)
            .build();

        let client = VeritasClient::new(config).await.unwrap();
        assert_eq!(client.state().await, ClientState::Created);
    }

    #[tokio::test]
    async fn test_client_with_data_dir() {
        let temp_dir = tempfile::tempdir().unwrap();
        let client = VeritasClient::with_data_dir(temp_dir.path()).await.unwrap();
        assert_eq!(client.state().await, ClientState::Created);
    }
}

// ============================================================================
// Concurrent Access Tests
// ============================================================================

mod concurrency {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_concurrent_state_queries() {
        let client = Arc::new(VeritasClient::in_memory().await.unwrap());
        client.unlock(b"password").await.unwrap();

        let mut handles = vec![];

        for _ in 0..10 {
            let client_clone = client.clone();
            handles.push(tokio::spawn(async move {
                let state = client_clone.state().await;
                assert_eq!(state, ClientState::Unlocked);
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_concurrent_identity_queries() {
        let client = Arc::new(VeritasClient::in_memory().await.unwrap());
        client.unlock(b"password").await.unwrap();
        client.create_identity(Some("Test")).await.unwrap();

        let mut handles = vec![];

        for _ in 0..10 {
            let client_clone = client.clone();
            handles.push(tokio::spawn(async move {
                let _ = client_clone.identity_hash().await.unwrap();
                let _ = client_clone.list_identities().await.unwrap();
                let _ = client_clone.identity_slots().await.unwrap();
            }));
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }
}

// ============================================================================
// Debug and Display Tests
// ============================================================================

mod display {
    use super::*;

    #[tokio::test]
    async fn test_client_debug_no_sensitive_data() {
        let client = VeritasClient::in_memory().await.unwrap();
        client.unlock(b"secret_password").await.unwrap();
        client
            .create_identity(Some("Sensitive Label"))
            .await
            .unwrap();

        let debug = format!("{:?}", client);

        // Debug output should not contain sensitive data
        assert!(debug.contains("VeritasClient"));
        assert!(!debug.contains("secret_password"));
    }

    #[test]
    fn test_config_debug() {
        let config = ClientConfig::default();
        let debug = format!("{:?}", config);

        // Should have readable debug output
        assert!(debug.contains("ClientConfig"));
        assert!(debug.contains("storage"));
        assert!(debug.contains("network"));
        assert!(debug.contains("reputation"));
        assert!(debug.contains("features"));
    }
}
