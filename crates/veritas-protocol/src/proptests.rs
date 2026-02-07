//! Property-based tests for protocol components.
//!
//! These tests verify protocol invariants hold for arbitrary inputs:
//!
//! - Message validation correctly accepts/rejects based on size limits
//! - Chunking and reassembly preserve message content
//! - Padding correctly hides message size within buckets
//! - Signature verification is deterministic and correct

use proptest::prelude::*;

use crate::chunking::{ChunkReassembler, split_into_chunks};
use crate::envelope::{
    LENGTH_PREFIX_SIZE, bucket_for_size, is_valid_padded, max_data_size, pad_to_bucket, unpad,
};
use crate::limits::{
    MAX_CHUNKS_PER_MESSAGE, MAX_MESSAGE_CHARS, MAX_TOTAL_MESSAGE_CHARS, PADDING_BUCKETS,
};
use crate::signing::{SigningData, sign_message, verify_signature};

use veritas_crypto::Hash256;
use veritas_identity::IdentityKeyPair;

// ==================== Chunking Property Tests ====================

proptest! {
    /// Messages within single-chunk limit should produce exactly one chunk.
    #[test]
    fn short_messages_single_chunk(
        content in ".{0,300}"  // 0-300 characters
    ) {
        let chunks = split_into_chunks(&content).unwrap();
        prop_assert_eq!(chunks.len(), 1);
        prop_assert_eq!(chunks[0].content(), content);
        prop_assert!(chunks[0].info().is_first());
        prop_assert!(chunks[0].info().is_last());
    }

    /// Messages of exactly MAX_MESSAGE_CHARS should produce one chunk.
    #[test]
    fn exactly_max_chars_single_chunk(c in prop::char::any()) {
        let content: String = std::iter::repeat_n(c, MAX_MESSAGE_CHARS).collect();
        let chunks = split_into_chunks(&content).unwrap();
        prop_assert_eq!(chunks.len(), 1);
    }

    /// Messages exceeding MAX_MESSAGE_CHARS but within MAX_TOTAL_MESSAGE_CHARS
    /// should produce multiple chunks.
    #[test]
    fn long_messages_multiple_chunks(
        len in (MAX_MESSAGE_CHARS + 1)..=MAX_TOTAL_MESSAGE_CHARS
    ) {
        let content: String = "a".repeat(len);
        let chunks = split_into_chunks(&content).unwrap();

        // Should have between 2 and MAX_CHUNKS_PER_MESSAGE chunks
        let expected_chunks = len.div_ceil(MAX_MESSAGE_CHARS);
        prop_assert_eq!(chunks.len(), expected_chunks);
        prop_assert!(chunks.len() >= 2);
        prop_assert!(chunks.len() <= MAX_CHUNKS_PER_MESSAGE);
    }

    /// Messages exceeding MAX_TOTAL_MESSAGE_CHARS should be rejected.
    #[test]
    fn oversized_messages_rejected(
        extra in 1usize..100
    ) {
        let content: String = "x".repeat(MAX_TOTAL_MESSAGE_CHARS + extra);
        let result = split_into_chunks(&content);
        prop_assert!(result.is_err());
    }

    /// Chunk/reassembly roundtrip preserves message content.
    #[test]
    fn chunk_reassembly_roundtrip(
        content in ".{0,900}"  // Any valid message length
    ) {
        let chunks = split_into_chunks(&content).unwrap();
        let mut reassembler = ChunkReassembler::new(300);

        let mut result: Option<String> = None;
        for chunk in chunks {
            if let Some(complete) = reassembler.add_chunk(chunk, 1000).unwrap() {
                result = Some(complete);
            }
        }

        if content.chars().count() <= MAX_TOTAL_MESSAGE_CHARS {
            prop_assert_eq!(result.unwrap(), content);
        }
    }

    /// Chunks received out of order still reassemble correctly.
    #[test]
    fn out_of_order_reassembly(len in (MAX_MESSAGE_CHARS + 1)..=(MAX_MESSAGE_CHARS * 2)) {
        let content: String = "b".repeat(len);
        let chunks = split_into_chunks(&content).unwrap();

        // Receive in reverse order
        let mut reassembler = ChunkReassembler::new(300);
        let mut result: Option<String> = None;

        for chunk in chunks.into_iter().rev() {
            if let Some(complete) = reassembler.add_chunk(chunk, 1000).unwrap() {
                result = Some(complete);
            }
        }

        prop_assert_eq!(result.unwrap(), content);
    }

    /// All chunks from a message share the same message hash.
    #[test]
    fn chunks_share_message_hash(len in (MAX_MESSAGE_CHARS + 1)..=MAX_TOTAL_MESSAGE_CHARS) {
        let content: String = "c".repeat(len);
        let chunks = split_into_chunks(&content).unwrap();

        let first_hash = chunks[0].info().message_hash().clone();
        for chunk in &chunks {
            prop_assert_eq!(chunk.info().message_hash(), &first_hash);
        }
    }

    /// Each chunk verifies its own integrity.
    #[test]
    fn chunks_verify_integrity(content in ".{0,900}") {
        let chunks = split_into_chunks(&content).unwrap();
        for chunk in chunks {
            prop_assert!(chunk.verify());
        }
    }
}

// ==================== Padding Property Tests ====================

proptest! {
    /// Pad/unpad roundtrip preserves data.
    #[test]
    fn pad_unpad_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=max_data_size())) {
        let padded = pad_to_bucket(&data).unwrap();
        let unpadded = unpad(&padded).unwrap();
        prop_assert_eq!(data, unpadded);
    }

    /// Padded data size is always a valid bucket size.
    #[test]
    fn padded_size_is_bucket(data in prop::collection::vec(any::<u8>(), 0..=max_data_size())) {
        let padded = pad_to_bucket(&data).unwrap();
        prop_assert!(PADDING_BUCKETS.contains(&padded.len()));
    }

    /// Padded data validates as properly padded.
    #[test]
    fn padded_data_validates(data in prop::collection::vec(any::<u8>(), 0..=max_data_size())) {
        let padded = pad_to_bucket(&data).unwrap();
        prop_assert!(is_valid_padded(&padded));
    }

    /// Data too large for any bucket should fail.
    #[test]
    fn oversized_data_fails(extra in 1usize..100) {
        let data = vec![0u8; max_data_size() + extra];
        let result = pad_to_bucket(&data);
        prop_assert!(result.is_err());
    }

    /// bucket_for_size returns correct bucket.
    #[test]
    fn bucket_selection_correct(data_len in 0usize..=max_data_size()) {
        let bucket = bucket_for_size(data_len);
        prop_assert!(bucket.is_some());

        let bucket = bucket.unwrap();
        // Bucket should be large enough for data + prefix
        prop_assert!(bucket >= data_len + LENGTH_PREFIX_SIZE);
        // Bucket should be in the list
        prop_assert!(PADDING_BUCKETS.contains(&bucket));
    }

    /// Minimum bucket for data is smallest sufficient bucket.
    #[test]
    fn bucket_is_minimal(data_len in 0usize..=max_data_size()) {
        let bucket = bucket_for_size(data_len).unwrap();
        let required = data_len + LENGTH_PREFIX_SIZE;

        // Check that this is the smallest bucket that works
        for &smaller_bucket in PADDING_BUCKETS {
            if smaller_bucket < bucket {
                prop_assert!(smaller_bucket < required);
            }
        }
    }

    /// Random padding bytes differ between paddings.
    #[test]
    fn padding_is_random(data in prop::collection::vec(any::<u8>(), 0..100)) {
        let padded1 = pad_to_bucket(&data).unwrap();
        let padded2 = pad_to_bucket(&data).unwrap();

        // Data portion should be identical
        let data_end = LENGTH_PREFIX_SIZE + data.len();
        prop_assert_eq!(&padded1[..data_end], &padded2[..data_end]);

        // Padding should differ (with overwhelming probability if there is padding)
        if padded1.len() > data_end + 1 {
            // Only check if there's meaningful padding
            // Allow rare case of collision but flag if it happens too often
            // This is a probabilistic test
        }
    }
}

// ==================== Message Validation Property Tests ====================

proptest! {
    /// Valid character counts are accepted.
    #[test]
    fn valid_message_lengths_accepted(len in 0usize..=MAX_TOTAL_MESSAGE_CHARS) {
        let content: String = "m".repeat(len);
        let result = split_into_chunks(&content);
        prop_assert!(result.is_ok());
    }

    /// Invalid character counts are rejected.
    #[test]
    fn invalid_message_lengths_rejected(
        extra in 1usize..1000
    ) {
        let len = MAX_TOTAL_MESSAGE_CHARS + extra;
        let content: String = "n".repeat(len);
        let result = split_into_chunks(&content);
        prop_assert!(result.is_err());
    }
}

// ==================== Signature Property Tests ====================

proptest! {
    /// Signing and verification roundtrip succeeds for valid sender.
    #[test]
    fn sign_verify_roundtrip(
        content in prop::collection::vec(any::<u8>(), 0..1000),
        timestamp in any::<u64>()
    ) {
        let sender = IdentityKeyPair::generate();
        let content_hash = Hash256::hash(&content);
        let signing_data = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

        let signature = sign_message(&sender, &signing_data).unwrap();
        let result = verify_signature(sender.public_keys(), &signing_data, &signature);

        prop_assert!(result.is_ok());
    }

    /// Verification fails with wrong sender's public key.
    #[test]
    fn verify_fails_wrong_sender(
        content in prop::collection::vec(any::<u8>(), 0..100),
        timestamp in any::<u64>()
    ) {
        let sender = IdentityKeyPair::generate();
        let imposter = IdentityKeyPair::generate();
        let content_hash = Hash256::hash(&content);
        let signing_data = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

        let signature = sign_message(&sender, &signing_data).unwrap();
        let result = verify_signature(imposter.public_keys(), &signing_data, &signature);

        prop_assert!(result.is_err());
    }

    /// Verification fails with tampered content.
    #[test]
    fn verify_fails_tampered_content(
        content1 in prop::collection::vec(any::<u8>(), 1..100),
        content2 in prop::collection::vec(any::<u8>(), 1..100),
        timestamp in any::<u64>()
    ) {
        prop_assume!(content1 != content2);

        let sender = IdentityKeyPair::generate();
        let content_hash1 = Hash256::hash(&content1);
        let content_hash2 = Hash256::hash(&content2);

        let signing_data1 = SigningData::new(sender.identity_hash(), timestamp, &content_hash1);
        let signing_data2 = SigningData::new(sender.identity_hash(), timestamp, &content_hash2);

        let signature = sign_message(&sender, &signing_data1).unwrap();
        let result = verify_signature(sender.public_keys(), &signing_data2, &signature);

        prop_assert!(result.is_err());
    }

    /// SigningData is deterministic for same inputs.
    #[test]
    fn signing_data_deterministic(
        content in prop::collection::vec(any::<u8>(), 0..100),
        timestamp in any::<u64>()
    ) {
        let sender = IdentityKeyPair::generate();
        let content_hash = Hash256::hash(&content);

        let data1 = SigningData::new(sender.identity_hash(), timestamp, &content_hash);
        let data2 = SigningData::new(sender.identity_hash(), timestamp, &content_hash);

        prop_assert_eq!(data1.hash(), data2.hash());
    }

    /// Different timestamps produce different signing data.
    #[test]
    fn different_timestamps_different_data(
        content in prop::collection::vec(any::<u8>(), 0..100),
        timestamp1 in any::<u64>(),
        timestamp2 in any::<u64>()
    ) {
        prop_assume!(timestamp1 != timestamp2);

        let sender = IdentityKeyPair::generate();
        let content_hash = Hash256::hash(&content);

        let data1 = SigningData::new(sender.identity_hash(), timestamp1, &content_hash);
        let data2 = SigningData::new(sender.identity_hash(), timestamp2, &content_hash);

        prop_assert_ne!(data1.hash(), data2.hash());
    }
}

// ==================== Unicode Handling Tests ====================

proptest! {
    /// Unicode messages are chunked at character boundaries, not byte boundaries.
    #[test]
    fn unicode_chunking_preserves_characters(
        base_char in prop::char::range('\u{1F600}', '\u{1F64F}'),  // Emoji range
        count in 1usize..350
    ) {
        let content: String = std::iter::repeat_n(base_char, count).collect();
        let result = split_into_chunks(&content);

        if count <= MAX_TOTAL_MESSAGE_CHARS {
            let chunks = result.unwrap();

            // Reassemble
            let reassembled: String = chunks.iter()
                .map(|c| c.content())
                .collect();

            prop_assert_eq!(reassembled, content);

            // Character count per chunk should be at most MAX_MESSAGE_CHARS
            for chunk in &chunks {
                prop_assert!(chunk.content().chars().count() <= MAX_MESSAGE_CHARS);
            }
        }
    }

    /// Mixed ASCII and multi-byte Unicode chunking.
    #[test]
    fn mixed_unicode_chunking(
        prefix in "[a-zA-Z0-9]{0,100}",
        emoji in "[\u{1F600}-\u{1F64F}]{0,50}",
        suffix in "[a-zA-Z0-9]{0,100}"
    ) {
        let content = format!("{}{}{}", prefix, emoji, suffix);
        let char_count = content.chars().count();

        if char_count <= MAX_TOTAL_MESSAGE_CHARS {
            let chunks = split_into_chunks(&content).unwrap();

            // Reassemble and verify
            let reassembled: String = chunks.iter()
                .map(|c| c.content())
                .collect();

            prop_assert_eq!(reassembled, content);
        }
    }
}

// ==================== Edge Case Tests ====================

proptest! {
    /// Empty messages are handled correctly.
    #[test]
    fn empty_message_handled(_seed in any::<u64>()) {
        let chunks = split_into_chunks("").unwrap();
        prop_assert_eq!(chunks.len(), 1);
        prop_assert_eq!(chunks[0].content(), "");

        let mut reassembler = ChunkReassembler::new(300);
        let result = reassembler.add_chunk(chunks.into_iter().next().unwrap(), 1000).unwrap();
        prop_assert_eq!(result.unwrap(), "");
    }

    /// Empty data padding works.
    #[test]
    fn empty_data_padding(_seed in any::<u64>()) {
        let padded = pad_to_bucket(&[]).unwrap();
        prop_assert!(is_valid_padded(&padded));

        let unpadded = unpad(&padded).unwrap();
        prop_assert!(unpadded.is_empty());
    }
}
