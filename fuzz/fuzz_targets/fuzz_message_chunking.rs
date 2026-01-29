//! Fuzz target for message chunking.
//!
//! Tests that message chunking handles arbitrary input safely.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_protocol::{split_into_chunks, ChunkReassembler, MAX_TOTAL_MESSAGE_CHARS};

fuzz_target!(|data: &[u8]| {
    // Try to interpret input as a UTF-8 string
    if let Ok(message) = std::str::from_utf8(data) {
        let char_count = message.chars().count();

        // Attempt to chunk the message
        let result = split_into_chunks(message);

        // Check expected outcome
        if char_count > MAX_TOTAL_MESSAGE_CHARS {
            // Should fail for messages too long
            assert!(result.is_err());
        } else {
            // Should succeed for valid messages
            let chunks = result.unwrap();

            // Verify chunk count
            assert!(chunks.len() >= 1);
            assert!(chunks.len() <= 3);

            // Each chunk should verify
            for chunk in &chunks {
                assert!(chunk.verify());
                // Each chunk should have <= 300 characters
                assert!(chunk.content().chars().count() <= 300);
            }

            // All chunks should share the same message hash
            let hash = chunks[0].info().message_hash();
            for chunk in &chunks {
                assert_eq!(chunk.info().message_hash(), hash);
            }

            // Reassembly should work
            let mut reassembler = ChunkReassembler::new(300);
            let mut result: Option<String> = None;

            for chunk in chunks {
                if let Some(complete) = reassembler.add_chunk(chunk, 1000).unwrap() {
                    result = Some(complete);
                }
            }

            // Reassembled message should match original
            assert_eq!(result.unwrap(), message);
        }
    }
});
