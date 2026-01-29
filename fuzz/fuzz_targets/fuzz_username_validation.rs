//! Fuzz target for Username validation.
//!
//! Tests that username validation handles arbitrary input safely and consistently.

#![no_main]

use libfuzzer_sys::fuzz_target;
use veritas_identity::Username;

fuzz_target!(|data: &[u8]| {
    // Try to interpret input as a string
    if let Ok(s) = std::str::from_utf8(data) {
        // Attempt to create a username
        // Should succeed or fail predictably - never panic
        let result = Username::new(s);

        // If successful, verify properties
        if let Ok(username) = result {
            // Content should match input
            assert_eq!(username.as_str(), s);

            // Normalized should be lowercase
            let normalized = username.normalized();
            assert_eq!(normalized, normalized.to_ascii_lowercase());

            // Should be case-insensitive equal to itself
            assert!(username.eq_ignore_case(&username));

            // Length should be within bounds
            assert!(s.len() >= 3);
            assert!(s.len() <= 32);
        }
    }
});
