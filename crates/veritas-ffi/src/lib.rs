//! # veritas-ffi
//!
//! C FFI bindings for VERITAS protocol.
//!
//! Provides a C-compatible API for using VERITAS from other languages.
//!
//! ## Safety
//!
//! All FFI functions validate inputs at the boundary before processing.
//! Error codes are used instead of exceptions/panics.
//! Memory allocated by this library must be freed using the provided `_free` functions.
//!
//! ## Example Usage
//!
//! ```c
//! // Create client
//! VeritasHandle* client = veritas_client_create(NULL);
//!
//! // Unlock with password
//! veritas_client_unlock(client, "password", 8);
//!
//! // Create identity
//! char hash[65];
//! veritas_create_identity(client, "Personal", hash, sizeof(hash));
//!
//! // Get identity slots
//! uint32_t used, max, available;
//! veritas_identity_slots(client, &used, &max, &available);
//!
//! // Lock and cleanup
//! veritas_client_lock(client);
//! veritas_client_free(client);
//! ```

#![warn(missing_docs)]

pub mod client;
pub mod error;
pub mod identity;
pub mod safety;
pub mod types;

pub use error::FfiError;
pub use types::{IdentitySlots, VeritasHandle};

// Re-export functions for convenience
pub use client::{
    veritas_client_create, veritas_client_free, veritas_client_lock, veritas_client_shutdown,
    veritas_client_unlock, veritas_version,
};
pub use identity::{veritas_create_identity, veritas_identity_hash, veritas_identity_slots};
pub use safety::{
    veritas_safety_number_compute, veritas_safety_number_to_numeric, veritas_safety_number_to_qr,
};

/// FFI error codes.
///
/// All FFI functions return an error code to indicate success or failure.
/// A return value of 0 indicates success, negative values indicate errors.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Success.
    Success = 0,
    /// Null pointer provided.
    NullPointer = -1,
    /// Invalid argument.
    InvalidArgument = -2,
    /// Crypto error.
    CryptoError = -3,
    /// Identity error.
    IdentityError = -4,
    /// Protocol error.
    ProtocolError = -5,
    /// Network error.
    NetworkError = -6,
    /// Storage error.
    StorageError = -7,
    /// FFI-FIX-4: Buffer too small for output data.
    BufferTooSmall = -8,
    /// Unknown error.
    Unknown = -99,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_error_code_values() {
        assert_eq!(ErrorCode::Success as i32, 0);
        assert_eq!(ErrorCode::NullPointer as i32, -1);
        assert_eq!(ErrorCode::InvalidArgument as i32, -2);
        assert_eq!(ErrorCode::CryptoError as i32, -3);
        assert_eq!(ErrorCode::IdentityError as i32, -4);
        assert_eq!(ErrorCode::ProtocolError as i32, -5);
        assert_eq!(ErrorCode::NetworkError as i32, -6);
        assert_eq!(ErrorCode::StorageError as i32, -7);
        assert_eq!(ErrorCode::Unknown as i32, -99);
    }

    #[test]
    fn test_version() {
        let version = veritas_version();
        assert!(!version.is_null());

        let version_str = unsafe { std::ffi::CStr::from_ptr(version) };
        let version_string = version_str.to_str().unwrap();

        // Should be a valid semver string
        assert!(!version_string.is_empty());
        assert!(version_string.contains('.'));
    }

    #[test]
    fn test_client_create_and_free() {
        unsafe {
            // Create in-memory client
            let handle = veritas_client_create(std::ptr::null());
            assert!(!handle.is_null());

            // Free it
            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_client_create_with_null_path() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            assert!(!handle.is_null());
            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_client_unlock_and_lock() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            assert!(!handle.is_null());

            // Unlock with password
            let password = b"test_password";
            let result = veritas_client_unlock(handle, password.as_ptr(), password.len());
            assert_eq!(result, ErrorCode::Success);

            // Lock
            let result = veritas_client_lock(handle);
            assert_eq!(result, ErrorCode::Success);

            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_client_operations_require_valid_handle() {
        unsafe {
            // Null handle should fail
            let result = veritas_client_unlock(std::ptr::null_mut(), b"test".as_ptr(), 4);
            assert_eq!(result, ErrorCode::NullPointer);

            let result = veritas_client_lock(std::ptr::null_mut());
            assert_eq!(result, ErrorCode::NullPointer);

            let result = veritas_client_shutdown(std::ptr::null_mut());
            assert_eq!(result, ErrorCode::NullPointer);
        }
    }

    #[test]
    fn test_create_identity() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            assert!(!handle.is_null());

            // Unlock
            let password = b"test_password";
            let result = veritas_client_unlock(handle, password.as_ptr(), password.len());
            assert_eq!(result, ErrorCode::Success);

            // Create identity
            let mut hash_buf = [0u8; 65];
            let label = CString::new("Test").unwrap();
            let result = veritas_create_identity(
                handle,
                label.as_ptr(),
                hash_buf.as_mut_ptr(),
                hash_buf.len(),
            );
            assert_eq!(result, ErrorCode::Success);

            // Verify hash is not empty
            let hash_str = std::ffi::CStr::from_ptr(hash_buf.as_ptr() as *const i8);
            let hash_string = hash_str.to_str().unwrap();
            assert!(!hash_string.is_empty());
            assert_eq!(hash_string.len(), 64); // 32 bytes = 64 hex chars

            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_identity_hash() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            let password = b"test_password";
            veritas_client_unlock(handle, password.as_ptr(), password.len());

            // Create identity first
            let mut hash_buf = [0u8; 65];
            let result = veritas_create_identity(
                handle,
                std::ptr::null(),
                hash_buf.as_mut_ptr(),
                hash_buf.len(),
            );
            assert_eq!(result, ErrorCode::Success);

            // Get identity hash
            let mut hash_buf2 = [0u8; 65];
            let result = veritas_identity_hash(handle, hash_buf2.as_mut_ptr(), hash_buf2.len());
            assert_eq!(result, ErrorCode::Success);

            // Should match the created identity
            assert_eq!(hash_buf, hash_buf2);

            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_identity_slots() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            let password = b"test_password";
            veritas_client_unlock(handle, password.as_ptr(), password.len());

            let mut used = 0u32;
            let mut max = 0u32;
            let mut available = 0u32;

            let result = veritas_identity_slots(handle, &mut used, &mut max, &mut available);
            assert_eq!(result, ErrorCode::Success);

            // Should have default limits
            assert_eq!(max, 3); // From CLAUDE.md - max 3 identities per origin
            assert_eq!(used, 0); // No identities created yet
            assert_eq!(available, 3);

            // Create an identity
            let mut hash_buf = [0u8; 65];
            veritas_create_identity(
                handle,
                std::ptr::null(),
                hash_buf.as_mut_ptr(),
                hash_buf.len(),
            );

            // Check slots again
            let result = veritas_identity_slots(handle, &mut used, &mut max, &mut available);
            assert_eq!(result, ErrorCode::Success);
            assert_eq!(used, 1);
            assert_eq!(available, 2);

            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_safety_number_functions() {
        use veritas_identity::IdentityKeyPair;

        // Generate two key pairs
        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_bytes = alice.public_keys().to_bytes();
        let bob_bytes = bob.public_keys().to_bytes();

        unsafe {
            // Compute safety number
            let mut raw = [0u8; 32];
            let result = veritas_safety_number_compute(
                alice_bytes.as_ptr(),
                alice_bytes.len(),
                bob_bytes.as_ptr(),
                bob_bytes.len(),
                raw.as_mut_ptr(),
                raw.len(),
            );
            assert_eq!(result, ErrorCode::Success);

            // Verify not all zeros
            assert!(raw.iter().any(|&b| b != 0));

            // Convert to numeric format
            let mut numeric = [0u8; 72];
            let result = veritas_safety_number_to_numeric(
                raw.as_ptr(),
                raw.len(),
                numeric.as_mut_ptr(),
                numeric.len(),
            );
            assert_eq!(result, ErrorCode::Success);

            // Verify numeric format
            let numeric_str = std::ffi::CStr::from_ptr(numeric.as_ptr() as *const i8);
            let numeric_string = numeric_str.to_str().unwrap();
            assert_eq!(numeric_string.len(), 71); // 60 digits + 11 spaces
            assert_eq!(numeric_string.chars().filter(|&c| c == ' ').count(), 11);

            // Convert to QR format
            let mut qr = [0u8; 65];
            let result =
                veritas_safety_number_to_qr(raw.as_ptr(), raw.len(), qr.as_mut_ptr(), qr.len());
            assert_eq!(result, ErrorCode::Success);

            // Verify QR format
            let qr_str = std::ffi::CStr::from_ptr(qr.as_ptr() as *const i8);
            let qr_string = qr_str.to_str().unwrap();
            assert_eq!(qr_string.len(), 64); // 32 bytes = 64 hex chars
            assert!(qr_string.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_safety_number_symmetric() {
        use veritas_identity::IdentityKeyPair;

        let alice = IdentityKeyPair::generate();
        let bob = IdentityKeyPair::generate();

        let alice_bytes = alice.public_keys().to_bytes();
        let bob_bytes = bob.public_keys().to_bytes();

        unsafe {
            // Compute Alice-Bob
            let mut raw1 = [0u8; 32];
            veritas_safety_number_compute(
                alice_bytes.as_ptr(),
                alice_bytes.len(),
                bob_bytes.as_ptr(),
                bob_bytes.len(),
                raw1.as_mut_ptr(),
                raw1.len(),
            );

            // Compute Bob-Alice (reversed)
            let mut raw2 = [0u8; 32];
            veritas_safety_number_compute(
                bob_bytes.as_ptr(),
                bob_bytes.len(),
                alice_bytes.as_ptr(),
                alice_bytes.len(),
                raw2.as_mut_ptr(),
                raw2.len(),
            );

            // Should be identical
            assert_eq!(raw1, raw2);
        }
    }

    #[test]
    fn test_buffer_too_small_errors() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            let password = b"test_password";
            veritas_client_unlock(handle, password.as_ptr(), password.len());

            // Create identity
            let mut hash_buf = [0u8; 65];
            veritas_create_identity(
                handle,
                std::ptr::null(),
                hash_buf.as_mut_ptr(),
                hash_buf.len(),
            );

            // Try to get hash with too small buffer
            let mut small_buf = [0u8; 10];
            let result = veritas_identity_hash(handle, small_buf.as_mut_ptr(), small_buf.len());
            assert_eq!(result, ErrorCode::BufferTooSmall); // FFI-FIX-4: BufferTooSmall has its own error code

            veritas_client_free(handle);
        }
    }

    #[test]
    fn test_null_pointer_checks() {
        unsafe {
            // All functions should check for null pointers
            assert_eq!(
                veritas_client_unlock(std::ptr::null_mut(), std::ptr::null(), 0),
                ErrorCode::NullPointer
            );

            assert_eq!(
                veritas_identity_hash(std::ptr::null_mut(), std::ptr::null_mut(), 0),
                ErrorCode::NullPointer
            );

            assert_eq!(
                veritas_create_identity(
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null_mut(),
                    0
                ),
                ErrorCode::NullPointer
            );

            assert_eq!(
                veritas_identity_slots(
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut()
                ),
                ErrorCode::NullPointer
            );
        }
    }

    #[test]
    fn test_client_shutdown() {
        unsafe {
            let handle = veritas_client_create(std::ptr::null());
            let password = b"test_password";
            veritas_client_unlock(handle, password.as_ptr(), password.len());

            // Shutdown
            let result = veritas_client_shutdown(handle);
            assert_eq!(result, ErrorCode::Success);

            // Can still free after shutdown
            veritas_client_free(handle);
        }
    }
}
