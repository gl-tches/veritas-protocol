//! Safety number FFI functions.

use veritas_core::SafetyNumber;
use veritas_identity::IdentityPublicKeys;

use crate::error::FfiError;
use crate::ErrorCode;

// ============================================================================
// Safety Number Computation
// ============================================================================

/// Compute a safety number from two sets of public keys.
///
/// The computation is symmetric: swapping the key sets produces the same result.
///
/// # Arguments
///
/// * `our_keys` - Our identity's public key bytes (must be valid serialized IdentityPublicKeys)
/// * `our_len` - Length of our_keys in bytes
/// * `their_keys` - Their identity's public key bytes (must be valid serialized IdentityPublicKeys)
/// * `their_len` - Length of their_keys in bytes
/// * `out_buf` - Buffer to write raw safety number bytes (32 bytes)
/// * `out_len` - Size of output buffer (must be at least 32)
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `our_keys` must point to `our_len` valid bytes.
/// - `their_keys` must point to `their_len` valid bytes.
/// - `out_buf` must point to at least `out_len` writable bytes.
/// - `out_len` must be at least 32 bytes.
///
/// # Example
///
/// ```c
/// uint8_t safety_number[32];
/// int32_t result = veritas_safety_number_compute(
///     our_keys_bytes, our_keys_len,
///     their_keys_bytes, their_keys_len,
///     safety_number, sizeof(safety_number)
/// );
/// if (result == 0) {
///     // Use safety_number
/// }
/// ```
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veritas_safety_number_compute(
    our_keys: *const u8,
    our_len: usize,
    their_keys: *const u8,
    their_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode { unsafe {
    // Check null pointers
    if our_keys.is_null() || their_keys.is_null() || out_buf.is_null() {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        safety_number_compute_impl(our_keys, our_len, their_keys, their_len, out_buf, out_len)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}}

unsafe fn safety_number_compute_impl(
    our_keys: *const u8,
    our_len: usize,
    their_keys: *const u8,
    their_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode { unsafe {
    // Check buffer size
    if out_len < 32 {
        return FfiError::BufferTooSmall {
            needed: 32,
            actual: out_len,
        }
        .into();
    }

    // Get key slices
    let our_slice = std::slice::from_raw_parts(our_keys, our_len);
    let their_slice = std::slice::from_raw_parts(their_keys, their_len);

    // Deserialize keys
    let our_public = match IdentityPublicKeys::from_bytes(our_slice) {
        Ok(k) => k,
        Err(_) => {
            return FfiError::InvalidArgument("Failed to parse our_keys".to_string()).into()
        }
    };

    let their_public = match IdentityPublicKeys::from_bytes(their_slice) {
        Ok(k) => k,
        Err(_) => {
            return FfiError::InvalidArgument("Failed to parse their_keys".to_string()).into()
        }
    };

    // Compute safety number
    let safety = SafetyNumber::compute(&our_public, &their_public);

    // Copy raw bytes to output
    let bytes = safety.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, 32);

    ErrorCode::Success
}}

// ============================================================================
// Safety Number Formatting
// ============================================================================

/// Convert raw safety number bytes to numeric string format.
///
/// Produces a 60-digit string in 12 groups of 5 digits, separated by spaces.
/// Format: "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"
///
/// # Arguments
///
/// * `raw` - Raw safety number bytes (32 bytes)
/// * `raw_len` - Length of raw bytes (must be 32)
/// * `out_buf` - Buffer to write formatted string
/// * `out_len` - Size of output buffer (must be at least 72 for string + null)
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `raw` must point to exactly 32 bytes.
/// - `out_buf` must point to at least `out_len` writable bytes.
/// - `out_len` should be at least 72 bytes (71 chars + null terminator).
///
/// # Example
///
/// ```c
/// uint8_t raw[32];
/// // ... compute raw safety number ...
///
/// char numeric[72];
/// int32_t result = veritas_safety_number_to_numeric(raw, 32, numeric, sizeof(numeric));
/// if (result == 0) {
///     printf("Safety Number: %s\n", numeric);
/// }
/// ```
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veritas_safety_number_to_numeric(
    raw: *const u8,
    raw_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode { unsafe {
    // Check null pointers
    if raw.is_null() || out_buf.is_null() {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        safety_number_to_numeric_impl(raw, raw_len, out_buf, out_len)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}}

unsafe fn safety_number_to_numeric_impl(
    raw: *const u8,
    raw_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode { unsafe {
    // Verify raw length
    if raw_len != 32 {
        return FfiError::InvalidArgument(format!(
            "Expected 32 bytes for safety number, got {}",
            raw_len
        ))
        .into();
    }

    // Check buffer size (71 chars + null terminator)
    let needed = 72;
    if out_len < needed {
        return FfiError::BufferTooSmall {
            needed,
            actual: out_len,
        }
        .into();
    }

    // Copy raw bytes to array
    let mut bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(raw, bytes.as_mut_ptr(), 32);

    // Create SafetyNumber from bytes
    // We need to use a hacky way since SafetyNumber doesn't expose from_bytes
    // For FFI purposes, we'll compute the numeric string directly
    let numeric_string = format_safety_number_numeric(&bytes);

    // Copy to output buffer
    let str_bytes = numeric_string.as_bytes();
    std::ptr::copy_nonoverlapping(str_bytes.as_ptr(), out_buf, str_bytes.len());
    *out_buf.add(str_bytes.len()) = 0; // Null terminator

    ErrorCode::Success
}}

/// Format safety number bytes as numeric string.
///
/// This replicates the logic from SafetyNumber::to_numeric_string().
fn format_safety_number_numeric(bytes: &[u8; 32]) -> String {
    // Convert first 30 bytes to 60 digits (each byte -> 2 digits via byte % 100)
    let mut all_digits = String::with_capacity(60);
    for &byte in bytes.iter().take(30) {
        let two_digits = byte % 100;
        all_digits.push_str(&format!("{:02}", two_digits));
    }

    // Format into 12 groups of 5 digits separated by spaces
    let mut result = String::with_capacity(71);
    for (i, chunk) in all_digits.as_bytes().chunks(5).enumerate() {
        if i > 0 {
            result.push(' ');
        }
        result.push_str(std::str::from_utf8(chunk).unwrap());
    }

    result
}

/// Convert raw safety number bytes to QR/hex string format.
///
/// Produces a 64-character lowercase hex string.
///
/// # Arguments
///
/// * `raw` - Raw safety number bytes (32 bytes)
/// * `raw_len` - Length of raw bytes (must be 32)
/// * `out_buf` - Buffer to write hex string
/// * `out_len` - Size of output buffer (must be at least 65 for string + null)
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `raw` must point to exactly 32 bytes.
/// - `out_buf` must point to at least `out_len` writable bytes.
/// - `out_len` should be at least 65 bytes (64 hex chars + null terminator).
///
/// # Example
///
/// ```c
/// uint8_t raw[32];
/// // ... compute raw safety number ...
///
/// char qr[65];
/// int32_t result = veritas_safety_number_to_qr(raw, 32, qr, sizeof(qr));
/// if (result == 0) {
///     printf("QR Data: %s\n", qr);
/// }
/// ```
#[unsafe(no_mangle)]
pub unsafe extern "C" fn veritas_safety_number_to_qr(
    raw: *const u8,
    raw_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode { unsafe {
    // Check null pointers
    if raw.is_null() || out_buf.is_null() {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        safety_number_to_qr_impl(raw, raw_len, out_buf, out_len)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}}

unsafe fn safety_number_to_qr_impl(
    raw: *const u8,
    raw_len: usize,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode { unsafe {
    // Verify raw length
    if raw_len != 32 {
        return FfiError::InvalidArgument(format!(
            "Expected 32 bytes for safety number, got {}",
            raw_len
        ))
        .into();
    }

    // Check buffer size (64 hex chars + null terminator)
    let needed = 65;
    if out_len < needed {
        return FfiError::BufferTooSmall {
            needed,
            actual: out_len,
        }
        .into();
    }

    // Convert to hex
    let raw_slice = std::slice::from_raw_parts(raw, 32);
    let mut hex = String::with_capacity(64);
    for byte in raw_slice {
        hex.push_str(&format!("{:02x}", byte));
    }

    // Copy to output buffer
    let hex_bytes = hex.as_bytes();
    std::ptr::copy_nonoverlapping(hex_bytes.as_ptr(), out_buf, hex_bytes.len());
    *out_buf.add(hex_bytes.len()) = 0; // Null terminator

    ErrorCode::Success
}}
