//! Identity management FFI functions.

use std::ffi::CStr;

use crate::error::FfiError;
use crate::types::{ClientHandle, IdentitySlots, VeritasHandle};
use crate::ErrorCode;

// ============================================================================
// Identity Hash
// ============================================================================

/// Get the primary identity hash as a hex string.
///
/// # Arguments
///
/// * `handle` - Valid unlocked client handle
/// * `out_buf` - Buffer to write hex string (must be at least 65 bytes for hash + null)
/// * `out_len` - Size of output buffer in bytes
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid unlocked client handle.
/// - `out_buf` must point to at least `out_len` writable bytes.
/// - `out_len` should be at least 65 bytes (64 hex chars + null terminator).
///
/// # Example
///
/// ```c
/// char hash[65];
/// int32_t result = veritas_identity_hash(client, hash, sizeof(hash));
/// if (result == 0) {
///     printf("Identity: %s\n", hash);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_identity_hash(
    handle: *mut VeritasHandle,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode {
    // Check null pointers
    if handle.is_null() {
        return ErrorCode::NullPointer;
    }
    if out_buf.is_null() {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        identity_hash_impl(handle, out_buf, out_len)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}

unsafe fn identity_hash_impl(
    handle: *mut VeritasHandle,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode {
    let client_handle = match ClientHandle::from_ptr(handle) {
        Some(h) => h,
        None => return ErrorCode::NullPointer,
    };

    // Create runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ErrorCode::Unknown,
    };

    // Get identity hash
    let hash = match runtime.block_on(client_handle.client.identity_hash()) {
        Ok(h) => h,
        Err(e) => return FfiError::from(e).into(),
    };

    // Convert to hex string
    let hex_string = hash.to_string();
    let needed = hex_string.len() + 1; // +1 for null terminator

    if out_len < needed {
        return FfiError::BufferTooSmall {
            needed,
            actual: out_len,
        }
        .into();
    }

    // Copy to output buffer
    let bytes = hex_string.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    *out_buf.add(bytes.len()) = 0; // Null terminator

    ErrorCode::Success
}

// ============================================================================
// Create Identity
// ============================================================================

/// Create a new identity.
///
/// # Arguments
///
/// * `handle` - Valid unlocked client handle
/// * `label` - Optional human-readable label (NULL for no label)
/// * `out_buf` - Buffer to write identity hash hex string
/// * `out_len` - Size of output buffer in bytes
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid unlocked client handle.
/// - `label`, if not NULL, must be a valid null-terminated C string.
/// - `out_buf` must point to at least `out_len` writable bytes.
/// - `out_len` should be at least 65 bytes.
///
/// # Example
///
/// ```c
/// char hash[65];
/// int32_t result = veritas_create_identity(client, "Personal", hash, sizeof(hash));
/// if (result == 0) {
///     printf("Created identity: %s\n", hash);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_create_identity(
    handle: *mut VeritasHandle,
    label: *const libc::c_char,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode {
    // Check null pointers
    if handle.is_null() {
        return ErrorCode::NullPointer;
    }
    if out_buf.is_null() {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        create_identity_impl(handle, label, out_buf, out_len)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}

unsafe fn create_identity_impl(
    handle: *mut VeritasHandle,
    label: *const libc::c_char,
    out_buf: *mut u8,
    out_len: usize,
) -> ErrorCode {
    let client_handle = match ClientHandle::from_ptr(handle) {
        Some(h) => h,
        None => return ErrorCode::NullPointer,
    };

    // Parse label
    let label_str = if label.is_null() {
        None
    } else {
        match CStr::from_ptr(label).to_str() {
            Ok(s) => Some(s),
            Err(_) => return FfiError::InvalidUtf8.into(),
        }
    };

    // Create runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ErrorCode::Unknown,
    };

    // Create identity
    let hash = match runtime.block_on(client_handle.client.create_identity(label_str)) {
        Ok(h) => h,
        Err(e) => return FfiError::from(e).into(),
    };

    // Convert to hex string
    let hex_string = hash.to_string();
    let needed = hex_string.len() + 1;

    if out_len < needed {
        return FfiError::BufferTooSmall {
            needed,
            actual: out_len,
        }
        .into();
    }

    // Copy to output buffer
    let bytes = hex_string.as_bytes();
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
    *out_buf.add(bytes.len()) = 0;

    ErrorCode::Success
}

// ============================================================================
// Identity Slots
// ============================================================================

/// Get information about identity slot usage.
///
/// # Arguments
///
/// * `handle` - Valid unlocked client handle
/// * `out_used` - Pointer to write number of used slots
/// * `out_max` - Pointer to write maximum number of slots
/// * `out_available` - Pointer to write number of available slots
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid unlocked client handle.
/// - `out_used`, `out_max`, and `out_available` must be valid pointers.
///
/// # Example
///
/// ```c
/// uint32_t used, max, available;
/// int32_t result = veritas_identity_slots(client, &used, &max, &available);
/// if (result == 0) {
///     printf("Identity slots: %u/%u (%u available)\n", used, max, available);
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_identity_slots(
    handle: *mut VeritasHandle,
    out_used: *mut u32,
    out_max: *mut u32,
    out_available: *mut u32,
) -> ErrorCode {
    // Check null pointers
    if handle.is_null() {
        return ErrorCode::NullPointer;
    }
    if out_used.is_null() || out_max.is_null() || out_available.is_null() {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        identity_slots_impl(handle, out_used, out_max, out_available)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}

unsafe fn identity_slots_impl(
    handle: *mut VeritasHandle,
    out_used: *mut u32,
    out_max: *mut u32,
    out_available: *mut u32,
) -> ErrorCode {
    let client_handle = match ClientHandle::from_ptr(handle) {
        Some(h) => h,
        None => return ErrorCode::NullPointer,
    };

    // Create runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ErrorCode::Unknown,
    };

    // Get slot info
    let info = match runtime.block_on(client_handle.client.identity_slots()) {
        Ok(i) => i,
        Err(e) => return FfiError::from(e).into(),
    };

    let slots = IdentitySlots::from_slot_info(&info);

    // Write outputs
    *out_used = slots.used;
    *out_max = slots.max;
    *out_available = slots.available;

    ErrorCode::Success
}
