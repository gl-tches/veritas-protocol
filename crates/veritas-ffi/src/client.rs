//! Client lifecycle FFI functions.

use std::ffi::CStr;
use std::path::PathBuf;

use veritas_core::{ClientConfig, VeritasClient};

use crate::error::FfiError;
use crate::types::{ClientHandle, VeritasHandle};
use crate::ErrorCode;

// ============================================================================
// Client Creation
// ============================================================================

/// Create a new VERITAS client.
///
/// # Arguments
///
/// * `config_path` - Optional path to data directory. Pass NULL for in-memory client.
///
/// # Returns
///
/// A handle to the client on success, or NULL on failure.
///
/// # Safety
///
/// - If `config_path` is not NULL, it must be a valid null-terminated C string.
/// - The returned handle must be freed with `veritas_client_free`.
///
/// # Example
///
/// ```c
/// // Create in-memory client
/// VeritasHandle* client = veritas_client_create(NULL);
///
/// // Create persistent client
/// VeritasHandle* client = veritas_client_create("/path/to/data");
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_client_create(config_path: *const libc::c_char) -> *mut VeritasHandle {
    // Catch panics at FFI boundary
    let result = std::panic::catch_unwind(|| {
        create_client_impl(config_path)
    });

    match result {
        Ok(handle) => handle,
        Err(_) => std::ptr::null_mut(),
    }
}

unsafe fn create_client_impl(config_path: *const libc::c_char) -> *mut VeritasHandle {
    // Create runtime for async operations
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return std::ptr::null_mut(),
    };

    // Parse config path
    let config = if config_path.is_null() {
        ClientConfig::in_memory()
    } else {
        match CStr::from_ptr(config_path).to_str() {
            Ok(path_str) => ClientConfig::builder()
                .with_data_dir(PathBuf::from(path_str))
                .build(),
            Err(_) => return std::ptr::null_mut(),
        }
    };

    // Create client
    let client = match runtime.block_on(VeritasClient::new(config)) {
        Ok(c) => c,
        Err(_) => return std::ptr::null_mut(),
    };

    ClientHandle::new(client)
}

// ============================================================================
// Client Unlock/Lock
// ============================================================================

/// Unlock the client with a password.
///
/// This initializes all services and prepares the client for operations.
///
/// # Arguments
///
/// * `handle` - Valid client handle
/// * `password` - Password bytes
/// * `password_len` - Length of password
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `veritas_client_create`.
/// - `password` must point to `password_len` valid bytes.
///
/// # Example
///
/// ```c
/// const char* password = "my_password";
/// int32_t result = veritas_client_unlock(client, password, strlen(password));
/// if (result != 0) {
///     // Handle error
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_client_unlock(
    handle: *mut VeritasHandle,
    password: *const u8,
    password_len: usize,
) -> ErrorCode {
    // Check null pointers first
    if handle.is_null() {
        return ErrorCode::NullPointer;
    }
    if password.is_null() && password_len > 0 {
        return ErrorCode::NullPointer;
    }

    // Catch panics
    let result = std::panic::catch_unwind(|| {
        unlock_impl(handle, password, password_len)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}

unsafe fn unlock_impl(
    handle: *mut VeritasHandle,
    password: *const u8,
    password_len: usize,
) -> ErrorCode {
    let client_handle = match ClientHandle::from_ptr(handle) {
        Some(h) => h,
        None => return ErrorCode::NullPointer,
    };

    // Get password slice
    let password_slice = if password_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(password, password_len)
    };

    // Create runtime for async operations
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ErrorCode::Unknown,
    };

    // Unlock
    match runtime.block_on(client_handle.client.unlock(password_slice)) {
        Ok(_) => ErrorCode::Success,
        Err(e) => FfiError::from(e).into(),
    }
}

/// Lock the client and zeroize sensitive data.
///
/// After locking, the client must be unlocked again before use.
///
/// # Arguments
///
/// * `handle` - Valid client handle
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `veritas_client_create`.
///
/// # Example
///
/// ```c
/// veritas_client_lock(client);
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_client_lock(handle: *mut VeritasHandle) -> ErrorCode {
    if handle.is_null() {
        return ErrorCode::NullPointer;
    }

    let result = std::panic::catch_unwind(|| {
        lock_impl(handle)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}

unsafe fn lock_impl(handle: *mut VeritasHandle) -> ErrorCode {
    let client_handle = match ClientHandle::from_ptr(handle) {
        Some(h) => h,
        None => return ErrorCode::NullPointer,
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ErrorCode::Unknown,
    };

    match runtime.block_on(client_handle.client.lock()) {
        Ok(_) => ErrorCode::Success,
        Err(e) => FfiError::from(e).into(),
    }
}

// ============================================================================
// Client Shutdown
// ============================================================================

/// Shutdown the client completely.
///
/// After shutdown, the client handle should not be used for any operations
/// except `veritas_client_free`.
///
/// # Arguments
///
/// * `handle` - Valid client handle
///
/// # Returns
///
/// ErrorCode::Success on success, or an error code on failure.
///
/// # Safety
///
/// - `handle` must be a valid handle from `veritas_client_create`.
///
/// # Example
///
/// ```c
/// veritas_client_shutdown(client);
/// veritas_client_free(client);
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_client_shutdown(handle: *mut VeritasHandle) -> ErrorCode {
    if handle.is_null() {
        return ErrorCode::NullPointer;
    }

    let result = std::panic::catch_unwind(|| {
        shutdown_impl(handle)
    });

    match result {
        Ok(code) => code,
        Err(_) => ErrorCode::Unknown,
    }
}

unsafe fn shutdown_impl(handle: *mut VeritasHandle) -> ErrorCode {
    let client_handle = match ClientHandle::from_ptr(handle) {
        Some(h) => h,
        None => return ErrorCode::NullPointer,
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(_) => return ErrorCode::Unknown,
    };

    match runtime.block_on(client_handle.client.shutdown()) {
        Ok(_) => ErrorCode::Success,
        Err(e) => FfiError::from(e).into(),
    }
}

// ============================================================================
// Client Free
// ============================================================================

/// Free a client handle and release all resources.
///
/// After calling this function, the handle must not be used.
///
/// # Arguments
///
/// * `handle` - Valid client handle, or NULL (no-op if NULL)
///
/// # Safety
///
/// - `handle` must be a valid handle from `veritas_client_create`, or NULL.
/// - `handle` must not be used after this function returns.
///
/// # Example
///
/// ```c
/// veritas_client_free(client);
/// client = NULL;
/// ```
#[no_mangle]
pub unsafe extern "C" fn veritas_client_free(handle: *mut VeritasHandle) {
    let _ = std::panic::catch_unwind(|| {
        ClientHandle::free(handle);
    });
}

// ============================================================================
// Version
// ============================================================================

/// Get the VERITAS library version string.
///
/// # Returns
///
/// A null-terminated static string containing the version.
/// This string must not be freed.
///
/// # Example
///
/// ```c
/// const char* version = veritas_version();
/// printf("VERITAS version: %s\n", version);
/// ```
#[no_mangle]
pub extern "C" fn veritas_version() -> *const libc::c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const libc::c_char
}
