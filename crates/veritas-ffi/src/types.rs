//! FFI-safe types and structures.

use std::sync::Arc;

use veritas_core::VeritasClient;

// ============================================================================
// Opaque Handle
// ============================================================================

/// Opaque handle to a VeritasClient instance.
///
/// This handle is passed to all FFI functions that operate on the client.
/// It must be created with `veritas_client_create` and freed with `veritas_client_free`.
///
/// # Safety
///
/// The handle is opaque and should only be manipulated through the provided
/// FFI functions. Do not attempt to dereference or interpret the pointer value.
#[repr(C)]
pub struct VeritasHandle {
    _private: [u8; 0],
}

/// Internal representation of the client handle.
///
/// This wraps the Arc<VeritasClient> and a shared tokio Runtime in a Box
/// so we can pass it across the FFI boundary safely. The runtime is created
/// once at client creation time and reused for all subsequent FFI calls,
/// avoiding the overhead of spawning a new thread pool per call.
pub(crate) struct ClientHandle {
    pub(crate) client: Arc<VeritasClient>,
    pub(crate) runtime: tokio::runtime::Runtime,
}

impl ClientHandle {
    /// Create a new handle from a client and its associated tokio runtime.
    ///
    /// The runtime is stored alongside the client so that all FFI calls
    /// can reuse the same thread pool instead of creating a new one each time.
    #[allow(clippy::new_ret_no_self)]
    pub(crate) fn new(
        client: VeritasClient,
        runtime: tokio::runtime::Runtime,
    ) -> *mut VeritasHandle {
        let handle = Box::new(ClientHandle {
            client: Arc::new(client),
            runtime,
        });
        Box::into_raw(handle) as *mut VeritasHandle
    }

    /// Convert a raw pointer back to a shared reference.
    ///
    /// Returns `&ClientHandle` (not `&mut`) to allow safe concurrent access
    /// from multiple FFI calls. The `VeritasClient` inside uses interior
    /// mutability (Arc<RwLock<...>>) and `Runtime::block_on` takes `&self`,
    /// so a shared reference is sufficient for all operations.
    ///
    /// # Safety
    ///
    /// The pointer must be a valid handle created by `new()` and not yet freed.
    pub(crate) unsafe fn from_ptr<'a>(ptr: *mut VeritasHandle) -> Option<&'a ClientHandle> {
        unsafe {
            if ptr.is_null() {
                None
            } else {
                Some(&*(ptr as *mut ClientHandle))
            }
        }
    }

    /// Consume the handle and free memory.
    ///
    /// # Safety
    ///
    /// The pointer must be a valid handle created by `new()` and not yet freed.
    pub(crate) unsafe fn free(ptr: *mut VeritasHandle) {
        unsafe {
            if !ptr.is_null() {
                let _ = Box::from_raw(ptr as *mut ClientHandle);
            }
        }
    }
}

// ============================================================================
// Identity Slot Info
// ============================================================================

/// Information about identity slot usage.
///
/// Each device origin is limited to a maximum number of identities.
/// This structure provides information about current usage.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IdentitySlots {
    /// Number of identity slots currently in use.
    pub used: u32,

    /// Maximum number of identity slots allowed.
    pub max: u32,

    /// Number of available slots (max - used).
    pub available: u32,
}

impl IdentitySlots {
    /// Create from IdentitySlotInfo.
    pub(crate) fn from_slot_info(info: &veritas_identity::IdentitySlotInfo) -> Self {
        Self {
            used: info.used,
            max: info.max,
            available: info.available,
        }
    }
}
