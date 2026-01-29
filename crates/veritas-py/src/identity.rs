//! Identity-related types for Python bindings.

use pyo3::prelude::*;
use veritas_core::IdentityInfo as CoreIdentityInfo;
use veritas_identity::IdentitySlotInfo as CoreIdentitySlotInfo;

/// Information about an identity.
///
/// Attributes:
///     hash (str): The identity hash in hex format.
///     label (str | None): User-friendly label for this identity.
///     is_primary (bool): Whether this is the primary identity.
///     created_at (int): Unix timestamp when the identity was created.
///     is_usable (bool): Whether this identity can be used for operations.
///     is_expiring (bool): Whether this identity is in the expiring warning period.
///     key_state (str): Current state of the identity keys.
#[pyclass]
#[derive(Clone)]
pub struct IdentityInfo {
    #[pyo3(get)]
    pub hash: String,
    #[pyo3(get)]
    pub label: Option<String>,
    #[pyo3(get)]
    pub is_primary: bool,
    #[pyo3(get)]
    pub created_at: u64,
    #[pyo3(get)]
    pub is_usable: bool,
    #[pyo3(get)]
    pub is_expiring: bool,
    #[pyo3(get)]
    pub key_state: String,
}

impl From<CoreIdentityInfo> for IdentityInfo {
    fn from(info: CoreIdentityInfo) -> Self {
        let is_usable = info.is_usable();
        let is_expiring = info.is_expiring();
        let key_state = format!("{:?}", info.key_state());

        Self {
            hash: info.hash.to_hex(),
            label: info.label,
            is_primary: info.is_primary,
            created_at: info.created_at,
            is_usable,
            is_expiring,
            key_state,
        }
    }
}

#[pymethods]
impl IdentityInfo {
    fn __repr__(&self) -> String {
        format!(
            "IdentityInfo(hash='{}', label={:?}, is_primary={}, created_at={})",
            &self.hash[..16],
            self.label,
            self.is_primary,
            self.created_at
        )
    }
}

/// Information about identity slot usage.
///
/// Each device origin is limited to 3 identities. This provides information
/// about how many slots are used and when the next slot will become available.
///
/// Attributes:
///     used (int): Number of slots currently in use.
///     max (int): Maximum allowed slots per origin (always 3).
///     available (int): Number of slots available for new identities.
///     next_slot_available (int | None): Unix timestamp when the next slot
///         will become available, or None if slots are available.
#[pyclass]
#[derive(Clone)]
pub struct IdentitySlots {
    #[pyo3(get)]
    pub used: u32,
    #[pyo3(get)]
    pub max: u32,
    #[pyo3(get)]
    pub available: u32,
    #[pyo3(get)]
    pub next_slot_available: Option<u64>,
}

impl From<CoreIdentitySlotInfo> for IdentitySlots {
    fn from(info: CoreIdentitySlotInfo) -> Self {
        Self {
            used: info.used,
            max: info.max,
            available: info.available,
            next_slot_available: info.next_slot_available,
        }
    }
}

#[pymethods]
impl IdentitySlots {
    /// Check if a new identity can be created.
    ///
    /// Returns:
    ///     bool: True if a slot is available for a new identity.
    fn can_create(&self) -> bool {
        self.available > 0
    }

    fn __repr__(&self) -> String {
        format!(
            "IdentitySlots(used={}, max={}, available={})",
            self.used, self.max, self.available
        )
    }
}
