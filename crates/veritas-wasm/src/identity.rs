//! Identity types for WASM bindings.

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use veritas_identity::{IdentityHash, IdentitySlotInfo, KeyLifecycle, KeyState};

/// Information about an identity for JavaScript usage.
#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct WasmIdentityInfo {
    hash: String,
    label: Option<String>,
    created_at: u64,
    last_active: u64,
    state: String,
    days_until_expiry: Option<u32>,
}

#[wasm_bindgen]
impl WasmIdentityInfo {
    /// Get the identity hash as hex string.
    #[wasm_bindgen(getter)]
    pub fn hash(&self) -> String {
        self.hash.clone()
    }

    /// Get the optional label.
    #[wasm_bindgen(getter)]
    pub fn label(&self) -> Option<String> {
        self.label.clone()
    }

    /// Get the creation timestamp.
    #[wasm_bindgen(getter, js_name = createdAt)]
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get the last active timestamp.
    #[wasm_bindgen(getter, js_name = lastActive)]
    pub fn last_active(&self) -> u64 {
        self.last_active
    }

    /// Get the current state.
    #[wasm_bindgen(getter)]
    pub fn state(&self) -> String {
        self.state.clone()
    }

    /// Get days until expiry.
    #[wasm_bindgen(getter, js_name = daysUntilExpiry)]
    pub fn days_until_expiry(&self) -> Option<u32> {
        self.days_until_expiry
    }
}

impl WasmIdentityInfo {
    /// Convert from internal types.
    pub fn from_internal(
        hash: &IdentityHash,
        label: Option<String>,
        lifecycle: &KeyLifecycle,
        current_time: u64,
    ) -> Self {
        let state_str = match &lifecycle.state {
            KeyState::Active => "Active",
            KeyState::Expiring => "Expiring",
            KeyState::Expired => "Expired",
            KeyState::Rotated { .. } => "Rotated",
            KeyState::Revoked => "Revoked",
        };

        let days_until_expiry = if matches!(lifecycle.state, KeyState::Active | KeyState::Expiring)
        {
            let expiry_time = lifecycle.created_at + veritas_identity::KEY_EXPIRY_SECS;
            if current_time < expiry_time {
                let seconds_remaining = expiry_time - current_time;
                Some((seconds_remaining / (24 * 60 * 60)) as u32)
            } else {
                Some(0)
            }
        } else {
            None
        };

        Self {
            hash: hash.to_hex(),
            label,
            created_at: lifecycle.created_at,
            last_active: lifecycle.last_active,
            state: state_str.to_string(),
            days_until_expiry,
        }
    }
}

/// Identity slot information wrapper for WASM.
#[derive(Serialize, Deserialize, Clone)]
#[wasm_bindgen]
pub struct WasmIdentitySlotInfo {
    used: u32,
    max: u32,
    available: u32,
    next_slot_available: Option<u64>,
}

#[wasm_bindgen]
impl WasmIdentitySlotInfo {
    /// Get the number of slots currently in use.
    #[wasm_bindgen(getter)]
    pub fn used(&self) -> u32 {
        self.used
    }

    /// Get the maximum allowed slots.
    #[wasm_bindgen(getter)]
    pub fn max(&self) -> u32 {
        self.max
    }

    /// Get the number of slots available.
    #[wasm_bindgen(getter)]
    pub fn available(&self) -> u32 {
        self.available
    }

    /// Get the Unix timestamp when next slot becomes available (if at limit).
    #[wasm_bindgen(getter, js_name = nextSlotAvailable)]
    pub fn next_slot_available(&self) -> Option<u64> {
        self.next_slot_available
    }

    /// Check if a new identity can be created.
    #[wasm_bindgen(js_name = canCreate)]
    pub fn can_create(&self) -> bool {
        self.available > 0
    }
}

impl From<IdentitySlotInfo> for WasmIdentitySlotInfo {
    fn from(info: IdentitySlotInfo) -> Self {
        Self {
            used: info.used,
            max: info.max,
            available: info.available,
            next_slot_available: info.next_slot_available,
        }
    }
}
