//! Safety number verification for Python bindings.

use pyo3::prelude::*;
use veritas_core::SafetyNumber as CoreSafetyNumber;
use veritas_identity::IdentityPublicKeys;

use crate::error::VeritasError;

/// A safety number for verifying secure communication between two parties.
///
/// Safety numbers allow users to verify they are communicating with the
/// correct party by comparing these values out-of-band (in person, phone call,
/// or QR code scan).
///
/// Both parties compute the same safety number from their combined public keys.
/// If the safety numbers match, users can be confident they have the correct keys
/// and are protected against man-in-the-middle attacks.
#[pyclass]
#[derive(Clone)]
pub struct SafetyNumber {
    inner: CoreSafetyNumber,
}

impl SafetyNumber {
    /// Create from a core SafetyNumber.
    pub fn from_core(inner: CoreSafetyNumber) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl SafetyNumber {
    /// Compute a safety number from two identities' public keys.
    ///
    /// The computation is symmetric: swapping the arguments produces
    /// the same result. This ensures both parties compute identical
    /// safety numbers.
    ///
    /// Args:
    ///     our_keys: Our identity's public keys (bytes).
    ///     their_keys: The other party's public keys (bytes).
    ///
    /// Returns:
    ///     SafetyNumber: A safety number that both parties can compare.
    ///
    /// Raises:
    ///     VeritasError: If the keys are invalid.
    ///
    /// Example:
    ///     >>> alice_keys = client1.public_keys()
    ///     >>> bob_keys = client2.public_keys()
    ///     >>> safety = SafetyNumber.compute(alice_keys, bob_keys)
    ///     >>> print(safety)  # Display for verbal comparison
    #[staticmethod]
    fn compute(our_keys: &[u8], their_keys: &[u8]) -> PyResult<Self> {
        let our = IdentityPublicKeys::from_bytes(our_keys)
            .map_err(|e: veritas_identity::IdentityError| VeritasError::new_err(e.into()))?;
        let their = IdentityPublicKeys::from_bytes(their_keys)
            .map_err(|e: veritas_identity::IdentityError| VeritasError::new_err(e.into()))?;

        let inner = CoreSafetyNumber::compute(&our, &their);
        Ok(Self { inner })
    }

    /// Format the safety number as a 60-digit numeric string.
    ///
    /// The output is formatted as 12 groups of 5 digits, separated by spaces.
    /// This format is ideal for verbal comparison between users.
    ///
    /// Returns:
    ///     str: 60 digits in format "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX"
    ///
    /// Example:
    ///     >>> numeric = safety.to_numeric_string()
    ///     >>> print(f"Verify these digits: {numeric}")
    fn to_numeric_string(&self) -> String {
        self.inner.to_numeric_string()
    }

    /// Format the safety number as a hex string for QR codes.
    ///
    /// Returns a 64-character lowercase hex string representing
    /// all 32 bytes. This format is ideal for QR code generation
    /// and automated verification.
    ///
    /// Returns:
    ///     str: 64-character hex string.
    ///
    /// Example:
    ///     >>> qr_data = safety.to_qr_string()
    ///     >>> # Generate QR code with qr_data
    fn to_qr_string(&self) -> String {
        self.inner.to_qr_string()
    }

    /// Get the raw bytes of the safety number.
    ///
    /// Returns:
    ///     bytes: The 32-byte safety number value.
    fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    fn __str__(&self) -> String {
        self.inner.to_numeric_string()
    }

    fn __repr__(&self) -> String {
        format!("SafetyNumber({}...)", &self.inner.to_qr_string()[..16])
    }

    fn __eq__(&self, other: &Self) -> bool {
        self.inner == other.inner
    }

    /// PY-FIX-2: Implement __hash__ so SafetyNumber can be used in sets and as dict keys.
    /// Required because defining __eq__ without __hash__ makes the type unhashable in Python.
    fn __hash__(&self) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.inner.as_bytes().hash(&mut hasher);
        hasher.finish()
    }
}
