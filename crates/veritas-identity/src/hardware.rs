//! Hardware attestation for origin fingerprinting.
//!
//! This module provides hardware-bound identity verification to prevent
//! Sybil attacks via unlimited identity creation. Production use requires
//! cryptographic proof from platform-specific secure hardware.
//!
//! # Security
//!
//! The `HardwareAttestation` system ensures that:
//! - Each physical device can only create a limited number of identities
//! - Origin fingerprints cannot be forged without access to secure hardware
//! - Attestations can be cryptographically verified
//!
//! # Platform Support
//!
//! - **Linux/Windows**: TPM 2.0 attestation
//! - **macOS/iOS**: Secure Enclave attestation
//! - **Android**: Hardware-backed Keystore attestation
//!
//! # Example
//!
//! ```ignore
//! use veritas_identity::hardware::{HardwareAttestation, AttestationPlatform};
//!
//! // Collect hardware attestation (platform-specific)
//! let attestation = HardwareAttestation::collect()?;
//!
//! // Verify the attestation is valid
//! attestation.verify()?;
//!
//! // Create a hardware-bound origin fingerprint
//! let origin = OriginFingerprint::from_hardware(&attestation)?;
//! ```

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{IdentityError, Result};

/// Maximum age of an attestation before it's considered stale (5 minutes).
pub const ATTESTATION_MAX_AGE_SECS: u64 = 300;

/// Minimum length for hardware identifier data.
pub const MIN_HARDWARE_ID_LEN: usize = 16;

/// Maximum length for hardware identifier data.
pub const MAX_HARDWARE_ID_LEN: usize = 256;

/// Maximum length for attestation signature.
pub const MAX_ATTESTATION_SIGNATURE_LEN: usize = 512;

/// Platform types for hardware attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AttestationPlatform {
    /// TPM 2.0 attestation (Linux, Windows).
    Tpm2,
    /// Apple Secure Enclave (macOS, iOS).
    SecureEnclave,
    /// Android Hardware-backed Keystore.
    AndroidKeystore,
    /// Generic hardware binding (fallback, lower trust).
    GenericHardware,
}

impl AttestationPlatform {
    /// Returns whether this platform provides strong hardware binding.
    ///
    /// Strong binding means the attestation is backed by dedicated secure
    /// hardware that cannot be easily spoofed or virtualized.
    pub fn is_strong_binding(&self) -> bool {
        matches!(
            self,
            AttestationPlatform::Tpm2
                | AttestationPlatform::SecureEnclave
                | AttestationPlatform::AndroidKeystore
        )
    }
}

/// Hardware attestation data for origin fingerprinting.
///
/// This struct contains platform-specific hardware identifiers and
/// cryptographic proof that the attestation came from secure hardware.
///
/// # Security Requirements
///
/// - `hardware_id`: Unique identifier from secure hardware (e.g., TPM EK, SE UID)
/// - `attestation_signature`: Cryptographic proof from the secure element
/// - `timestamp`: When the attestation was created (prevents replay)
/// - `nonce`: Random value to ensure freshness
#[derive(Clone, Serialize, Deserialize)]
pub struct HardwareAttestation {
    /// Platform type for this attestation.
    platform: AttestationPlatform,
    /// Hardware-specific unique identifier.
    /// For TPM: Endorsement Key certificate hash
    /// For Secure Enclave: Device UID
    /// For Android: Hardware-backed key attestation
    hardware_id: Vec<u8>,
    /// Optional enclave binding data (e.g., Secure Enclave attestation blob).
    enclave_binding: Option<Vec<u8>>,
    /// Cryptographic signature from the secure hardware.
    attestation_signature: Vec<u8>,
    /// Timestamp when attestation was created (Unix seconds).
    timestamp: u64,
    /// Random nonce to ensure attestation freshness.
    nonce: [u8; 32],
}

impl HardwareAttestation {
    /// Collect hardware attestation from the current platform.
    ///
    /// This function detects the available secure hardware and collects
    /// a cryptographic attestation proving device identity.
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::HardwareNotAvailable` if no supported
    /// secure hardware is detected on the current platform.
    ///
    /// Returns `IdentityError::HardwareAttestationFailed` if attestation
    /// collection fails (e.g., TPM locked, permission denied).
    #[cfg(not(test))]
    pub fn collect() -> Result<Self> {
        // Detect platform and collect attestation
        #[cfg(target_os = "macos")]
        {
            Self::collect_secure_enclave()
        }

        #[cfg(target_os = "ios")]
        {
            Self::collect_secure_enclave()
        }

        #[cfg(target_os = "android")]
        {
            Self::collect_android_keystore()
        }

        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            Self::_collect_tpm2()
        }

        #[cfg(not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "android",
            target_os = "linux",
            target_os = "windows"
        )))]
        {
            Err(IdentityError::HardwareNotAvailable {
                reason: "unsupported platform".into(),
            })
        }
    }

    /// Create a test attestation (only available in tests).
    ///
    /// # Security Warning
    ///
    /// This function creates attestations that are NOT hardware-bound
    /// and should NEVER be used in production code.
    #[cfg(test)]
    pub fn test_attestation() -> Self {
        use rand::rngs::OsRng;
        use rand::RngCore;

        let mut hardware_id = vec![0u8; 32];
        let mut nonce = [0u8; 32];
        let mut attestation_signature = vec![0u8; 64];

        OsRng.fill_bytes(&mut hardware_id);
        OsRng.fill_bytes(&mut nonce);
        OsRng.fill_bytes(&mut attestation_signature);

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            platform: AttestationPlatform::GenericHardware,
            hardware_id,
            enclave_binding: None,
            attestation_signature,
            timestamp,
            nonce,
        }
    }

    /// Collect attestation from Apple Secure Enclave.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn collect_secure_enclave() -> Result<Self> {
        use rand::rngs::OsRng;
        use rand::RngCore;

        // TODO: Implement actual Secure Enclave attestation via Security.framework
        // This requires:
        // 1. Generate a key pair in the Secure Enclave (kSecAttrTokenIDSecureEnclave)
        // 2. Request attestation for the key (SecKeyCreateAttestation)
        // 3. Extract the device UID from the attestation certificate chain
        //
        // For now, return an error indicating this needs implementation
        Err(IdentityError::HardwareAttestationFailed {
            reason: "Secure Enclave attestation not yet implemented".into(),
        })
    }

    /// Collect attestation from Android Hardware-backed Keystore.
    #[cfg(target_os = "android")]
    fn collect_android_keystore() -> Result<Self> {
        // TODO: Implement actual Android Keystore attestation via JNI
        // This requires:
        // 1. Generate a key in hardware-backed keystore with attestation
        // 2. Retrieve the attestation certificate chain
        // 3. Verify the chain roots to Google's attestation root
        //
        // For now, return an error indicating this needs implementation
        Err(IdentityError::HardwareAttestationFailed {
            reason: "Android Keystore attestation not yet implemented".into(),
        })
    }

    /// Collect attestation from TPM 2.0.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    fn _collect_tpm2() -> Result<Self> {
        // TODO: Implement actual TPM 2.0 attestation
        // This requires:
        // 1. Connect to TPM via TCTI/TBS
        // 2. Read the EK certificate
        // 3. Create an attestation key under the EK
        // 4. Generate a quote signed by the AK
        //
        // For now, return an error indicating this needs implementation
        Err(IdentityError::HardwareAttestationFailed {
            reason: "TPM 2.0 attestation not yet implemented".into(),
        })
    }

    /// Verify the hardware attestation is valid.
    ///
    /// This performs cryptographic verification that:
    /// 1. The attestation came from genuine secure hardware
    /// 2. The signature is valid for the claimed platform
    /// 3. The attestation is not stale (within MAX_AGE)
    /// 4. The data formats are valid
    ///
    /// # Errors
    ///
    /// Returns `IdentityError::HardwareAttestationFailed` if verification fails.
    pub fn verify(&self) -> Result<()> {
        // Validate hardware_id length
        if self.hardware_id.len() < MIN_HARDWARE_ID_LEN {
            return Err(IdentityError::HardwareAttestationFailed {
                reason: format!(
                    "hardware_id too short: {} < {}",
                    self.hardware_id.len(),
                    MIN_HARDWARE_ID_LEN
                ),
            });
        }

        if self.hardware_id.len() > MAX_HARDWARE_ID_LEN {
            return Err(IdentityError::HardwareAttestationFailed {
                reason: format!(
                    "hardware_id too long: {} > {}",
                    self.hardware_id.len(),
                    MAX_HARDWARE_ID_LEN
                ),
            });
        }

        // Validate attestation_signature length
        if self.attestation_signature.is_empty() {
            return Err(IdentityError::HardwareAttestationFailed {
                reason: "attestation_signature is empty".into(),
            });
        }

        if self.attestation_signature.len() > MAX_ATTESTATION_SIGNATURE_LEN {
            return Err(IdentityError::HardwareAttestationFailed {
                reason: format!(
                    "attestation_signature too long: {} > {}",
                    self.attestation_signature.len(),
                    MAX_ATTESTATION_SIGNATURE_LEN
                ),
            });
        }

        // Check timestamp freshness
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| IdentityError::HardwareAttestationFailed {
                reason: "system time error".into(),
            })?
            .as_secs();

        // Reject future timestamps (allow 5 seconds of clock skew)
        if self.timestamp > now + 5 {
            return Err(IdentityError::HardwareAttestationFailed {
                reason: "attestation timestamp is in the future".into(),
            });
        }

        // Reject stale attestations
        if now.saturating_sub(self.timestamp) > ATTESTATION_MAX_AGE_SECS {
            return Err(IdentityError::HardwareAttestationFailed {
                reason: format!(
                    "attestation is stale: {} seconds old",
                    now.saturating_sub(self.timestamp)
                ),
            });
        }

        // Platform-specific signature verification
        match self.platform {
            AttestationPlatform::Tpm2 => self.verify_tpm2_attestation(),
            AttestationPlatform::SecureEnclave => self.verify_secure_enclave_attestation(),
            AttestationPlatform::AndroidKeystore => self.verify_android_attestation(),
            AttestationPlatform::GenericHardware => {
                // Generic hardware provides weaker guarantees
                // In production, this should be rejected or require additional verification
                #[cfg(test)]
                {
                    Ok(())
                }
                #[cfg(not(test))]
                {
                    Err(IdentityError::HardwareAttestationFailed {
                        reason: "generic hardware attestation not allowed in production".into(),
                    })
                }
            }
        }
    }

    /// Verify TPM 2.0 attestation signature.
    fn verify_tpm2_attestation(&self) -> Result<()> {
        // TODO: Implement TPM attestation verification
        // 1. Parse the attestation structure (TPMS_ATTEST)
        // 2. Verify the signature against the AK public key
        // 3. Verify the AK certificate chains to a trusted TPM CA
        // 4. Check the nonce matches what we expected
        //
        // For now, verification is not implemented
        Err(IdentityError::HardwareAttestationFailed {
            reason: "TPM attestation verification not yet implemented".into(),
        })
    }

    /// Verify Apple Secure Enclave attestation.
    fn verify_secure_enclave_attestation(&self) -> Result<()> {
        // TODO: Implement Secure Enclave attestation verification
        // 1. Parse the attestation certificate chain
        // 2. Verify the chain roots to Apple's attestation CA
        // 3. Extract and verify the nonce from the attestation
        // 4. Verify the device UID matches the hardware_id
        //
        // For now, verification is not implemented
        Err(IdentityError::HardwareAttestationFailed {
            reason: "Secure Enclave attestation verification not yet implemented".into(),
        })
    }

    /// Verify Android Keystore attestation.
    fn verify_android_attestation(&self) -> Result<()> {
        // TODO: Implement Android attestation verification
        // 1. Parse the attestation certificate chain
        // 2. Verify the chain roots to Google's attestation root
        // 3. Check the attestation extension for security level
        // 4. Verify the nonce and other attestation properties
        //
        // For now, verification is not implemented
        Err(IdentityError::HardwareAttestationFailed {
            reason: "Android attestation verification not yet implemented".into(),
        })
    }

    /// Compute a deterministic fingerprint from the hardware attestation.
    ///
    /// This fingerprint is derived from the hardware identity and can be
    /// used to create an `OriginFingerprint` for identity limiting.
    ///
    /// The fingerprint is computed as:
    /// `BLAKE3(platform || hardware_id || enclave_binding?)`
    pub fn fingerprint(&self) -> HardwareFingerprint {
        let platform_bytes = [self.platform as u8];
        let empty: &[u8] = &[];

        let hash = Hash256::hash_many(&[
            &platform_bytes,
            &self.hardware_id,
            self.enclave_binding.as_deref().unwrap_or(empty),
        ]);

        HardwareFingerprint(hash)
    }

    /// Get the attestation platform.
    pub fn platform(&self) -> AttestationPlatform {
        self.platform
    }

    /// Get the attestation timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Check if this attestation provides strong hardware binding.
    pub fn is_strong_binding(&self) -> bool {
        self.platform.is_strong_binding()
    }
}

impl std::fmt::Debug for HardwareAttestation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HardwareAttestation")
            .field("platform", &self.platform)
            .field("hardware_id_len", &self.hardware_id.len())
            .field("has_enclave_binding", &self.enclave_binding.is_some())
            .field("timestamp", &self.timestamp)
            .field("nonce", &"[REDACTED]")
            .field("attestation_signature", &"[REDACTED]")
            .finish()
    }
}

/// A deterministic fingerprint derived from hardware attestation.
///
/// This is the intermediate value used to create an `OriginFingerprint`.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct HardwareFingerprint(Hash256);

impl HardwareFingerprint {
    /// Get the fingerprint as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    /// Format as hex string.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl std::fmt::Debug for HardwareFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HardwareFingerprint({}...)", &self.to_hex()[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_platform_strong_binding() {
        assert!(AttestationPlatform::Tpm2.is_strong_binding());
        assert!(AttestationPlatform::SecureEnclave.is_strong_binding());
        assert!(AttestationPlatform::AndroidKeystore.is_strong_binding());
        assert!(!AttestationPlatform::GenericHardware.is_strong_binding());
    }

    #[test]
    fn test_hardware_attestation_test_attestation() {
        let attestation = HardwareAttestation::test_attestation();
        assert_eq!(attestation.platform(), AttestationPlatform::GenericHardware);
        assert!(!attestation.is_strong_binding());
    }

    #[test]
    fn test_hardware_attestation_verify_test() {
        let attestation = HardwareAttestation::test_attestation();
        // Test attestations should pass verification in test mode
        assert!(attestation.verify().is_ok());
    }

    #[test]
    fn test_hardware_attestation_fingerprint_deterministic() {
        let attestation = HardwareAttestation::test_attestation();
        let fp1 = attestation.fingerprint();
        let fp2 = attestation.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_hardware_attestation_fingerprint_unique() {
        let attestation1 = HardwareAttestation::test_attestation();
        let attestation2 = HardwareAttestation::test_attestation();
        // Different test attestations should have different fingerprints
        // (they have random hardware_id)
        assert_ne!(attestation1.fingerprint(), attestation2.fingerprint());
    }

    #[test]
    fn test_hardware_fingerprint_debug_redacted() {
        let attestation = HardwareAttestation::test_attestation();
        let fp = attestation.fingerprint();
        let debug = format!("{:?}", fp);
        // Should show truncated hex, not full value
        assert!(debug.contains("..."));
        assert!(debug.len() < 100);
    }

    #[test]
    fn test_hardware_attestation_debug_redacted() {
        let attestation = HardwareAttestation::test_attestation();
        let debug = format!("{:?}", attestation);
        // Should not expose sensitive data
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&hex::encode(attestation.nonce)));
    }

    #[test]
    fn test_attestation_verify_hardware_id_too_short() {
        let mut attestation = HardwareAttestation::test_attestation();
        attestation.hardware_id = vec![0u8; MIN_HARDWARE_ID_LEN - 1];
        let result = attestation.verify();
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(IdentityError::HardwareAttestationFailed { .. })
        ));
    }

    #[test]
    fn test_attestation_verify_hardware_id_too_long() {
        let mut attestation = HardwareAttestation::test_attestation();
        attestation.hardware_id = vec![0u8; MAX_HARDWARE_ID_LEN + 1];
        let result = attestation.verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_verify_empty_signature() {
        let mut attestation = HardwareAttestation::test_attestation();
        attestation.attestation_signature = vec![];
        let result = attestation.verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_verify_signature_too_long() {
        let mut attestation = HardwareAttestation::test_attestation();
        attestation.attestation_signature = vec![0u8; MAX_ATTESTATION_SIGNATURE_LEN + 1];
        let result = attestation.verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_verify_future_timestamp() {
        let mut attestation = HardwareAttestation::test_attestation();
        // Set timestamp 1 hour in the future
        attestation.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let result = attestation.verify();
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_verify_stale_timestamp() {
        let mut attestation = HardwareAttestation::test_attestation();
        // Set timestamp beyond max age
        attestation.timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - ATTESTATION_MAX_AGE_SECS
            - 100;
        let result = attestation.verify();
        assert!(result.is_err());
    }
}
