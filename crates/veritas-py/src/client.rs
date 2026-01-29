//! VERITAS client for Python bindings.

use std::sync::Arc;

use pyo3::prelude::*;
use tokio::runtime::Runtime;
use veritas_core::VeritasClient as CoreClient;
use veritas_identity::IdentityHash;

use crate::error::{IntoPyErr, VeritasError};
use crate::identity::{IdentityInfo, IdentitySlots};

/// The main VERITAS protocol client.
///
/// `VeritasClient` provides a high-level API for:
/// - Identity management
/// - Encrypted messaging
/// - Group conversations
/// - Blockchain verification
/// - Reputation tracking
///
/// The client follows a state machine pattern and must be unlocked
/// before use.
///
/// Example:
///     >>> # Create in-memory client
///     >>> client = VeritasClient()
///     >>> client.unlock(b"my_password")
///     >>>
///     >>> # Create identity
///     >>> identity_hash = client.create_identity("Personal")
///     >>> print(f"Created identity: {identity_hash}")
///     >>>
///     >>> # Lock when done
///     >>> client.lock()
///
/// Example:
///     >>> # Create client with persistent storage
///     >>> client = VeritasClient(path="/path/to/data")
///     >>> client.unlock(b"my_password")
///     >>> # ... use client ...
///     >>> client.shutdown()
#[pyclass]
pub struct VeritasClient {
    inner: Arc<CoreClient>,
    runtime: Runtime,
}

#[pymethods]
impl VeritasClient {
    /// Create a new VERITAS client.
    ///
    /// Args:
    ///     path: Optional path to data directory. If not provided,
    ///           uses in-memory storage (data lost on shutdown).
    ///
    /// Returns:
    ///     VeritasClient: A new client instance.
    ///
    /// Raises:
    ///     VeritasError: If client creation fails.
    ///
    /// Example:
    ///     >>> # In-memory client
    ///     >>> client = VeritasClient()
    ///     >>>
    ///     >>> # Persistent storage
    ///     >>> client = VeritasClient(path="/data/veritas")
    #[new]
    #[pyo3(signature = (path=None))]
    fn new(path: Option<&str>) -> PyResult<Self> {
        let runtime = Runtime::new()
            .map_err(|e| VeritasError::new_err(veritas_core::CoreError::Config(e.to_string())))?;

        let inner = runtime.block_on(async {
            if let Some(p) = path {
                CoreClient::with_data_dir(p).await
            } else {
                CoreClient::in_memory().await
            }
        }).map_err(|e| e.into_py_err())?;

        Ok(Self {
            inner: Arc::new(inner),
            runtime,
        })
    }

    // ========================================================================
    // Lifecycle Methods
    // ========================================================================

    /// Unlock the client with a password.
    ///
    /// This initializes all services and decrypts stored identity keys.
    /// The client must be unlocked before performing any operations.
    ///
    /// Args:
    ///     password: The password or key material for decryption (bytes).
    ///
    /// Raises:
    ///     VeritasError: If unlock fails (wrong password, already unlocked, etc.)
    ///
    /// Example:
    ///     >>> client = VeritasClient()
    ///     >>> client.unlock(b"my_secure_password")
    fn unlock(&self, password: &[u8]) -> PyResult<()> {
        self.runtime
            .block_on(async { self.inner.unlock(password).await })
            .map_err(|e| e.into_py_err())?;
        Ok(())
    }

    /// Lock the client and zeroize sensitive data.
    ///
    /// After locking, the client cannot be used for operations until
    /// unlocked again. This is recommended when the client is idle.
    ///
    /// Raises:
    ///     VeritasError: If locking fails.
    ///
    /// Example:
    ///     >>> client.lock()
    ///     >>> # Later, unlock again
    ///     >>> client.unlock(b"my_secure_password")
    fn lock(&self) -> PyResult<()> {
        self.runtime.block_on(async { self.inner.lock().await })
            .map_err(|e| e.into_py_err())?;
        Ok(())
    }

    /// Shutdown the client completely.
    ///
    /// This performs a clean shutdown:
    /// - Stops accepting new operations
    /// - Waits for pending operations to complete
    /// - Closes network connections
    /// - Persists any pending data
    /// - Zeroizes all sensitive data
    ///
    /// After shutdown, the client cannot be reused.
    ///
    /// Raises:
    ///     VeritasError: If shutdown fails.
    ///
    /// Example:
    ///     >>> client.shutdown()
    fn shutdown(&self) -> PyResult<()> {
        self.runtime
            .block_on(async { self.inner.shutdown().await })
            .map_err(|e| e.into_py_err())?;
        Ok(())
    }

    /// Check if the client is unlocked and ready for operations.
    ///
    /// Returns:
    ///     bool: True if the client is unlocked.
    ///
    /// Example:
    ///     >>> if client.is_unlocked():
    ///     ...     print("Client is ready")
    fn is_unlocked(&self) -> bool {
        self.runtime.block_on(async { self.inner.is_unlocked().await })
    }

    /// Get the current client state.
    ///
    /// Returns:
    ///     str: The current state ("Created", "Locked", "Unlocked", or "ShuttingDown").
    ///
    /// Example:
    ///     >>> state = client.state()
    ///     >>> print(f"Client state: {state}")
    fn state(&self) -> String {
        let state = self.runtime.block_on(async { self.inner.state().await });
        state.to_string()
    }

    // ========================================================================
    // Identity Methods
    // ========================================================================

    /// Get the hash of the primary identity.
    ///
    /// The primary identity is used by default for all operations.
    ///
    /// Returns:
    ///     str: The identity hash in hex format.
    ///
    /// Raises:
    ///     VeritasError: If the client is not unlocked or no primary identity is set.
    ///
    /// Example:
    ///     >>> hash = client.identity_hash()
    ///     >>> print(f"My identity: {hash}")
    fn identity_hash(&self) -> PyResult<String> {
        let hash = self
            .runtime
            .block_on(async { self.inner.identity_hash().await })
            .map_err(|e| e.into_py_err())?;
        Ok(hash.to_hex())
    }

    /// Get the public keys of the primary identity.
    ///
    /// These keys can be shared with others to enable encrypted communication.
    ///
    /// Returns:
    ///     bytes: Serialized public keys.
    ///
    /// Raises:
    ///     VeritasError: If the client is not unlocked or no primary identity is set.
    ///
    /// Example:
    ///     >>> keys = client.public_keys()
    ///     >>> # Share keys with a contact
    fn public_keys(&self) -> PyResult<Vec<u8>> {
        let keys = self
            .runtime
            .block_on(async { self.inner.public_keys().await })
            .map_err(|e| e.into_py_err())?;
        Ok(keys.to_bytes())
    }

    /// Create a new identity.
    ///
    /// Args:
    ///     label: Optional human-readable label for the identity.
    ///
    /// Returns:
    ///     str: The hash of the created identity in hex format.
    ///
    /// Raises:
    ///     VeritasError: If the client is not unlocked or the maximum
    ///                   identities per origin has been reached.
    ///
    /// Example:
    ///     >>> # Create with label
    ///     >>> hash = client.create_identity("Personal")
    ///     >>>
    ///     >>> # Create without label
    ///     >>> hash = client.create_identity()
    #[pyo3(signature = (label=None))]
    fn create_identity(&self, label: Option<&str>) -> PyResult<String> {
        let hash = self
            .runtime
            .block_on(async { self.inner.create_identity(label).await })
            .map_err(|e| e.into_py_err())?;
        Ok(hash.to_hex())
    }

    /// List all identities managed by this client.
    ///
    /// Returns:
    ///     List[IdentityInfo]: List of identity information objects.
    ///
    /// Raises:
    ///     VeritasError: If the client is not unlocked.
    ///
    /// Example:
    ///     >>> identities = client.list_identities()
    ///     >>> for identity in identities:
    ///     ...     print(f"{identity.hash}: {identity.label}")
    fn list_identities(&self) -> PyResult<Vec<IdentityInfo>> {
        let identities = self
            .runtime
            .block_on(async { self.inner.list_identities().await })
            .map_err(|e| e.into_py_err())?;
        Ok(identities.into_iter().map(|i| i.into()).collect())
    }

    /// Set the primary identity.
    ///
    /// The primary identity is used by default for all operations.
    ///
    /// Args:
    ///     hash: The identity hash in hex format.
    ///
    /// Raises:
    ///     VeritasError: If the client is not unlocked or the identity is not found.
    ///
    /// Example:
    ///     >>> identities = client.list_identities()
    ///     >>> client.set_primary_identity(identities[1].hash)
    fn set_primary_identity(&self, hash: &str) -> PyResult<()> {
        let identity_hash = IdentityHash::from_hex(hash)
            .map_err(|e: veritas_identity::IdentityError| VeritasError::new_err(e.into()))?;
        self.runtime.block_on(async {
            self.inner.set_primary_identity(&identity_hash).await
        }).map_err(|e| e.into_py_err())?;
        Ok(())
    }

    /// Get information about identity slot usage.
    ///
    /// Each device origin is limited to 3 identities. This method returns
    /// information about how many slots are used and available.
    ///
    /// Returns:
    ///     IdentitySlots: Information about slot usage.
    ///
    /// Raises:
    ///     VeritasError: If the client is not unlocked.
    ///
    /// Example:
    ///     >>> slots = client.identity_slots()
    ///     >>> print(f"Used {slots.used}/{slots.max} identity slots")
    ///     >>> if slots.can_create():
    ///     ...     client.create_identity("Work")
    fn identity_slots(&self) -> PyResult<IdentitySlots> {
        let slots = self
            .runtime
            .block_on(async { self.inner.identity_slots().await })
            .map_err(|e| e.into_py_err())?;
        Ok(slots.into())
    }

    fn __repr__(&self) -> String {
        let state = self.runtime.block_on(async { self.inner.state().await });
        format!("VeritasClient(state={})", state)
    }
}
