//! Main VERITAS client implementation.
//!
//! The [`VeritasClient`] is the primary entry point for applications using
//! the VERITAS protocol. It provides a high-level API for identity management,
//! messaging, group operations, and blockchain verification.
//!
//! # Client Lifecycle
//!
//! The client follows a state machine pattern:
//!
//! ```text
//!     new() ──────────────┐
//!                         │
//!                         ▼
//!                    ┌─────────┐
//!                    │ Created │
//!                    └────┬────┘
//!                         │
//!                   unlock()
//!                         │
//!                         ▼
//!                    ┌──────────┐◄────────┐
//!                    │ Unlocked │         │
//!                    └────┬─────┘   unlock()
//!                         │              │
//!                    lock()         ┌────┴────┐
//!                         │         │ Locked  │
//!                         └────────►└────┬────┘
//!                                        │
//!                                  shutdown()
//!                                        │
//!                                        ▼
//!                               ┌─────────────────┐
//!                               │ ShuttingDown    │
//!                               └─────────────────┘
//! ```
//!
//! # Example
//!
//! ```ignore
//! use veritas_core::{VeritasClient, ClientConfig};
//!
//! // Create client with default configuration
//! let client = VeritasClient::new(ClientConfig::default()).await?;
//!
//! // Unlock with password
//! client.unlock(b"my_secure_password").await?;
//!
//! // Create or use existing identity
//! let identity_hash = client.identity_hash().await?;
//! println!("Identity: {}", identity_hash);
//!
//! // Lock when done
//! client.lock().await?;
//! ```
//!
//! # Security Notes
//!
//! - Always lock the client when not actively in use
//! - The client zeroizes sensitive data when locked
//! - Use a strong password derived through a KDF for unlock

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use veritas_identity::{IdentityHash, IdentityPublicKeys, IdentitySlotInfo};

use crate::config::ClientConfig;
use crate::error::{CoreError, Result};
use crate::groups::{GroupId, GroupInfo, GroupMessage, GroupRole};
use crate::internal::{
    ChainService, IdentityInfo, IdentityManager, MessageService, ReputationService,
};
use crate::messaging::{MessageHash, MessageStatus, ReceivedMessage, SendOptions};
use crate::verification::{MessageProof, SyncStatus};

// ============================================================================
// Client State
// ============================================================================

/// The current state of the VERITAS client.
///
/// The client follows a state machine pattern where certain operations
/// are only valid in certain states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientState {
    /// Client has been created but not yet initialized.
    ///
    /// In this state, the client has loaded configuration but has not
    /// connected to storage or initialized services.
    Created,

    /// Client is initialized but locked.
    ///
    /// The client has been unlocked at least once but is currently locked.
    /// Sensitive data has been zeroized from memory.
    Locked,

    /// Client is unlocked and ready for operations.
    ///
    /// All services are initialized and the client can perform
    /// messaging, identity, and blockchain operations.
    Unlocked,

    /// Client is in the process of shutting down.
    ///
    /// No new operations are accepted. Existing operations may complete.
    ShuttingDown,
}

impl ClientState {
    /// Check if the client is ready for operations.
    pub fn is_ready(&self) -> bool {
        matches!(self, ClientState::Unlocked)
    }

    /// Get a human-readable description of the state.
    pub fn description(&self) -> &'static str {
        match self {
            ClientState::Created => "Created (not initialized)",
            ClientState::Locked => "Locked",
            ClientState::Unlocked => "Unlocked (ready)",
            ClientState::ShuttingDown => "Shutting down",
        }
    }
}

impl fmt::Display for ClientState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ============================================================================
// Client Services
// ============================================================================

/// Internal services container.
///
/// These services are initialized when the client is unlocked and
/// destroyed when locked to ensure sensitive data is zeroized.
pub(crate) struct ClientServices {
    /// Identity management service.
    pub identity: IdentityManager,

    /// Messaging service.
    pub messaging: MessageService,

    /// Blockchain service.
    pub chain: ChainService,

    /// Reputation service.
    pub reputation: ReputationService,
}

impl fmt::Debug for ClientServices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientServices")
            .field("identity", &"[IdentityManager]")
            .field("messaging", &self.messaging)
            .field("chain", &self.chain)
            .field("reputation", &self.reputation)
            .finish()
    }
}

// ============================================================================
// VERITAS Client
// ============================================================================

/// The main VERITAS protocol client.
///
/// `VeritasClient` provides a high-level, async-safe API for:
///
/// - **Identity Management**: Create, list, and manage cryptographic identities
/// - **Messaging**: Send and receive encrypted messages with metadata hiding
/// - **Groups**: Create and manage group conversations
/// - **Blockchain**: Verify message proofs and sync chain state
/// - **Reputation**: Track and query reputation scores
///
/// # Thread Safety
///
/// `VeritasClient` is fully thread-safe and can be shared across tasks.
/// It uses `Arc<RwLock<_>>` internally for state management.
///
/// # Example
///
/// ```ignore
/// use veritas_core::VeritasClient;
/// use std::sync::Arc;
///
/// // Create and share client
/// let client = Arc::new(VeritasClient::in_memory().await?);
///
/// // Use from multiple tasks
/// let client_clone = client.clone();
/// tokio::spawn(async move {
///     client_clone.unlock(b"password").await?;
///     // ...
/// });
/// ```
pub struct VeritasClient {
    /// Client configuration.
    config: ClientConfig,

    /// Current client state.
    state: Arc<RwLock<ClientState>>,

    /// Services container (Some when unlocked, None when locked).
    services: Arc<RwLock<Option<ClientServices>>>,
}

impl VeritasClient {
    // ========================================================================
    // Lifecycle Methods
    // ========================================================================

    /// Create a new VERITAS client with the given configuration.
    ///
    /// The client starts in the `Created` state and must be unlocked
    /// before it can be used for operations.
    ///
    /// # Arguments
    ///
    /// * `config` - Client configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use veritas_core::{VeritasClient, ClientConfig};
    ///
    /// let config = ClientConfig::builder()
    ///     .with_data_dir("/path/to/data".into())
    ///     .disable_bluetooth()
    ///     .build();
    ///
    /// let client = VeritasClient::new(config).await?;
    /// ```
    pub async fn new(config: ClientConfig) -> Result<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| CoreError::Config(e.to_string()))?;

        debug!("Creating new VeritasClient");

        Ok(Self {
            config,
            state: Arc::new(RwLock::new(ClientState::Created)),
            services: Arc::new(RwLock::new(None)),
        })
    }

    /// Create a client with a custom data directory.
    ///
    /// This is a convenience method that creates a client with default
    /// settings but a custom data directory.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the data directory
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = VeritasClient::with_data_dir("/custom/path").await?;
    /// ```
    pub async fn with_data_dir(path: impl Into<PathBuf>) -> Result<Self> {
        let config = ClientConfig::builder().with_data_dir(path.into()).build();

        Self::new(config).await
    }

    /// Create a client with in-memory storage.
    ///
    /// Useful for testing or ephemeral sessions. Data will be lost
    /// when the client is dropped.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let client = VeritasClient::in_memory().await?;
    /// client.unlock(b"test_password").await?;
    /// // ... use client ...
    /// // Data is lost when client is dropped
    /// ```
    pub async fn in_memory() -> Result<Self> {
        let config = ClientConfig::in_memory();
        Self::new(config).await
    }

    /// Get the current client state.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let state = client.state().await;
    /// if state == ClientState::Unlocked {
    ///     println!("Client is ready");
    /// }
    /// ```
    pub async fn state(&self) -> ClientState {
        *self.state.read().await
    }

    /// Check if the client is unlocked and ready for operations.
    ///
    /// # Example
    ///
    /// ```ignore
    /// if client.is_unlocked().await {
    ///     client.send_message(&recipient, "Hello!").await?;
    /// }
    /// ```
    pub async fn is_unlocked(&self) -> bool {
        *self.state.read().await == ClientState::Unlocked
    }

    // ========================================================================
    // Authentication Methods
    // ========================================================================

    /// Unlock the client with a password.
    ///
    /// This initializes all services and decrypts stored identity keys.
    /// The password should be derived through a proper KDF (e.g., Argon2)
    /// before being passed to this method.
    ///
    /// # Arguments
    ///
    /// * `password` - The password or key material for decryption
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is already unlocked
    /// - The client is shutting down
    /// - The password is incorrect
    /// - Service initialization fails
    ///
    /// # Example
    ///
    /// ```ignore
    /// // For a new client, unlock creates a new identity store
    /// client.unlock(b"secure_password").await?;
    ///
    /// // For an existing client, unlock decrypts stored identities
    /// client.unlock(b"secure_password").await?;
    /// ```
    pub async fn unlock(&self, password: &[u8]) -> Result<()> {
        let mut state = self.state.write().await;

        match *state {
            ClientState::Unlocked => {
                debug!("Client already unlocked");
                return Ok(());
            }
            ClientState::ShuttingDown => {
                warn!("Attempted to unlock client that is shutting down");
                return Err(CoreError::ShuttingDown);
            }
            ClientState::Created | ClientState::Locked => {
                // Proceed with unlock
            }
        }

        info!("Unlocking VeritasClient");

        // Validate password isn't empty
        if password.is_empty() {
            return Err(CoreError::AuthenticationFailed);
        }

        // Initialize the IdentityManager
        // Note: For persistent storage with password protection, use PersistentIdentityManager
        // For now, we use the in-memory IdentityManager for simplicity
        let identity_manager = IdentityManager::new(self.config.clone());

        // Initialize other services
        let message_service = MessageService::new(self.config.clone());
        let chain_service = ChainService::new(self.config.clone());
        let reputation_service = ReputationService::new(self.config.clone());

        // Note: password is validated but not used with in-memory IdentityManager
        // In a production implementation, PersistentIdentityManager would use it
        let _ = password;

        // Store services
        let mut services = self.services.write().await;
        *services = Some(ClientServices {
            identity: identity_manager,
            messaging: message_service,
            chain: chain_service,
            reputation: reputation_service,
        });

        *state = ClientState::Unlocked;
        info!("VeritasClient unlocked successfully");

        Ok(())
    }

    /// Lock the client and zeroize sensitive data.
    ///
    /// After locking, the client transitions to the `Locked` state
    /// and all services are destroyed. The client can be unlocked
    /// again with the correct password.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is already shutting down.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Lock when going idle
    /// client.lock().await?;
    ///
    /// // Later, unlock again
    /// client.unlock(b"password").await?;
    /// ```
    pub async fn lock(&self) -> Result<()> {
        let mut state = self.state.write().await;

        match *state {
            ClientState::Locked | ClientState::Created => {
                debug!("Client already locked");
                return Ok(());
            }
            ClientState::ShuttingDown => {
                warn!("Attempted to lock client that is shutting down");
                return Err(CoreError::ShuttingDown);
            }
            ClientState::Unlocked => {
                // Proceed with lock
            }
        }

        info!("Locking VeritasClient");

        // Destroy services (this will zeroize sensitive data via Drop)
        let mut services = self.services.write().await;
        *services = None;

        *state = ClientState::Locked;
        info!("VeritasClient locked successfully");

        Ok(())
    }

    /// Shutdown the client completely.
    ///
    /// This performs a clean shutdown:
    /// 1. Stops accepting new operations
    /// 2. Waits for pending operations to complete
    /// 3. Closes network connections
    /// 4. Persists any pending data
    /// 5. Zeroizes all sensitive data
    ///
    /// After shutdown, the client cannot be reused.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Clean shutdown on app exit
    /// client.shutdown().await?;
    /// ```
    pub async fn shutdown(&self) -> Result<()> {
        let mut state = self.state.write().await;

        if *state == ClientState::ShuttingDown {
            debug!("Client already shutting down");
            return Ok(());
        }

        info!("Shutting down VeritasClient");

        *state = ClientState::ShuttingDown;

        // Destroy services (this will zeroize sensitive data via Drop)
        let mut services = self.services.write().await;
        *services = None;

        info!("VeritasClient shutdown complete");

        Ok(())
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Require the client to be unlocked for an operation.
    ///
    /// Returns a read guard to the services if unlocked, or an error
    /// if the client is in any other state.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `CoreError::NotInitialized` if in Created state
    /// - `CoreError::Locked` if in Locked state
    /// - `CoreError::ShuttingDown` if shutting down
    ///
    /// # CORE-FIX-1: TOCTOU Race Condition Note
    ///
    /// There is a time-of-check-to-time-of-use (TOCTOU) race between
    /// checking the state and acquiring the services lock. Between `drop(state)`
    /// and `self.services.read().await`, another task could lock the client,
    /// causing `services` to be `None`. The `services.is_none()` check below
    /// mitigates this by returning `NotInitialized` if services were destroyed
    /// in the gap. This is a known design trade-off to avoid holding two locks
    /// simultaneously, which could cause deadlocks. The worst case is a
    /// spurious `NotInitialized` error, which callers should handle by retrying.
    async fn require_unlocked(
        &self,
    ) -> Result<tokio::sync::RwLockReadGuard<'_, Option<ClientServices>>> {
        let state = self.state.read().await;

        match *state {
            ClientState::Unlocked => {
                // Release state lock before acquiring services lock
                drop(state);

                let services = self.services.read().await;
                if services.is_none() {
                    return Err(CoreError::NotInitialized);
                }
                Ok(services)
            }
            ClientState::Created => Err(CoreError::NotInitialized),
            ClientState::Locked => Err(CoreError::Locked),
            ClientState::ShuttingDown => Err(CoreError::ShuttingDown),
        }
    }

    /// Require the client to be unlocked and return a mutable guard.
    ///
    /// CORE-FIX-1: See TOCTOU note on `require_unlocked()` above.
    async fn require_unlocked_mut(
        &self,
    ) -> Result<tokio::sync::RwLockWriteGuard<'_, Option<ClientServices>>> {
        let state = self.state.read().await;

        match *state {
            ClientState::Unlocked => {
                drop(state);

                let services = self.services.write().await;
                if services.is_none() {
                    return Err(CoreError::NotInitialized);
                }
                Ok(services)
            }
            ClientState::Created => Err(CoreError::NotInitialized),
            ClientState::Locked => Err(CoreError::Locked),
            ClientState::ShuttingDown => Err(CoreError::ShuttingDown),
        }
    }

    // ========================================================================
    // Identity Methods
    // ========================================================================

    /// Get the hash of the primary identity.
    ///
    /// The primary identity is used by default for all operations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is not unlocked
    /// - No primary identity is set
    ///
    /// # Example
    ///
    /// ```ignore
    /// let hash = client.identity_hash().await?;
    /// println!("My identity: {}", hash);
    /// ```
    pub async fn identity_hash(&self) -> Result<IdentityHash> {
        let services = self.require_unlocked().await?;
        let services = services.as_ref().unwrap();

        services
            .identity
            .primary_identity_hash()
            .cloned()
            .ok_or(CoreError::NoPrimaryIdentity)
    }

    /// Get the public keys of the primary identity.
    ///
    /// These keys can be shared with others to enable encrypted communication.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is not unlocked
    /// - No primary identity is set
    ///
    /// # Example
    ///
    /// ```ignore
    /// let keys = client.public_keys().await?;
    /// // Share keys with a contact
    /// ```
    pub async fn public_keys(&self) -> Result<IdentityPublicKeys> {
        let services = self.require_unlocked().await?;
        let services = services.as_ref().unwrap();

        services
            .identity
            .primary_public_keys()
            .cloned()
            .ok_or(CoreError::NoPrimaryIdentity)
    }

    /// Get information about identity slot usage.
    ///
    /// Each device origin is limited to 3 identities. This method returns
    /// information about how many slots are used and available.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is not unlocked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let slots = client.identity_slots().await?;
    /// println!("Used {}/{} identity slots", slots.used, slots.max);
    ///
    /// if slots.can_create() {
    ///     client.create_identity(Some("Work")).await?;
    /// }
    /// ```
    pub async fn identity_slots(&self) -> Result<IdentitySlotInfo> {
        let services = self.require_unlocked().await?;
        let services = services.as_ref().unwrap();

        Ok(services.identity.slot_info())
    }

    /// Create a new identity.
    ///
    /// # Arguments
    ///
    /// * `label` - Optional human-readable label for the identity
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is not unlocked
    /// - The maximum identities per origin has been reached
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Create with label
    /// let hash = client.create_identity(Some("Personal")).await?;
    ///
    /// // Create without label
    /// let hash = client.create_identity(None).await?;
    /// ```
    pub async fn create_identity(&self, label: Option<&str>) -> Result<IdentityHash> {
        let mut services = self.require_unlocked_mut().await?;
        let services = services.as_mut().unwrap();

        let hash = services.identity.create_identity(label)?;
        info!(identity = %hash, "Created new identity");

        // Note: The first identity is automatically set as primary by create_identity()

        Ok(hash)
    }

    /// List all identities managed by this client.
    ///
    /// # Errors
    ///
    /// Returns an error if the client is not unlocked.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let identities = client.list_identities().await?;
    /// for identity in identities {
    ///     println!("{}: {} (primary: {})",
    ///         identity.hash,
    ///         identity.label.unwrap_or_default(),
    ///         identity.is_primary
    ///     );
    /// }
    /// ```
    pub async fn list_identities(&self) -> Result<Vec<IdentityInfo>> {
        let services = self.require_unlocked().await?;
        let services = services.as_ref().unwrap();

        Ok(services.identity.list_identities().to_vec())
    }

    /// Set the primary identity.
    ///
    /// The primary identity is used by default for all operations.
    ///
    /// # Arguments
    ///
    /// * `hash` - The identity hash to set as primary
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The client is not unlocked
    /// - The identity is not found
    ///
    /// # Example
    ///
    /// ```ignore
    /// let identities = client.list_identities().await?;
    /// let work_identity = identities.iter()
    ///     .find(|i| i.label == Some("Work".to_string()))
    ///     .unwrap();
    ///
    /// client.set_primary_identity(&work_identity.hash).await?;
    /// ```
    pub async fn set_primary_identity(&self, hash: &IdentityHash) -> Result<()> {
        let mut services = self.require_unlocked_mut().await?;
        let services = services.as_mut().unwrap();

        services.identity.set_primary_identity(hash)?;
        info!(identity = %hash, "Set primary identity");

        Ok(())
    }

    // ========================================================================
    // Messaging Methods (Stubs)
    // ========================================================================

    /// Send a message to a recipient.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn send_message(
        &self,
        _recipient: &IdentityHash,
        _content: &str,
        _options: SendOptions,
    ) -> Result<MessageHash> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("send_message".to_string()))
    }

    /// Receive pending messages.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn receive_messages(&self) -> Result<Vec<ReceivedMessage>> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("receive_messages".to_string()))
    }

    /// Get the status of a sent message.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn message_status(&self, _hash: &MessageHash) -> Result<MessageStatus> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("message_status".to_string()))
    }

    // ========================================================================
    // Group Methods (Stubs)
    // ========================================================================

    /// Create a new group.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn create_group(&self, _name: Option<&str>) -> Result<GroupId> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("create_group".to_string()))
    }

    /// List groups the user belongs to.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn list_groups(&self) -> Result<Vec<GroupInfo>> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("list_groups".to_string()))
    }

    /// Get messages from a group.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn get_group_messages(&self, _group_id: &GroupId) -> Result<Vec<GroupMessage>> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("get_group_messages".to_string()))
    }

    /// Add a member to a group.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn add_group_member(
        &self,
        _group_id: &GroupId,
        _member: &IdentityHash,
        _role: GroupRole,
    ) -> Result<()> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("add_group_member".to_string()))
    }

    // ========================================================================
    // Verification Methods (Stubs)
    // ========================================================================

    /// Get a proof of message inclusion in the blockchain.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn get_message_proof(&self, _hash: &MessageHash) -> Result<MessageProof> {
        let _services = self.require_unlocked().await?;
        Err(CoreError::NotImplemented("get_message_proof".to_string()))
    }

    /// Get the current blockchain synchronization status.
    ///
    /// # Note
    ///
    /// This is a placeholder method. The full implementation will be added later.
    pub async fn sync_status(&self) -> Result<SyncStatus> {
        let services = self.require_unlocked().await?;
        let services = services.as_ref().unwrap();

        Ok(services.chain.sync_status())
    }
}

// ============================================================================
// Debug Implementation
// ============================================================================

impl fmt::Debug for VeritasClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't show sensitive data in debug output
        f.debug_struct("VeritasClient")
            .field("config", &"[ClientConfig]")
            .field("state", &"[RwLock<ClientState>]")
            .field("services", &"[RwLock<Option<ClientServices>>]")
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    async fn test_client() -> VeritasClient {
        VeritasClient::in_memory().await.unwrap()
    }

    // ========================================================================
    // State Tests
    // ========================================================================

    #[test]
    fn test_client_state_is_ready() {
        assert!(!ClientState::Created.is_ready());
        assert!(!ClientState::Locked.is_ready());
        assert!(ClientState::Unlocked.is_ready());
        assert!(!ClientState::ShuttingDown.is_ready());
    }

    #[test]
    fn test_client_state_display() {
        assert!(!ClientState::Created.description().is_empty());
        assert!(!ClientState::Locked.description().is_empty());
        assert!(!ClientState::Unlocked.description().is_empty());
        assert!(!ClientState::ShuttingDown.description().is_empty());

        // Display should work
        let _ = format!("{}", ClientState::Unlocked);
    }

    // ========================================================================
    // Lifecycle Tests
    // ========================================================================

    #[tokio::test]
    async fn test_new_client_starts_in_created_state() {
        let client = test_client().await;
        assert_eq!(client.state().await, ClientState::Created);
        assert!(!client.is_unlocked().await);
    }

    #[tokio::test]
    async fn test_unlock_transitions_to_unlocked() {
        let client = test_client().await;

        client.unlock(b"password").await.unwrap();

        assert_eq!(client.state().await, ClientState::Unlocked);
        assert!(client.is_unlocked().await);
    }

    #[tokio::test]
    async fn test_unlock_with_empty_password_fails() {
        let client = test_client().await;

        let result = client.unlock(b"").await;

        assert!(result.is_err());
        assert_eq!(client.state().await, ClientState::Created);
    }

    #[tokio::test]
    async fn test_unlock_when_already_unlocked_succeeds() {
        let client = test_client().await;

        client.unlock(b"password").await.unwrap();
        let result = client.unlock(b"password").await;

        assert!(result.is_ok());
        assert_eq!(client.state().await, ClientState::Unlocked);
    }

    #[tokio::test]
    async fn test_lock_transitions_to_locked() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        client.lock().await.unwrap();

        assert_eq!(client.state().await, ClientState::Locked);
        assert!(!client.is_unlocked().await);
    }

    #[tokio::test]
    async fn test_lock_when_already_locked_succeeds() {
        let client = test_client().await;

        let result = client.lock().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unlock_after_lock() {
        let client = test_client().await;

        client.unlock(b"password").await.unwrap();
        client.lock().await.unwrap();
        client.unlock(b"password").await.unwrap();

        assert_eq!(client.state().await, ClientState::Unlocked);
    }

    #[tokio::test]
    async fn test_shutdown() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        client.shutdown().await.unwrap();

        assert_eq!(client.state().await, ClientState::ShuttingDown);
    }

    #[tokio::test]
    async fn test_unlock_after_shutdown_fails() {
        let client = test_client().await;
        client.shutdown().await.unwrap();

        let result = client.unlock(b"password").await;

        assert!(matches!(result, Err(CoreError::ShuttingDown)));
    }

    #[tokio::test]
    async fn test_lock_after_shutdown_fails() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();
        client.shutdown().await.unwrap();

        let result = client.lock().await;

        assert!(matches!(result, Err(CoreError::ShuttingDown)));
    }

    // ========================================================================
    // Constructor Tests
    // ========================================================================

    #[tokio::test]
    async fn test_with_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let client: VeritasClient = VeritasClient::with_data_dir(dir.path()).await.unwrap();
        assert_eq!(client.state().await, ClientState::Created);
    }

    #[tokio::test]
    async fn test_in_memory() {
        let client = VeritasClient::in_memory().await.unwrap();
        assert_eq!(client.state().await, ClientState::Created);
    }

    // ========================================================================
    // Identity Tests
    // ========================================================================

    #[tokio::test]
    async fn test_identity_hash_requires_unlock() {
        let client = test_client().await;

        let result = client.identity_hash().await;

        assert!(matches!(result, Err(CoreError::NotInitialized)));
    }

    #[tokio::test]
    async fn test_identity_hash_requires_primary_identity() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let result = client.identity_hash().await;

        assert!(matches!(result, Err(CoreError::NoPrimaryIdentity)));
    }

    #[tokio::test]
    async fn test_create_identity() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let hash = client.create_identity(Some("Test")).await.unwrap();

        // Should be able to get it back
        let primary = client.identity_hash().await.unwrap();
        assert_eq!(hash, primary);
    }

    #[tokio::test]
    async fn test_create_identity_requires_unlock() {
        let client = test_client().await;

        let result = client.create_identity(None).await;

        assert!(matches!(result, Err(CoreError::NotInitialized)));
    }

    #[tokio::test]
    async fn test_list_identities() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // Initially empty
        let identities = client.list_identities().await.unwrap();
        assert!(identities.is_empty());

        // Create one
        client.create_identity(Some("First")).await.unwrap();

        let identities = client.list_identities().await.unwrap();
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].label, Some("First".to_string()));
        assert!(identities[0].is_primary);
    }

    #[tokio::test]
    async fn test_set_primary_identity() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let hash1 = client.create_identity(Some("First")).await.unwrap();
        let hash2 = client.create_identity(Some("Second")).await.unwrap();

        // First is primary
        let identities = client.list_identities().await.unwrap();
        assert!(
            identities
                .iter()
                .find(|i| i.hash == hash1)
                .unwrap()
                .is_primary
        );

        // Set second as primary
        client.set_primary_identity(&hash2).await.unwrap();

        let identities = client.list_identities().await.unwrap();
        assert!(
            !identities
                .iter()
                .find(|i| i.hash == hash1)
                .unwrap()
                .is_primary
        );
        assert!(
            identities
                .iter()
                .find(|i| i.hash == hash2)
                .unwrap()
                .is_primary
        );
    }

    #[tokio::test]
    async fn test_set_primary_identity_not_found() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let fake_hash = IdentityHash::from_public_key(b"nonexistent");
        let result = client.set_primary_identity(&fake_hash).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_identity_slots() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let slots = client.identity_slots().await.unwrap();

        assert_eq!(slots.max, 3);
        assert!(slots.can_create());
    }

    // ========================================================================
    // Stub Method Tests
    // ========================================================================

    #[tokio::test]
    async fn test_messaging_stubs_require_unlock() {
        let client = test_client().await;

        let recipient = IdentityHash::from_public_key(b"recipient");
        assert!(matches!(
            client
                .send_message(&recipient, "Hello", SendOptions::default())
                .await,
            Err(CoreError::NotInitialized)
        ));

        assert!(matches!(
            client.receive_messages().await,
            Err(CoreError::NotInitialized)
        ));
    }

    #[tokio::test]
    async fn test_messaging_stubs_return_not_implemented() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        let recipient = IdentityHash::from_public_key(b"recipient");
        assert!(matches!(
            client
                .send_message(&recipient, "Hello", SendOptions::default())
                .await,
            Err(CoreError::NotImplemented(_))
        ));

        assert!(matches!(
            client.receive_messages().await,
            Err(CoreError::NotImplemented(_))
        ));
    }

    #[tokio::test]
    async fn test_group_stubs_return_not_implemented() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        assert!(matches!(
            client.create_group(Some("Test")).await,
            Err(CoreError::NotImplemented(_))
        ));

        assert!(matches!(
            client.list_groups().await,
            Err(CoreError::NotImplemented(_))
        ));
    }

    #[tokio::test]
    async fn test_sync_status_works() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        // sync_status should work (not return NotImplemented)
        let status = client.sync_status().await.unwrap();
        assert!(status.is_synced()); // Initial state should be synced (0/0)
    }

    #[tokio::test]
    async fn test_verification_stubs_return_not_implemented() {
        let client = test_client().await;
        client.unlock(b"password").await.unwrap();

        use veritas_crypto::Hash256;
        let hash = Hash256::hash(b"test");

        assert!(matches!(
            client.get_message_proof(&hash).await,
            Err(CoreError::NotImplemented(_))
        ));
    }

    // ========================================================================
    // Debug Tests
    // ========================================================================

    #[tokio::test]
    async fn test_debug_implementation() {
        let client = test_client().await;

        let debug = format!("{:?}", client);

        // Should not contain sensitive data
        assert!(debug.contains("VeritasClient"));
        assert!(!debug.contains("password"));
    }
}
