//! Session persistence for Double Ratchet sessions.
//!
//! Stores and retrieves encrypted session state for 1:1 messaging sessions.
//! All session data is encrypted at rest using the encrypted database.

use veritas_identity::IdentityHash;
use veritas_protocol::session::{PersistedSession, SessionId};

use crate::encrypted_db::EncryptedDb;
use crate::error::{Result, StoreError};

/// Key prefix for session data in the encrypted database.
const SESSION_PREFIX: &[u8] = b"session:";
/// Key prefix for session index by peer.
const SESSION_PEER_PREFIX: &[u8] = b"session-peer:";
/// Key for the list of all session IDs.
const SESSION_LIST_KEY: &[u8] = b"session-list";

/// Maximum number of concurrent sessions.
pub const MAX_SESSIONS: usize = 1000;

/// Manages session persistence in the encrypted database.
pub struct SessionStore<'a> {
    db: &'a EncryptedDb,
}

impl<'a> SessionStore<'a> {
    /// Create a new session store backed by the given encrypted database.
    pub fn new(db: &'a EncryptedDb) -> Self {
        Self { db }
    }

    /// Save a session to the store.
    ///
    /// Encrypts and persists the session state. Also updates the
    /// peer index for lookup by peer identity.
    pub fn save_session(&self, session: &PersistedSession) -> Result<()> {
        let session_key = self.session_key(&session.info.session_id);
        let session_bytes = bincode::serialize(session)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;

        self.db.put(&session_key, &session_bytes)?;

        // Update peer index
        let peer_key = self.peer_key(&session.info.peer_identity);
        self.db
            .put(&peer_key, &session.info.session_id)?;

        // Update session list
        self.add_to_session_list(&session.info.session_id)?;

        Ok(())
    }

    /// Load a session by its session ID.
    pub fn load_session(&self, session_id: &SessionId) -> Result<Option<PersistedSession>> {
        let session_key = self.session_key(session_id);

        match self.db.get(&session_key)? {
            Some(bytes) => {
                let session: PersistedSession = bincode::deserialize(&bytes)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    /// Load a session by peer identity hash.
    ///
    /// Returns the most recent session with the given peer.
    pub fn load_session_by_peer(
        &self,
        peer_identity: &IdentityHash,
    ) -> Result<Option<PersistedSession>> {
        let peer_key = self.peer_key(peer_identity);

        match self.db.get(&peer_key)? {
            Some(session_id_bytes) => {
                if session_id_bytes.len() != 32 {
                    return Ok(None);
                }
                let mut session_id = [0u8; 32];
                session_id.copy_from_slice(&session_id_bytes);
                self.load_session(&session_id)
            }
            None => Ok(None),
        }
    }

    /// Delete a session.
    pub fn delete_session(&self, session_id: &SessionId) -> Result<()> {
        // Load session to get peer info for index cleanup
        if let Some(session) = self.load_session(session_id)? {
            let peer_key = self.peer_key(&session.info.peer_identity);
            self.db.delete(&peer_key)?;
        }

        let session_key = self.session_key(session_id);
        self.db.delete(&session_key)?;

        self.remove_from_session_list(session_id)?;

        Ok(())
    }

    /// List all session IDs.
    pub fn list_sessions(&self) -> Result<Vec<SessionId>> {
        match self.db.get(SESSION_LIST_KEY)? {
            Some(bytes) => {
                let ids: Vec<SessionId> = bincode::deserialize(&bytes)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                Ok(ids)
            }
            None => Ok(Vec::new()),
        }
    }

    /// Check if a session exists for a given peer.
    pub fn has_session_with_peer(&self, peer_identity: &IdentityHash) -> Result<bool> {
        let peer_key = self.peer_key(peer_identity);
        Ok(self.db.get(&peer_key)?.is_some())
    }

    /// Get the count of stored sessions.
    pub fn session_count(&self) -> Result<usize> {
        Ok(self.list_sessions()?.len())
    }

    /// Build the database key for a session.
    fn session_key(&self, session_id: &SessionId) -> Vec<u8> {
        let mut key = Vec::with_capacity(SESSION_PREFIX.len() + 32);
        key.extend_from_slice(SESSION_PREFIX);
        key.extend_from_slice(session_id);
        key
    }

    /// Build the database key for a peer index entry.
    fn peer_key(&self, peer_identity: &IdentityHash) -> Vec<u8> {
        let mut key = Vec::with_capacity(SESSION_PEER_PREFIX.len() + 32);
        key.extend_from_slice(SESSION_PEER_PREFIX);
        key.extend_from_slice(peer_identity.as_bytes());
        key
    }

    /// Add a session ID to the session list.
    fn add_to_session_list(&self, session_id: &SessionId) -> Result<()> {
        let mut ids = self.list_sessions()?;

        // Check for duplicates
        if ids.contains(session_id) {
            return Ok(());
        }

        // Enforce maximum
        if ids.len() >= MAX_SESSIONS {
            return Err(StoreError::StoreFull(
                "Maximum session count reached".to_string(),
            ));
        }

        ids.push(*session_id);
        let bytes = bincode::serialize(&ids)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        self.db.put(SESSION_LIST_KEY, &bytes)?;
        Ok(())
    }

    /// Remove a session ID from the session list.
    fn remove_from_session_list(&self, session_id: &SessionId) -> Result<()> {
        let mut ids = self.list_sessions()?;
        ids.retain(|id| id != session_id);
        let bytes = bincode::serialize(&ids)
            .map_err(|e| StoreError::Serialization(e.to_string()))?;
        self.db.put(SESSION_LIST_KEY, &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::TempDir;

    fn create_test_db() -> (TempDir, EncryptedDb) {
        let dir = TempDir::new().unwrap();
        let db = EncryptedDb::open(dir.path(), b"test-password").unwrap();
        (dir, db)
    }

    #[test]
    fn test_session_store_save_load() {
        let (_dir, db) = create_test_db();
        let store = SessionStore::new(&db);

        let session_id = [0x42u8; 32];
        let peer_identity = IdentityHash::from_bytes(&[0xAA; 32]).unwrap();

        // We can't easily create a full PersistedSession without the crypto
        // layer, but we can test the store infrastructure with list operations
        let sessions = store.list_sessions().unwrap();
        assert!(sessions.is_empty());

        assert_eq!(store.session_count().unwrap(), 0);
        assert!(!store.has_session_with_peer(&peer_identity).unwrap());
    }

    #[test]
    fn test_session_key_format() {
        let (_dir, db) = create_test_db();
        let store = SessionStore::new(&db);

        let session_id = [0x42u8; 32];
        let key = store.session_key(&session_id);
        assert!(key.starts_with(SESSION_PREFIX));
        assert_eq!(key.len(), SESSION_PREFIX.len() + 32);
    }

    #[test]
    fn test_load_nonexistent_session() {
        let (_dir, db) = create_test_db();
        let store = SessionStore::new(&db);

        let session_id = [0x42u8; 32];
        let result = store.load_session(&session_id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_load_session_by_nonexistent_peer() {
        let (_dir, db) = create_test_db();
        let store = SessionStore::new(&db);

        let peer = IdentityHash::from_bytes(&[0xBB; 32]).unwrap();
        let result = store.load_session_by_peer(&peer).unwrap();
        assert!(result.is_none());
    }
}
