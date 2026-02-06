//! Chain synchronization protocol.
//!
//! This module provides the synchronization protocol for the VERITAS blockchain,
//! enabling nodes to catch up with the network and stay synchronized.
//!
//! ## Synchronization Flow
//!
//! ```text
//! 1. Request chain tip from peers
//! 2. Compare local tip with peer tip
//! 3. If behind:
//!    a. Request headers starting from local tip
//!    b. Validate header chain
//!    c. Request full blocks for valid headers
//!    d. Add blocks to local chain
//! 4. Repeat until synchronized
//! ```
//!
//! ## Message Types
//!
//! - `GetHeaders` / `Headers`: Request/response for block headers
//! - `GetBlocks` / `Blocks`: Request/response for full blocks
//! - `NewBlock`: Announce a new block at the tip
//! - `GetTip` / `Tip`: Request/response for chain tip
//! - `Status`: Report sync status to peers
//!
//! ## Example
//!
//! ```
//! use veritas_chain::sync::{SyncManager, SyncState, SyncAction};
//!
//! let mut manager = SyncManager::new();
//! assert!(manager.is_synced());
//!
//! // Start syncing when we discover we're behind
//! let messages = manager.start_sync(100, 150);
//! assert!(!manager.is_synced());
//!
//! // Check sync progress
//! if let Some((current, target)) = manager.progress() {
//!     println!("Syncing: {} / {}", current, target);
//! }
//! ```

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use veritas_crypto::Hash256;

use crate::{Block, BlockHeader};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum headers to request in a single message.
pub const DEFAULT_MAX_HEADERS_PER_REQUEST: u32 = 500;

/// Default maximum blocks to request in a single message.
pub const DEFAULT_MAX_BLOCKS_PER_REQUEST: u32 = 100;

/// Default timeout for sync requests in milliseconds.
pub const DEFAULT_REQUEST_TIMEOUT_MS: u64 = 30000;

/// Maximum number of pending headers during sync.
///
/// SECURITY: Bounds the `pending_headers` vector to prevent memory exhaustion
/// from a malicious peer sending an unbounded stream of headers.
pub const MAX_PENDING_HEADERS: usize = 1000;

/// Maximum number of received blocks during sync.
///
/// SECURITY: Bounds the `received_blocks` vector to prevent memory exhaustion
/// from a malicious peer sending an unbounded stream of blocks.
pub const MAX_RECEIVED_BLOCKS: usize = 1000;

// ============================================================================
// Sync Message Types
// ============================================================================

/// Messages used in the synchronization protocol.
///
/// These messages enable nodes to:
/// - Discover chain state from peers
/// - Request missing headers and blocks
/// - Announce new blocks
/// - Report sync status
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncMessage {
    /// Request block headers from a starting height.
    ///
    /// The response should include up to `max_count` headers
    /// starting from `start_height` in ascending order.
    GetHeaders {
        /// Starting block height.
        start_height: u64,
        /// Maximum number of headers to return.
        max_count: u32,
        /// Request identifier for matching responses.
        request_id: u64,
    },

    /// Response with block headers.
    ///
    /// Contains headers in ascending height order.
    Headers {
        /// Block headers.
        headers: Vec<BlockHeader>,
        /// Request identifier matching the `GetHeaders` request.
        request_id: u64,
    },

    /// Request full blocks by their hashes.
    ///
    /// Used after receiving headers to fetch full block content.
    GetBlocks {
        /// Block hashes to retrieve.
        hashes: Vec<Hash256>,
        /// Request identifier for matching responses.
        request_id: u64,
    },

    /// Response with full blocks.
    ///
    /// Blocks should be in the same order as requested hashes.
    Blocks {
        /// Full blocks with headers and bodies.
        blocks: Vec<Block>,
        /// Request identifier matching the `GetBlocks` request.
        request_id: u64,
    },

    /// Announce a new block at the chain tip.
    ///
    /// Sent by validators when they produce a new block.
    NewBlock {
        /// Header of the new block.
        header: BlockHeader,
    },

    /// Request the current chain tip from a peer.
    GetTip {
        /// Request identifier for matching responses.
        request_id: u64,
    },

    /// Response with the current chain tip.
    Tip {
        /// Height of the tip block.
        height: u64,
        /// Hash of the tip block.
        hash: Hash256,
        /// Request identifier matching the `GetTip` request.
        request_id: u64,
    },

    /// Report sync status to peers.
    ///
    /// Used for peer discovery and tracking network health.
    Status {
        /// Current chain height.
        height: u64,
        /// Hash of the tip block.
        tip_hash: Hash256,
        /// Whether this node is currently syncing.
        syncing: bool,
    },
}

impl SyncMessage {
    /// Get the request ID if this message has one.
    pub fn request_id(&self) -> Option<u64> {
        match self {
            SyncMessage::GetHeaders { request_id, .. }
            | SyncMessage::Headers { request_id, .. }
            | SyncMessage::GetBlocks { request_id, .. }
            | SyncMessage::Blocks { request_id, .. }
            | SyncMessage::GetTip { request_id }
            | SyncMessage::Tip { request_id, .. } => Some(*request_id),
            SyncMessage::NewBlock { .. } | SyncMessage::Status { .. } => None,
        }
    }

    /// Check if this is a request message.
    pub fn is_request(&self) -> bool {
        matches!(
            self,
            SyncMessage::GetHeaders { .. }
                | SyncMessage::GetBlocks { .. }
                | SyncMessage::GetTip { .. }
        )
    }

    /// Check if this is a response message.
    pub fn is_response(&self) -> bool {
        matches!(
            self,
            SyncMessage::Headers { .. } | SyncMessage::Blocks { .. } | SyncMessage::Tip { .. }
        )
    }

    /// Serialize the message to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("serialization failed: {}", e))
    }

    /// Deserialize a message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        bincode::deserialize(bytes).map_err(|e| format!("deserialization failed: {}", e))
    }
}

// ============================================================================
// Sync State
// ============================================================================

/// Current synchronization state of the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncState {
    /// Not syncing, at the chain tip.
    Synced,

    /// Currently downloading block headers.
    SyncingHeaders {
        /// Target height to sync to.
        target_height: u64,
        /// Current sync height.
        current_height: u64,
    },

    /// Currently downloading full blocks.
    SyncingBlocks {
        /// Target height to sync to.
        target_height: u64,
        /// Current sync height.
        current_height: u64,
        /// Number of pending block requests.
        pending: usize,
    },

    /// Syncing is paused due to no available peers.
    Paused {
        /// Last synchronized height before pause.
        last_height: u64,
    },
}

impl SyncState {
    /// Check if the node is fully synchronized.
    pub fn is_synced(&self) -> bool {
        matches!(self, SyncState::Synced)
    }

    /// Check if the node is currently syncing.
    pub fn is_syncing(&self) -> bool {
        matches!(
            self,
            SyncState::SyncingHeaders { .. } | SyncState::SyncingBlocks { .. }
        )
    }

    /// Check if syncing is paused.
    pub fn is_paused(&self) -> bool {
        matches!(self, SyncState::Paused { .. })
    }

    /// Get the current height in the sync process.
    pub fn current_height(&self) -> Option<u64> {
        match self {
            SyncState::Synced => None,
            SyncState::SyncingHeaders { current_height, .. } => Some(*current_height),
            SyncState::SyncingBlocks { current_height, .. } => Some(*current_height),
            SyncState::Paused { last_height } => Some(*last_height),
        }
    }

    /// Get the target height in the sync process.
    pub fn target_height(&self) -> Option<u64> {
        match self {
            SyncState::Synced | SyncState::Paused { .. } => None,
            SyncState::SyncingHeaders { target_height, .. } => Some(*target_height),
            SyncState::SyncingBlocks { target_height, .. } => Some(*target_height),
        }
    }
}

// ============================================================================
// Pending Request
// ============================================================================

/// A pending synchronization request awaiting a response.
#[derive(Clone, Debug)]
pub struct PendingRequest {
    /// The message that was sent.
    pub message: SyncMessage,
    /// Unix timestamp in milliseconds when the request was sent.
    pub sent_at: u64,
    /// Timeout in milliseconds.
    pub timeout_ms: u64,
}

impl PendingRequest {
    /// Create a new pending request.
    pub fn new(message: SyncMessage, sent_at: u64, timeout_ms: u64) -> Self {
        Self {
            message,
            sent_at,
            timeout_ms,
        }
    }

    /// Check if the request has timed out.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Current Unix timestamp in milliseconds
    pub fn is_timed_out(&self, current_time_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.sent_at) > self.timeout_ms
    }

    /// Get the deadline for this request.
    pub fn deadline(&self) -> u64 {
        self.sent_at.saturating_add(self.timeout_ms)
    }
}

// ============================================================================
// Sync Action
// ============================================================================

/// Actions to take based on sync state changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncAction {
    /// No action needed.
    None,

    /// Send these messages to peers.
    Send(Vec<SyncMessage>),

    /// Add these blocks to the chain.
    AddBlocks(Vec<Block>),

    /// Synchronization is complete.
    Complete,

    /// A request has timed out.
    Timeout {
        /// The request ID that timed out.
        request_id: u64,
    },
}

impl SyncAction {
    /// Check if this action requires no operation.
    pub fn is_none(&self) -> bool {
        matches!(self, SyncAction::None)
    }

    /// Check if this action requires sending messages.
    pub fn is_send(&self) -> bool {
        matches!(self, SyncAction::Send(_))
    }

    /// Check if this action provides blocks to add.
    pub fn is_add_blocks(&self) -> bool {
        matches!(self, SyncAction::AddBlocks(_))
    }

    /// Check if synchronization is complete.
    pub fn is_complete(&self) -> bool {
        matches!(self, SyncAction::Complete)
    }

    /// Check if this is a timeout action.
    pub fn is_timeout(&self) -> bool {
        matches!(self, SyncAction::Timeout { .. })
    }
}

// ============================================================================
// Sync Manager
// ============================================================================

/// Manages blockchain synchronization.
///
/// The `SyncManager` tracks synchronization state, pending requests,
/// and generates appropriate messages for the sync protocol.
///
/// ## Example
///
/// ```
/// use veritas_chain::sync::{SyncManager, SyncState};
///
/// let mut manager = SyncManager::new();
///
/// // When behind the network, start syncing
/// let messages = manager.start_sync(100, 200);
///
/// // Process received headers
/// // let action = manager.handle_headers(received_headers);
/// ```
#[derive(Debug)]
pub struct SyncManager {
    /// Current synchronization state.
    state: SyncState,
    /// Pending requests awaiting responses.
    pending_requests: HashMap<u64, PendingRequest>,
    /// Next request ID to use.
    next_request_id: u64,
    /// Maximum headers to request per message.
    max_headers_per_request: u32,
    /// Maximum blocks to request per message.
    max_blocks_per_request: u32,
    /// Headers received during sync (pending block fetch).
    pending_headers: Vec<BlockHeader>,
    /// Blocks received, awaiting ordering and addition.
    received_blocks: Vec<Block>,
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncManager {
    /// Create a new sync manager in the synced state.
    pub fn new() -> Self {
        Self {
            state: SyncState::Synced,
            pending_requests: HashMap::new(),
            next_request_id: 1,
            max_headers_per_request: DEFAULT_MAX_HEADERS_PER_REQUEST,
            max_blocks_per_request: DEFAULT_MAX_BLOCKS_PER_REQUEST,
            pending_headers: Vec::new(),
            received_blocks: Vec::new(),
        }
    }

    /// Create a new sync manager with custom limits.
    pub fn with_limits(max_headers_per_request: u32, max_blocks_per_request: u32) -> Self {
        Self {
            state: SyncState::Synced,
            pending_requests: HashMap::new(),
            next_request_id: 1,
            max_headers_per_request,
            max_blocks_per_request,
            pending_headers: Vec::new(),
            received_blocks: Vec::new(),
        }
    }

    /// Get the current sync state.
    pub fn state(&self) -> &SyncState {
        &self.state
    }

    /// Check if the node is synchronized.
    pub fn is_synced(&self) -> bool {
        self.state.is_synced()
    }

    /// Get sync progress as (current, target) heights.
    ///
    /// Returns `None` if not currently syncing.
    pub fn progress(&self) -> Option<(u64, u64)> {
        match &self.state {
            SyncState::SyncingHeaders {
                current_height,
                target_height,
            } => Some((*current_height, *target_height)),
            SyncState::SyncingBlocks {
                current_height,
                target_height,
                ..
            } => Some((*current_height, *target_height)),
            _ => None,
        }
    }

    /// Get pending requests.
    pub fn get_pending_requests(&self) -> &HashMap<u64, PendingRequest> {
        &self.pending_requests
    }

    /// Get the number of pending requests.
    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Generate the next request ID.
    fn next_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.wrapping_add(1);
        if self.next_request_id == 0 {
            self.next_request_id = 1;
        }
        id
    }

    /// Start synchronization from our current height to peer's height.
    ///
    /// # Arguments
    ///
    /// * `our_height` - Our current chain height
    /// * `peer_height` - The peer's chain height
    ///
    /// # Returns
    ///
    /// Messages to send to peers to begin synchronization.
    pub fn start_sync(&mut self, our_height: u64, peer_height: u64) -> Vec<SyncMessage> {
        // Already at or ahead of peer
        if our_height >= peer_height {
            self.state = SyncState::Synced;
            return Vec::new();
        }

        // Update state to syncing headers
        self.state = SyncState::SyncingHeaders {
            target_height: peer_height,
            current_height: our_height,
        };

        // Clear any existing state
        self.pending_headers.clear();
        self.received_blocks.clear();

        // Request headers starting from our height + 1
        self.request_headers(our_height + 1)
    }

    /// Request headers starting from a given height.
    fn request_headers(&mut self, start_height: u64) -> Vec<SyncMessage> {
        let request_id = self.next_request_id();
        let message = SyncMessage::GetHeaders {
            start_height,
            max_count: self.max_headers_per_request,
            request_id,
        };

        // Track pending request
        let pending = PendingRequest::new(
            message.clone(),
            chrono::Utc::now().timestamp_millis() as u64,
            DEFAULT_REQUEST_TIMEOUT_MS,
        );
        self.pending_requests.insert(request_id, pending);

        vec![message]
    }

    /// Request blocks by their hashes.
    fn request_blocks(&mut self, hashes: Vec<Hash256>) -> Vec<SyncMessage> {
        if hashes.is_empty() {
            return Vec::new();
        }

        let mut messages = Vec::new();

        // Split into batches if needed
        for chunk in hashes.chunks(self.max_blocks_per_request as usize) {
            let request_id = self.next_request_id();
            let message = SyncMessage::GetBlocks {
                hashes: chunk.to_vec(),
                request_id,
            };

            let pending = PendingRequest::new(
                message.clone(),
                chrono::Utc::now().timestamp_millis() as u64,
                DEFAULT_REQUEST_TIMEOUT_MS,
            );
            self.pending_requests.insert(request_id, pending);

            messages.push(message);
        }

        messages
    }

    /// Handle received headers.
    ///
    /// # Arguments
    ///
    /// * `headers` - Block headers received from a peer
    ///
    /// # Returns
    ///
    /// Action to take based on the headers.
    pub fn handle_headers(&mut self, headers: Vec<BlockHeader>) -> SyncAction {
        // Ignore if not syncing headers
        let (target_height, mut current_height) = match &self.state {
            SyncState::SyncingHeaders {
                target_height,
                current_height,
            } => (*target_height, *current_height),
            _ => return SyncAction::None,
        };

        // Empty response - peer doesn't have the data
        if headers.is_empty() {
            // If we have pending headers, move to block fetching
            if !self.pending_headers.is_empty() {
                return self.transition_to_block_sync();
            }
            // Otherwise we might be synced or need to try another peer
            self.state = SyncState::Synced;
            return SyncAction::Complete;
        }

        // SECURITY: Check if adding headers would exceed the maximum bound.
        // Prevents memory exhaustion from a malicious peer.
        if self.pending_headers.len() + headers.len() > MAX_PENDING_HEADERS {
            return SyncAction::None;
        }

        // Validate headers are in order and link correctly
        let mut last_height = current_height;
        for (i, header) in headers.iter().enumerate() {
            if header.height != last_height + 1 {
                // Gap in headers - invalid response
                return SyncAction::None;
            }

            // SECURITY: Verify parent hash linkage to prevent fabricated chain segments.
            // For the first header in the batch, verify against the last pending header
            // or use the expected parent from the chain state.
            // For subsequent headers, verify against the previous header in this batch.
            if i == 0 {
                // Check parent hash against the last header we already have
                let expected_parent = if let Some(last_pending) = self.pending_headers.last() {
                    &last_pending.hash
                } else {
                    // No pending headers yet; we cannot verify the first header's
                    // parent hash without the chain state, so skip this check.
                    // The caller is responsible for verifying the first block
                    // connects to the local chain tip.
                    &header.parent_hash // no-op comparison
                };
                if header.parent_hash != *expected_parent {
                    return SyncAction::None;
                }
            } else {
                // Subsequent headers must link to the previous header's hash
                if header.parent_hash != headers[i - 1].hash {
                    return SyncAction::None;
                }
            }

            last_height = header.height;
        }

        // Store headers and update current height
        self.pending_headers.extend(headers.iter().cloned());
        current_height = last_height;

        // Update state
        self.state = SyncState::SyncingHeaders {
            target_height,
            current_height,
        };

        // Check if we have all headers
        if current_height >= target_height {
            // Got all headers, now fetch blocks
            return self.transition_to_block_sync();
        }

        // Need more headers
        let messages = self.request_headers(current_height + 1);
        SyncAction::Send(messages)
    }

    /// Transition from header sync to block sync.
    fn transition_to_block_sync(&mut self) -> SyncAction {
        let target_height = match &self.state {
            SyncState::SyncingHeaders { target_height, .. } => *target_height,
            SyncState::SyncingBlocks { target_height, .. } => *target_height,
            _ => return SyncAction::Complete,
        };

        if self.pending_headers.is_empty() {
            self.state = SyncState::Synced;
            return SyncAction::Complete;
        }

        // Get first header height as current
        let current_height = self
            .pending_headers
            .first()
            .map(|h| h.height.saturating_sub(1))
            .unwrap_or(0);

        // Collect hashes for block requests
        let hashes: Vec<Hash256> = self
            .pending_headers
            .iter()
            .map(|h| h.hash.clone())
            .collect();

        // Update state
        self.state = SyncState::SyncingBlocks {
            target_height,
            current_height,
            pending: hashes.len(),
        };

        // Request blocks
        let messages = self.request_blocks(hashes);
        SyncAction::Send(messages)
    }

    /// Handle received blocks.
    ///
    /// # Arguments
    ///
    /// * `blocks` - Blocks received from a peer
    ///
    /// # Returns
    ///
    /// Action to take based on the blocks.
    pub fn handle_blocks(&mut self, blocks: Vec<Block>) -> SyncAction {
        // Ignore if not syncing blocks
        let (target_height, current_height, pending) = match &self.state {
            SyncState::SyncingBlocks {
                target_height,
                current_height,
                pending,
            } => (*target_height, *current_height, *pending),
            _ => return SyncAction::None,
        };

        if blocks.is_empty() {
            return SyncAction::None;
        }

        // SECURITY: Check if adding blocks would exceed the maximum bound.
        // Prevents memory exhaustion from a malicious peer.
        if self.received_blocks.len() + blocks.len() > MAX_RECEIVED_BLOCKS {
            return SyncAction::None;
        }

        // Store received blocks
        self.received_blocks.extend(blocks);

        // Check if we have all blocks
        let new_pending = pending.saturating_sub(self.received_blocks.len());

        if self.received_blocks.len() >= self.pending_headers.len() {
            // Sort blocks by height
            self.received_blocks.sort_by_key(|b| b.height());

            // Take blocks for adding to chain
            let blocks_to_add: Vec<Block> = self.received_blocks.drain(..).collect();
            let new_height = blocks_to_add
                .last()
                .map(|b| b.height())
                .unwrap_or(current_height);

            // Clear pending headers
            self.pending_headers.clear();

            // Check if we've reached target
            if new_height >= target_height {
                self.state = SyncState::Synced;
                return SyncAction::AddBlocks(blocks_to_add);
            }

            // Need more - restart header sync
            self.state = SyncState::SyncingHeaders {
                target_height,
                current_height: new_height,
            };

            // Return blocks to add (caller should add them, then continue sync)
            return SyncAction::AddBlocks(blocks_to_add);
        }

        // Update pending count
        self.state = SyncState::SyncingBlocks {
            target_height,
            current_height,
            pending: new_pending,
        };

        SyncAction::None
    }

    /// Handle a new block announcement.
    ///
    /// # Arguments
    ///
    /// * `header` - Header of the newly announced block
    ///
    /// # Returns
    ///
    /// Action to take based on the announcement.
    pub fn handle_new_block(&mut self, header: BlockHeader) -> SyncAction {
        match &self.state {
            SyncState::Synced => {
                // We're synced but got a new block - might need to sync
                // The caller should check if this block connects to our tip
                // and either add it directly or start a sync
                SyncAction::None
            }
            SyncState::SyncingHeaders {
                target_height,
                current_height,
            } => {
                // Update target if new block is higher
                if header.height > *target_height {
                    self.state = SyncState::SyncingHeaders {
                        target_height: header.height,
                        current_height: *current_height,
                    };
                }
                SyncAction::None
            }
            SyncState::SyncingBlocks {
                target_height,
                current_height,
                pending,
            } => {
                // Update target if new block is higher
                if header.height > *target_height {
                    self.state = SyncState::SyncingBlocks {
                        target_height: header.height,
                        current_height: *current_height,
                        pending: *pending,
                    };
                }
                SyncAction::None
            }
            SyncState::Paused { last_height } => {
                // We were paused, now we have a peer - resume sync
                let messages = self.start_sync(*last_height, header.height);
                if messages.is_empty() {
                    SyncAction::None
                } else {
                    SyncAction::Send(messages)
                }
            }
        }
    }

    /// Check for timed out requests.
    ///
    /// # Arguments
    ///
    /// * `current_time_ms` - Current Unix timestamp in milliseconds
    ///
    /// # Returns
    ///
    /// List of actions for timed out requests.
    pub fn check_timeouts(&mut self, current_time_ms: u64) -> Vec<SyncAction> {
        let timed_out: Vec<u64> = self
            .pending_requests
            .iter()
            .filter(|(_, req)| req.is_timed_out(current_time_ms))
            .map(|(id, _)| *id)
            .collect();

        timed_out
            .into_iter()
            .map(|request_id| {
                self.pending_requests.remove(&request_id);
                SyncAction::Timeout { request_id }
            })
            .collect()
    }

    /// Complete a request by its ID.
    ///
    /// Called when a response is received to remove the request from pending.
    pub fn complete_request(&mut self, request_id: u64) -> Option<PendingRequest> {
        self.pending_requests.remove(&request_id)
    }

    /// Pause synchronization (e.g., no peers available).
    pub fn pause(&mut self) {
        let last_height = self.state.current_height().unwrap_or(0);
        self.state = SyncState::Paused { last_height };
    }

    /// Resume synchronization to a target height.
    ///
    /// # Arguments
    ///
    /// * `target_height` - Target height to sync to
    ///
    /// # Returns
    ///
    /// Messages to send to resume sync.
    pub fn resume(&mut self, target_height: u64) -> Vec<SyncMessage> {
        let last_height = match &self.state {
            SyncState::Paused { last_height } => *last_height,
            _ => return Vec::new(),
        };

        self.start_sync(last_height, target_height)
    }

    /// Reset the sync manager to initial state.
    pub fn reset(&mut self) {
        self.state = SyncState::Synced;
        self.pending_requests.clear();
        self.pending_headers.clear();
        self.received_blocks.clear();
    }

    /// Create a status message for the current state.
    ///
    /// # Arguments
    ///
    /// * `height` - Current chain height
    /// * `tip_hash` - Hash of the current tip block
    pub fn create_status(&self, height: u64, tip_hash: Hash256) -> SyncMessage {
        SyncMessage::Status {
            height,
            tip_hash,
            syncing: self.state.is_syncing(),
        }
    }

    /// Create a get tip request.
    pub fn create_get_tip(&mut self) -> SyncMessage {
        let request_id = self.next_request_id();
        let message = SyncMessage::GetTip { request_id };

        let pending = PendingRequest::new(
            message.clone(),
            chrono::Utc::now().timestamp_millis() as u64,
            DEFAULT_REQUEST_TIMEOUT_MS,
        );
        self.pending_requests.insert(request_id, pending);

        message
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use veritas_identity::IdentityHash;

    // Helper to create a test hash
    fn test_hash(seed: u8) -> Hash256 {
        Hash256::from_bytes(&[seed; 32]).unwrap()
    }

    // Helper to create a test identity
    fn test_identity(seed: u8) -> IdentityHash {
        IdentityHash::from_bytes(&[seed; 32]).unwrap()
    }

    // Helper to create a test block header (standalone, no parent chain linkage)
    fn test_header(height: u64, parent_seed: u8) -> BlockHeader {
        BlockHeader::new(
            test_hash(parent_seed),
            height,
            1700000000 + height,
            test_hash((height % 256) as u8),
            test_identity(1),
        )
    }

    // Helper to create a properly chained sequence of headers.
    // Each header's parent_hash equals the previous header's computed hash,
    // which is required for parent hash validation during sync.
    fn chained_headers(start_height: u64, count: u64) -> Vec<BlockHeader> {
        let mut headers = Vec::new();
        let mut parent_hash = test_hash(0); // Genesis parent hash for height 1

        for i in 0..count {
            let height = start_height + i;
            let merkle_root = test_hash((height % 256) as u8);
            let header = BlockHeader::new(
                parent_hash.clone(),
                height,
                1700000000 + height,
                merkle_root,
                test_identity(1),
            );
            parent_hash = header.hash.clone();
            headers.push(header);
        }
        headers
    }

    // Helper to create a test block
    fn test_block(height: u64, parent_seed: u8) -> Block {
        Block::new(
            test_hash(parent_seed),
            height,
            1700000000 + height,
            vec![],
            test_identity(1),
        )
    }

    // Helper to create properly chained blocks matching chained headers.
    fn chained_blocks(start_height: u64, count: u64) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut parent_hash = test_hash(0);

        for i in 0..count {
            let height = start_height + i;
            let block = Block::new(
                parent_hash.clone(),
                height,
                1700000000 + height,
                vec![],
                test_identity(1),
            );
            parent_hash = block.hash().clone();
            blocks.push(block);
        }
        blocks
    }

    // ==================== SyncMessage Tests ====================

    #[test]
    fn test_sync_message_serialization_get_headers() {
        let message = SyncMessage::GetHeaders {
            start_height: 100,
            max_count: 500,
            request_id: 42,
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_serialization_headers() {
        let headers = vec![test_header(1, 0), test_header(2, 1), test_header(3, 2)];

        let message = SyncMessage::Headers {
            headers,
            request_id: 123,
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_serialization_get_blocks() {
        let message = SyncMessage::GetBlocks {
            hashes: vec![test_hash(1), test_hash(2), test_hash(3)],
            request_id: 456,
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_serialization_blocks() {
        let blocks = vec![test_block(1, 0), test_block(2, 1)];

        let message = SyncMessage::Blocks {
            blocks,
            request_id: 789,
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_serialization_new_block() {
        let message = SyncMessage::NewBlock {
            header: test_header(100, 99),
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_serialization_tip() {
        let message = SyncMessage::Tip {
            height: 1000,
            hash: test_hash(42),
            request_id: 999,
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_serialization_status() {
        let message = SyncMessage::Status {
            height: 500,
            tip_hash: test_hash(50),
            syncing: true,
        };

        let bytes = message.to_bytes().unwrap();
        let restored = SyncMessage::from_bytes(&bytes).unwrap();

        assert_eq!(message, restored);
    }

    #[test]
    fn test_sync_message_request_id() {
        assert_eq!(
            SyncMessage::GetHeaders {
                start_height: 0,
                max_count: 10,
                request_id: 42
            }
            .request_id(),
            Some(42)
        );

        assert_eq!(
            SyncMessage::NewBlock {
                header: test_header(1, 0)
            }
            .request_id(),
            None
        );
    }

    #[test]
    fn test_sync_message_is_request_response() {
        assert!(SyncMessage::GetHeaders {
            start_height: 0,
            max_count: 10,
            request_id: 1
        }
        .is_request());
        assert!(SyncMessage::GetBlocks {
            hashes: vec![],
            request_id: 1
        }
        .is_request());
        assert!(SyncMessage::GetTip { request_id: 1 }.is_request());

        assert!(SyncMessage::Headers {
            headers: vec![],
            request_id: 1
        }
        .is_response());
        assert!(SyncMessage::Blocks {
            blocks: vec![],
            request_id: 1
        }
        .is_response());
        assert!(SyncMessage::Tip {
            height: 0,
            hash: test_hash(0),
            request_id: 1
        }
        .is_response());
    }

    // ==================== SyncState Tests ====================

    #[test]
    fn test_sync_state_is_synced() {
        assert!(SyncState::Synced.is_synced());
        assert!(!SyncState::SyncingHeaders {
            target_height: 100,
            current_height: 50
        }
        .is_synced());
    }

    #[test]
    fn test_sync_state_is_syncing() {
        assert!(SyncState::SyncingHeaders {
            target_height: 100,
            current_height: 50
        }
        .is_syncing());
        assert!(SyncState::SyncingBlocks {
            target_height: 100,
            current_height: 50,
            pending: 10
        }
        .is_syncing());
        assert!(!SyncState::Synced.is_syncing());
        assert!(!SyncState::Paused { last_height: 50 }.is_syncing());
    }

    #[test]
    fn test_sync_state_is_paused() {
        assert!(SyncState::Paused { last_height: 50 }.is_paused());
        assert!(!SyncState::Synced.is_paused());
    }

    #[test]
    fn test_sync_state_heights() {
        let state = SyncState::SyncingHeaders {
            target_height: 200,
            current_height: 100,
        };
        assert_eq!(state.current_height(), Some(100));
        assert_eq!(state.target_height(), Some(200));

        assert_eq!(SyncState::Synced.current_height(), None);
        assert_eq!(SyncState::Synced.target_height(), None);
    }

    // ==================== SyncManager Tests ====================

    #[test]
    fn test_sync_manager_new() {
        let manager = SyncManager::new();
        assert!(manager.is_synced());
        assert_eq!(manager.pending_request_count(), 0);
    }

    #[test]
    fn test_start_sync_generates_get_headers() {
        let mut manager = SyncManager::new();
        let messages = manager.start_sync(100, 150);

        assert_eq!(messages.len(), 1);
        match &messages[0] {
            SyncMessage::GetHeaders {
                start_height,
                max_count,
                ..
            } => {
                assert_eq!(*start_height, 101);
                assert_eq!(*max_count, DEFAULT_MAX_HEADERS_PER_REQUEST);
            }
            _ => panic!("Expected GetHeaders message"),
        }

        assert!(!manager.is_synced());
        assert_eq!(manager.pending_request_count(), 1);
    }

    #[test]
    fn test_start_sync_already_synced() {
        let mut manager = SyncManager::new();

        // Already at or ahead of peer
        let messages = manager.start_sync(100, 100);
        assert!(messages.is_empty());
        assert!(manager.is_synced());

        let messages = manager.start_sync(100, 50);
        assert!(messages.is_empty());
        assert!(manager.is_synced());
    }

    #[test]
    fn test_handle_headers_when_behind() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 10);

        // Create properly chained headers for blocks 1-5
        let headers = chained_headers(1, 5);

        let action = manager.handle_headers(headers);

        // Should request more headers
        match action {
            SyncAction::Send(messages) => {
                assert!(!messages.is_empty());
                match &messages[0] {
                    SyncMessage::GetHeaders { start_height, .. } => {
                        assert_eq!(*start_height, 6);
                    }
                    _ => panic!("Expected GetHeaders"),
                }
            }
            _ => panic!("Expected Send action"),
        }
    }

    #[test]
    fn test_handle_headers_complete_triggers_block_fetch() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 3);

        // Create properly chained headers for blocks 1-3 (complete set)
        let headers = chained_headers(1, 3);

        let action = manager.handle_headers(headers);

        // Should now request blocks
        match action {
            SyncAction::Send(messages) => {
                assert!(!messages.is_empty());
                match &messages[0] {
                    SyncMessage::GetBlocks { hashes, .. } => {
                        assert_eq!(hashes.len(), 3);
                    }
                    _ => panic!("Expected GetBlocks"),
                }
            }
            _ => panic!("Expected Send action"),
        }

        // State should be SyncingBlocks
        match manager.state() {
            SyncState::SyncingBlocks { pending, .. } => {
                assert_eq!(*pending, 3);
            }
            _ => panic!("Expected SyncingBlocks state"),
        }
    }

    #[test]
    fn test_handle_blocks_completes_batch() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 3);

        // Receive properly chained headers
        let headers = chained_headers(1, 3);
        manager.handle_headers(headers);

        // Receive blocks
        let blocks = chained_blocks(1, 3);
        let action = manager.handle_blocks(blocks);

        match action {
            SyncAction::AddBlocks(blocks) => {
                assert_eq!(blocks.len(), 3);
                // Should be sorted by height
                assert_eq!(blocks[0].height(), 1);
                assert_eq!(blocks[1].height(), 2);
                assert_eq!(blocks[2].height(), 3);
            }
            _ => panic!("Expected AddBlocks action"),
        }

        // Should be synced now
        assert!(manager.is_synced());
    }

    #[test]
    fn test_progress_tracking() {
        let mut manager = SyncManager::new();

        // No progress when synced
        assert!(manager.progress().is_none());

        // Start sync
        manager.start_sync(100, 200);

        let (current, target) = manager.progress().unwrap();
        assert_eq!(current, 100);
        assert_eq!(target, 200);
    }

    #[test]
    fn test_request_id_management() {
        let mut manager = SyncManager::new();

        // Request IDs should increment
        let messages1 = manager.start_sync(0, 10);
        let id1 = messages1[0].request_id().unwrap();

        manager.reset();
        let messages2 = manager.start_sync(0, 10);
        let id2 = messages2[0].request_id().unwrap();

        assert!(id2 > id1);
    }

    #[test]
    fn test_state_transitions() {
        let mut manager = SyncManager::new();

        // Start: Synced
        assert!(matches!(manager.state(), SyncState::Synced));

        // Start sync -> SyncingHeaders
        manager.start_sync(0, 5);
        assert!(matches!(manager.state(), SyncState::SyncingHeaders { .. }));

        // Receive all properly chained headers -> SyncingBlocks
        let headers = chained_headers(1, 5);
        manager.handle_headers(headers);
        assert!(matches!(manager.state(), SyncState::SyncingBlocks { .. }));

        // Receive all blocks -> Synced
        let blocks = chained_blocks(1, 5);
        manager.handle_blocks(blocks);
        assert!(matches!(manager.state(), SyncState::Synced));
    }

    #[test]
    fn test_new_block_announcement() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 100);

        // Announce new block at higher height
        let header = test_header(150, 149);
        let action = manager.handle_new_block(header);

        assert!(action.is_none());

        // Target should be updated
        match manager.state() {
            SyncState::SyncingHeaders { target_height, .. } => {
                assert_eq!(*target_height, 150);
            }
            _ => panic!("Expected SyncingHeaders"),
        }
    }

    #[test]
    fn test_empty_headers_response() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 10);

        // Empty response
        let action = manager.handle_headers(vec![]);

        // Should complete sync (might be synced or peer doesn't have data)
        assert!(matches!(action, SyncAction::Complete));
    }

    #[test]
    fn test_pause_and_resume() {
        let mut manager = SyncManager::new();
        manager.start_sync(50, 100);

        // Pause
        manager.pause();
        assert!(matches!(
            manager.state(),
            SyncState::Paused { last_height: 50 }
        ));

        // Resume
        let messages = manager.resume(150);
        assert!(!messages.is_empty());
        assert!(matches!(
            manager.state(),
            SyncState::SyncingHeaders {
                target_height: 150,
                ..
            }
        ));
    }

    #[test]
    fn test_pending_request_timeout() {
        let request = PendingRequest::new(SyncMessage::GetTip { request_id: 1 }, 1000, 5000);

        assert!(!request.is_timed_out(5000));
        assert!(!request.is_timed_out(6000));
        assert!(request.is_timed_out(6001));
        assert_eq!(request.deadline(), 6000);
    }

    #[test]
    fn test_check_timeouts() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 100);

        // Check timeouts with old time - nothing should timeout
        let actions = manager.check_timeouts(0);
        assert!(actions.is_empty());

        // Check timeouts with future time - should timeout
        let actions = manager.check_timeouts(u64::MAX);
        assert!(!actions.is_empty());
        assert!(matches!(actions[0], SyncAction::Timeout { .. }));
    }

    #[test]
    fn test_create_status() {
        let manager = SyncManager::new();
        let status = manager.create_status(100, test_hash(42));

        match status {
            SyncMessage::Status {
                height,
                tip_hash,
                syncing,
            } => {
                assert_eq!(height, 100);
                assert_eq!(tip_hash, test_hash(42));
                assert!(!syncing);
            }
            _ => panic!("Expected Status message"),
        }
    }

    #[test]
    fn test_create_get_tip() {
        let mut manager = SyncManager::new();
        let message = manager.create_get_tip();

        assert!(matches!(message, SyncMessage::GetTip { .. }));
        assert_eq!(manager.pending_request_count(), 1);
    }

    #[test]
    fn test_complete_request() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 10);

        let request_id = manager
            .get_pending_requests()
            .keys()
            .next()
            .copied()
            .unwrap();
        let pending = manager.complete_request(request_id);

        assert!(pending.is_some());
        assert_eq!(manager.pending_request_count(), 0);
    }

    #[test]
    fn test_multiple_batch_fetching() {
        let mut manager = SyncManager::with_limits(5, 2);
        manager.start_sync(0, 10);

        // Receive 10 properly chained headers
        let headers = chained_headers(1, 10);
        let action = manager.handle_headers(headers);

        // Should generate multiple GetBlocks requests (10 hashes, max 2 per request = 5 requests)
        match action {
            SyncAction::Send(messages) => {
                assert_eq!(messages.len(), 5);
                for msg in messages {
                    match msg {
                        SyncMessage::GetBlocks { hashes, .. } => {
                            assert!(hashes.len() <= 2);
                        }
                        _ => panic!("Expected GetBlocks"),
                    }
                }
            }
            _ => panic!("Expected Send action"),
        }
    }

    #[test]
    fn test_sync_complete_detection() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 2);

        // Receive all properly chained headers
        let headers = chained_headers(1, 2);
        manager.handle_headers(headers);

        // Receive all blocks
        let blocks = chained_blocks(1, 2);
        let action = manager.handle_blocks(blocks);

        // Should be AddBlocks and synced
        assert!(action.is_add_blocks());
        assert!(manager.is_synced());
    }

    #[test]
    fn test_handle_blocks_out_of_order() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 3);

        // Receive properly chained headers
        let headers = chained_headers(1, 3);
        manager.handle_headers(headers);

        // Receive blocks out of order
        let mut blocks = chained_blocks(1, 3);
        blocks.swap(0, 2); // Swap first and last to make them out of order
        let action = manager.handle_blocks(blocks);

        match action {
            SyncAction::AddBlocks(blocks) => {
                // Should be sorted by height
                assert_eq!(blocks[0].height(), 1);
                assert_eq!(blocks[1].height(), 2);
                assert_eq!(blocks[2].height(), 3);
            }
            _ => panic!("Expected AddBlocks action"),
        }
    }

    #[test]
    fn test_sync_action_helpers() {
        assert!(SyncAction::None.is_none());
        assert!(SyncAction::Send(vec![]).is_send());
        assert!(SyncAction::AddBlocks(vec![]).is_add_blocks());
        assert!(SyncAction::Complete.is_complete());
        assert!(SyncAction::Timeout { request_id: 1 }.is_timeout());
    }

    #[test]
    fn test_new_block_resumes_paused_sync() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 50);
        manager.pause();

        assert!(matches!(manager.state(), SyncState::Paused { .. }));

        // Announce new block while paused
        let header = test_header(100, 99);
        let action = manager.handle_new_block(header);

        // Should resume sync
        match action {
            SyncAction::Send(messages) => {
                assert!(!messages.is_empty());
            }
            _ => panic!("Expected Send action to resume sync"),
        }

        assert!(matches!(
            manager.state(),
            SyncState::SyncingHeaders {
                target_height: 100,
                ..
            }
        ));
    }

    #[test]
    fn test_default_impl() {
        let manager = SyncManager::default();
        assert!(manager.is_synced());
    }

    // ==================== Property Tests ====================

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_sync_message_roundtrip(height in 0u64..1000000, count in 1u32..1000) {
            let message = SyncMessage::GetHeaders {
                start_height: height,
                max_count: count,
                request_id: 1,
            };

            let bytes = message.to_bytes().unwrap();
            let restored = SyncMessage::from_bytes(&bytes).unwrap();
            prop_assert_eq!(message, restored);
        }

        #[test]
        fn prop_start_sync_creates_valid_state(
            our_height in 0u64..1000000,
            peer_height in 0u64..1000000
        ) {
            let mut manager = SyncManager::new();
            let messages = manager.start_sync(our_height, peer_height);

            if our_height >= peer_height {
                prop_assert!(manager.is_synced());
                prop_assert!(messages.is_empty());
            } else {
                prop_assert!(!manager.is_synced());
                prop_assert!(!messages.is_empty());
            }
        }

        #[test]
        fn prop_request_timeout_consistent(sent_at in 0u64..u64::MAX/2, timeout_ms in 1u64..100000) {
            let request = PendingRequest::new(
                SyncMessage::GetTip { request_id: 1 },
                sent_at,
                timeout_ms,
            );

            let deadline = request.deadline();
            prop_assert_eq!(deadline, sent_at.saturating_add(timeout_ms));

            // Should not be timed out at deadline
            prop_assert!(!request.is_timed_out(deadline));

            // Should be timed out after deadline
            prop_assert!(request.is_timed_out(deadline + 1));
        }
    }

    // ==================== Security Tests ====================

    #[test]
    fn test_parent_hash_linkage_rejected_when_broken() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 5);

        // Create headers with correct heights but broken parent hash linkage
        let headers = vec![
            test_header(1, 0),  // parent_hash = test_hash(0)
            test_header(2, 99), // parent_hash = test_hash(99) -- wrong! should be hash of header at height 1
        ];

        // Should reject due to broken parent hash linkage
        let action = manager.handle_headers(headers);
        assert!(action.is_none(), "Headers with broken parent hash linkage should be rejected");
    }

    #[test]
    fn test_parent_hash_linkage_accepted_when_correct() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 5);

        // Create properly chained headers
        let headers = chained_headers(1, 3);

        // Should accept and request more headers
        let action = manager.handle_headers(headers);
        assert!(!action.is_none(), "Headers with correct parent hash linkage should be accepted");
    }

    #[test]
    fn test_parent_hash_linkage_across_batches() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 10);

        // First batch: properly chained headers 1-3
        let headers_batch1 = chained_headers(1, 3);
        let last_hash_batch1 = headers_batch1.last().unwrap().hash.clone();
        let action = manager.handle_headers(headers_batch1);
        assert!(matches!(action, SyncAction::Send(_)));

        // Second batch: properly chained starting from header 4,
        // but with the correct parent hash linking to batch 1's last header.
        let mut headers_batch2 = Vec::new();
        let mut parent_hash = last_hash_batch1;
        for i in 0..3 {
            let height = 4 + i;
            let header = BlockHeader::new(
                parent_hash.clone(),
                height,
                1700000000 + height,
                test_hash((height % 256) as u8),
                test_identity(1),
            );
            parent_hash = header.hash.clone();
            headers_batch2.push(header);
        }

        let action = manager.handle_headers(headers_batch2);
        assert!(!action.is_none(), "Second batch with correct parent linkage should be accepted");
    }

    #[test]
    fn test_parent_hash_linkage_broken_across_batches() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 10);

        // First batch: properly chained headers 1-3
        let headers_batch1 = chained_headers(1, 3);
        let action = manager.handle_headers(headers_batch1);
        assert!(matches!(action, SyncAction::Send(_)));

        // Second batch: starts at height 4 but with wrong parent hash
        // (doesn't link to the last header of batch 1)
        let headers_batch2 = chained_headers(4, 3); // starts from test_hash(0), not batch1's last hash
        let action = manager.handle_headers(headers_batch2);
        assert!(action.is_none(), "Second batch with broken parent linkage should be rejected");
    }

    #[test]
    fn test_pending_headers_bounded() {
        let mut manager = SyncManager::new();
        // Set a target much larger than MAX_PENDING_HEADERS
        manager.start_sync(0, (MAX_PENDING_HEADERS as u64) + 500);

        // Create a batch of MAX_PENDING_HEADERS headers (at the limit)
        let headers = chained_headers(1, MAX_PENDING_HEADERS as u64);
        let action = manager.handle_headers(headers);
        // Should be accepted (exactly at limit)
        assert!(!action.is_none(), "Headers exactly at MAX_PENDING_HEADERS should be accepted");
    }

    #[test]
    fn test_pending_headers_overflow_rejected() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, (MAX_PENDING_HEADERS as u64) + 500);

        // Fill to near capacity
        let headers = chained_headers(1, MAX_PENDING_HEADERS as u64 - 1);
        let last_hash = headers.last().unwrap().hash.clone();
        let last_height = headers.last().unwrap().height;
        let action = manager.handle_headers(headers);
        assert!(!action.is_none());

        // Try to add a batch that would exceed the limit
        let mut overflow_headers = Vec::new();
        let mut parent_hash = last_hash;
        for i in 0..2 {
            let height = last_height + 1 + i;
            let header = BlockHeader::new(
                parent_hash.clone(),
                height,
                1700000000 + height,
                test_hash((height % 256) as u8),
                test_identity(1),
            );
            parent_hash = header.hash.clone();
            overflow_headers.push(header);
        }
        let action = manager.handle_headers(overflow_headers);
        assert!(action.is_none(), "Headers exceeding MAX_PENDING_HEADERS should be rejected");
    }

    #[test]
    fn test_received_blocks_bounded() {
        let mut manager = SyncManager::new();
        manager.start_sync(0, 5);

        // Set up headers and transition to block sync
        let headers = chained_headers(1, 5);
        manager.handle_headers(headers);

        // Try to add more blocks than MAX_RECEIVED_BLOCKS
        let mut huge_blocks = Vec::new();
        for i in 0..=MAX_RECEIVED_BLOCKS {
            huge_blocks.push(test_block((i + 1) as u64, i as u8));
        }
        let action = manager.handle_blocks(huge_blocks);
        assert!(action.is_none(), "Blocks exceeding MAX_RECEIVED_BLOCKS should be rejected");
    }
}
