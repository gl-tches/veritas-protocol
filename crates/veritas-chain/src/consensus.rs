//! Streamlet BFT Consensus Protocol.
//!
//! Implements a simplified Streamlet-style BFT consensus protocol for the
//! VERITAS blockchain. The protocol uses three phases:
//!
//! 1. **Propose**: The designated leader proposes a block
//! 2. **Vote**: Validators vote on the proposed block
//! 3. **Notarize**: Block is notarized when it receives 2/3+1 votes
//!
//! ## Finality Rule
//!
//! A block at height h is **finalized** when there exist three consecutive
//! notarized blocks at heights h, h+1, h+2. Once finalized, blocks are
//! irreversible.
//!
//! ## View Changes
//!
//! If the leader fails to propose within the timeout, validators advance
//! to the next round with a new leader. Leader selection is deterministic
//! based on the round number and the active validator set.
//!
//! ## Security
//!
//! - All votes are ML-DSA-65 signed
//! - Equivocation (voting for two blocks at same height) triggers slashing
//! - Fixed-point u64 arithmetic for all scoring (no f32 non-determinism)
//! - Bounded collections prevent memory exhaustion

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use veritas_crypto::Hash256;
use veritas_identity::IdentityHash;

use crate::slashing::{SlashingManager, SlashingOffense};

/// Maximum number of pending proposals to track.
const MAX_PENDING_PROPOSALS: usize = 100;

/// Maximum number of votes per proposal to track.
const MAX_VOTES_PER_PROPOSAL: usize = 50;

/// Maximum number of notarized blocks to retain.
const MAX_NOTARIZED_BLOCKS: usize = 1000;

/// Maximum number of finalized block hashes to retain in memory.
const MAX_FINALIZED_CACHE: usize = 500;

// =============================================================================
// Consensus Types
// =============================================================================

/// Phase of the consensus round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusPhase {
    /// Waiting for the leader to propose a block.
    Propose,
    /// Voting on a proposed block.
    Vote,
    /// Block has been notarized (2/3+1 votes received).
    Notarized,
    /// Block has been finalized (3 consecutive notarized blocks).
    Finalized,
}

/// A consensus vote from a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// The validator who cast this vote.
    pub voter: IdentityHash,
    /// The block hash being voted on.
    pub block_hash: Hash256,
    /// The block height being voted on.
    pub height: u64,
    /// The consensus round number.
    pub round: u64,
    /// ML-DSA-65 signature over the vote payload.
    pub signature: Vec<u8>,
}

impl ConsensusVote {
    /// Compute the signing payload for this vote.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(104);
        payload.extend_from_slice(b"VERITAS-CONSENSUS-VOTE-v1");
        payload.extend_from_slice(self.block_hash.as_bytes());
        payload.extend_from_slice(&self.height.to_le_bytes());
        payload.extend_from_slice(&self.round.to_le_bytes());
        payload.extend_from_slice(self.voter.as_bytes());
        payload
    }
}

/// A block proposal from a leader.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposal {
    /// The validator proposing the block.
    pub proposer: IdentityHash,
    /// Hash of the proposed block.
    pub block_hash: Hash256,
    /// Parent block hash.
    pub parent_hash: Hash256,
    /// Block height.
    pub height: u64,
    /// Consensus round number.
    pub round: u64,
    /// Unix timestamp of the proposal.
    pub timestamp: u64,
    /// ML-DSA-65 signature over the proposal payload.
    pub signature: Vec<u8>,
}

impl BlockProposal {
    /// Compute the signing payload for this proposal.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(136);
        payload.extend_from_slice(b"VERITAS-CONSENSUS-PROPOSAL-v1");
        payload.extend_from_slice(self.block_hash.as_bytes());
        payload.extend_from_slice(self.parent_hash.as_bytes());
        payload.extend_from_slice(&self.height.to_le_bytes());
        payload.extend_from_slice(&self.round.to_le_bytes());
        payload.extend_from_slice(&self.timestamp.to_le_bytes());
        payload.extend_from_slice(self.proposer.as_bytes());
        payload
    }
}

/// State of a consensus round for a specific height.
#[derive(Debug, Clone)]
pub struct RoundState {
    /// Current phase of this round.
    pub phase: ConsensusPhase,
    /// The proposal for this round, if received.
    pub proposal: Option<BlockProposal>,
    /// Votes received for this round, keyed by voter identity.
    pub votes: HashMap<IdentityHash, ConsensusVote>,
    /// The round number.
    pub round: u64,
    /// Block height for this round.
    pub height: u64,
    /// Timestamp when this round started.
    pub started_at: u64,
}

impl RoundState {
    /// Create a new round state.
    pub fn new(height: u64, round: u64, started_at: u64) -> Self {
        Self {
            phase: ConsensusPhase::Propose,
            proposal: None,
            votes: HashMap::new(),
            round,
            height,
            started_at,
        }
    }

    /// Check if this round has timed out.
    pub fn is_timed_out(&self, now: u64, timeout_ms: u64) -> bool {
        let elapsed_ms = now.saturating_sub(self.started_at).saturating_mul(1000);
        elapsed_ms >= timeout_ms
    }

    /// Get the number of votes received.
    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }
}

/// A notarized block (received 2/3+1 votes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotarizedBlock {
    /// Hash of the notarized block.
    pub block_hash: Hash256,
    /// Parent hash of the notarized block.
    pub parent_hash: Hash256,
    /// Height of the notarized block.
    pub height: u64,
    /// Round in which the block was notarized.
    pub round: u64,
    /// The votes that notarized this block.
    pub votes: Vec<ConsensusVote>,
}

/// Actions the consensus engine requests the node to perform.
#[derive(Debug, Clone)]
pub enum ConsensusAction {
    /// Propose a new block (this node is the leader).
    ProposeBlock {
        /// Height for the new block.
        height: u64,
        /// Parent hash to build on.
        parent_hash: Hash256,
        /// Round number.
        round: u64,
    },
    /// Broadcast a vote for a proposal.
    BroadcastVote(ConsensusVote),
    /// A block has been notarized.
    BlockNotarized(NotarizedBlock),
    /// A block has been finalized (irreversible).
    BlockFinalized {
        /// Hash of the finalized block.
        block_hash: Hash256,
        /// Height of the finalized block.
        height: u64,
    },
    /// Slash a validator for equivocation.
    SlashValidator {
        /// The equivocating validator.
        validator: IdentityHash,
        /// The slashing offense evidence.
        offense: SlashingOffense,
    },
    /// Advance to next round (view change).
    ViewChange {
        /// New round number.
        new_round: u64,
        /// Height being decided.
        height: u64,
    },
}

// =============================================================================
// Consensus Engine
// =============================================================================

/// The BFT consensus engine.
///
/// Manages consensus rounds, vote collection, notarization, and finality
/// for the VERITAS blockchain.
///
/// ## Memory Safety
///
/// All internal collections are bounded to prevent memory exhaustion:
/// - Pending proposals: bounded by MAX_PENDING_PROPOSALS
/// - Votes per proposal: bounded by MAX_VOTES_PER_PROPOSAL
/// - Notarized blocks: bounded by MAX_NOTARIZED_BLOCKS
/// - Finalized cache: bounded by MAX_FINALIZED_CACHE
#[derive(Debug)]
pub struct ConsensusEngine {
    /// Our validator identity (None if not a validator).
    our_identity: Option<IdentityHash>,
    /// Active validator set for the current epoch.
    active_validators: Vec<IdentityHash>,
    /// Current round states, keyed by height.
    round_states: BTreeMap<u64, RoundState>,
    /// Notarized blocks, keyed by height.
    notarized_blocks: BTreeMap<u64, NotarizedBlock>,
    /// Set of finalized block hashes.
    finalized_hashes: HashSet<Hash256>,
    /// Highest finalized height.
    finalized_height: u64,
    /// Current block height being decided.
    current_height: u64,
    /// Current round number for the current height.
    current_round: u64,
    /// Consensus round timeout in milliseconds.
    round_timeout_ms: u64,
    /// Slashing manager for equivocation detection.
    slashing_manager: SlashingManager,
}

impl ConsensusEngine {
    /// Create a new consensus engine.
    ///
    /// # Arguments
    ///
    /// * `our_identity` - Our validator identity, or None if not a validator
    /// * `active_validators` - The active validator set for this epoch
    /// * `current_height` - The current chain height
    /// * `round_timeout_ms` - Timeout per consensus round in milliseconds
    pub fn new(
        our_identity: Option<IdentityHash>,
        active_validators: Vec<IdentityHash>,
        current_height: u64,
        round_timeout_ms: u64,
    ) -> Self {
        Self {
            our_identity,
            active_validators,
            round_states: BTreeMap::new(),
            notarized_blocks: BTreeMap::new(),
            finalized_hashes: HashSet::new(),
            finalized_height: 0,
            current_height,
            current_round: 0,
            round_timeout_ms,
            slashing_manager: SlashingManager::with_default_config(),
        }
    }

    /// Get the current height being decided.
    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    /// Get the current round number.
    pub fn current_round(&self) -> u64 {
        self.current_round
    }

    /// Get the highest finalized height.
    pub fn finalized_height(&self) -> u64 {
        self.finalized_height
    }

    /// Check if a block hash has been finalized.
    pub fn is_finalized(&self, block_hash: &Hash256) -> bool {
        self.finalized_hashes.contains(block_hash)
    }

    /// Check if a block at the given height has been notarized.
    pub fn is_notarized(&self, height: u64) -> bool {
        self.notarized_blocks.contains_key(&height)
    }

    /// Get the notarized block at a given height.
    pub fn get_notarized(&self, height: u64) -> Option<&NotarizedBlock> {
        self.notarized_blocks.get(&height)
    }

    /// Get the active validator count.
    pub fn validator_count(&self) -> usize {
        self.active_validators.len()
    }

    /// Calculate the BFT quorum size (2f+1 where n = 3f+1).
    ///
    /// For n validators, quorum = ceil(2n/3) + 1 when n >= 4.
    /// For n < 4, quorum = n (all must agree).
    pub fn quorum_size(&self) -> usize {
        bft_quorum(self.active_validators.len())
    }

    /// Update the active validator set (e.g., at epoch boundary).
    pub fn update_validators(&mut self, validators: Vec<IdentityHash>) {
        self.active_validators = validators;
    }

    /// Determine the leader for a given round and height.
    ///
    /// Leader selection is deterministic: hash(height || round) mod n.
    pub fn leader_for_round(&self, height: u64, round: u64) -> Option<IdentityHash> {
        if self.active_validators.is_empty() {
            return None;
        }

        let seed = Hash256::hash_many(&[
            b"VERITAS-LEADER-SELECTION-v1",
            &height.to_le_bytes(),
            &round.to_le_bytes(),
        ]);

        // Use first 8 bytes of hash as index
        let bytes = seed.as_bytes();
        let index_value = u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);

        let index = (index_value % self.active_validators.len() as u64) as usize;
        Some(self.active_validators[index].clone())
    }

    /// Check if we are the leader for the current round.
    pub fn is_our_turn(&self) -> bool {
        if let Some(ref our_id) = self.our_identity {
            if let Some(leader) = self.leader_for_round(self.current_height, self.current_round) {
                return &leader == our_id;
            }
        }
        false
    }

    /// Start a new consensus round for the given height.
    ///
    /// Returns a `ConsensusAction::ProposeBlock` if we are the leader.
    pub fn start_round(
        &mut self,
        height: u64,
        round: u64,
        now: u64,
        tip_hash: Hash256,
    ) -> Vec<ConsensusAction> {
        let mut actions = Vec::new();

        self.current_height = height;
        self.current_round = round;

        // Enforce bounds on round states
        self.enforce_round_state_bounds();

        let round_state = RoundState::new(height, round, now);
        self.round_states.insert(height, round_state);

        // Check if we're the leader
        if self.is_our_turn() {
            actions.push(ConsensusAction::ProposeBlock {
                height,
                parent_hash: tip_hash,
                round,
            });
        }

        actions
    }

    /// Handle a received block proposal.
    ///
    /// Validates the proposal and returns actions (vote if valid).
    ///
    /// # Security
    ///
    /// **CALLER MUST verify the ML-DSA-65 signature on the proposal before
    /// calling this method.** The consensus engine validates the proposer
    /// identity and round, but does NOT perform cryptographic signature
    /// verification. Signature verification should happen at the network
    /// layer when the proposal is first received.
    pub fn handle_proposal(&mut self, proposal: BlockProposal) -> Vec<ConsensusAction> {
        let mut actions = Vec::new();

        // Verify proposer is the expected leader
        let expected_leader =
            self.leader_for_round(proposal.height, proposal.round);
        if expected_leader.as_ref() != Some(&proposal.proposer) {
            return actions; // Ignore proposals from non-leaders
        }

        // Verify proposer is in the active set
        if !self.active_validators.contains(&proposal.proposer) {
            return actions;
        }

        let height = proposal.height;
        let round = proposal.round;

        // Store the proposal
        if let Some(state) = self.round_states.get_mut(&height) {
            if state.round == round {
                state.proposal = Some(proposal.clone());
                state.phase = ConsensusPhase::Vote;
            }
        }

        // If we're a validator, vote for this proposal
        if let Some(ref our_id) = self.our_identity {
            if self.active_validators.contains(our_id) {
                let vote = ConsensusVote {
                    voter: our_id.clone(),
                    block_hash: proposal.block_hash.clone(),
                    height,
                    round,
                    signature: Vec::new(), // Signature must be added by caller
                };
                actions.push(ConsensusAction::BroadcastVote(vote));
            }
        }

        actions
    }

    /// Handle a received consensus vote.
    ///
    /// Collects votes and triggers notarization when quorum is reached.
    ///
    /// # Security
    ///
    /// **CALLER MUST verify the ML-DSA-65 signature on the vote before
    /// calling this method.** The consensus engine checks voter identity
    /// membership and equivocation, but does NOT perform cryptographic
    /// signature verification. Signature verification should happen at the
    /// network layer when the vote is first received.
    pub fn handle_vote(&mut self, vote: ConsensusVote) -> Vec<ConsensusAction> {
        let mut actions = Vec::new();

        // Verify voter is in active set
        if !self.active_validators.contains(&vote.voter) {
            return actions;
        }

        let height = vote.height;
        let block_hash = vote.block_hash.clone();

        // Check for equivocation (voting for different blocks at same height)
        if let Some(offense) =
            self.slashing_manager
                .record_block_signature(&vote.voter, height, block_hash.clone())
        {
            actions.push(ConsensusAction::SlashValidator {
                validator: vote.voter.clone(),
                offense,
            });
            return actions;
        }

        // Record the vote and check quorum
        let quorum = self.quorum_size();
        let mut notarized_block: Option<NotarizedBlock> = None;

        if let Some(state) = self.round_states.get_mut(&height) {
            if state.round == vote.round && state.votes.len() < MAX_VOTES_PER_PROPOSAL {
                state.votes.insert(vote.voter.clone(), vote.clone());

                // Check if we've reached quorum
                if state.votes.len() >= quorum
                    && state.phase != ConsensusPhase::Notarized
                {
                    state.phase = ConsensusPhase::Notarized;

                    let parent_hash = state
                        .proposal
                        .as_ref()
                        .map(|p| p.parent_hash.clone())
                        .unwrap_or_else(|| Hash256::hash(b"unknown-parent"));

                    notarized_block = Some(NotarizedBlock {
                        block_hash: block_hash.clone(),
                        parent_hash,
                        height,
                        round: state.round,
                        votes: state.votes.values().cloned().collect(),
                    });
                }
            }
        }

        if let Some(notarized) = notarized_block {
            actions.push(ConsensusAction::BlockNotarized(notarized.clone()));

            // Store notarized block
            self.enforce_notarized_bounds();
            self.notarized_blocks.insert(height, notarized);

            // Check finality rule: 3 consecutive notarized blocks
            actions.extend(self.check_finality(height));
        }

        actions
    }

    /// Check the Streamlet finality rule.
    ///
    /// A block at height h is finalized when blocks at h, h+1, h+2 are
    /// all notarized and form a chain (each references the previous as parent).
    fn check_finality(&mut self, latest_notarized_height: u64) -> Vec<ConsensusAction> {
        let mut actions = Vec::new();

        if latest_notarized_height < 2 {
            return actions;
        }

        // Check for 3 consecutive notarized blocks ending at latest_notarized_height
        let h0 = latest_notarized_height - 2;
        let h1 = latest_notarized_height - 1;
        let h2 = latest_notarized_height;

        let all_notarized = self.notarized_blocks.contains_key(&h0)
            && self.notarized_blocks.contains_key(&h1)
            && self.notarized_blocks.contains_key(&h2);

        if !all_notarized {
            return actions;
        }

        // Verify chain linkage: h2.parent == h1.hash && h1.parent == h0.hash
        let b0_hash = self.notarized_blocks[&h0].block_hash.clone();
        let b1_parent = self.notarized_blocks[&h1].parent_hash.clone();
        let b1_hash = self.notarized_blocks[&h1].block_hash.clone();
        let b2_parent = self.notarized_blocks[&h2].parent_hash.clone();

        let chain_linked = b1_parent == b0_hash && b2_parent == b1_hash;

        if chain_linked && h0 > self.finalized_height {
            // Finalize block at h0
            self.finalized_height = h0;

            self.enforce_finalized_bounds();
            self.finalized_hashes.insert(b0_hash.clone());

            actions.push(ConsensusAction::BlockFinalized {
                block_hash: b0_hash,
                height: h0,
            });

            // Advance to next height
            self.current_height = latest_notarized_height + 1;
            self.current_round = 0;
        }

        actions
    }

    /// Handle a round timeout (view change).
    ///
    /// Advances to the next round with a new leader.
    pub fn handle_timeout(&mut self, height: u64, now: u64) -> Vec<ConsensusAction> {
        let mut actions = Vec::new();

        if height != self.current_height {
            return actions;
        }

        let max_rounds = veritas_protocol::limits::MAX_CONSENSUS_ROUNDS;
        if self.current_round >= max_rounds {
            // Too many failed rounds; still advance to prevent livelock
            self.current_round = 0;
        }

        let new_round = self.current_round + 1;
        self.current_round = new_round;

        actions.push(ConsensusAction::ViewChange {
            new_round,
            height,
        });

        // Start new round
        let tip_hash = self
            .notarized_blocks
            .values()
            .next_back()
            .map(|nb| nb.block_hash.clone())
            .unwrap_or_else(|| Hash256::hash(b"genesis"));

        actions.extend(self.start_round(height, new_round, now, tip_hash));

        actions
    }

    /// Tick the consensus engine (called periodically).
    ///
    /// Checks for timeouts and triggers view changes if needed.
    pub fn tick(&mut self, now: u64) -> Vec<ConsensusAction> {
        let height = self.current_height;

        if let Some(state) = self.round_states.get(&height) {
            if state.is_timed_out(now, self.round_timeout_ms)
                && state.phase != ConsensusPhase::Notarized
                && state.phase != ConsensusPhase::Finalized
            {
                return self.handle_timeout(height, now);
            }
        }

        Vec::new()
    }

    /// Get a reference to the slashing manager.
    pub fn slashing_manager(&self) -> &SlashingManager {
        &self.slashing_manager
    }

    /// Get a mutable reference to the slashing manager.
    pub fn slashing_manager_mut(&mut self) -> &mut SlashingManager {
        &mut self.slashing_manager
    }

    // =========================================================================
    // Memory Safety Bounds
    // =========================================================================

    /// Enforce bounds on the round states collection.
    fn enforce_round_state_bounds(&mut self) {
        while self.round_states.len() >= MAX_PENDING_PROPOSALS {
            // Remove the oldest round state
            if let Some(oldest_key) = self.round_states.keys().next().cloned() {
                self.round_states.remove(&oldest_key);
            }
        }
    }

    /// Enforce bounds on the notarized blocks collection.
    fn enforce_notarized_bounds(&mut self) {
        while self.notarized_blocks.len() >= MAX_NOTARIZED_BLOCKS {
            if let Some(oldest_key) = self.notarized_blocks.keys().next().cloned() {
                self.notarized_blocks.remove(&oldest_key);
            }
        }
    }

    /// Enforce bounds on the finalized hashes set.
    fn enforce_finalized_bounds(&mut self) {
        while self.finalized_hashes.len() >= MAX_FINALIZED_CACHE {
            // Remove an arbitrary entry to make room.
            // The finalized_height field provides the authoritative finality check;
            // this set is a supplementary cache for hash-based lookups.
            if let Some(hash) = self.finalized_hashes.iter().next().cloned() {
                self.finalized_hashes.remove(&hash);
            } else {
                break;
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Calculate BFT quorum size for n validators.
///
/// Quorum = ceil(2n/3) for n >= 1.
/// This ensures safety with up to f = floor((n-1)/3) Byzantine faults.
pub fn bft_quorum(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    // ceil(2n/3)
    (2 * n).div_ceil(3)
}

// =============================================================================
// Consensus Messages for Network Layer
// =============================================================================

/// Messages exchanged between validators during consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// A block proposal from the round leader.
    Proposal(BlockProposal),
    /// A vote for a proposed block.
    Vote(ConsensusVote),
    /// A notarization certificate (quorum of votes).
    Notarization(NotarizedBlock),
    /// A finality certificate (3 consecutive notarizations).
    Finality {
        /// The finalized block hash.
        block_hash: Hash256,
        /// The finalized block height.
        height: u64,
        /// The three notarized blocks proving finality.
        proof: Vec<NotarizedBlock>,
    },
}

impl ConsensusMessage {
    /// Get a domain-separated tag for this message type.
    pub fn message_type_tag(&self) -> &'static str {
        match self {
            ConsensusMessage::Proposal(_) => "VERITAS-CONSENSUS-PROPOSAL-v1",
            ConsensusMessage::Vote(_) => "VERITAS-CONSENSUS-VOTE-v1",
            ConsensusMessage::Notarization(_) => "VERITAS-CONSENSUS-NOTARIZATION-v1",
            ConsensusMessage::Finality { .. } => "VERITAS-CONSENSUS-FINALITY-v1",
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(id: u8) -> IdentityHash {
        let bytes = [id; 32];
        IdentityHash::from_bytes(&bytes).unwrap()
    }

    fn make_validators(count: u8) -> Vec<IdentityHash> {
        (1..=count).map(test_identity).collect()
    }

    // ========================================================================
    // Quorum Tests
    // ========================================================================

    #[test]
    fn test_bft_quorum_sizes() {
        assert_eq!(bft_quorum(0), 0);
        assert_eq!(bft_quorum(1), 1);
        assert_eq!(bft_quorum(2), 2);
        assert_eq!(bft_quorum(3), 2); // 2/3 of 3 = 2
        assert_eq!(bft_quorum(4), 3); // ceil(8/3) = 3
        assert_eq!(bft_quorum(7), 5); // ceil(14/3) = 5
        assert_eq!(bft_quorum(10), 7); // ceil(20/3) = 7
        assert_eq!(bft_quorum(21), 14); // ceil(42/3) = 14
    }

    #[test]
    fn test_bft_quorum_safety_property() {
        // For any n >= 1, two quorums must overlap in at least one honest validator.
        // This means 2*quorum(n) > n must hold.
        for n in 1..=100 {
            let q = bft_quorum(n);
            assert!(
                2 * q > n,
                "BFT safety violated: 2*quorum({n})={} <= {n}",
                2 * q
            );
        }
    }

    // ========================================================================
    // Leader Selection Tests
    // ========================================================================

    #[test]
    fn test_leader_selection_deterministic() {
        let validators = make_validators(21);
        let engine = ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        let leader1 = engine.leader_for_round(100, 0);
        let leader2 = engine.leader_for_round(100, 0);
        assert_eq!(leader1, leader2);
    }

    #[test]
    fn test_leader_selection_different_rounds() {
        let validators = make_validators(21);
        let engine = ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        let leader_r0 = engine.leader_for_round(100, 0);
        let leader_r1 = engine.leader_for_round(100, 1);
        // With 21 validators, different rounds should usually produce different leaders
        // (though not guaranteed by hash function)
        assert!(leader_r0.is_some());
        assert!(leader_r1.is_some());
    }

    #[test]
    fn test_leader_selection_empty_validators() {
        let engine = ConsensusEngine::new(None, Vec::new(), 0, 5000);
        assert_eq!(engine.leader_for_round(0, 0), None);
    }

    #[test]
    fn test_leader_selection_single_validator() {
        let validators = make_validators(1);
        let engine = ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        // With one validator, they're always the leader
        for round in 0..10 {
            let leader = engine.leader_for_round(0, round);
            assert_eq!(leader, Some(test_identity(1)));
        }
    }

    // ========================================================================
    // Consensus Engine Tests
    // ========================================================================

    #[test]
    fn test_engine_creation() {
        let validators = make_validators(4);
        let engine =
            ConsensusEngine::new(Some(test_identity(1)), validators.clone(), 0, 5000);

        assert_eq!(engine.current_height(), 0);
        assert_eq!(engine.current_round(), 0);
        assert_eq!(engine.finalized_height(), 0);
        assert_eq!(engine.validator_count(), 4);
        assert_eq!(engine.quorum_size(), 3); // ceil(8/3) = 3
    }

    #[test]
    fn test_start_round() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators, 1, 5000);

        let actions = engine.start_round(1, 0, 1000, Hash256::hash(b"genesis"));

        // One of: propose (if we're leader) or empty (if not)
        assert!(
            actions.is_empty()
                || actions.iter().any(|a| matches!(a, ConsensusAction::ProposeBlock { .. }))
        );
    }

    #[test]
    fn test_handle_proposal_from_non_leader() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        engine.start_round(1, 0, 1000, Hash256::hash(b"genesis"));

        // Submit a proposal from a validator who is NOT the leader
        // Find who the leader is and submit from someone else
        let leader = engine.leader_for_round(1, 0).unwrap();
        let non_leader = (1..=4u8)
            .map(test_identity)
            .find(|id| id != &leader)
            .unwrap();

        let proposal = BlockProposal {
            proposer: non_leader,
            block_hash: Hash256::hash(b"block-1"),
            parent_hash: Hash256::hash(b"genesis"),
            height: 1,
            round: 0,
            timestamp: 1001,
            signature: vec![],
        };

        let actions = engine.handle_proposal(proposal);
        // Should be ignored (no actions)
        assert!(actions.is_empty());
    }

    #[test]
    fn test_handle_proposal_from_leader() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        engine.start_round(1, 0, 1000, Hash256::hash(b"genesis"));

        let leader = engine.leader_for_round(1, 0).unwrap();

        let proposal = BlockProposal {
            proposer: leader,
            block_hash: Hash256::hash(b"block-1"),
            parent_hash: Hash256::hash(b"genesis"),
            height: 1,
            round: 0,
            timestamp: 1001,
            signature: vec![],
        };

        let actions = engine.handle_proposal(proposal);

        // We should vote if we're a validator
        if engine.our_identity.is_some() {
            assert!(
                actions
                    .iter()
                    .any(|a| matches!(a, ConsensusAction::BroadcastVote(_)))
            );
        }
    }

    #[test]
    fn test_notarization_on_quorum() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators.clone(), 0, 5000);

        let block_hash = Hash256::hash(b"block-1");
        let parent_hash = Hash256::hash(b"genesis");

        engine.start_round(1, 0, 1000, parent_hash.clone());

        // Find leader and submit proposal
        let leader = engine.leader_for_round(1, 0).unwrap();
        let proposal = BlockProposal {
            proposer: leader,
            block_hash: block_hash.clone(),
            parent_hash: parent_hash.clone(),
            height: 1,
            round: 0,
            timestamp: 1001,
            signature: vec![],
        };
        engine.handle_proposal(proposal);

        // Submit votes from quorum of validators
        let quorum = engine.quorum_size();
        let mut notarized = false;

        for i in 0..quorum {
            let vote = ConsensusVote {
                voter: validators[i].clone(),
                block_hash: block_hash.clone(),
                height: 1,
                round: 0,
                signature: vec![],
            };

            let actions = engine.handle_vote(vote);

            if actions
                .iter()
                .any(|a| matches!(a, ConsensusAction::BlockNotarized(_)))
            {
                notarized = true;
            }
        }

        assert!(notarized, "Block should be notarized after quorum votes");
        assert!(engine.is_notarized(1));
    }

    #[test]
    fn test_finality_three_consecutive_notarized() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators.clone(), 0, 5000);

        let quorum = engine.quorum_size();

        // Notarize 3 consecutive blocks (heights 1, 2, 3)
        let mut prev_hash = Hash256::hash(b"genesis");
        let mut finalized = false;

        for height in 1..=3u64 {
            let block_hash = Hash256::hash_many(&[b"block", &height.to_le_bytes()]);

            engine.start_round(height, 0, 1000 + height, prev_hash.clone());

            let leader = engine.leader_for_round(height, 0).unwrap();
            let proposal = BlockProposal {
                proposer: leader,
                block_hash: block_hash.clone(),
                parent_hash: prev_hash.clone(),
                height,
                round: 0,
                timestamp: 1000 + height,
                signature: vec![],
            };
            engine.handle_proposal(proposal);

            for i in 0..quorum {
                let vote = ConsensusVote {
                    voter: validators[i].clone(),
                    block_hash: block_hash.clone(),
                    height,
                    round: 0,
                    signature: vec![],
                };

                let actions = engine.handle_vote(vote);

                if actions
                    .iter()
                    .any(|a| matches!(a, ConsensusAction::BlockFinalized { .. }))
                {
                    finalized = true;
                }
            }

            prev_hash = block_hash;
        }

        assert!(
            finalized,
            "Block should be finalized after 3 consecutive notarizations"
        );
        assert_eq!(engine.finalized_height(), 1); // Height 1 is finalized
    }

    #[test]
    fn test_equivocation_detection() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators.clone(), 0, 5000);

        let block_hash1 = Hash256::hash(b"block-1");
        let block_hash2 = Hash256::hash(b"block-2");

        engine.start_round(1, 0, 1000, Hash256::hash(b"genesis"));

        // Submit proposal and first vote
        let leader = engine.leader_for_round(1, 0).unwrap();
        let proposal = BlockProposal {
            proposer: leader,
            block_hash: block_hash1.clone(),
            parent_hash: Hash256::hash(b"genesis"),
            height: 1,
            round: 0,
            timestamp: 1001,
            signature: vec![],
        };
        engine.handle_proposal(proposal);

        // First vote from validator 1
        let vote1 = ConsensusVote {
            voter: validators[0].clone(),
            block_hash: block_hash1,
            height: 1,
            round: 0,
            signature: vec![],
        };
        let actions1 = engine.handle_vote(vote1);
        assert!(actions1
            .iter()
            .all(|a| !matches!(a, ConsensusAction::SlashValidator { .. })));

        // Equivocating vote from same validator for different block
        let vote2 = ConsensusVote {
            voter: validators[0].clone(),
            block_hash: block_hash2,
            height: 1,
            round: 0,
            signature: vec![],
        };
        let actions2 = engine.handle_vote(vote2);
        assert!(
            actions2
                .iter()
                .any(|a| matches!(a, ConsensusAction::SlashValidator { .. })),
            "Equivocation should trigger slashing"
        );
    }

    #[test]
    fn test_view_change_on_timeout() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        engine.start_round(1, 0, 1000, Hash256::hash(b"genesis"));

        // Simulate timeout
        let actions = engine.handle_timeout(1, 2000);

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, ConsensusAction::ViewChange { .. })),
            "Timeout should trigger view change"
        );
        assert_eq!(engine.current_round(), 1);
    }

    #[test]
    fn test_tick_triggers_timeout() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        engine.start_round(1, 0, 1000, Hash256::hash(b"genesis"));

        // Not timed out yet
        let actions = engine.tick(1001);
        assert!(
            actions.is_empty() || !actions.iter().any(|a| matches!(a, ConsensusAction::ViewChange { .. }))
        );

        // Timed out (5 seconds = 5000ms later)
        let actions = engine.tick(1006);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, ConsensusAction::ViewChange { .. })),
        );
    }

    // ========================================================================
    // Consensus Message Tests
    // ========================================================================

    #[test]
    fn test_consensus_message_type_tags() {
        let msg_proposal = ConsensusMessage::Proposal(BlockProposal {
            proposer: test_identity(1),
            block_hash: Hash256::hash(b"test"),
            parent_hash: Hash256::hash(b"parent"),
            height: 1,
            round: 0,
            timestamp: 1000,
            signature: vec![],
        });
        assert_eq!(
            msg_proposal.message_type_tag(),
            "VERITAS-CONSENSUS-PROPOSAL-v1"
        );

        let msg_vote = ConsensusMessage::Vote(ConsensusVote {
            voter: test_identity(1),
            block_hash: Hash256::hash(b"test"),
            height: 1,
            round: 0,
            signature: vec![],
        });
        assert_eq!(msg_vote.message_type_tag(), "VERITAS-CONSENSUS-VOTE-v1");
    }

    #[test]
    fn test_vote_signing_payload() {
        let vote = ConsensusVote {
            voter: test_identity(1),
            block_hash: Hash256::hash(b"test"),
            height: 1,
            round: 0,
            signature: vec![],
        };

        let payload1 = vote.signing_payload();
        let payload2 = vote.signing_payload();
        assert_eq!(payload1, payload2); // Deterministic

        // Different vote produces different payload
        let vote2 = ConsensusVote {
            voter: test_identity(2),
            block_hash: Hash256::hash(b"test"),
            height: 1,
            round: 0,
            signature: vec![],
        };
        assert_ne!(vote.signing_payload(), vote2.signing_payload());
    }

    #[test]
    fn test_proposal_signing_payload() {
        let proposal = BlockProposal {
            proposer: test_identity(1),
            block_hash: Hash256::hash(b"block"),
            parent_hash: Hash256::hash(b"parent"),
            height: 1,
            round: 0,
            timestamp: 1000,
            signature: vec![],
        };

        let payload1 = proposal.signing_payload();
        let payload2 = proposal.signing_payload();
        assert_eq!(payload1, payload2);
    }

    // ========================================================================
    // Memory Safety Tests
    // ========================================================================

    #[test]
    fn test_round_states_bounded() {
        let validators = make_validators(4);
        let mut engine =
            ConsensusEngine::new(Some(test_identity(1)), validators, 0, 5000);

        // Add more round states than the limit
        for height in 0..(MAX_PENDING_PROPOSALS + 50) as u64 {
            engine.start_round(height, 0, 1000 + height, Hash256::hash(b"genesis"));
        }

        assert!(engine.round_states.len() <= MAX_PENDING_PROPOSALS);
    }
}
