"""
QRTB Validator Node
- Complete validator implementation
- Coordinates crypto, measurement, detection, consensus
- Epoch lifecycle management
"""

import time
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
from enum import Enum

from .crypto import (
    sha3_256, sha3_512, concat, secure_random,
    WOTSPlus, TemporalKey, MerkleTree
)
from .measurement import (
    MeasurementProtocol, PeerInfo, RTTMeasurement,
    MeasurementCommitment, MeasurementReveal,
    get_random_location, ZONE_LOCATIONS
)
from .detection import DetectionEngine, DetectionResult
from .epoch import EpochManager, EntropyWell, EpochPhase
from .consensus import BFTConsensus, ConsensusProposal, ConsensusVote, ConsensusBlock

# =============================================================================
# VALIDATOR STATE
# =============================================================================

class ValidatorState(Enum):
    """Validator operational state"""
    INITIALIZING = 0
    SYNCING = 1
    ACTIVE = 2
    MEASURING = 3
    VOTING = 4
    SLASHED = 5
    OFFLINE = 6


@dataclass
class ValidatorConfig:
    """Configuration for a validator"""
    zone_id: int
    stake: int
    location: Optional[Tuple[float, float]] = None
    city: Optional[str] = None
    is_adversary: bool = False
    
    def __post_init__(self):
        if self.location is None:
            self.city, self.location = get_random_location(self.zone_id)


@dataclass
class ValidatorStats:
    """Performance statistics for a validator"""
    epochs_participated: int = 0
    blocks_proposed: int = 0
    votes_cast: int = 0
    measurements_made: int = 0
    detection_flags: int = 0
    slashing_proposals: int = 0


# =============================================================================
# VALIDATOR NODE
# =============================================================================

class ValidatorNode:
    """
    Complete QRTB validator node implementation
    """
    
    def __init__(self, config: ValidatorConfig, genesis_time: Optional[float] = None):
        self.config = config
        self.validator_id = secure_random(32)
        self.state = ValidatorState.INITIALIZING
        self.stats = ValidatorStats()
        
        # Cryptographic components
        self.wots = WOTSPlus()
        self.temporal_key = TemporalKey.create()
        
        # Protocol components
        self.epoch_manager = EpochManager(genesis_time)
        self.measurement_protocol = MeasurementProtocol(
            validator_id=self.validator_id,
            location=config.location,
            zone_id=config.zone_id
        )
        self.consensus = BFTConsensus(
            validator_id=self.validator_id,
            stake=config.stake
        )
        
        # Peer registry
        self.peers: Dict[bytes, 'ValidatorNode'] = {}
        
        # Message queues (for simulation)
        self.inbox: List[Tuple[str, any]] = []
        self.outbox: List[Tuple[str, bytes, any]] = []  # (msg_type, target, data)
        
        # Current epoch state
        self.current_measurements: List[RTTMeasurement] = []
        self.current_commitment: Optional[MeasurementCommitment] = None
        
        # Logging
        self.log_callback: Optional[Callable] = None
    
    def log(self, message: str) -> None:
        """Log a message"""
        if self.log_callback:
            self.log_callback(f"[{self.validator_id.hex()[:8]}] {message}")
    
    # =========================================================================
    # PEER MANAGEMENT
    # =========================================================================
    
    def add_peer(self, peer: 'ValidatorNode') -> None:
        """Add a peer validator"""
        self.peers[peer.validator_id] = peer
        
        # Add to measurement protocol
        peer_info = PeerInfo(
            validator_id=peer.validator_id,
            location=peer.config.location,
            zone_id=peer.config.zone_id,
            stake=peer.config.stake,
            last_seen=time.time()
        )
        self.measurement_protocol.add_peer(peer_info)
        
        # Add to consensus
        self.consensus.register_validator(peer.validator_id, peer.config.stake)
    
    def remove_peer(self, peer_id: bytes) -> None:
        """Remove a peer validator"""
        self.peers.pop(peer_id, None)
        self.measurement_protocol.remove_peer(peer_id)
    
    # =========================================================================
    # EPOCH LIFECYCLE
    # =========================================================================
    
    def start_epoch(self, epoch: int) -> None:
        """Begin a new epoch"""
        self.log(f"Starting epoch {epoch}")
        self.state = ValidatorState.ACTIVE
        
        # Get epoch entropy and evolve key
        _, entropy = self.epoch_manager.advance_epoch()
        self.temporal_key.evolve(entropy.combined_entropy)
        
        # Reset protocol state
        self.measurement_protocol.start_epoch(epoch)
        self.consensus.start_round(epoch)
        
        self.current_measurements = []
        self.current_commitment = None
        self.stats.epochs_participated += 1
    
    def run_measurement_phase(self) -> List[RTTMeasurement]:
        """Execute measurement phase"""
        self.state = ValidatorState.MEASURING
        self.log("Running measurement phase")
        
        # Select targets
        self.measurement_protocol.select_targets()
        
        # Execute measurements (simulated based on distance)
        measurements = self.measurement_protocol.execute_measurements(
            is_adversary=self.config.is_adversary
        )
        
        self.current_measurements = measurements
        self.stats.measurements_made += len(measurements)
        
        return measurements
    
    def create_measurement_commitment(self) -> MeasurementCommitment:
        """Create commitment to measurements"""
        self.current_commitment = self.measurement_protocol.create_commitment()
        return self.current_commitment
    
    def broadcast_commitment(self) -> None:
        """Broadcast commitment to all peers"""
        if self.current_commitment is None:
            return
        
        for peer_id in self.peers:
            self.outbox.append((
                "commitment",
                peer_id,
                self.current_commitment
            ))
    
    def receive_commitment(self, commitment: MeasurementCommitment) -> bool:
        """Receive commitment from peer"""
        return self.measurement_protocol.receive_commitment(commitment)
    
    def create_reveal(self) -> MeasurementReveal:
        """Create reveal with measurements"""
        return self.measurement_protocol.create_reveal()
    
    def broadcast_reveal(self) -> None:
        """Broadcast reveal to all peers"""
        reveal = self.create_reveal()
        
        for peer_id in self.peers:
            self.outbox.append((
                "reveal",
                peer_id,
                reveal
            ))
    
    def receive_reveal(self, reveal: MeasurementReveal) -> Tuple[bool, str]:
        """Receive reveal from peer"""
        return self.measurement_protocol.receive_reveal(reveal)
    
    # =========================================================================
    # CONSENSUS
    # =========================================================================
    
    def run_consensus_phase(self) -> Optional[ConsensusBlock]:
        """Run complete consensus phase"""
        self.state = ValidatorState.VOTING
        self.log("Running consensus phase")
        
        # Collect all measurements
        all_measurements = self.measurement_protocol.get_all_measurements()
        locations = {vid: peer.config.location for vid, peer in self.peers.items()}
        locations[self.validator_id] = self.config.location
        
        # Check if we're proposer
        if self.consensus.am_i_proposer():
            self.log("I am the proposer")
            proposal = self.consensus.create_proposal(
                measurements=all_measurements,
                locations=locations
            )
            self.stats.blocks_proposed += 1
            self.broadcast_proposal(proposal)
        
        # Wait for proposal and vote
        # (In simulation, this is handled by the network coordinator)
        
        return None  # Block returned after voting completes
    
    def broadcast_proposal(self, proposal: ConsensusProposal) -> None:
        """Broadcast proposal to all peers"""
        for peer_id in self.peers:
            self.outbox.append((
                "proposal",
                peer_id,
                proposal
            ))
    
    def receive_proposal(self, proposal: ConsensusProposal) -> Tuple[bool, str]:
        """Receive proposal from peer"""
        valid, reason = self.consensus.receive_proposal(proposal)
        if valid:
            # Automatically pre-vote for valid proposals
            vote = self.consensus.create_pre_vote(proposal.proposal_hash)
            self.broadcast_vote(vote)
            self.stats.votes_cast += 1
        return valid, reason
    
    def broadcast_vote(self, vote: ConsensusVote) -> None:
        """Broadcast vote to all peers"""
        for peer_id in self.peers:
            self.outbox.append((
                "vote",
                peer_id,
                vote
            ))
    
    def receive_vote(self, vote: ConsensusVote) -> Tuple[bool, str]:
        """Receive vote from peer"""
        if vote.vote_type == "pre-vote":
            valid, reason = self.consensus.receive_pre_vote(vote)
            if valid:
                # Check if we should pre-commit
                threshold, _ = self.consensus.check_pre_vote_threshold(vote.proposal_hash)
                if threshold:
                    commit_vote = self.consensus.create_pre_commit(vote.proposal_hash)
                    if commit_vote:
                        self.broadcast_vote(commit_vote)
                        self.stats.votes_cast += 1
        else:
            valid, reason = self.consensus.receive_pre_commit(vote)
            if valid:
                # Check if we can finalize
                threshold, _ = self.consensus.check_pre_commit_threshold(vote.proposal_hash)
                if threshold:
                    block = self.consensus.try_finalize(vote.proposal_hash)
                    if block:
                        self.on_block_finalized(block)
        
        return valid, reason
    
    def on_block_finalized(self, block: ConsensusBlock) -> None:
        """Handle finalized block"""
        self.log(f"Block finalized for epoch {block.epoch}")
        self.state = ValidatorState.ACTIVE
        
        # Update epoch manager
        self.epoch_manager.finalize_epoch(block.epoch, block.block_hash)
        
        # Process detection results - flag suspicious validators
        for vid, result in block.proposal.detection_results.items():
            if result.is_suspicious:
                self.log(f"Flagged suspicious validator: {vid.hex()[:8]}")
                self.stats.detection_flags += 1
    
    # =========================================================================
    # MESSAGE PROCESSING
    # =========================================================================
    
    def process_inbox(self) -> None:
        """Process all messages in inbox"""
        while self.inbox:
            msg_type, data = self.inbox.pop(0)
            
            if msg_type == "commitment":
                self.receive_commitment(data)
            elif msg_type == "reveal":
                self.receive_reveal(data)
            elif msg_type == "proposal":
                self.receive_proposal(data)
            elif msg_type == "vote":
                self.receive_vote(data)
    
    def deliver_outbox(self) -> List[Tuple[str, bytes, any]]:
        """Get and clear outbox messages"""
        messages = self.outbox.copy()
        self.outbox.clear()
        return messages
    
    # =========================================================================
    # FULL EPOCH SIMULATION
    # =========================================================================
    
    def simulate_full_epoch(self) -> Optional[ConsensusBlock]:
        """
        Simulate a complete epoch (for single-node testing)
        """
        epoch = self.epoch_manager.get_current_epoch()
        self.start_epoch(epoch)
        
        # Measurement phase
        self.run_measurement_phase()
        self.create_measurement_commitment()
        
        # In single-node mode, just finalize with our own measurements
        if not self.peers:
            locations = {self.validator_id: self.config.location}
            measurements = {self.validator_id: self.current_measurements}
            
            proposal = self.consensus.create_proposal(
                measurements=measurements,
                locations=locations
            )
            
            # Self-vote
            vote = self.consensus.create_pre_vote(proposal.proposal_hash)
            self.consensus.receive_pre_vote(vote)
            
            commit = self.consensus.create_pre_commit(proposal.proposal_hash)
            if commit:
                self.consensus.receive_pre_commit(commit)
            
            block = self.consensus.try_finalize(proposal.proposal_hash)
            if block:
                self.on_block_finalized(block)
                return block
        
        return None
    
    # =========================================================================
    # STATUS
    # =========================================================================
    
    def get_status(self) -> dict:
        """Get validator status"""
        return {
            "validator_id": self.validator_id.hex()[:16] + "...",
            "state": self.state.name,
            "zone_id": self.config.zone_id,
            "city": self.config.city,
            "stake": self.config.stake,
            "is_adversary": self.config.is_adversary,
            "current_epoch": self.epoch_manager.current_epoch,
            "peer_count": len(self.peers),
            "stats": {
                "epochs": self.stats.epochs_participated,
                "blocks_proposed": self.stats.blocks_proposed,
                "votes_cast": self.stats.votes_cast,
                "measurements": self.stats.measurements_made,
                "detection_flags": self.stats.detection_flags,
            },
            "consensus": self.consensus.get_consensus_stats(),
        }
