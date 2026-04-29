"""
QRTB BFT Consensus
- Measurement-based proposal generation
- Three-phase voting (pre-vote, pre-commit, commit)
- Stake-weighted finalization
- Physics-bounded timing
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum
from collections import defaultdict

from .crypto import sha3_256, sha3_512, concat, WOTSPlus
from .measurement import RTTMeasurement, MeasurementReveal
from .detection import DetectionEngine, DetectionResult, aggregate_detection_results
from .epoch import EpochEntropy

# =============================================================================
# CONSTANTS
# =============================================================================

# BFT threshold: need 67% (2/3 + 1) of stake
BFT_THRESHOLD = 0.67

# Consensus phases timeout (milliseconds)
COMMIT_TIMEOUT_MS = 100
REVEAL_TIMEOUT_MS = 100
VOTE_TIMEOUT_MS = 200
FINALIZE_TIMEOUT_MS = 200

# =============================================================================
# CONSENSUS DATA STRUCTURES
# =============================================================================

class ConsensusPhase(Enum):
    """Phases of BFT consensus"""
    IDLE = 0
    PROPOSE = 1
    PRE_VOTE = 2
    PRE_COMMIT = 3
    COMMIT = 4
    FINALIZED = 5


@dataclass
class ConsensusProposal:
    """
    Block proposal containing aggregated measurements
    """
    proposer_id: bytes
    epoch: int
    round: int
    
    # Aggregated measurement data
    measurement_root: bytes  # Merkle root of all measurements
    detection_results: Dict[bytes, DetectionResult] = field(default_factory=dict)
    
    # Block content
    transaction_root: bytes = b""
    state_root: bytes = b""
    
    # Metadata
    timestamp: int = 0
    signature: bytes = b""
    
    @property
    def proposal_hash(self) -> bytes:
        """Hash of proposal for voting"""
        return sha3_256(concat(
            self.proposer_id,
            self.epoch,
            self.round,
            self.measurement_root,
            self.transaction_root,
            self.state_root
        ))


@dataclass
class ConsensusVote:
    """Vote on a proposal"""
    voter_id: bytes
    epoch: int
    round: int
    proposal_hash: bytes
    vote_type: str  # "pre-vote" or "pre-commit"
    stake: int
    timestamp: int
    signature: bytes = b""
    
    def vote_hash(self) -> bytes:
        """Hash of vote for verification"""
        return sha3_256(concat(
            self.voter_id,
            self.proposal_hash,
            self.vote_type,
            self.stake
        ))


@dataclass 
class ConsensusBlock:
    """Finalized block"""
    epoch: int
    round: int
    proposal: ConsensusProposal
    votes: List[ConsensusVote]
    total_stake: int
    supporting_stake: int
    finalization_time: float
    block_hash: bytes = b""
    
    def __post_init__(self):
        self.block_hash = sha3_256(concat(
            self.proposal.proposal_hash,
            self.total_stake,
            self.supporting_stake,
            int(self.finalization_time * 1000)
        ))


# =============================================================================
# BFT CONSENSUS ENGINE
# =============================================================================

class BFTConsensus:
    """
    Byzantine Fault Tolerant consensus on measurements
    
    Three-phase voting:
    1. PRE-VOTE: Vote on proposal validity
    2. PRE-COMMIT: Vote to commit if 67% pre-voted
    3. COMMIT: Finalize if 67% pre-committed
    """
    
    def __init__(self, validator_id: bytes, stake: int):
        self.validator_id = validator_id
        self.stake = stake

        # Current state
        self.current_epoch = 0
        self.current_round = 0
        self.phase = ConsensusPhase.IDLE

        # Proposals and votes
        self.current_proposal: Optional[ConsensusProposal] = None
        self.received_proposals: Dict[bytes, ConsensusProposal] = {}
        self.pre_votes: Dict[bytes, List[ConsensusVote]] = defaultdict(list)
        self.pre_commits: Dict[bytes, List[ConsensusVote]] = defaultdict(list)

        # O(1) equivocation tracking: voter_id -> proposal_hash they voted for
        self._pre_vote_choices: Dict[bytes, bytes] = {}
        self._pre_commit_choices: Dict[bytes, bytes] = {}

        # Validator registry -- self-register so am_i_proposer() and
        # threshold math include this node from the start
        self.validators: Dict[bytes, int] = {}
        self.total_stake = 0
        self.register_validator(self.validator_id, self.stake)

        # Detection engine
        self.detection_engine = DetectionEngine()
        
        # Finalized blocks
        self.finalized_blocks: Dict[int, ConsensusBlock] = {}
    
    def register_validator(self, validator_id: bytes, stake: int) -> None:
        """Register a validator with their stake"""
        self.validators[validator_id] = stake
        self.total_stake = sum(self.validators.values())
    
    def start_round(self, epoch: int, round_num: int = 0) -> None:
        """Start a new consensus round"""
        self.current_epoch = epoch
        self.current_round = round_num
        self.phase = ConsensusPhase.PROPOSE
        self.current_proposal = None
        self.received_proposals.clear()
        self.pre_votes.clear()
        self.pre_commits.clear()
        self._pre_vote_choices.clear()
        self._pre_commit_choices.clear()
    
    def am_i_proposer(self) -> bool:
        """
        Determine if this validator is the proposer for this round
        
        Uses deterministic selection based on epoch + round
        """
        if not self.validators:
            return True
        
        # Deterministic proposer selection
        seed = sha3_256(concat(
            b"proposer",
            self.current_epoch,
            self.current_round
        ))
        selection_value = int.from_bytes(seed[:8], 'big')
        
        # Stake-weighted selection
        target = selection_value % self.total_stake
        cumulative = 0
        for vid, stake in sorted(self.validators.items()):
            cumulative += stake
            if cumulative > target:
                return vid == self.validator_id
        
        return False
    
    def create_proposal(self, 
                       measurements: Dict[bytes, List[RTTMeasurement]],
                       locations: Dict[bytes, Tuple[float, float]],
                       transaction_root: bytes = b"",
                       state_root: bytes = b"") -> ConsensusProposal:
        """
        Create block proposal from measurements
        """
        # Run detection on all measurements
        self.detection_engine.load_measurements(measurements, locations)
        detection_results = self.detection_engine.analyze_all()
        
        # Create measurement Merkle root
        measurement_hashes = []
        for vid, mlist in measurements.items():
            for m in mlist:
                measurement_hashes.append(m.commitment())
        
        if measurement_hashes:
            measurement_hashes.sort()
            measurement_root = sha3_256(b"".join(measurement_hashes))
        else:
            measurement_root = sha3_256(b"empty")
        
        proposal = ConsensusProposal(
            proposer_id=self.validator_id,
            epoch=self.current_epoch,
            round=self.current_round,
            measurement_root=measurement_root,
            detection_results=detection_results,
            transaction_root=transaction_root,
            state_root=state_root,
            timestamp=int(time.time() * 1000)
        )
        
        self.current_proposal = proposal
        self.received_proposals[proposal.proposal_hash] = proposal
        self.phase = ConsensusPhase.PRE_VOTE
        
        return proposal
    
    def _expected_proposer(self) -> Optional[bytes]:
        """Compute the deterministic proposer for this epoch+round."""
        if not self.validators:
            return None
        seed = sha3_256(concat(
            b"proposer",
            self.current_epoch,
            self.current_round
        ))
        selection_value = int.from_bytes(seed[:8], 'big')
        target = selection_value % self.total_stake
        cumulative = 0
        for vid, stake in sorted(self.validators.items()):
            cumulative += stake
            if cumulative > target:
                return vid
        return None

    def receive_proposal(self, proposal: ConsensusProposal) -> Tuple[bool, str]:
        """Receive and validate a proposal"""
        if proposal.epoch != self.current_epoch:
            return False, "wrong epoch"
        if proposal.round != self.current_round:
            return False, "wrong round"

        if proposal.proposer_id not in self.validators:
            return False, "unknown proposer"

        # Enforce deterministic proposer selection
        expected = self._expected_proposer()
        if expected is not None and proposal.proposer_id != expected:
            return False, "proposer not selected for this epoch+round"

        self.received_proposals[proposal.proposal_hash] = proposal
        return True, "valid"
    
    def create_pre_vote(self, proposal_hash: bytes) -> ConsensusVote:
        """Create pre-vote for a proposal"""
        vote = ConsensusVote(
            voter_id=self.validator_id,
            epoch=self.current_epoch,
            round=self.current_round,
            proposal_hash=proposal_hash,
            vote_type="pre-vote",
            stake=self.stake,
            timestamp=int(time.time() * 1000)
        )
        
        self.pre_votes[proposal_hash].append(vote)
        return vote
    
    def receive_pre_vote(self, vote: ConsensusVote) -> Tuple[bool, str]:
        """Receive and validate a pre-vote"""
        if vote.epoch != self.current_epoch:
            return False, "wrong epoch"
        if vote.vote_type != "pre-vote":
            return False, "wrong vote type"
        if vote.voter_id not in self.validators:
            return False, "unknown voter"

        # Enforce registered stake -- ignore self-reported vote.stake
        vote.stake = self.validators[vote.voter_id]

        # O(1) equivocation detection
        prev = self._pre_vote_choices.get(vote.voter_id)
        if prev is not None and prev != vote.proposal_hash:
            return False, "equivocation: voter already pre-voted for different proposal"

        self._pre_vote_choices[vote.voter_id] = vote.proposal_hash
        self.pre_votes[vote.proposal_hash].append(vote)
        return True, "valid"

    def check_pre_vote_threshold(self, proposal_hash: bytes) -> Tuple[bool, float]:
        """Check if proposal has 67% pre-vote stake"""
        votes = self.pre_votes.get(proposal_hash, [])

        # Deduplicate by voter, use registered stake (not self-reported)
        voter_stakes = {}
        for v in votes:
            voter_stakes[v.voter_id] = self.validators.get(v.voter_id, 0)

        supporting_stake = sum(voter_stakes.values())
        ratio = supporting_stake / self.total_stake if self.total_stake > 0 else 0

        return ratio >= BFT_THRESHOLD, ratio
    
    def create_pre_commit(self, proposal_hash: bytes) -> Optional[ConsensusVote]:
        """Create pre-commit if pre-vote threshold reached"""
        threshold_met, ratio = self.check_pre_vote_threshold(proposal_hash)
        if not threshold_met:
            return None
        
        vote = ConsensusVote(
            voter_id=self.validator_id,
            epoch=self.current_epoch,
            round=self.current_round,
            proposal_hash=proposal_hash,
            vote_type="pre-commit",
            stake=self.stake,
            timestamp=int(time.time() * 1000)
        )
        
        self.pre_commits[proposal_hash].append(vote)
        self.phase = ConsensusPhase.PRE_COMMIT
        return vote
    
    def receive_pre_commit(self, vote: ConsensusVote) -> Tuple[bool, str]:
        """Receive and validate a pre-commit"""
        if vote.epoch != self.current_epoch:
            return False, "wrong epoch"
        if vote.vote_type != "pre-commit":
            return False, "wrong vote type"
        if vote.voter_id not in self.validators:
            return False, "unknown voter"

        # Enforce registered stake
        vote.stake = self.validators[vote.voter_id]

        # O(1) equivocation detection
        prev = self._pre_commit_choices.get(vote.voter_id)
        if prev is not None and prev != vote.proposal_hash:
            return False, "equivocation: voter already pre-committed for different proposal"

        self._pre_commit_choices[vote.voter_id] = vote.proposal_hash
        self.pre_commits[vote.proposal_hash].append(vote)
        return True, "valid"

    def check_pre_commit_threshold(self, proposal_hash: bytes) -> Tuple[bool, float]:
        """Check if proposal has 67% pre-commit stake"""
        votes = self.pre_commits.get(proposal_hash, [])

        # Use registered stake
        voter_stakes = {}
        for v in votes:
            voter_stakes[v.voter_id] = self.validators.get(v.voter_id, 0)

        supporting_stake = sum(voter_stakes.values())
        ratio = supporting_stake / self.total_stake if self.total_stake > 0 else 0

        return ratio >= BFT_THRESHOLD, ratio
    
    def try_finalize(self, proposal_hash: bytes) -> Optional[ConsensusBlock]:
        """Try to finalize if pre-commit threshold reached"""
        threshold_met, ratio = self.check_pre_commit_threshold(proposal_hash)
        if not threshold_met:
            return None
        
        proposal = self.received_proposals.get(proposal_hash)
        if proposal is None:
            return None
        
        # Collect all votes
        all_votes = (
            self.pre_votes.get(proposal_hash, []) +
            self.pre_commits.get(proposal_hash, [])
        )
        
        # Calculate supporting stake from registry, not self-reported
        voter_stakes = {}
        for v in self.pre_commits.get(proposal_hash, []):
            voter_stakes[v.voter_id] = self.validators.get(v.voter_id, 0)
        supporting_stake = sum(voter_stakes.values())
        
        block = ConsensusBlock(
            epoch=self.current_epoch,
            round=self.current_round,
            proposal=proposal,
            votes=all_votes,
            total_stake=self.total_stake,
            supporting_stake=supporting_stake,
            finalization_time=time.time()
        )
        
        self.finalized_blocks[self.current_epoch] = block
        self.phase = ConsensusPhase.FINALIZED
        
        return block
    
    def get_consensus_stats(self) -> dict:
        """Get current consensus statistics"""
        best_proposal = None
        best_support = 0
        
        for proposal_hash, votes in self.pre_commits.items():
            support = sum(self.validators.get(v.voter_id, 0) for v in votes)
            if support > best_support:
                best_support = support
                best_proposal = proposal_hash
        
        return {
            "epoch": self.current_epoch,
            "round": self.current_round,
            "phase": self.phase.name,
            "proposals_received": len(self.received_proposals),
            "total_stake": self.total_stake,
            "best_proposal_support": best_support,
            "support_ratio": best_support / self.total_stake if self.total_stake > 0 else 0,
            "finalized": self.phase == ConsensusPhase.FINALIZED,
        }


# =============================================================================
# SLASHING
# =============================================================================

@dataclass
class SlashingProposal:
    """Proposal to slash a misbehaving validator"""
    target_id: bytes
    epoch: int
    reason: str
    evidence_hash: bytes
    proposer_id: bytes
    supporting_stake: int = 0
    voters: Set[bytes] = field(default_factory=set)
    executed: bool = False


class SlashingManager:
    """
    Manages slashing proposals for detected adversaries.
    Uses stake-weighted voting, not raw vote count.
    """
    
    def __init__(self):
        self.proposals: Dict[bytes, SlashingProposal] = {}
        self.slashed_validators: Set[bytes] = set()
    
    def create_proposal(self, 
                       target_id: bytes,
                       epoch: int,
                       detection_result: DetectionResult,
                       proposer_id: bytes) -> SlashingProposal:
        """Create slashing proposal from detection result"""
        evidence_hash = sha3_256(concat(
            target_id,
            epoch,
            detection_result.confidence,
            b"".join(r.encode() for r in detection_result.reasons)
        ))
        
        proposal = SlashingProposal(
            target_id=target_id,
            epoch=epoch,
            reason="; ".join(detection_result.reasons),
            evidence_hash=evidence_hash,
            proposer_id=proposer_id
        )
        
        self.proposals[evidence_hash] = proposal
        return proposal
    
    def vote_for_slashing(self, evidence_hash: bytes,
                          voter_id: bytes, voter_stake: int) -> bool:
        """Vote for a slashing proposal (stake-weighted)."""
        proposal = self.proposals.get(evidence_hash)
        if proposal is None:
            return False
        if proposal.executed:
            return False
        if voter_id in proposal.voters:
            return False  # Already voted

        proposal.voters.add(voter_id)
        proposal.supporting_stake += voter_stake
        return True

    def execute_slashing(self, evidence_hash: bytes,
                         total_stake: int,
                         threshold: float = BFT_THRESHOLD) -> bool:
        """Execute slashing if stake-weighted threshold met."""
        proposal = self.proposals.get(evidence_hash)
        if proposal is None:
            return False
        if proposal.executed:
            return False
        if total_stake == 0:
            return False
        if proposal.supporting_stake / total_stake < threshold:
            return False

        proposal.executed = True
        self.slashed_validators.add(proposal.target_id)
        return True
    
    def is_slashed(self, validator_id: bytes) -> bool:
        """Check if validator has been slashed"""
        return validator_id in self.slashed_validators
