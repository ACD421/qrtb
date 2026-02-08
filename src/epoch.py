"""
QRTB Epoch and Entropy Management
- Four-source entropy generation
- Epoch lifecycle management
- Key evolution coordination
- Epoch synchronization
"""

import time
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

from .crypto import sha3_256, sha3_512, concat, secure_random, MerkleTree

# =============================================================================
# CONSTANTS
# =============================================================================

EPOCH_DURATION_SEC = 15 * 60  # 15 minutes
GRACE_PERIOD_SEC = 5 * 60     # 5 minutes for late transactions

# =============================================================================
# ENTROPY SOURCES
# =============================================================================

class EntropySourceType(Enum):
    NETWORK_MEASUREMENTS = 0
    BLOCKCHAIN_STATE = 1
    EXTERNAL_BEACONS = 2
    HISTORICAL_CHAIN = 3


@dataclass
class EntropyContribution:
    """Single entropy contribution from one source"""
    source_type: EntropySourceType
    data: bytes
    timestamp: int
    available: bool = True
    
    def weighted_entropy(self, weight: float = 0.25) -> bytes:
        """Get weighted entropy contribution"""
        if not self.available or not self.data:
            return b""
        return self.data


@dataclass
class EpochEntropy:
    """Combined entropy for an epoch"""
    epoch: int
    contributions: Dict[EntropySourceType, EntropyContribution]
    combined_entropy: bytes
    generation_timestamp: int
    sources_used: int
    
    @property
    def security_bits(self) -> int:
        """Estimated security bits based on sources"""
        return self.sources_used * 64
    
    def is_secure(self) -> bool:
        """At least one source must contribute"""
        return self.sources_used >= 1


class EntropyWell:
    """
    Four-source entropy generation system
    
    Sources:
    1. Network Measurements (25%) - RTT timing jitter
    2. Blockchain State (25%) - Previous block hashes
    3. External Beacons (25%) - NIST, drand, Ethereum
    4. Historical Chain (25%) - Recursive entropy chain
    """
    
    def __init__(self):
        self.network_measurements: bytes = b""
        self.blockchain_state: bytes = b""
        self.external_beacons: bytes = b""
        self.historical_chain: bytes = secure_random(64)  # Genesis
        
        self.history: Dict[int, EpochEntropy] = {}
    
    def update_network_measurements(self, rtt_data: List[float]) -> None:
        """Update from RTT measurements"""
        if not rtt_data:
            return
        
        # Extract entropy from measurement timing
        rtt_bytes = b"".join(
            struct.pack('>d', r) for r in rtt_data[:100]
        )
        self.network_measurements = sha3_512(
            concat(b"network", rtt_bytes, int(time.time() * 1000))
        )
    
    def update_blockchain_state(self, block_hash: bytes) -> None:
        """Update from latest block hash"""
        self.blockchain_state = sha3_512(
            concat(b"blockchain", self.blockchain_state, block_hash)
        )
    
    def update_external_beacons(self, beacon_data: bytes) -> None:
        """Update from external randomness beacons"""
        self.external_beacons = sha3_512(
            concat(b"external", self.external_beacons, beacon_data)
        )
    
    def simulate_external_beacons(self) -> None:
        """Simulate external beacon data for testing"""
        # In production: Fetch from NIST, drand, Ethereum
        simulated = secure_random(64)
        self.update_external_beacons(simulated)
    
    def generate_epoch_entropy(self, epoch: int) -> EpochEntropy:
        """Generate combined entropy for an epoch"""
        timestamp = int(time.time() * 1000)
        
        contributions = {}
        sources_used = 0
        
        # Network measurements
        if self.network_measurements:
            contributions[EntropySourceType.NETWORK_MEASUREMENTS] = EntropyContribution(
                source_type=EntropySourceType.NETWORK_MEASUREMENTS,
                data=self.network_measurements,
                timestamp=timestamp
            )
            sources_used += 1
        
        # Blockchain state
        if self.blockchain_state:
            contributions[EntropySourceType.BLOCKCHAIN_STATE] = EntropyContribution(
                source_type=EntropySourceType.BLOCKCHAIN_STATE,
                data=self.blockchain_state,
                timestamp=timestamp
            )
            sources_used += 1
        
        # External beacons
        if self.external_beacons:
            contributions[EntropySourceType.EXTERNAL_BEACONS] = EntropyContribution(
                source_type=EntropySourceType.EXTERNAL_BEACONS,
                data=self.external_beacons,
                timestamp=timestamp
            )
            sources_used += 1
        
        # Historical chain (always available)
        contributions[EntropySourceType.HISTORICAL_CHAIN] = EntropyContribution(
            source_type=EntropySourceType.HISTORICAL_CHAIN,
            data=self.historical_chain,
            timestamp=timestamp
        )
        sources_used += 1
        
        # Combine all sources
        combined_data = concat(
            b"epoch_entropy",
            epoch,
            self.network_measurements or b"",
            self.blockchain_state or b"",
            self.external_beacons or b"",
            self.historical_chain
        )
        combined_entropy = sha3_512(combined_data)
        
        # Update historical chain
        self.historical_chain = sha3_512(
            concat(self.historical_chain, combined_entropy)
        )
        
        result = EpochEntropy(
            epoch=epoch,
            contributions=contributions,
            combined_entropy=combined_entropy,
            generation_timestamp=timestamp,
            sources_used=sources_used
        )
        
        self.history[epoch] = result
        return result


# =============================================================================
# EPOCH MANAGEMENT
# =============================================================================

class EpochPhase(Enum):
    """Phases within an epoch"""
    ACTIVE = 0          # Normal transaction processing
    MEASUREMENT = 1     # RTT measurement period
    CONSENSUS = 2       # Consensus on measurements
    TRANSITION = 3      # Key evolution and epoch transition


@dataclass
class EpochState:
    """State of a single epoch"""
    epoch_number: int
    start_time: float
    end_time: float
    phase: EpochPhase
    entropy: Optional[EpochEntropy] = None
    validator_commitments: Dict[bytes, bytes] = field(default_factory=dict)
    finalized: bool = False
    block_root: Optional[bytes] = None


class EpochManager:
    """
    Manages epoch lifecycle and coordination
    """
    
    def __init__(self, genesis_time: Optional[float] = None):
        self.genesis_time = genesis_time or time.time()
        self.current_epoch = 0
        self.epochs: Dict[int, EpochState] = {}
        self.entropy_well = EntropyWell()
        
        # Initialize genesis epoch
        self._initialize_epoch(0)
    
    def _initialize_epoch(self, epoch_number: int) -> EpochState:
        """Initialize a new epoch"""
        start_time = self.genesis_time + (epoch_number * EPOCH_DURATION_SEC)
        end_time = start_time + EPOCH_DURATION_SEC
        
        state = EpochState(
            epoch_number=epoch_number,
            start_time=start_time,
            end_time=end_time,
            phase=EpochPhase.ACTIVE
        )
        
        self.epochs[epoch_number] = state
        return state
    
    def get_current_epoch(self) -> int:
        """Calculate current epoch from time"""
        elapsed = time.time() - self.genesis_time
        return max(0, int(elapsed / EPOCH_DURATION_SEC))
    
    def get_epoch_phase(self, epoch: Optional[int] = None) -> EpochPhase:
        """Get current phase within epoch"""
        if epoch is None:
            epoch = self.get_current_epoch()
        
        state = self.epochs.get(epoch)
        if state is None:
            state = self._initialize_epoch(epoch)
        
        elapsed_in_epoch = time.time() - state.start_time
        
        # Phase timing within 15-minute epoch:
        # 0-12 min: ACTIVE (transaction processing)
        # 12-13 min: MEASUREMENT (RTT measurement)
        # 13-14 min: CONSENSUS (BFT on measurements)
        # 14-15 min: TRANSITION (key evolution)
        
        if elapsed_in_epoch < EPOCH_DURATION_SEC * 0.8:
            return EpochPhase.ACTIVE
        elif elapsed_in_epoch < EPOCH_DURATION_SEC * 0.867:
            return EpochPhase.MEASUREMENT
        elif elapsed_in_epoch < EPOCH_DURATION_SEC * 0.933:
            return EpochPhase.CONSENSUS
        else:
            return EpochPhase.TRANSITION
    
    def is_in_grace_period(self, tx_epoch: int) -> bool:
        """Check if transaction from previous epoch is still valid"""
        current = self.get_current_epoch()
        if tx_epoch == current:
            return True
        if tx_epoch == current - 1:
            elapsed_in_current = time.time() - self.epochs.get(current, self._initialize_epoch(current)).start_time
            return elapsed_in_current < GRACE_PERIOD_SEC
        return False
    
    def advance_epoch(self) -> Tuple[int, EpochEntropy]:
        """
        Advance to next epoch
        
        Returns:
            (new_epoch_number, epoch_entropy)
        """
        self.current_epoch += 1
        
        # Generate entropy for new epoch
        entropy = self.entropy_well.generate_epoch_entropy(self.current_epoch)
        
        # Initialize new epoch state
        state = self._initialize_epoch(self.current_epoch)
        state.entropy = entropy
        
        # Mark previous epoch as finalized
        prev_epoch = self.epochs.get(self.current_epoch - 1)
        if prev_epoch:
            prev_epoch.finalized = True
            prev_epoch.phase = EpochPhase.TRANSITION
        
        return self.current_epoch, entropy
    
    def finalize_epoch(self, epoch: int, block_root: bytes) -> None:
        """Finalize an epoch with block root"""
        state = self.epochs.get(epoch)
        if state:
            state.finalized = True
            state.block_root = block_root
            # Update blockchain state entropy
            self.entropy_well.update_blockchain_state(block_root)
    
    def add_validator_commitment(self, epoch: int, validator_id: bytes, commitment: bytes) -> None:
        """Add validator's measurement commitment"""
        state = self.epochs.get(epoch)
        if state:
            state.validator_commitments[validator_id] = commitment
    
    def get_epoch_info(self, epoch: Optional[int] = None) -> dict:
        """Get information about an epoch"""
        if epoch is None:
            epoch = self.current_epoch
        
        state = self.epochs.get(epoch)
        if state is None:
            return {"error": "epoch not found"}
        
        return {
            "epoch_number": state.epoch_number,
            "start_time": state.start_time,
            "end_time": state.end_time,
            "phase": state.phase.name,
            "finalized": state.finalized,
            "validator_commitments": len(state.validator_commitments),
            "entropy_sources": state.entropy.sources_used if state.entropy else 0,
            "security_bits": state.entropy.security_bits if state.entropy else 0,
        }


# =============================================================================
# EPOCH SYNCHRONIZATION
# =============================================================================

@dataclass
class EpochSyncMessage:
    """Message for epoch synchronization"""
    sender_id: bytes
    epoch: int
    timestamp: float
    entropy_hash: bytes
    signature: bytes = b""


class EpochSynchronizer:
    """
    Handles epoch synchronization across validators
    """
    
    def __init__(self, validator_id: bytes, epoch_manager: EpochManager):
        self.validator_id = validator_id
        self.epoch_manager = epoch_manager
        self.peer_epochs: Dict[bytes, int] = {}
        self.sync_messages: Dict[int, List[EpochSyncMessage]] = {}
    
    def create_sync_message(self) -> EpochSyncMessage:
        """Create sync message for current epoch"""
        current = self.epoch_manager.current_epoch
        state = self.epoch_manager.epochs.get(current)
        
        entropy_hash = b""
        if state and state.entropy:
            entropy_hash = sha3_256(state.entropy.combined_entropy)
        
        return EpochSyncMessage(
            sender_id=self.validator_id,
            epoch=current,
            timestamp=time.time(),
            entropy_hash=entropy_hash
        )
    
    def receive_sync_message(self, msg: EpochSyncMessage) -> Tuple[bool, str]:
        """
        Process sync message from peer
        
        Returns:
            (is_synced, status)
        """
        self.peer_epochs[msg.sender_id] = msg.epoch
        
        if msg.epoch not in self.sync_messages:
            self.sync_messages[msg.epoch] = []
        self.sync_messages[msg.epoch].append(msg)
        
        my_epoch = self.epoch_manager.current_epoch
        
        if msg.epoch == my_epoch:
            return True, "in sync"
        elif msg.epoch > my_epoch:
            return False, f"peer ahead by {msg.epoch - my_epoch} epochs"
        else:
            return False, f"peer behind by {my_epoch - msg.epoch} epochs"
    
    def get_consensus_epoch(self) -> int:
        """Get epoch that majority of peers agree on"""
        if not self.peer_epochs:
            return self.epoch_manager.current_epoch
        
        epoch_counts: Dict[int, int] = {}
        for epoch in self.peer_epochs.values():
            epoch_counts[epoch] = epoch_counts.get(epoch, 0) + 1
        
        # Return epoch with most votes
        return max(epoch_counts, key=epoch_counts.get)
    
    def is_synchronized(self, threshold: float = 0.67) -> bool:
        """Check if synchronized with threshold of peers"""
        if not self.peer_epochs:
            return True
        
        my_epoch = self.epoch_manager.current_epoch
        matching = sum(1 for e in self.peer_epochs.values() if e == my_epoch)
        
        return matching / len(self.peer_epochs) >= threshold
