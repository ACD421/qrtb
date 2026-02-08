"""
QRTB Measurement Protocol
- RTT measurement between peers
- Commit-reveal scheme
- Physics bounds validation
- Measurement aggregation
"""

import time
import random
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
from enum import Enum
import struct

from .crypto import sha3_256, sha3_512, concat, secure_random

# =============================================================================
# CONSTANTS
# =============================================================================

# Speed of light in fiber (accounting for refractive index ~1.5)
SPEED_OF_LIGHT_FIBER_KM_MS = 198.0  # km per millisecond

# Minimum peers for measurement validity
MIN_PEERS = 5

# RTT ratio thresholds
HONEST_RTT_RATIO_MEAN = 1.15    # Honest validators: measured/theoretical
HONEST_RTT_RATIO_STD = 0.08
ADVERSARY_RTT_RATIO_MEAN = 0.82  # Optimized routes
ADVERSARY_RTT_RATIO_STD = 0.04

# Detection threshold (sigma)
DETECTION_THRESHOLD_SIGMA = 3.9

# =============================================================================
# DATA STRUCTURES
# =============================================================================

class MeasurementPhase(Enum):
    """Phases of the measurement protocol"""
    IDLE = 0
    COMMIT = 1      # Validators commit to measurement targets
    MEASURE = 2     # Execute RTT measurements
    REVEAL = 3      # Reveal measurements and proofs
    VERIFY = 4      # Cross-validate measurements
    FINALIZE = 5    # Aggregate and finalize


@dataclass
class PeerInfo:
    """Information about a peer validator"""
    validator_id: bytes
    location: Tuple[float, float]  # (lat, lon) for distance calculation
    zone_id: int
    stake: int
    last_seen: float = 0.0


@dataclass
class RTTMeasurement:
    """Single RTT measurement"""
    source_id: bytes
    target_id: bytes
    rtt_ms: float
    timestamp: int
    theoretical_rtt_ms: float  # Based on distance
    nonce: bytes = field(default_factory=lambda: secure_random(32))
    
    @property
    def ratio(self) -> float:
        """RTT ratio: measured / theoretical"""
        if self.theoretical_rtt_ms <= 0:
            return 1.0
        return self.rtt_ms / self.theoretical_rtt_ms
    
    def commitment(self) -> bytes:
        """Hash commitment for commit phase"""
        return sha3_256(concat(
            self.source_id,
            self.target_id,
            self.rtt_ms,
            self.timestamp,
            self.nonce
        ))
    
    def to_bytes(self) -> bytes:
        """Serialize for transmission"""
        return concat(
            self.source_id,
            self.target_id,
            self.rtt_ms,
            self.timestamp,
            self.theoretical_rtt_ms,
            self.nonce
        )


@dataclass
class MeasurementCommitment:
    """Commitment to a set of measurements"""
    validator_id: bytes
    epoch: int
    target_ids: List[bytes]
    commitment_hash: bytes  # Hash of all measurement commitments
    timestamp: int
    signature: bytes = b""


@dataclass
class MeasurementReveal:
    """Revealed measurements with proofs"""
    validator_id: bytes
    epoch: int
    measurements: List[RTTMeasurement]
    commitment: MeasurementCommitment
    signature: bytes = b""
    
    def verify_commitment(self) -> bool:
        """Verify measurements match commitment"""
        # Reconstruct commitment from measurements
        measurement_hashes = [m.commitment() for m in self.measurements]
        combined = sha3_256(b"".join(sorted(measurement_hashes)))
        return combined == self.commitment.commitment_hash


# =============================================================================
# DISTANCE AND RTT CALCULATION
# =============================================================================

def haversine_distance_km(loc1: Tuple[float, float], loc2: Tuple[float, float]) -> float:
    """
    Calculate great-circle distance between two points
    
    Args:
        loc1, loc2: (latitude, longitude) in degrees
        
    Returns:
        Distance in kilometers
    """
    import math
    
    lat1, lon1 = map(math.radians, loc1)
    lat2, lon2 = map(math.radians, loc2)
    
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    earth_radius_km = 6371
    return earth_radius_km * c


def theoretical_rtt_ms(distance_km: float) -> float:
    """
    Calculate theoretical minimum RTT based on distance
    
    RTT = 2 × distance / speed_of_light_in_fiber
    """
    return 2 * distance_km / SPEED_OF_LIGHT_FIBER_KM_MS


def simulate_rtt(theoretical_ms: float, is_adversary: bool = False) -> float:
    """
    Simulate realistic RTT with noise
    
    Honest validators: ~1.15× theoretical (routing overhead)
    Adversarial (optimized): ~0.82× theoretical (premium routes)
    """
    if is_adversary:
        ratio = random.gauss(ADVERSARY_RTT_RATIO_MEAN, ADVERSARY_RTT_RATIO_STD)
    else:
        ratio = random.gauss(HONEST_RTT_RATIO_MEAN, HONEST_RTT_RATIO_STD)
    
    # Ensure positive
    ratio = max(0.5, min(2.0, ratio))
    return theoretical_ms * ratio


# =============================================================================
# MEASUREMENT PROTOCOL
# =============================================================================

class MeasurementProtocol:
    """
    Implements the commit-reveal measurement protocol
    """
    
    def __init__(self, validator_id: bytes, location: Tuple[float, float], zone_id: int):
        self.validator_id = validator_id
        self.location = location
        self.zone_id = zone_id
        
        self.peers: Dict[bytes, PeerInfo] = {}
        self.current_epoch = 0
        self.phase = MeasurementPhase.IDLE
        
        # Current round state
        self.selected_targets: List[bytes] = []
        self.measurements: List[RTTMeasurement] = []
        self.commitment: Optional[MeasurementCommitment] = None
        
        # Received from other validators
        self.received_commitments: Dict[bytes, MeasurementCommitment] = {}
        self.received_reveals: Dict[bytes, MeasurementReveal] = {}
    
    def add_peer(self, peer: PeerInfo) -> None:
        """Register a peer validator"""
        self.peers[peer.validator_id] = peer
    
    def remove_peer(self, peer_id: bytes) -> None:
        """Remove a peer validator"""
        self.peers.pop(peer_id, None)
    
    def start_epoch(self, epoch: int) -> None:
        """Begin new epoch - reset state"""
        self.current_epoch = epoch
        self.phase = MeasurementPhase.IDLE
        self.selected_targets = []
        self.measurements = []
        self.commitment = None
        self.received_commitments = {}
        self.received_reveals = {}
    
    def select_targets(self, num_targets: int = MIN_PEERS) -> List[bytes]:
        """
        Randomly select measurement targets
        Uses epoch entropy for deterministic but unpredictable selection
        """
        available = list(self.peers.keys())
        if len(available) < num_targets:
            num_targets = len(available)
        
        # Deterministic shuffle based on epoch + validator ID
        seed = sha3_256(concat(self.validator_id, self.current_epoch))
        random.seed(int.from_bytes(seed[:8], 'big'))
        random.shuffle(available)
        
        self.selected_targets = available[:num_targets]
        return self.selected_targets
    
    def execute_measurements(self, is_adversary: bool = False) -> List[RTTMeasurement]:
        """
        Execute RTT measurements to selected targets
        
        In production: Actual network ping
        Here: Simulated based on distance
        """
        self.measurements = []
        timestamp = int(time.time() * 1000)
        
        for target_id in self.selected_targets:
            peer = self.peers.get(target_id)
            if peer is None:
                continue
            
            # Calculate theoretical RTT based on distance
            distance = haversine_distance_km(self.location, peer.location)
            theoretical = theoretical_rtt_ms(distance)
            
            # Simulate actual RTT
            actual = simulate_rtt(theoretical, is_adversary)
            
            measurement = RTTMeasurement(
                source_id=self.validator_id,
                target_id=target_id,
                rtt_ms=actual,
                timestamp=timestamp,
                theoretical_rtt_ms=theoretical
            )
            self.measurements.append(measurement)
        
        return self.measurements
    
    def create_commitment(self) -> MeasurementCommitment:
        """Create hash commitment to measurements"""
        measurement_hashes = [m.commitment() for m in self.measurements]
        combined_hash = sha3_256(b"".join(sorted(measurement_hashes)))
        
        self.commitment = MeasurementCommitment(
            validator_id=self.validator_id,
            epoch=self.current_epoch,
            target_ids=self.selected_targets.copy(),
            commitment_hash=combined_hash,
            timestamp=int(time.time() * 1000)
        )
        
        self.phase = MeasurementPhase.COMMIT
        return self.commitment
    
    def receive_commitment(self, commitment: MeasurementCommitment) -> bool:
        """Receive and store commitment from another validator"""
        if commitment.epoch != self.current_epoch:
            return False
        
        self.received_commitments[commitment.validator_id] = commitment
        return True
    
    def create_reveal(self) -> MeasurementReveal:
        """Create reveal with measurements and proof"""
        reveal = MeasurementReveal(
            validator_id=self.validator_id,
            epoch=self.current_epoch,
            measurements=self.measurements.copy(),
            commitment=self.commitment
        )
        
        self.phase = MeasurementPhase.REVEAL
        return reveal
    
    def receive_reveal(self, reveal: MeasurementReveal) -> Tuple[bool, str]:
        """
        Receive and validate reveal from another validator
        
        Returns:
            (valid, reason)
        """
        # Check epoch
        if reveal.epoch != self.current_epoch:
            return False, "wrong epoch"
        
        # Check we have their commitment
        commitment = self.received_commitments.get(reveal.validator_id)
        if commitment is None:
            return False, "no commitment found"
        
        # Verify reveal matches commitment
        if not reveal.verify_commitment():
            return False, "commitment mismatch"
        
        self.received_reveals[reveal.validator_id] = reveal
        return True, "valid"
    
    def get_all_measurements(self) -> Dict[bytes, List[RTTMeasurement]]:
        """Get all measurements including our own"""
        result = {self.validator_id: self.measurements}
        for vid, reveal in self.received_reveals.items():
            result[vid] = reveal.measurements
        return result


# =============================================================================
# GEOGRAPHIC ZONES
# =============================================================================

# Representative locations for each zone (city coordinates)
ZONE_LOCATIONS = {
    0: [  # North America
        ("New York", (40.7128, -74.0060)),
        ("Los Angeles", (34.0522, -118.2437)),
        ("Chicago", (41.8781, -87.6298)),
        ("Dallas", (32.7767, -96.7970)),
        ("Seattle", (47.6062, -122.3321)),
    ],
    1: [  # Europe
        ("London", (51.5074, -0.1278)),
        ("Frankfurt", (50.1109, 8.6821)),
        ("Paris", (48.8566, 2.3522)),
        ("Amsterdam", (52.3676, 4.9041)),
        ("Stockholm", (59.3293, 18.0686)),
    ],
    2: [  # Asia-Pacific
        ("Tokyo", (35.6762, 139.6503)),
        ("Singapore", (1.3521, 103.8198)),
        ("Sydney", (-33.8688, 151.2093)),
        ("Hong Kong", (22.3193, 114.1694)),
        ("Seoul", (37.5665, 126.9780)),
    ],
    3: [  # South America
        ("São Paulo", (-23.5505, -46.6333)),
        ("Buenos Aires", (-34.6037, -58.3816)),
        ("Lima", (-12.0464, -77.0428)),
        ("Bogotá", (4.7110, -74.0721)),
        ("Santiago", (-33.4489, -70.6693)),
    ],
    4: [  # Africa
        ("Cape Town", (-33.9249, 18.4241)),
        ("Lagos", (6.5244, 3.3792)),
        ("Cairo", (30.0444, 31.2357)),
        ("Nairobi", (-1.2921, 36.8219)),
        ("Johannesburg", (-26.2041, 28.0473)),
    ],
    5: [  # Middle East
        ("Dubai", (25.2048, 55.2708)),
        ("Tel Aviv", (32.0853, 34.7818)),
        ("Istanbul", (41.0082, 28.9784)),
        ("Riyadh", (24.7136, 46.6753)),
        ("Doha", (25.2854, 51.5310)),
    ],
}


def get_random_location(zone_id: int) -> Tuple[str, Tuple[float, float]]:
    """Get random location within a zone"""
    locations = ZONE_LOCATIONS.get(zone_id, ZONE_LOCATIONS[0])
    return random.choice(locations)
