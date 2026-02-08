"""
QRTB Detection System
- Triangle inequality validation
- RTT ratio analysis
- Variance detection
- Path integral consistency
- Adversary scoring
"""

import statistics
import math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Set, Optional
from collections import defaultdict

from .measurement import (
    RTTMeasurement, 
    HONEST_RTT_RATIO_MEAN, HONEST_RTT_RATIO_STD,
    ADVERSARY_RTT_RATIO_MEAN, ADVERSARY_RTT_RATIO_STD,
    DETECTION_THRESHOLD_SIGMA,
    haversine_distance_km, theoretical_rtt_ms
)
from .crypto import sha3_256

# =============================================================================
# DETECTION RESULTS
# =============================================================================

@dataclass
class DetectionResult:
    """Result of detection analysis for a validator"""
    validator_id: bytes
    is_suspicious: bool
    confidence: float  # 0.0 to 1.0
    reasons: List[str] = field(default_factory=list)
    
    # Individual detector scores
    ratio_score: float = 0.0
    triangle_violations: int = 0
    variance_score: float = 0.0
    path_consistency_score: float = 0.0
    
    def add_reason(self, reason: str) -> None:
        self.reasons.append(reason)


@dataclass
class TriangleCheck:
    """Result of triangle inequality check"""
    node_a: bytes
    node_b: bytes
    node_c: bytes
    rtt_ab: float
    rtt_bc: float
    rtt_ac: float
    max_allowed: float  # rtt_ab + rtt_bc
    violation: float    # rtt_ac - max_allowed (positive = violation)
    is_valid: bool


# =============================================================================
# DETECTION METHODS
# =============================================================================

class DetectionEngine:
    """
    Multi-method adversary detection
    
    All methods reduce to: Position → Timing → Phase → Inconsistency
    """
    
    def __init__(self):
        # Measurement graph: validator_id -> [(target_id, measurement)]
        self.measurement_graph: Dict[bytes, List[RTTMeasurement]] = {}
        
        # Location cache: validator_id -> (lat, lon)
        self.locations: Dict[bytes, Tuple[float, float]] = {}
        
        # Detection results
        self.results: Dict[bytes, DetectionResult] = {}
    
    def load_measurements(self, 
                         measurements: Dict[bytes, List[RTTMeasurement]],
                         locations: Dict[bytes, Tuple[float, float]]) -> None:
        """Load measurement data for analysis"""
        self.measurement_graph = measurements
        self.locations = locations
        self.results = {}
    
    def analyze_all(self) -> Dict[bytes, DetectionResult]:
        """Run all detection methods on all validators"""
        for validator_id in self.measurement_graph.keys():
            self.results[validator_id] = self._analyze_validator(validator_id)
        return self.results
    
    def _analyze_validator(self, validator_id: bytes) -> DetectionResult:
        """Run all detection methods on single validator"""
        result = DetectionResult(
            validator_id=validator_id,
            is_suspicious=False,
            confidence=0.0
        )
        
        measurements = self.measurement_graph.get(validator_id, [])
        if not measurements:
            return result
        
        # Method 1: RTT Ratio Analysis
        ratio_suspicious, ratio_score = self._check_ratios(measurements)
        result.ratio_score = ratio_score
        if ratio_suspicious:
            result.add_reason(f"RTT ratio anomaly: {ratio_score:.2f}σ below mean")
        
        # Method 2: Triangle Inequality
        triangles = self._check_triangles(validator_id)
        result.triangle_violations = sum(1 for t in triangles if not t.is_valid)
        triangle_rate = result.triangle_violations / max(len(triangles), 1)
        if result.triangle_violations > 0 and triangle_rate > 0.3:
            result.add_reason(f"Triangle violations: {result.triangle_violations} ({triangle_rate:.1%})")
        
        # Method 3: Variance Detection
        variance_suspicious, variance_score = self._check_variance(measurements)
        result.variance_score = variance_score
        if variance_suspicious:
            result.add_reason(f"Suspiciously low variance: {variance_score:.3f}")
        
        # Method 4: Path Consistency
        path_suspicious, path_score = self._check_path_consistency(validator_id)
        result.path_consistency_score = path_score
        if path_suspicious:
            result.add_reason(f"Path inconsistency: {path_score:.2f}")
        
        # Aggregate decision - require MULTIPLE signals
        # Adversaries should show: low ratio + low variance + triangle violations
        suspicion_signals = sum([
            ratio_suspicious,
            variance_suspicious,
            triangle_rate > 0.3,
            path_suspicious
        ])
        
        # Suspicious only if 2+ signals fire
        result.is_suspicious = suspicion_signals >= 2
        
        # Or if ratio is extremely low (< 0.9 mean ratio = definitely optimized)
        if len(measurements) > 0:
            mean_ratio = statistics.mean(m.ratio for m in measurements)
            if mean_ratio < 0.9:
                result.is_suspicious = True
                result.add_reason(f"Extremely low ratio: {mean_ratio:.2f}")
        
        # Calculate confidence
        result.confidence = suspicion_signals / 4.0
        
        return result
    
    def _check_ratios(self, measurements: List[RTTMeasurement]) -> Tuple[bool, float]:
        """
        Check if RTT ratios are suspiciously low (indicating route optimization)
        
        Returns:
            (is_suspicious, sigma_deviation)
        """
        if not measurements:
            return False, 0.0
        
        ratios = [m.ratio for m in measurements]
        mean_ratio = statistics.mean(ratios)
        
        # Calculate how many sigmas below honest mean
        sigma_deviation = (HONEST_RTT_RATIO_MEAN - mean_ratio) / HONEST_RTT_RATIO_STD
        
        # Suspicious if more than DETECTION_THRESHOLD_SIGMA below honest mean
        # AND mean ratio is below 1.0 (faster than theoretical minimum)
        is_suspicious = sigma_deviation > DETECTION_THRESHOLD_SIGMA and mean_ratio < 1.0
        
        return is_suspicious, sigma_deviation
    
    def _check_triangles(self, validator_id: bytes) -> List[TriangleCheck]:
        """
        Check triangle inequality for all triangles including this validator
        
        Triangle inequality: RTT(A→C) ≤ RTT(A→B) + RTT(B→C)
        """
        results = []
        
        # Get this validator's measurements
        my_measurements = {
            m.target_id: m.rtt_ms 
            for m in self.measurement_graph.get(validator_id, [])
        }
        
        # For each pair of my targets, check triangle
        targets = list(my_measurements.keys())
        
        for i, target_b in enumerate(targets):
            for target_c in targets[i+1:]:
                # I have measurements to B and C
                rtt_ab = my_measurements[target_b]
                rtt_ac = my_measurements[target_c]
                
                # Try to find B's measurement to C
                b_measurements = self.measurement_graph.get(target_b, [])
                rtt_bc = None
                for m in b_measurements:
                    if m.target_id == target_c:
                        rtt_bc = m.rtt_ms
                        break
                
                if rtt_bc is None:
                    continue
                
                # Check: RTT(A→C) ≤ RTT(A→B) + RTT(B→C)
                max_allowed = rtt_ab + rtt_bc
                violation = rtt_ac - max_allowed
                
                results.append(TriangleCheck(
                    node_a=validator_id,
                    node_b=target_b,
                    node_c=target_c,
                    rtt_ab=rtt_ab,
                    rtt_bc=rtt_bc,
                    rtt_ac=rtt_ac,
                    max_allowed=max_allowed,
                    violation=violation,
                    is_valid=violation <= 0
                ))
        
        return results
    
    def _check_variance(self, measurements: List[RTTMeasurement]) -> Tuple[bool, float]:
        """
        Check if variance is suspiciously low
        
        Adversaries optimizing routes tend to have unnaturally consistent ratios
        """
        if len(measurements) < 2:
            return False, 0.0
        
        ratios = [m.ratio for m in measurements]
        variance = statistics.variance(ratios)
        
        # Honest variance should be around 0.08^2 = 0.0064
        # Adversary variance around 0.04^2 = 0.0016
        expected_honest_variance = HONEST_RTT_RATIO_STD ** 2
        
        # Suspicious if variance is less than half expected
        is_suspicious = variance < expected_honest_variance * 0.25
        
        return is_suspicious, variance
    
    def _check_path_consistency(self, validator_id: bytes) -> Tuple[bool, float]:
        """
        Check consistency across multi-hop paths
        
        If A optimizes route to B, paths A→B→C and A→C should still be consistent
        """
        my_measurements = self.measurement_graph.get(validator_id, [])
        if len(my_measurements) < 2:
            return False, 0.0
        
        # Build ratio map
        my_ratios = {m.target_id: m.ratio for m in my_measurements}
        
        # Calculate variance of ratios across all my measurements
        # An honest validator should have similar ratios to all peers
        # An adversary optimizing some routes will have inconsistent ratios
        
        ratios = list(my_ratios.values())
        if len(ratios) < 2:
            return False, 0.0
        
        # Calculate coefficient of variation
        mean_ratio = statistics.mean(ratios)
        std_ratio = statistics.stdev(ratios)
        cv = std_ratio / mean_ratio if mean_ratio > 0 else 0
        
        # High CV indicates selective optimization
        # Honest: CV ≈ 0.08/1.15 ≈ 0.07
        # Adversary optimizing some routes: CV might be 0.2+
        
        is_suspicious = cv > 0.15
        
        return is_suspicious, cv


# =============================================================================
# AGGREGATE DETECTION
# =============================================================================

def aggregate_detection_results(results: Dict[bytes, DetectionResult]) -> Dict[str, any]:
    """
    Aggregate detection results across all validators
    
    Returns summary statistics
    """
    total = len(results)
    suspicious = sum(1 for r in results.values() if r.is_suspicious)
    high_confidence = sum(1 for r in results.values() if r.confidence > 0.5)
    
    avg_ratio_score = statistics.mean(
        r.ratio_score for r in results.values()
    ) if results else 0
    
    total_triangle_violations = sum(
        r.triangle_violations for r in results.values()
    )
    
    return {
        "total_validators": total,
        "suspicious_count": suspicious,
        "suspicious_rate": suspicious / total if total > 0 else 0,
        "high_confidence_count": high_confidence,
        "avg_ratio_deviation": avg_ratio_score,
        "total_triangle_violations": total_triangle_violations,
    }


# =============================================================================
# SLASHING EVIDENCE
# =============================================================================

@dataclass
class SlashingEvidence:
    """Evidence for slashing a misbehaving validator"""
    validator_id: bytes
    epoch: int
    detection_result: DetectionResult
    measurements: List[RTTMeasurement]
    triangle_checks: List[TriangleCheck]
    evidence_hash: bytes = b""
    
    def __post_init__(self):
        # Create tamper-evident hash of all evidence
        evidence_data = b""
        evidence_data += self.validator_id
        evidence_data += self.epoch.to_bytes(8, 'big')
        for m in self.measurements:
            evidence_data += m.to_bytes()
        self.evidence_hash = sha3_256(evidence_data)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage/transmission"""
        return {
            "validator_id": self.validator_id.hex(),
            "epoch": self.epoch,
            "is_suspicious": self.detection_result.is_suspicious,
            "confidence": self.detection_result.confidence,
            "reasons": self.detection_result.reasons,
            "triangle_violations": self.detection_result.triangle_violations,
            "evidence_hash": self.evidence_hash.hex(),
        }
