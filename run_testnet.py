#!/usr/bin/env python3
"""
QRTB Testnet Runner
Execute full testnet simulation with configurable parameters
"""

import sys
import os
import time
import argparse

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.network import create_testnet, NetworkConfig, QRTBTestnet
from src.crypto import WOTSPlus, TemporalKey
from src.detection import DetectionEngine

def test_cryptographic_primitives():
    """Test WOTS+ and key evolution"""
    print("\n" + "=" * 60)
    print("TEST: Cryptographic Primitives")
    print("=" * 60)
    
    # WOTS+ test
    wots = WOTSPlus()
    key = TemporalKey.create()
    
    priv, pub = key.get_signing_keypair(wots)
    print(f"  Private key: {len(priv)} bytes")
    print(f"  Public key: {len(pub)} bytes")
    
    message = b"Test transaction data"
    signature = wots.sign(message, priv)
    print(f"  Signature: {len(signature)} bytes")
    
    valid = wots.verify(message, signature, pub)
    print(f"  Verification: {'PASS' if valid else 'FAIL'}")
    
    # Tamper test
    tampered = message + b"x"
    invalid = wots.verify(tampered, signature, pub)
    print(f"  Tamper detection: {'PASS' if not invalid else 'FAIL'}")
    
    # Key evolution test
    initial_key = key.current_key
    key.evolve(b"epoch_entropy_1")
    evolved = key.current_key != initial_key
    print(f"  Key evolution: {'PASS' if evolved else 'FAIL'}")
    
    return valid and not invalid and evolved


def test_detection_engine():
    """Test adversary detection"""
    print("\n" + "=" * 60)
    print("TEST: Detection Engine")
    print("=" * 60)
    
    from src.measurement import RTTMeasurement
    from src.crypto import secure_random
    
    engine = DetectionEngine()
    
    # Create honest measurements
    honest_id = secure_random(32)
    honest_measurements = []
    for i in range(5):
        target = secure_random(32)
        theoretical = 50 + i * 10
        actual = theoretical * 1.15  # Honest ratio
        
        m = RTTMeasurement(
            source_id=honest_id,
            target_id=target,
            rtt_ms=actual,
            timestamp=int(time.time() * 1000),
            theoretical_rtt_ms=theoretical
        )
        honest_measurements.append(m)
    
    # Create adversarial measurements
    adversary_id = secure_random(32)
    adversary_measurements = []
    for i in range(5):
        target = secure_random(32)
        theoretical = 50 + i * 10
        actual = theoretical * 0.82  # Adversarial ratio (optimized)
        
        m = RTTMeasurement(
            source_id=adversary_id,
            target_id=target,
            rtt_ms=actual,
            timestamp=int(time.time() * 1000),
            theoretical_rtt_ms=theoretical
        )
        adversary_measurements.append(m)
    
    # Load and analyze
    engine.load_measurements(
        {honest_id: honest_measurements, adversary_id: adversary_measurements},
        {honest_id: (40.7, -74.0), adversary_id: (34.0, -118.2)}
    )
    
    results = engine.analyze_all()
    
    honest_result = results[honest_id]
    adversary_result = results[adversary_id]
    
    print(f"  Honest validator flagged: {honest_result.is_suspicious}")
    print(f"  Adversary validator flagged: {adversary_result.is_suspicious}")
    print(f"  Adversary ratio score: {adversary_result.ratio_score:.2f}σ")
    
    # Correct detection: adversary flagged, honest not flagged
    correct = adversary_result.is_suspicious and not honest_result.is_suspicious
    print(f"  Detection accuracy: {'PASS' if correct else 'PARTIAL'}")
    
    return correct


def test_single_validator():
    """Test single validator epoch simulation"""
    print("\n" + "=" * 60)
    print("TEST: Single Validator Epoch")
    print("=" * 60)
    
    from src.validator import ValidatorNode, ValidatorConfig
    
    config = ValidatorConfig(zone_id=0, stake=1000)
    node = ValidatorNode(config)
    
    # Register self for consensus
    node.consensus.register_validator(node.validator_id, node.config.stake)
    
    print(f"  Validator ID: {node.validator_id.hex()[:16]}...")
    print(f"  Zone: {config.zone_id} ({config.city})")
    
    # Run epoch
    block = node.simulate_full_epoch()
    
    print(f"  Block finalized: {block is not None}")
    if block:
        print(f"  Block hash: {block.block_hash.hex()[:16]}...")
        print(f"  Supporting stake: {block.supporting_stake}")
    
    return block is not None


def test_multi_validator_network():
    """Test multi-validator network"""
    print("\n" + "=" * 60)
    print("TEST: Multi-Validator Network")
    print("=" * 60)
    
    config = NetworkConfig(
        num_zones=3,
        validators_per_zone=5,
        adversary_percentage=0.2  # 20% adversaries
    )
    
    testnet = QRTBTestnet(config)
    testnet.verbose = False
    testnet.initialize_network()
    
    print(f"  Validators: {len(testnet.validators)}")
    print(f"  Zones: {config.num_zones}")
    print(f"  Adversaries: {int(len(testnet.validators) * config.adversary_percentage)}")
    
    # Run epochs
    num_epochs = 5
    results = testnet.run(num_epochs)
    
    print(f"\n  Epochs run: {results['epochs_run']}")
    print(f"  Epochs finalized: {results['epochs_finalized']}")
    print(f"  Finalization rate: {results['finalization_rate']*100:.1f}%")
    print(f"  Avg consensus: {results['avg_consensus_ratio']*100:.1f}%")
    print(f"  Detection rate: {results['detection_rate']*100:.1f}%")
    print(f"  False positive rate: {results['false_positive_rate']*100:.2f}%")
    
    success = results['finalization_rate'] >= 0.8
    print(f"\n  Network test: {'PASS' if success else 'FAIL'}")
    
    return success


def test_full_scale():
    """Test full 6-zone network"""
    print("\n" + "=" * 60)
    print("TEST: Full Scale Network (6 zones × 15 validators)")
    print("=" * 60)
    
    config = NetworkConfig(
        num_zones=6,
        validators_per_zone=15,
        adversary_percentage=0.1  # 10% adversaries
    )
    
    testnet = QRTBTestnet(config)
    testnet.verbose = False
    testnet.initialize_network()
    
    print(f"  Validators: {len(testnet.validators)}")
    print(f"  Zones: {config.num_zones}")
    
    # Run epochs
    num_epochs = 10
    start = time.time()
    results = testnet.run(num_epochs)
    duration = time.time() - start
    
    print(f"\n  Total duration: {duration:.2f}s")
    print(f"  Per-epoch avg: {duration/num_epochs*1000:.1f}ms")
    print(f"  Finalization rate: {results['finalization_rate']*100:.1f}%")
    print(f"  Detection rate: {results['detection_rate']*100:.1f}%")
    
    testnet.print_final_report(results)
    
    return results['finalization_rate'] >= 0.8


def main():
    parser = argparse.ArgumentParser(description='QRTB Testnet Runner')
    parser.add_argument('--quick', action='store_true', help='Run quick test only')
    parser.add_argument('--full', action='store_true', help='Run full scale test')
    parser.add_argument('--epochs', type=int, default=5, help='Number of epochs')
    parser.add_argument('--zones', type=int, default=6, help='Number of zones')
    parser.add_argument('--validators', type=int, default=15, help='Validators per zone')
    parser.add_argument('--adversaries', type=float, default=0.1, help='Adversary percentage')
    args = parser.parse_args()
    
    print("=" * 60)
    print("QRTB TESTNET - Quantum-Resistant Temporal Blockchain")
    print("=" * 60)
    
    all_passed = True
    
    # Always run basic tests
    all_passed &= test_cryptographic_primitives()
    all_passed &= test_detection_engine()
    all_passed &= test_single_validator()
    
    if args.quick:
        all_passed &= test_multi_validator_network()
    elif args.full:
        all_passed &= test_full_scale()
    else:
        # Custom configuration
        config = NetworkConfig(
            num_zones=args.zones,
            validators_per_zone=args.validators,
            adversary_percentage=args.adversaries
        )
        
        testnet = QRTBTestnet(config)
        testnet.initialize_network()
        results = testnet.run(args.epochs)
        testnet.print_final_report(results)
        all_passed &= results['finalization_rate'] >= 0.8
    
    print("\n" + "=" * 60)
    print(f"FINAL RESULT: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 60)
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
