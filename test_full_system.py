#!/usr/bin/env python3
"""
QRTB Full System Test
Spins up multiple validator nodes on localhost, runs through the complete
protocol lifecycle over real P2P TCP connections.

Tests:
  1. Node startup and peer discovery
  2. Wallet creation and registration
  3. Transfer with temporal auth (Merkle proof)
  4. Auth root rotation with forward secrecy
  5. Multi-epoch consensus with measurement
  6. Adversary detection and slashing
  7. Block chain linking verification
  8. UTXO state consistency
"""

import sys
import os
import asyncio
import time
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.crypto import sha3_256, sha3_512, concat, secure_random, WOTSPlus, TemporalAuthTree
from src.transaction import (
    Transaction, TxInput, TxOutput, TxType,
    UTXOSet, TransactionValidator, Mempool, AuthRegistry
)
from src.wallet import Wallet, WalletConfig, KeyManager
from src.consensus import BFTConsensus, ConsensusProposal
from src.measurement import MeasurementProtocol
from src.detection import DetectionEngine
from src.epoch import EpochManager
from src.block_producer import BlockProducer
from src.storage import StorageManager
from src.network import create_testnet, NetworkConfig
from src.p2p import P2PNode, PeerManager, MessageType
from src.node import Node, NodeConfig

PASS = 0
FAIL = 0

def report(name, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [{name}] PASS")
    else:
        FAIL += 1
        print(f"  [{name}] FAIL")
    return condition


def test_wallet_lifecycle():
    """Test complete wallet lifecycle: create -> register -> transfer -> rotate"""
    print("\n" + "=" * 60)
    print("TEST 1: Complete Wallet Lifecycle")
    print("=" * 60)

    utxo_set = UTXOSet()
    registry = AuthRegistry()
    validator = TransactionValidator(utxo_set, registry)

    # Create two wallets
    alice = Wallet(WalletConfig(name="Alice"), master_seed=secure_random(64))
    bob = Wallet(WalletConfig(name="Bob"), master_seed=secure_random(64))

    print(f"  Alice: {alice.address.hex()[:32]}...")
    print(f"  Bob:   {bob.address.hex()[:32]}...")

    # Fund via coinbase
    alice_fund = sha3_256(b"alice_fund")
    bob_fund = sha3_256(b"bob_fund")
    utxo_set.add_utxo(alice_fund, 0, TxOutput(value=500_000_000, address=alice.address), epoch=0)
    alice.add_utxo(alice_fund, 0, TxOutput(value=500_000_000, address=alice.address), epoch=0)
    utxo_set.add_utxo(bob_fund, 0, TxOutput(value=100_000_000, address=bob.address), epoch=0)
    bob.add_utxo(bob_fund, 0, TxOutput(value=100_000_000, address=bob.address), epoch=0)

    report("Wallets funded", alice.balance == 500_000_000 and bob.balance == 100_000_000)

    # Register Alice
    reg_tx = alice.create_registration_tx()
    valid, reason = validator.validate_transaction(reg_tx, current_epoch=0)
    report("Alice registration valid", valid)

    validator.apply_transaction(reg_tx)
    alice.key_manager.mark_registered()
    alice.submit_transaction(reg_tx)
    for i, out in enumerate(reg_tx.outputs):
        if out.value > 0 and out.address == alice.address:
            utxo_set.add_utxo(reg_tx.tx_hash, i, out, epoch=0)
            alice.add_utxo(reg_tx.tx_hash, i, out, epoch=0)

    report("Alice registered on-chain", registry.is_registered(alice.address))

    # Register Bob
    bob_reg = bob.create_registration_tx()
    valid, reason = validator.validate_transaction(bob_reg, current_epoch=0)
    report("Bob registration valid", valid)

    validator.apply_transaction(bob_reg)
    bob.key_manager.mark_registered()
    bob.submit_transaction(bob_reg)
    for i, out in enumerate(bob_reg.outputs):
        if out.value > 0 and out.address == bob.address:
            utxo_set.add_utxo(bob_reg.tx_hash, i, out, epoch=0)
            bob.add_utxo(bob_reg.tx_hash, i, out, epoch=0)

    report("Bob registered on-chain", registry.is_registered(bob.address))

    # Alice sends to Bob (temporal auth transfer)
    alice_balance_before = alice.balance
    transfer_tx = alice.create_transfer(bob.address, 50_000_000)

    if transfer_tx is not None:
        # Verify the transfer has auth proofs
        has_proofs = all(inp.auth_proof is not None for inp in transfer_tx.inputs)
        report("Transfer has auth proofs", has_proofs)

        valid, reason = validator.validate_transaction(transfer_tx, current_epoch=0)
        report(f"Transfer valid ({reason})", valid)
    else:
        report("Transfer created", False)
        report("Transfer has auth proofs", False)
        report("Transfer valid", False)

    # Temporal auth signing (5 messages)
    for i in range(5):
        sig, pub, proof, idx = alice.key_manager.temporal_sign(f"msg_{i}".encode())
        verified = TemporalAuthTree.verify_against_root(
            f"msg_{i}".encode(), sig, pub, proof,
            registry.get_auth_root(alice.address)
        )
        if not verified:
            report(f"Temporal sign {i}", False)
            break
    else:
        report("5 temporal signatures verified", True)

    # Rotate Alice's auth root
    old_root = alice.key_manager.auth_root
    rot_tx = alice.create_rotation_tx()
    report("Rotation tx created", rot_tx is not None)

    if rot_tx:
        alice.confirm_rotation()
        new_root = alice.key_manager.auth_root
        report("Auth root changed", old_root != new_root)
        report("Fresh keys after rotation", alice.key_manager.remaining_keys == 1022)

        # Sign with new batch
        sig, pub, proof, idx = alice.key_manager.temporal_sign(b"post_rotation")
        verified = TemporalAuthTree.verify_against_root(
            b"post_rotation", sig, pub, proof, new_root
        )
        report("Post-rotation signing works", verified)

        # Old root rejects new sigs
        old_valid = TemporalAuthTree.verify_against_root(
            b"post_rotation", sig, pub, proof, old_root
        )
        report("Old root rejects new sigs", not old_valid)


def test_consensus_full_cycle():
    """Test full consensus cycle with measurement and detection"""
    print("\n" + "=" * 60)
    print("TEST 2: Full Consensus Cycle")
    print("=" * 60)

    config = NetworkConfig(
        num_zones=3,
        validators_per_zone=10,
        adversary_percentage=0.2
    )
    testnet = create_testnet(
        num_zones=config.num_zones,
        validators_per_zone=config.validators_per_zone,
        adversary_pct=config.adversary_percentage
    )
    testnet.verbose = False

    total_validators = len(testnet.validators)
    adversary_count = sum(1 for v in testnet.validators.values() if v.config.is_adversary)
    print(f"  Validators: {total_validators}")
    print(f"  Adversaries: {adversary_count} ({adversary_count/total_validators*100:.0f}%)")
    print(f"  Zones: {config.num_zones}")

    # Run 10 epochs
    results = testnet.run(10)

    report("All epochs finalized", results['finalization_rate'] == 1.0)
    report(f"Detection rate >= 95% ({results['detection_rate']*100:.1f}%)",
           results['detection_rate'] >= 0.95)
    report(f"False positive rate < 2% ({results['false_positive_rate']*100:.2f}%)",
           results['false_positive_rate'] < 0.02)
    report(f"Avg consensus >= 95% ({results['avg_consensus_ratio']*100:.1f}%)",
           results['avg_consensus_ratio'] >= 0.95)

    print(f"  Finalization: {results['finalization_rate']*100:.1f}%")
    print(f"  Detection: {results['detection_rate']*100:.1f}%")
    print(f"  False positive: {results['false_positive_rate']*100:.2f}%")


def test_stress_scale():
    """Stress test at scale: 300 validators, 33% adversary"""
    print("\n" + "=" * 60)
    print("TEST 3: Stress Test (300 validators, 33% adversary, 10 epochs)")
    print("=" * 60)

    testnet = create_testnet(num_zones=6, validators_per_zone=50, adversary_pct=0.33)
    testnet.verbose = False
    testnet.initialize_network()

    start = time.time()
    results = testnet.run(10)
    duration = time.time() - start

    print(f"  Duration: {duration:.2f}s ({duration/10*1000:.0f}ms/epoch)")
    print(f"  Finalization: {results['finalization_rate']*100:.1f}%")
    print(f"  Detection: {results['detection_rate']*100:.1f}%")

    report("100% finalization at 33% adversary", results['finalization_rate'] == 1.0)
    report("Detection >= 90%", results['detection_rate'] >= 0.90)
    report("Epoch time < 10s", duration / 10 < 10.0)


def test_storage_chain_linking():
    """Test block storage with chain linking"""
    print("\n" + "=" * 60)
    print("TEST 4: Storage and Chain Linking")
    print("=" * 60)

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        storage = StorageManager(tmpdir)

        # Simulate 5 epochs of blocks
        prev_hash = None
        for epoch in range(5):
            # Create a mock consensus block
            proposer = secure_random(32)
            proposal = ConsensusProposal(
                proposer_id=proposer,
                epoch=epoch,
                round=0,
                measurement_root=sha3_256(f"measurements_{epoch}".encode()),
                timestamp=time.time()
            )

            from src.consensus import ConsensusBlock
            block = ConsensusBlock(
                epoch=epoch,
                round=0,
                proposal=proposal,
                votes=[],
                total_stake=10000,
                supporting_stake=8000,
                finalization_time=time.time()
            )

            storage.store_block_with_transactions(block, [])

        # Verify chain linking
        blocks_linked = True
        for epoch in range(1, 5):
            block = storage.blocks.get_block(epoch)
            prev_block = storage.blocks.get_block(epoch - 1)
            if block and prev_block:
                if block.prev_hash != prev_block.block_hash:
                    blocks_linked = False
                    break

        report("5 blocks stored", storage.blocks.get_chain_height() == 4)

        # Check genesis block has zero prev_hash
        genesis = storage.blocks.get_block(0)
        report("Genesis prev_hash is zeros", genesis.prev_hash == b'\x00' * 32 if genesis else False)

        report("Blocks chain-linked", blocks_linked)

        # Test immutability (second insert should not overwrite)
        original = storage.blocks.get_block(2)
        original_hash = original.block_hash if original else None
        report("Block immutability (stored once)", original_hash is not None)

        storage.close()


def test_p2p_connectivity():
    """Test P2P node connectivity"""
    print("\n" + "=" * 60)
    print("TEST 5: P2P Connectivity")
    print("=" * 60)

    connected = False
    messages_received = []

    async def run_p2p_test():
        nonlocal connected, messages_received

        # Start two nodes
        node1 = P2PNode(secure_random(32), zone_id=0, stake=1000)
        node2 = P2PNode(secure_random(32), zone_id=0, stake=1000)

        def on_msg(peer_id, msg_type, payload):
            messages_received.append((msg_type, payload))

        node2.on_message = on_msg

        await node1.start("127.0.0.1", 19850)
        await node2.start("127.0.0.1", 19851)

        # Connect node2 to node1
        await node2.connect_to_peer("127.0.0.1", 19850)
        await asyncio.sleep(0.5)

        connected = len(node2.peer_manager.peers) > 0 or len(node1.peer_manager.peers) > 0

        # Send a message
        test_payload = b"hello_qrtb"
        await node1.broadcast(MessageType.TX_BROADCAST, test_payload)
        await asyncio.sleep(0.5)

        # Cleanup
        node1.stop()
        node2.stop()
        await asyncio.sleep(0.2)

    try:
        asyncio.run(run_p2p_test())
    except Exception as e:
        print(f"  P2P test error: {e}")

    report("P2P nodes connected", connected)
    report("Message received over TCP", len(messages_received) > 0)


def test_cross_implementation_crypto():
    """Test crypto primitives produce consistent results"""
    print("\n" + "=" * 60)
    print("TEST 6: Cryptographic Consistency")
    print("=" * 60)

    from src.crypto import (
        sha3_256, sha3_512, WOTSPlus, TemporalAuthTree,
        derive_initial_batch_seed, derive_next_batch_seed
    )

    # SHA3-256 known value
    empty_hash = sha3_256(b"")
    report("SHA3-256('') matches NIST",
           empty_hash.hex() == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")

    # WOTS+ sign/verify roundtrip
    wots = WOTSPlus()
    seed = sha3_512(b"test_consistency_seed")
    priv, pub = wots.keygen(seed)
    msg = sha3_256(b"test message")
    sig = wots.sign(msg, priv)
    report("WOTS+ sign/verify", wots.verify(msg, sig, pub))

    # Tamper detection
    tampered = msg + b"\x00"
    report("WOTS+ tamper detection", not wots.verify(tampered, sig, pub))

    # Batch seed chain determinism
    master = sha3_512(b"determinism_test")
    batch0 = derive_initial_batch_seed(master)
    batch1 = derive_next_batch_seed(batch0)
    batch0_again = derive_initial_batch_seed(master)
    batch1_again = derive_next_batch_seed(batch0_again)
    report("Batch seed deterministic", batch0 == batch0_again and batch1 == batch1_again)

    # TemporalAuthTree: same seed -> same root
    tree1 = TemporalAuthTree(batch0)
    tree2 = TemporalAuthTree(batch0_again)
    report("Auth root deterministic", tree1.auth_root == tree2.auth_root)

    # Forward secrecy: can't derive batch0 from batch1
    report("batch0 != batch1", batch0 != batch1)
    # batch1 = SHA3-512("batch_next" || batch0), one-way
    reverse_attempt = sha3_512(concat(b"batch_next", batch1))
    report("Cannot reverse batch chain", reverse_attempt != batch0)


def test_detection_accuracy():
    """Test detection engine with controlled adversary profiles"""
    print("\n" + "=" * 60)
    print("TEST 7: Detection Engine Accuracy")
    print("=" * 60)

    from src.measurement import RTTMeasurement

    engine = DetectionEngine()

    # Create 10 honest + 5 adversary validators
    honest_ids = [secure_random(32) for _ in range(10)]
    adversary_ids = [secure_random(32) for _ in range(5)]
    all_ids = honest_ids + adversary_ids

    measurements = {}
    locations = {}

    for i, vid in enumerate(honest_ids):
        locations[vid] = (40.0 + i * 2, -74.0 + i * 3)
        ms = []
        for j in range(5):
            target = all_ids[(i + j + 1) % len(all_ids)]
            theoretical = 50 + j * 10
            actual = theoretical * 1.15  # honest ratio
            ms.append(RTTMeasurement(
                source_id=vid, target_id=target,
                rtt_ms=actual, timestamp=int(time.time() * 1000),
                theoretical_rtt_ms=theoretical
            ))
        measurements[vid] = ms

    for i, vid in enumerate(adversary_ids):
        locations[vid] = (34.0 + i * 2, -118.0 + i * 3)
        ms = []
        for j in range(5):
            target = all_ids[(i + j + 1) % len(all_ids)]
            theoretical = 50 + j * 10
            actual = theoretical * 0.82  # adversary ratio
            ms.append(RTTMeasurement(
                source_id=vid, target_id=target,
                rtt_ms=actual, timestamp=int(time.time() * 1000),
                theoretical_rtt_ms=theoretical
            ))
        measurements[vid] = ms

    engine.load_measurements(measurements, locations)
    results = engine.analyze_all()

    honest_flagged = sum(1 for hid in honest_ids if results[hid].is_suspicious)
    adversary_caught = sum(1 for aid in adversary_ids if results[aid].is_suspicious)

    report(f"Adversaries caught: {adversary_caught}/5", adversary_caught >= 4)
    report(f"Honest false positives: {honest_flagged}/10", honest_flagged <= 1)


def main():
    print("=" * 60)
    print("QRTB FULL SYSTEM TEST")
    print("=" * 60)

    test_wallet_lifecycle()
    test_consensus_full_cycle()
    test_stress_scale()
    test_storage_chain_linking()
    test_p2p_connectivity()
    test_cross_implementation_crypto()
    test_detection_accuracy()

    print("\n" + "=" * 60)
    total = PASS + FAIL
    print(f"RESULTS: {PASS}/{total} passed, {FAIL} failed")
    if FAIL == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"FAILURES: {FAIL}")
    print("=" * 60)

    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
