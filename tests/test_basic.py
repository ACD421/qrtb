#!/usr/bin/env python3
"""
QRTB Security Tests
Tests for temporal auth, registration, forward secrecy, and rotation.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.crypto import (
    sha3_256, sha3_512, concat, secure_random, WOTSPlus,
    TemporalAuthTree, derive_initial_batch_seed, derive_next_batch_seed,
    USABLE_KEYS, RESERVED_ROTATION, TOTAL_KEYS_PER_BATCH, MerkleTree
)
from src.transaction import (
    Transaction, TxInput, TxOutput, TxType,
    UTXOSet, TransactionValidator, AuthRegistry
)
from src.wallet import Wallet, WalletConfig, KeyManager


def test_temporal_auth():
    """Test TemporalAuthTree: batch_seed API, 1022 usable keys, rotation signing."""
    print("\n" + "=" * 60)
    print("TEST: Temporal Auth Tree")
    print("=" * 60)

    seed = secure_random(64)
    batch_seed = derive_initial_batch_seed(seed)
    tree = TemporalAuthTree(batch_seed)

    # Check auth_root is 32 bytes (SHA3-256 Merkle root)
    assert len(tree.auth_root) == 32, f"auth_root should be 32 bytes, got {len(tree.auth_root)}"
    print(f"  Auth root: {tree.auth_root.hex()[:32]}...")

    # Check key counts
    assert tree.remaining_keys == USABLE_KEYS, f"Expected {USABLE_KEYS} usable keys, got {tree.remaining_keys}"
    assert tree.remaining_rotation_keys == RESERVED_ROTATION
    print(f"  Usable keys: {tree.remaining_keys}")
    print(f"  Rotation keys: {tree.remaining_rotation_keys}")

    # Sign a message and verify
    message = b"test transaction data"
    sig, pub, proof, idx = tree.sign(message)

    assert idx == 0, f"First key index should be 0, got {idx}"
    assert tree.remaining_keys == USABLE_KEYS - 1
    print(f"  Signed with key {idx}, remaining: {tree.remaining_keys}")

    # Verify signature
    valid = tree.verify_auth(message, sig, pub, proof, idx)
    assert valid, "Signature verification failed"
    print(f"  Verification: PASS")

    # Static verification against known root
    valid_static = TemporalAuthTree.verify_against_root(
        message, sig, pub, proof, tree.auth_root
    )
    assert valid_static, "Static verification failed"
    print(f"  Static verification: PASS")

    # Tampered message should fail
    tampered = b"tampered data"
    invalid = tree.verify_auth(tampered, sig, pub, proof, idx)
    assert not invalid, "Tampered message should not verify"
    print(f"  Tamper detection: PASS")

    # Use multiple keys
    for i in range(9):
        tree.sign(b"msg_" + bytes([i]))
    assert tree.remaining_keys == USABLE_KEYS - 10
    print(f"  After 10 signs, remaining: {tree.remaining_keys}")

    # Test rotation signing
    rot_msg = b"rotation message"
    rot_sig, rot_pub, rot_proof, rot_idx = tree.sign_rotation(rot_msg)
    assert rot_idx == USABLE_KEYS  # 1022
    assert tree.remaining_rotation_keys == 1
    print(f"  Rotation sign key {rot_idx}: PASS")

    # Verify rotation signature
    rot_valid = tree.verify_auth(rot_msg, rot_sig, rot_pub, rot_proof, rot_idx)
    assert rot_valid, "Rotation signature verification failed"
    print(f"  Rotation verification: PASS")

    # Second rotation key
    rot_sig2, rot_pub2, rot_proof2, rot_idx2 = tree.sign_rotation(b"rotate2")
    assert rot_idx2 == USABLE_KEYS + 1  # 1023
    assert tree.remaining_rotation_keys == 0
    print(f"  Second rotation key {rot_idx2}: PASS")

    # No more rotation keys
    try:
        tree.sign_rotation(b"overflow")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  Rotation key exhaustion: PASS ({e})")

    print("  ALL TEMPORAL AUTH TESTS PASSED")
    return True


def test_registration():
    """Test inner_hash -> address derivation and registration flow."""
    print("\n" + "=" * 60)
    print("TEST: Registration")
    print("=" * 60)

    # Create a key manager
    seed = secure_random(64)
    km = KeyManager(seed)

    # Verify address derivation
    inner = sha3_512(concat(b"address_inner", seed))
    outer = sha3_512(concat(b"address_outer", inner))
    assert km.address == outer, "Address derivation mismatch"
    assert km.inner_hash == inner, "Inner hash mismatch"
    print(f"  Address: {km.address.hex()[:32]}...")
    print(f"  Inner hash matches: PASS")

    # Verify registration state
    assert not km.is_registered
    km.mark_registered()
    assert km.is_registered
    print(f"  Registration state: PASS")

    # Test AuthRegistry
    registry = AuthRegistry()
    auth_root = km.auth_root
    address = km.address

    # Register
    assert registry.register_via_tx(address, auth_root)
    assert registry.is_registered(address)
    assert registry.get_auth_root(address) == auth_root
    print(f"  Registry registration: PASS")

    # Reject double registration
    assert not registry.register_via_tx(address, secure_random(32))
    print(f"  Double registration rejected: PASS")

    # Unregistered address
    fake = secure_random(64)
    assert not registry.is_registered(fake)
    assert registry.get_auth_root(fake) is None
    print(f"  Unregistered check: PASS")

    # Test full wallet registration tx creation
    wallet = Wallet(WalletConfig(name="test"), master_seed=seed)

    # Fund the wallet
    funding_hash = sha3_256(b"funding")
    wallet.add_utxo(
        funding_hash, 0,
        TxOutput(value=1000000, address=wallet.address),
        epoch=0
    )

    # Create registration tx
    reg_tx = wallet.create_registration_tx()
    assert reg_tx is not None, "Failed to create registration tx"
    assert reg_tx.tx_type == TxType.REGISTER
    assert len(reg_tx.outputs[0].data) == 96  # inner_hash(64) + auth_root(32)
    print(f"  Registration tx created: PASS")

    # Verify the output data contains correct inner_hash and auth_root
    reg_inner = reg_tx.outputs[0].data[:64]
    reg_auth = reg_tx.outputs[0].data[64:96]
    assert reg_inner == km.inner_hash
    assert reg_auth == km.auth_root
    print(f"  Registration data correct: PASS")

    print("  ALL REGISTRATION TESTS PASSED")
    return True


def test_forward_secrecy():
    """Test batch chain one-way property."""
    print("\n" + "=" * 60)
    print("TEST: Forward Secrecy")
    print("=" * 60)

    seed = secure_random(64)

    # Derive batch chain
    batch_0 = derive_initial_batch_seed(seed)
    batch_1 = derive_next_batch_seed(batch_0)
    batch_2 = derive_next_batch_seed(batch_1)

    # All different
    assert batch_0 != batch_1 != batch_2
    assert batch_0 != seed
    print(f"  Batch seeds are unique: PASS")

    # One-way: batch_1 cannot derive batch_0
    # (This is inherent in SHA3-512 — no test can prove it,
    # but we verify they're different and the function is one-way by design)
    assert derive_next_batch_seed(batch_0) == batch_1  # Deterministic
    assert derive_next_batch_seed(batch_1) == batch_2
    print(f"  Batch chain deterministic: PASS")

    # master_seed only derives batch_0
    assert derive_initial_batch_seed(seed) == batch_0
    # master_seed cannot directly derive batch_1
    assert derive_initial_batch_seed(seed) != batch_1
    print(f"  Master seed isolation: PASS")

    # Different auth roots per batch
    tree_0 = TemporalAuthTree(batch_0)
    tree_1 = TemporalAuthTree(batch_1)
    assert tree_0.auth_root != tree_1.auth_root
    print(f"  Different auth roots per batch: PASS")

    # Destroy test
    root_before = tree_0.auth_root
    tree_0.destroy()
    # After destroy, batch_seed is zeroed
    assert tree_0._batch_seed == b'\x00' * 64
    assert tree_0._auth_tree is None
    print(f"  Batch destroy: PASS")

    # KeyManager rotation flow
    km = KeyManager(seed)
    km.mark_registered()

    initial_root = km.auth_root
    initial_remaining = km.remaining_keys

    # Use some keys
    km.temporal_sign(b"msg1")
    km.temporal_sign(b"msg2")
    assert km.remaining_keys == initial_remaining - 2
    print(f"  Keys consumed: PASS")

    # Prepare rotation
    next_root = km.prepare_rotation()
    assert next_root != initial_root
    # Current batch still active
    assert km.auth_root == initial_root
    print(f"  Prepare rotation (no change to current): PASS")

    # Execute rotation
    km.execute_rotation()
    assert km.auth_root == next_root
    assert km.remaining_keys == USABLE_KEYS  # Fresh batch
    print(f"  Execute rotation: PASS")

    # Old root's keys can't be used (tree was destroyed)
    # New batch works fine
    sig, pub, proof, idx = km.temporal_sign(b"new batch msg")
    valid = TemporalAuthTree.verify_against_root(
        b"new batch msg", sig, pub, proof, next_root
    )
    assert valid
    print(f"  New batch signing works: PASS")

    print("  ALL FORWARD SECRECY TESTS PASSED")
    return True


def test_rotation_lifecycle():
    """Test prepare -> sign rotation -> execute -> verify new root active."""
    print("\n" + "=" * 60)
    print("TEST: Rotation Lifecycle")
    print("=" * 60)

    seed = secure_random(64)
    wallet = Wallet(WalletConfig(name="rotation_test"), master_seed=seed)

    # Fund wallet
    funding_hash = sha3_256(b"funding_rotation")
    wallet.add_utxo(
        funding_hash, 0,
        TxOutput(value=5000000, address=wallet.address),
        epoch=0
    )

    # Register first
    wallet.key_manager.mark_registered()
    initial_root = wallet.key_manager.auth_root
    print(f"  Initial auth root: {initial_root.hex()[:32]}...")

    # Use some keys to simulate normal operation
    for i in range(5):
        wallet.key_manager.temporal_sign(f"tx_{i}".encode())
    print(f"  Used 5 keys, remaining: {wallet.key_manager.remaining_keys}")

    # Create rotation tx
    rot_tx = wallet.create_rotation_tx()
    assert rot_tx is not None, "Failed to create rotation tx"
    assert rot_tx.tx_type == TxType.ROTATE_AUTH
    print(f"  Rotation tx created: PASS")

    # Verify the new auth root is in the output
    new_root_from_tx = rot_tx.outputs[0].data[:64]
    print(f"  New auth root: {new_root_from_tx.hex()[:32]}...")

    # Confirm rotation (simulates on-chain confirmation)
    wallet.confirm_rotation()
    assert wallet.key_manager.auth_root == new_root_from_tx
    assert wallet.key_manager.remaining_keys == USABLE_KEYS  # Fresh batch
    print(f"  Rotation confirmed, new root active: PASS")
    print(f"  Fresh batch keys: {wallet.key_manager.remaining_keys}")

    # Old root signatures should not verify against new root
    old_msg = b"old_batch_msg"
    # We can't sign with old batch (destroyed), which is the point
    # Verify new batch works
    sig, pub, proof, idx = wallet.key_manager.temporal_sign(b"post_rotation_msg")
    valid = TemporalAuthTree.verify_against_root(
        b"post_rotation_msg", sig, pub, proof, wallet.key_manager.auth_root
    )
    assert valid
    print(f"  Post-rotation signing works: PASS")

    # Verify old root proofs fail against new root
    invalid = TemporalAuthTree.verify_against_root(
        b"post_rotation_msg", sig, pub, proof, initial_root
    )
    assert not invalid, "Old root should not verify new batch signatures"
    print(f"  Old root rejects new batch sigs: PASS")

    # Test should_rotate threshold
    km = KeyManager(secure_random(64))
    km.mark_registered()
    assert not km.should_rotate  # Full batch
    # Exhaust keys to threshold
    for i in range(USABLE_KEYS - 10):
        km.temporal_sign(f"exhaust_{i}".encode())
    assert km.should_rotate
    print(f"  should_rotate threshold: PASS")

    # Test exhaustion raises error
    for i in range(10):
        km.temporal_sign(f"last_{i}".encode())
    try:
        km.temporal_sign(b"overflow")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  Key exhaustion error: PASS ({e})")

    print("  ALL ROTATION LIFECYCLE TESTS PASSED")
    return True


def test_unregistered_rejection():
    """Verify unregistered address temporal auth is rejected."""
    print("\n" + "=" * 60)
    print("TEST: Unregistered Address Rejection")
    print("=" * 60)

    km = KeyManager(secure_random(64))

    # temporal_sign should raise if not registered
    try:
        km.temporal_sign(b"should fail")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  Unregistered temporal_sign rejected: PASS")

    # temporal_sign_rotation should also raise
    try:
        km.temporal_sign_rotation(b"should fail")
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  Unregistered rotation rejected: PASS")

    # After registration, should work
    km.mark_registered()
    sig, pub, proof, idx = km.temporal_sign(b"now works")
    assert sig is not None
    print(f"  Registered temporal_sign works: PASS")

    print("  ALL UNREGISTERED REJECTION TESTS PASSED")
    return True


def test_auth_registry_in_validator():
    """Test AuthRegistry with TransactionValidator."""
    print("\n" + "=" * 60)
    print("TEST: Auth Registry in Validator")
    print("=" * 60)

    utxo_set = UTXOSet()
    registry = AuthRegistry()
    validator = TransactionValidator(utxo_set, registry)

    # Create a wallet and fund it
    seed = secure_random(64)
    km = KeyManager(seed)
    address = km.address

    # Add UTXO for the wallet
    funding_hash = sha3_256(b"fund_auth_test")
    utxo_set.add_utxo(
        funding_hash, 0,
        TxOutput(value=1000000, address=address),
        epoch=0
    )

    # Create a proper REGISTER transaction
    inner_hash = km.inner_hash
    auth_root = km.auth_root
    reg_data = inner_hash + auth_root

    reg_priv, reg_pub = km.get_wots_keypair_for_registration()

    reg_tx = Transaction(
        version=1,
        tx_type=TxType.REGISTER,
        inputs=[TxInput(
            prev_tx_hash=funding_hash,
            output_index=0,
            signature=b"",
            public_key=reg_pub
        )],
        outputs=[
            TxOutput(value=0, address=address, data=reg_data),
            TxOutput(value=990000, address=address),
        ],
        epoch=0,
        timestamp=1000000,
        fee=10000
    )

    # Sign
    signing_hash = reg_tx.signing_hash()
    reg_tx.inputs[0].signature = WOTSPlus().sign(signing_hash, reg_priv)

    # Validate
    valid, reason = validator.validate_transaction(reg_tx, current_epoch=0)
    assert valid, f"Registration validation failed: {reason}"
    print(f"  Registration tx valid: PASS")

    # Apply
    applied = validator.apply_transaction(reg_tx)
    assert applied
    assert registry.is_registered(address)
    assert registry.get_auth_root(address) == auth_root
    print(f"  Registration applied: PASS")

    # Double registration should fail
    funding_hash2 = sha3_256(b"fund2")
    utxo_set.add_utxo(
        funding_hash2, 0,
        TxOutput(value=1000000, address=address),
        epoch=0
    )

    reg_tx2 = Transaction(
        version=1,
        tx_type=TxType.REGISTER,
        inputs=[TxInput(
            prev_tx_hash=funding_hash2,
            output_index=0,
            signature=b"",
            public_key=reg_pub
        )],
        outputs=[
            TxOutput(value=0, address=address, data=reg_data),
            TxOutput(value=990000, address=address),
        ],
        epoch=0,
        timestamp=1000001,
        fee=10000
    )
    signing_hash2 = reg_tx2.signing_hash()
    reg_tx2.inputs[0].signature = WOTSPlus().sign(signing_hash2, reg_priv)

    valid2, reason2 = validator.validate_transaction(reg_tx2, current_epoch=0)
    assert not valid2, "Double registration should fail"
    assert "already registered" in reason2
    print(f"  Double registration rejected: PASS ({reason2})")

    print("  ALL AUTH REGISTRY VALIDATOR TESTS PASSED")
    return True


def main():
    print("=" * 60)
    print("QRTB SECURITY TESTS")
    print("=" * 60)

    all_passed = True

    all_passed &= test_temporal_auth()
    all_passed &= test_registration()
    all_passed &= test_forward_secrecy()
    all_passed &= test_rotation_lifecycle()
    all_passed &= test_unregistered_rejection()
    all_passed &= test_auth_registry_in_validator()

    print("\n" + "=" * 60)
    print(f"RESULT: {'ALL TESTS PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("=" * 60)

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
