"""
Python baseline benchmark for QRTB crypto primitives.
Run from the native/ directory: python python_baseline.py
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from src.crypto import (
    sha3_256, sha3_512, WOTSPlus, MerkleTree,
    TemporalAuthTree, derive_initial_batch_seed, derive_next_batch_seed
)


def bench(name, iterations, func):
    # Warmup
    for _ in range(min(3, iterations)):
        func()

    start = time.perf_counter_ns()
    for _ in range(iterations):
        func()
    elapsed_ns = time.perf_counter_ns() - start
    ns_per_op = elapsed_ns / iterations

    if ns_per_op < 1_000:
        print(f"  {name:<35} {ns_per_op:>8.1f} ns/op    ({1_000 / ns_per_op:.1f} M ops/sec)")
    elif ns_per_op < 1_000_000:
        print(f"  {name:<35} {ns_per_op / 1_000:>8.2f} us/op    ({1_000_000 / ns_per_op:.1f} K ops/sec)")
    else:
        print(f"  {name:<35} {ns_per_op / 1_000_000:>8.3f} ms/op    ({1_000_000_000 / ns_per_op:.1f} ops/sec)")


def main():
    print("=" * 52)
    print("       QRTB Python Baseline Benchmarks")
    print("=" * 52)

    input_32 = b'\x42' * 32
    input_64 = b'\x42' * 64

    # SHA3-256
    print("\n--- SHA3-256 (32B input) ---")
    bench("Python (hashlib)", 10_000, lambda: sha3_256(input_32))

    # SHA3-512
    print("\n--- SHA3-512 (64B input) ---")
    bench("Python (hashlib)", 10_000, lambda: sha3_512(input_64))

    # WOTS+ keygen
    print("\n--- WOTS+ Keygen ---")
    wots = WOTSPlus()
    seed = sha3_512(b"bench_keygen_seed")
    bench("Python", 2, lambda: wots.keygen(seed))

    # WOTS+ sign
    print("\n--- WOTS+ Sign ---")
    priv_key, pub_key = wots.keygen(seed)
    msg = b"benchmark message for signing"
    bench("Python", 2, lambda: wots.sign(msg, priv_key))

    # WOTS+ verify
    print("\n--- WOTS+ Verify ---")
    sig = wots.sign(msg, priv_key)
    bench("Python", 2, lambda: wots.verify(msg, sig, pub_key))

    # Merkle tree build (1024 leaves)
    print("\n--- Merkle Tree Build (1024 leaves) ---")
    leaves = [sha3_256(i.to_bytes(4, 'little')) for i in range(1024)]
    bench("Python", 2, lambda: MerkleTree(leaves))

    # Merkle proof verify
    print("\n--- Merkle Proof Verify ---")
    tree = MerkleTree(leaves)
    proof = tree.get_proof(500)
    leaf = leaves[500]
    root = tree.root
    bench("Python", 100, lambda: tree.verify_proof(leaf, proof, root))

    # TemporalAuthTree init
    print("\n--- TemporalAuthTree Init (1024 keys) ---")
    batch_seed = derive_initial_batch_seed(b"bench_temporal")
    bench("Python", 1, lambda: TemporalAuthTree(batch_seed))

    # TemporalAuthTree sign
    print("\n--- TemporalAuthTree Sign ---")
    tat = TemporalAuthTree(batch_seed)
    bench("Python", 2, lambda: tat.sign(b"bench sign message"))

    # Batch seed derivation
    print("\n--- Batch Seed Derivation ---")
    current = derive_initial_batch_seed(b"bench_chain")
    def derive_step():
        nonlocal current
        current = derive_next_batch_seed(current)
    bench("Python", 10_000, derive_step)

    print("\n=== Done ===")


if __name__ == "__main__":
    main()
