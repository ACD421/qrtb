#!/usr/bin/env python3
"""
QRTB Python TPS Benchmark (multiprocessing)

Uses ProcessPoolExecutor to dodge the GIL for CPU-bound WOTS+ verification.
Provides a reference-implementation comparison against the native Rust benchmark.
"""

import sys
import os
import time
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.crypto import sha3_256, sha3_512, secure_random, WOTSPlus

# Global WOTS instance for worker processes
_wots = None

def _init_worker():
    global _wots
    _wots = WOTSPlus()

def _verify_one(args):
    msg, sig, pub = args
    return _wots.verify(msg, sig, pub)

def _generate_one(i):
    wots = WOTSPlus()
    seed = sha3_512(i.to_bytes(8, 'little') + b'qrtb_tps')
    priv, pub = wots.keygen(seed)
    msg = sha3_256(i.to_bytes(8, 'little'))
    sig = wots.sign(msg, priv)
    return (msg, sig, pub)


def main():
    cores = mp.cpu_count()
    print("=" * 70)
    print("  QRTB Python TPS Benchmark (multiprocessing)")
    print("=" * 70)
    print(f"  CPU cores: {cores}")
    print(f"  Workers:   {cores}")

    # Generate test transactions
    n = 2000  # Python is slower, 2K is enough for stable measurement
    print(f"\n  Generating {n} transactions (parallel)...")
    t0 = time.time()
    with ProcessPoolExecutor(max_workers=cores, initializer=_init_worker) as pool:
        txs = list(pool.map(_generate_one, range(n), chunksize=max(1, n // cores)))
    gen_time = time.time() - t0
    print(f"  Generated in {gen_time:.2f}s ({n / gen_time:.0f} tx/s)")

    # Benchmark: parallel signature verification
    for nworkers in [1, 4, 8, cores]:
        print(f"\n--- {nworkers} worker(s), {n} transactions ---")

        with ProcessPoolExecutor(max_workers=nworkers, initializer=_init_worker) as pool:
            # Warmup
            list(pool.map(_verify_one, txs[:min(100, n)], chunksize=10))

            t0 = time.time()
            results = list(pool.map(_verify_one, txs, chunksize=max(1, n // (nworkers * 4))))
            verify_time = time.time() - t0

        valid = sum(results)
        print(f"  Verify: {verify_time:.3f}s  {n / verify_time:.0f} verify/s  ({valid}/{n} valid)")

        # UTXO lookup simulation (dict)
        utxo_set = {sha3_256(f"utxo_{i}".encode()): 10000 for i in range(n)}
        keys = list(utxo_set.keys())
        t0 = time.time()
        found = sum(1 for k in keys if k in utxo_set)
        utxo_time = time.time() - t0
        print(f"  UTXO:   {utxo_time:.4f}s  {n / max(utxo_time, 1e-9):.0f} lookup/s")

        # Merkle tree
        from src.crypto import sha3_256 as h
        leaves = [h(f"leaf_{i}".encode()) for i in range(n)]
        t0 = time.time()
        while len(leaves) > 1:
            if len(leaves) % 2 == 1:
                leaves.append(leaves[-1])
            leaves = [h(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
        merkle_time = time.time() - t0
        print(f"  Merkle: {merkle_time:.4f}s  {n / max(merkle_time, 1e-9):.0f} leaves/s")

        total = verify_time + utxo_time + merkle_time
        tps = n / total
        print(f"  Pipeline: {total:.3f}s  {tps:.0f} TPS (single zone)  {tps * 6:.0f} TPS (6-zone)")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
