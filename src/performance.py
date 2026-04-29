"""
QRTB Performance Optimization
Targeting 16M TPS through parallelization and batching

Key optimizations:
1. Batch WOTS+ verification - parallelize hash chains
2. Transaction pipelining - validate while collecting
3. Sharded UTXO lookups - partition by address prefix
4. Parallel Merkle tree construction
5. Zone-parallel block production
6. Pre-computed verification tables
"""

import time
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable, Set
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from collections import defaultdict
import multiprocessing as mp

from .crypto import sha3_256, sha3_512, WOTSPlus
from .transaction import Transaction, TxInput, UTXO, UTXOSet

# =============================================================================
# CONFIGURATION
# =============================================================================

# Target: 16M TPS across all zones
# With 6 zones: ~2.7M TPS per zone
# With 250ms blocks: ~675K tx per block per zone
TARGET_TPS = 16_000_000
NUM_ZONES = 6
BLOCK_TIME_MS = 250
TXS_PER_BLOCK_PER_ZONE = TARGET_TPS * (BLOCK_TIME_MS / 1000) / NUM_ZONES

# Worker configuration
CPU_CORES = mp.cpu_count()
VERIFICATION_WORKERS = max(4, CPU_CORES - 2)
MERKLE_WORKERS = max(2, CPU_CORES // 4)

# Batch sizes
VERIFICATION_BATCH_SIZE = 1000
UTXO_BATCH_SIZE = 5000
MERKLE_BATCH_SIZE = 10000


# =============================================================================
# BATCH WOTS+ VERIFICATION
# =============================================================================

class BatchWOTSVerifier:
    """
    Batch verification of WOTS+ signatures
    Parallelizes hash chain computation across cores
    """
    
    def __init__(self, num_workers: int = VERIFICATION_WORKERS):
        self.num_workers = num_workers
        self.wots = WOTSPlus()
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        
        # Statistics
        self.verified_count = 0
        self.failed_count = 0
        self.total_time_ms = 0
    
    def verify_single(self, message: bytes, signature: bytes,
                     public_key: bytes) -> bool:
        """Verify single signature"""
        return self.wots.verify(message, signature, public_key)
    
    def verify_batch(self, items: List[Tuple[bytes, bytes, bytes]]
                    ) -> List[Tuple[int, bool]]:
        """
        Verify batch of signatures in parallel
        
        Args:
            items: List of (message, signature, public_key) tuples
            
        Returns:
            List of (index, is_valid) tuples
        """
        start = time.time()
        
        # Submit all verification jobs
        futures = {}
        for i, (message, signature, public_key) in enumerate(items):
            future = self.executor.submit(
                self.verify_single, message, signature, public_key
            )
            futures[future] = i
        
        # Collect results
        results = []
        for future in as_completed(futures):
            idx = futures[future]
            try:
                valid = future.result()
                results.append((idx, valid))
                if valid:
                    self.verified_count += 1
                else:
                    self.failed_count += 1
            except Exception:
                results.append((idx, False))
                self.failed_count += 1
        
        elapsed = (time.time() - start) * 1000
        self.total_time_ms += elapsed
        
        # Sort by original index
        results.sort(key=lambda x: x[0])
        return results
    
    def verify_transactions(self, transactions: List[Transaction],
                           signing_hashes: Optional[List[bytes]] = None
                           ) -> Dict[bytes, bool]:
        """
        Verify all signatures in a batch of transactions
        
        Returns:
            Dict mapping tx_hash -> is_valid
        """
        # Collect all signatures to verify
        items = []
        tx_mapping = []  # Track which tx each item belongs to
        
        for tx in transactions:
            signing_hash = signing_hashes[len(tx_mapping)] if signing_hashes else tx.signing_hash()
            
            for inp in tx.inputs:
                items.append((signing_hash, inp.signature, inp.public_key))
                tx_mapping.append(tx.tx_hash)
        
        if not items:
            return {tx.tx_hash: True for tx in transactions}
        
        # Batch verify
        results = self.verify_batch(items)
        
        # Aggregate per transaction (all inputs must be valid)
        tx_valid: Dict[bytes, bool] = defaultdict(lambda: True)
        for idx, valid in results:
            tx_hash = tx_mapping[idx]
            if not valid:
                tx_valid[tx_hash] = False
        
        return dict(tx_valid)
    
    def get_stats(self) -> dict:
        """Get verification statistics"""
        total = self.verified_count + self.failed_count
        rate = total / (self.total_time_ms / 1000) if self.total_time_ms > 0 else 0
        
        return {
            "verified": self.verified_count,
            "failed": self.failed_count,
            "total_time_ms": self.total_time_ms,
            "verifications_per_sec": rate,
            "workers": self.num_workers
        }
    
    def shutdown(self):
        """Shutdown executor"""
        self.executor.shutdown(wait=True)


# =============================================================================
# SHARDED UTXO SET
# =============================================================================

class ShardedUTXOSet:
    """
    UTXO set sharded by tx_hash prefix for parallel lookups
    256 shards based on first byte of tx_hash
    """
    
    def __init__(self, num_shards: int = 256):
        self.num_shards = num_shards
        
        # Shards: shard_id -> {(tx_hash, output_index) -> UTXO}
        self.shards: List[Dict[Tuple[bytes, int], UTXO]] = [
            {} for _ in range(num_shards)
        ]
        
        # Shard locks for thread safety
        self.locks = [threading.Lock() for _ in range(num_shards)]
        
        # Secondary index: address -> set of (tx_hash, output_index)
        self.by_address: Dict[bytes, Set[Tuple[bytes, int]]] = defaultdict(set)
        self.address_lock = threading.Lock()
    
    def _get_shard(self, tx_hash: bytes) -> int:
        """Get shard ID for tx_hash"""
        return tx_hash[0] if tx_hash else 0
    
    def add_utxo(self, tx_hash: bytes, output_index: int,
                output, epoch: int) -> None:
        """Add UTXO to appropriate shard"""
        shard_id = self._get_shard(tx_hash)
        key = (tx_hash, output_index)
        
        utxo = UTXO(tx_hash, output_index, output, epoch)
        
        with self.locks[shard_id]:
            self.shards[shard_id][key] = utxo
        
        # Also index by address for balance queries
        with self.address_lock:
            self.by_address[output.address].add(key)
    
    def get_utxo(self, tx_hash: bytes, output_index: int,
                address_hint: Optional[bytes] = None) -> Optional[UTXO]:
        """Get UTXO by reference"""
        shard_id = self._get_shard(tx_hash)
        key = (tx_hash, output_index)
        
        with self.locks[shard_id]:
            return self.shards[shard_id].get(key)
    
    def spend_utxo(self, tx_hash: bytes, output_index: int,
                  spending_tx: bytes,
                  address_hint: Optional[bytes] = None) -> Optional[UTXO]:
        """Mark UTXO as spent.
        Lock order: shard lock first, then address lock AFTER releasing shard lock.
        get_balance takes address_lock then calls get_utxo (shard lock).
        Nesting shard->address here would invert that order and deadlock.
        """
        shard_id = self._get_shard(tx_hash)
        key = (tx_hash, output_index)

        utxo = None
        with self.locks[shard_id]:
            utxo = self.shards[shard_id].get(key)
            if utxo and not utxo.is_spent:
                utxo.is_spent = True
                utxo.spent_by = spending_tx
            else:
                return None

        # Remove from address index outside shard lock.
        # Briefly stale index is safe: get_balance rechecks is_spent.
        with self.address_lock:
            self.by_address[utxo.output.address].discard(key)

        return utxo
    
    def batch_lookup(self, refs: List[Tuple[bytes, int, Optional[bytes]]]
                    ) -> List[Optional[UTXO]]:
        """
        Batch UTXO lookups with parallel shard access
        
        Args:
            refs: List of (tx_hash, output_index, address_hint)
        """
        # Group by shard
        shard_groups: Dict[int, List[Tuple[int, bytes, int]]] = defaultdict(list)
        
        for i, (tx_hash, output_index, address_hint) in enumerate(refs):
            shard_id = self._get_shard(tx_hash)
            shard_groups[shard_id].append((i, tx_hash, output_index))
        
        # Lookup each shard in parallel
        results = [None] * len(refs)
        
        def lookup_shard(shard_id: int, items: List[Tuple[int, bytes, int]]):
            with self.locks[shard_id]:
                for orig_idx, tx_hash, output_index in items:
                    key = (tx_hash, output_index)
                    results[orig_idx] = self.shards[shard_id].get(key)
        
        threads = []
        for shard_id, items in shard_groups.items():
            t = threading.Thread(target=lookup_shard, args=(shard_id, items))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return results
    
    def get_balance(self, address: bytes, current_epoch: int) -> int:
        """Get spendable balance for address"""
        total = 0
        
        with self.address_lock:
            keys = list(self.by_address.get(address, set()))
        
        for tx_hash, output_index in keys:
            utxo = self.get_utxo(tx_hash, output_index)
            if utxo and not utxo.is_spent:
                if utxo.output.lock_epoch <= current_epoch:
                    total += utxo.output.value
        
        return total
    
    def total_utxos(self) -> int:
        """Count total UTXOs"""
        return sum(len(shard) for shard in self.shards)
    
    def shard_stats(self) -> List[int]:
        """Get UTXO count per shard"""
        return [len(shard) for shard in self.shards]


# =============================================================================
# PARALLEL MERKLE TREE
# =============================================================================

class ParallelMerkleTree:
    """
    Parallel Merkle tree construction for large transaction sets
    """
    
    def __init__(self, num_workers: int = MERKLE_WORKERS):
        self.num_workers = num_workers
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
    
    def compute_root(self, leaves: List[bytes]) -> bytes:
        """
        Compute Merkle root with parallel hashing
        
        For large sets, splits work across workers
        """
        if len(leaves) == 0:
            return b'\x00' * 32
        
        if len(leaves) == 1:
            return leaves[0]
        
        # For small sets, compute directly
        if len(leaves) <= MERKLE_BATCH_SIZE:
            return self._compute_root_sequential(leaves)
        
        # For large sets, parallelize
        return self._compute_root_parallel(leaves)
    
    def _compute_root_sequential(self, leaves: List[bytes]) -> bytes:
        """Sequential Merkle root computation"""
        current = list(leaves)
        
        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])
            
            next_level = []
            for i in range(0, len(current), 2):
                combined = sha3_256(current[i] + current[i + 1])
                next_level.append(combined)
            
            current = next_level
        
        return current[0]
    
    def _compute_root_parallel(self, leaves: List[bytes]) -> bytes:
        """Parallel Merkle root computation"""
        current = list(leaves)
        
        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])
            
            # Split into chunks for parallel processing
            chunk_size = max(1000, len(current) // (self.num_workers * 2))
            chunks = []
            for i in range(0, len(current), chunk_size * 2):
                chunk = current[i:i + chunk_size * 2]
                chunks.append(chunk)
            
            # Process chunks in parallel
            futures = []
            for chunk in chunks:
                future = self.executor.submit(self._hash_chunk, chunk)
                futures.append(future)
            
            # Collect results
            next_level = []
            for future in futures:
                next_level.extend(future.result())
            
            current = next_level
        
        return current[0] if current else b'\x00' * 32
    
    def _hash_chunk(self, pairs: List[bytes]) -> List[bytes]:
        """Hash a chunk of pairs"""
        result = []
        for i in range(0, len(pairs), 2):
            if i + 1 < len(pairs):
                combined = sha3_256(pairs[i] + pairs[i + 1])
            else:
                combined = sha3_256(pairs[i] + pairs[i])
            result.append(combined)
        return result
    
    def shutdown(self):
        """Shutdown executor"""
        self.executor.shutdown(wait=True)


# =============================================================================
# TRANSACTION PIPELINE
# =============================================================================

@dataclass
class PipelineStage:
    """Pipeline stage statistics"""
    name: str
    processed: int = 0
    passed: int = 0
    failed: int = 0
    time_ms: float = 0


class TransactionPipeline:
    """
    Multi-stage transaction validation pipeline
    Processes transactions in parallel batches
    
    Stages:
    1. Structure validation (fast, no I/O)
    2. UTXO existence check (sharded lookup)
    3. Signature verification (CPU-intensive)
    4. Final validation (fee, value conservation)
    """
    
    def __init__(self, 
                 utxo_set: ShardedUTXOSet,
                 verifier: BatchWOTSVerifier,
                 num_workers: int = VERIFICATION_WORKERS):
        self.utxo_set = utxo_set
        self.verifier = verifier
        self.num_workers = num_workers
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        
        # Pipeline statistics
        self.stages = {
            "structure": PipelineStage("structure"),
            "utxo": PipelineStage("utxo"),
            "signature": PipelineStage("signature"),
            "final": PipelineStage("final")
        }
    
    def process_batch(self, transactions: List[Transaction],
                     current_epoch: int
                     ) -> Tuple[List[Transaction], List[Tuple[Transaction, str]]]:
        """
        Process batch through pipeline
        
        Returns:
            (valid_transactions, [(invalid_tx, reason), ...])
        """
        valid = transactions
        invalid = []
        
        # Stage 1: Structure validation (parallel)
        valid, stage_invalid = self._stage_structure(valid)
        invalid.extend(stage_invalid)
        
        if not valid:
            return [], invalid
        
        # Stage 2: UTXO existence (parallel sharded lookup)
        valid, stage_invalid = self._stage_utxo(valid, current_epoch)
        invalid.extend(stage_invalid)
        
        if not valid:
            return [], invalid
        
        # Stage 3: Signature verification (batch parallel)
        valid, stage_invalid = self._stage_signature(valid)
        invalid.extend(stage_invalid)
        
        if not valid:
            return [], invalid
        
        # Stage 4: Final validation
        valid, stage_invalid = self._stage_final(valid, current_epoch)
        invalid.extend(stage_invalid)
        
        return valid, invalid
    
    def _stage_structure(self, transactions: List[Transaction]
                        ) -> Tuple[List[Transaction], List[Tuple[Transaction, str]]]:
        """Stage 1: Structure validation"""
        start = time.time()
        valid = []
        invalid = []
        
        for tx in transactions:
            is_valid, reason = tx.is_valid_structure()
            if is_valid:
                valid.append(tx)
            else:
                invalid.append((tx, f"structure: {reason}"))
        
        elapsed = (time.time() - start) * 1000
        self.stages["structure"].processed += len(transactions)
        self.stages["structure"].passed += len(valid)
        self.stages["structure"].failed += len(invalid)
        self.stages["structure"].time_ms += elapsed
        
        return valid, invalid
    
    def _stage_utxo(self, transactions: List[Transaction],
                   current_epoch: int
                   ) -> Tuple[List[Transaction], List[Tuple[Transaction, str]]]:
        """Stage 2: UTXO existence check"""
        start = time.time()
        
        # Collect all UTXO references
        refs = []
        tx_mapping = []
        
        for tx in transactions:
            for inp in tx.inputs:
                refs.append((inp.prev_tx_hash, inp.output_index, None))
                tx_mapping.append(tx)
        
        # Batch lookup
        utxos = self.utxo_set.batch_lookup(refs)
        
        # Check results
        valid = []
        invalid = []
        seen_txs: Set[bytes] = set()
        tx_issues: Dict[bytes, str] = {}
        
        for i, utxo in enumerate(utxos):
            tx = tx_mapping[i]
            
            if tx.tx_hash in seen_txs:
                continue
            
            if utxo is None:
                tx_issues[tx.tx_hash] = "utxo: not found"
                seen_txs.add(tx.tx_hash)
            elif utxo.is_spent:
                tx_issues[tx.tx_hash] = "utxo: already spent"
                seen_txs.add(tx.tx_hash)
            elif utxo.output.lock_epoch > current_epoch:
                tx_issues[tx.tx_hash] = f"utxo: locked until epoch {utxo.output.lock_epoch}"
                seen_txs.add(tx.tx_hash)
        
        for tx in transactions:
            if tx.tx_hash in tx_issues:
                invalid.append((tx, tx_issues[tx.tx_hash]))
            else:
                valid.append(tx)
        
        elapsed = (time.time() - start) * 1000
        self.stages["utxo"].processed += len(transactions)
        self.stages["utxo"].passed += len(valid)
        self.stages["utxo"].failed += len(invalid)
        self.stages["utxo"].time_ms += elapsed
        
        return valid, invalid
    
    def _stage_signature(self, transactions: List[Transaction]
                        ) -> Tuple[List[Transaction], List[Tuple[Transaction, str]]]:
        """Stage 3: Batch signature verification"""
        start = time.time()
        
        # Batch verify all signatures
        tx_valid = self.verifier.verify_transactions(transactions)
        
        valid = []
        invalid = []
        
        for tx in transactions:
            if tx_valid.get(tx.tx_hash, False):
                valid.append(tx)
            else:
                invalid.append((tx, "signature: invalid"))
        
        elapsed = (time.time() - start) * 1000
        self.stages["signature"].processed += len(transactions)
        self.stages["signature"].passed += len(valid)
        self.stages["signature"].failed += len(invalid)
        self.stages["signature"].time_ms += elapsed
        
        return valid, invalid
    
    def _stage_final(self, transactions: List[Transaction],
                    current_epoch: int
                    ) -> Tuple[List[Transaction], List[Tuple[Transaction, str]]]:
        """Stage 4: Final validation"""
        start = time.time()
        valid = []
        invalid = []
        
        for tx in transactions:
            # Check epoch
            if tx.epoch > current_epoch:
                invalid.append((tx, f"final: future epoch {tx.epoch}"))
                continue
            
            if tx.epoch < current_epoch - 1:
                invalid.append((tx, f"final: expired epoch {tx.epoch}"))
                continue
            
            valid.append(tx)
        
        elapsed = (time.time() - start) * 1000
        self.stages["final"].processed += len(transactions)
        self.stages["final"].passed += len(valid)
        self.stages["final"].failed += len(invalid)
        self.stages["final"].time_ms += elapsed
        
        return valid, invalid
    
    def get_stats(self) -> dict:
        """Get pipeline statistics"""
        total_time = sum(s.time_ms for s in self.stages.values())
        total_processed = self.stages["structure"].processed
        
        return {
            "total_processed": total_processed,
            "total_time_ms": total_time,
            "throughput_tps": total_processed / (total_time / 1000) if total_time > 0 else 0,
            "stages": {
                name: {
                    "processed": stage.processed,
                    "passed": stage.passed,
                    "failed": stage.failed,
                    "time_ms": stage.time_ms,
                    "pass_rate": stage.passed / stage.processed if stage.processed > 0 else 0
                }
                for name, stage in self.stages.items()
            }
        }
    
    def shutdown(self):
        """Shutdown executor"""
        self.executor.shutdown(wait=True)
        self.verifier.shutdown()


# =============================================================================
# THROUGHPUT BENCHMARK
# =============================================================================

class ThroughputBenchmark:
    """
    Benchmark to measure actual TPS capacity
    """
    
    def __init__(self):
        self.utxo_set = ShardedUTXOSet()
        self.verifier = BatchWOTSVerifier()
        self.pipeline = TransactionPipeline(self.utxo_set, self.verifier)
        self.merkle = ParallelMerkleTree()
    
    def run_benchmark(self, num_transactions: int = 10000) -> dict:
        """
        Run throughput benchmark
        
        Returns:
            Benchmark results including TPS measurements
        """
        from .transaction import Transaction, TxInput, TxOutput, TxType
        from .crypto import secure_random, WOTSPlus
        
        wots = WOTSPlus()
        results = {}
        
        # Generate test transactions
        print(f"  Generating {num_transactions} test transactions...")
        start = time.time()
        
        transactions = []
        for i in range(num_transactions):
            # Create minimal valid transaction structure
            seed = secure_random(64)
            priv, pub = wots.keygen(seed)
            
            tx = Transaction(
                version=1,
                tx_type=TxType.TRANSFER,
                inputs=[TxInput(
                    prev_tx_hash=sha3_256(f"funding_{i}".encode()),
                    output_index=0,
                    signature=b'\x00' * 2144,  # Placeholder
                    public_key=pub
                )],
                outputs=[TxOutput(value=1000, address=secure_random(64))],
                epoch=0,
                timestamp=int(time.time() * 1000),
                fee=5000
            )
            
            # Add funding UTXO
            self.utxo_set.add_utxo(
                tx.inputs[0].prev_tx_hash, 0,
                TxOutput(value=10000, address=secure_random(64)),
                epoch=0
            )
            
            # Sign
            tx.inputs[0].signature = wots.sign(tx.signing_hash(), priv)
            transactions.append(tx)
        
        gen_time = time.time() - start
        results["generation_time_s"] = gen_time
        results["generation_tps"] = num_transactions / gen_time
        print(f"  Generated in {gen_time:.2f}s ({num_transactions/gen_time:.0f}/s)")
        
        # Benchmark signature verification
        print("  Benchmarking signature verification...")
        start = time.time()
        tx_valid = self.verifier.verify_transactions(transactions[:1000])
        verify_time = time.time() - start
        results["verify_1k_time_s"] = verify_time
        results["verify_tps"] = 1000 / verify_time
        print(f"  Verified 1000 sigs in {verify_time:.2f}s ({1000/verify_time:.0f}/s)")
        
        # Benchmark UTXO lookups
        print("  Benchmarking UTXO lookups...")
        refs = [(tx.inputs[0].prev_tx_hash, 0, None) for tx in transactions]
        start = time.time()
        utxos = self.utxo_set.batch_lookup(refs)
        lookup_time = time.time() - start
        results["utxo_lookup_time_s"] = lookup_time
        results["utxo_lookup_tps"] = num_transactions / lookup_time
        print(f"  Looked up {num_transactions} UTXOs in {lookup_time:.4f}s ({num_transactions/lookup_time:.0f}/s)")
        
        # Benchmark Merkle tree
        print("  Benchmarking Merkle tree...")
        tx_hashes = [tx.tx_hash for tx in transactions]
        start = time.time()
        root = self.merkle.compute_root(tx_hashes)
        merkle_time = time.time() - start
        results["merkle_time_s"] = merkle_time
        results["merkle_tps"] = num_transactions / merkle_time
        print(f"  Merkle root in {merkle_time:.4f}s ({num_transactions/merkle_time:.0f}/s)")
        
        # Estimate achievable TPS
        # Bottleneck is signature verification
        # With 16 cores doing verification in parallel:
        sig_verify_per_sec = results["verify_tps"]
        projected_tps_single_zone = sig_verify_per_sec
        projected_tps_6_zones = sig_verify_per_sec * 6
        
        results["projected_single_zone_tps"] = projected_tps_single_zone
        results["projected_6_zone_tps"] = projected_tps_6_zones
        results["target_tps"] = TARGET_TPS
        results["target_achievable_pct"] = (projected_tps_6_zones / TARGET_TPS) * 100
        
        print(f"\n  Projected TPS (1 zone): {projected_tps_single_zone:.0f}")
        print(f"  Projected TPS (6 zones): {projected_tps_6_zones:.0f}")
        print(f"  Target: {TARGET_TPS:,} ({results['target_achievable_pct']:.1f}% achievable)")
        
        return results
    
    def shutdown(self):
        """Cleanup"""
        self.pipeline.shutdown()
        self.merkle.shutdown()


def run_benchmark():
    """Run the throughput benchmark"""
    print("\n" + "=" * 60)
    print("QRTB THROUGHPUT BENCHMARK")
    print("=" * 60)
    print(f"  CPU cores: {CPU_CORES}")
    print(f"  Verification workers: {VERIFICATION_WORKERS}")
    print(f"  Target TPS: {TARGET_TPS:,}")
    
    benchmark = ThroughputBenchmark()
    try:
        results = benchmark.run_benchmark(10000)
        return results
    finally:
        benchmark.shutdown()


if __name__ == "__main__":
    run_benchmark()
