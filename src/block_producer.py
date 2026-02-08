"""
QRTB Block Production
Integrates transaction layer with consensus finalization

Block production flow:
1. Collect transactions from mempool (priority ordered)
2. Validate transactions against UTXO set
3. Build Merkle tree of transaction hashes
4. Create consensus proposal with measurement data
5. Collect votes, reach 2/3+ stake threshold
6. Finalize block, apply to state
"""

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

from .crypto import sha3_256, MerkleTree
from .transaction import (
    Transaction, TxType, TxOutput,
    UTXOSet, TransactionValidator, Mempool, AuthRegistry
)
from .consensus import (
    BFTConsensus, ConsensusProposal, ConsensusBlock
)
from .measurement import MeasurementProtocol, PeerInfo
from .epoch import EpochManager
from .storage import StorageManager

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_BLOCK_SIZE = 4 * 1024 * 1024  # 4 MB per block
MAX_TXS_PER_BLOCK = 1000          # Transaction limit per block
BLOCK_TIME_TARGET = 250           # 250ms target (15 min epochs / ~3600 blocks)
COINBASE_REWARD = 50_00000000     # 50 tokens in smallest unit

# =============================================================================
# BLOCK TEMPLATE
# =============================================================================

@dataclass
class BlockTemplate:
    """Template for block being produced"""
    epoch: int
    proposer_id: bytes
    transactions: List[Transaction] = field(default_factory=list)
    tx_merkle_root: bytes = b'\x00' * 32
    state_root: bytes = b'\x00' * 32
    total_fees: int = 0
    total_size: int = 0
    created_at: float = field(default_factory=time.time)
    
    def add_transaction(self, tx: Transaction) -> bool:
        """Add transaction if it fits"""
        if len(self.transactions) >= MAX_TXS_PER_BLOCK:
            return False
        if self.total_size + tx.size > MAX_BLOCK_SIZE:
            return False
        
        self.transactions.append(tx)
        self.total_fees += tx.fee
        self.total_size += tx.size
        return True
    
    def compute_merkle_root(self) -> bytes:
        """Compute Merkle root of transactions"""
        if not self.transactions:
            return b'\x00' * 32
        
        tx_hashes = [tx.tx_hash for tx in self.transactions]
        tree = MerkleTree(tx_hashes)
        self.tx_merkle_root = tree.root
        return self.tx_merkle_root


# =============================================================================
# BLOCK PRODUCER
# =============================================================================

class BlockProducer:
    """
    Produces blocks from mempool transactions
    """
    
    def __init__(self,
                 validator_id: bytes,
                 utxo_set: UTXOSet,
                 mempool: Mempool,
                 storage: Optional[StorageManager] = None,
                 auth_registry: Optional[AuthRegistry] = None):
        self.validator_id = validator_id
        self.utxo_set = utxo_set
        self.mempool = mempool
        self.storage = storage
        self.auth_registry = auth_registry or AuthRegistry()
        self.tx_validator = TransactionValidator(utxo_set, self.auth_registry)
        
        # Current block being built
        self.current_template: Optional[BlockTemplate] = None
        
        # Statistics
        self.blocks_produced = 0
        self.txs_included = 0
        self.txs_rejected = 0
    
    def create_template(self, epoch: int) -> BlockTemplate:
        """Create new block template for epoch"""
        self.current_template = BlockTemplate(
            epoch=epoch,
            proposer_id=self.validator_id
        )
        return self.current_template
    
    def fill_template(self, template: BlockTemplate) -> int:
        """
        Fill template with transactions from mempool
        
        Returns:
            Number of transactions added
        """
        # Get prioritized transactions
        candidates = self.mempool.get_transactions_for_block(MAX_BLOCK_SIZE)
        
        added = 0
        rejected = 0
        
        for tx in candidates:
            # Validate against current UTXO state
            valid, reason = self.tx_validator.validate_transaction(
                tx, template.epoch
            )
            
            if valid:
                if template.add_transaction(tx):
                    added += 1
                else:
                    break  # Block full
            else:
                rejected += 1
                # Remove invalid tx from mempool
                self.mempool.remove_transaction(tx.tx_hash)
        
        self.txs_included += added
        self.txs_rejected += rejected
        
        return added
    
    def create_coinbase(self, template: BlockTemplate, 
                       reward_address: bytes) -> Transaction:
        """Create coinbase transaction for block reward"""
        # Reward = base reward + total fees
        total_reward = COINBASE_REWARD + template.total_fees
        
        coinbase = Transaction(
            version=1,
            tx_type=TxType.COINBASE,
            inputs=[],
            outputs=[
                TxOutput(
                    value=total_reward,
                    address=reward_address,
                    lock_epoch=template.epoch + 100  # Lock for 100 epochs
                )
            ],
            epoch=template.epoch,
            timestamp=int(time.time() * 1000),
            fee=0
        )
        
        return coinbase
    
    def build_block(self, template: BlockTemplate,
                   measurement_root: bytes,
                   reward_address: bytes) -> ConsensusProposal:
        """
        Build consensus proposal from template
        
        Args:
            template: Block template with transactions
            measurement_root: Merkle root of RTT measurements
            reward_address: Address to receive block reward
        """
        # Add coinbase as first transaction
        coinbase = self.create_coinbase(template, reward_address)
        all_txs = [coinbase] + template.transactions
        
        # Compute transaction Merkle root
        tx_hashes = [tx.tx_hash for tx in all_txs]
        tx_tree = MerkleTree(tx_hashes)
        
        # Build proposal
        proposal = ConsensusProposal(
            epoch=template.epoch,
            proposer_id=self.validator_id,
            measurement_root=measurement_root,
            timestamp=time.time()
        )
        
        # Store transaction data in proposal
        proposal.tx_merkle_root = tx_tree.root
        proposal.tx_count = len(all_txs)
        proposal.transactions = all_txs
        
        self.blocks_produced += 1
        
        return proposal
    
    def apply_block(self, block: ConsensusBlock,
                   transactions: List[Transaction]) -> bool:
        """
        Apply finalized block to state
        
        Args:
            block: Finalized consensus block
            transactions: Transactions in the block
        """
        try:
            # Apply each transaction to UTXO set
            for tx in transactions:
                success = self.tx_validator.apply_transaction(tx)
                if not success:
                    return False
            
            # Remove from mempool
            tx_hashes = {tx.tx_hash for tx in transactions}
            self.mempool.clear_confirmed(tx_hashes)
            
            # Persist to storage
            if self.storage:
                self.storage.store_block_with_transactions(block, transactions)
            
            return True
        except Exception as e:
            print(f"Error applying block: {e}")
            return False


# =============================================================================
# BLOCK COORDINATOR
# =============================================================================

class BlockCoordinator:
    """
    Coordinates block production across zones
    Handles proposer selection and block assembly
    """
    
    def __init__(self,
                 zone_id: int,
                 validators: Dict[bytes, 'ValidatorNode'],
                 epoch_manager: EpochManager,
                 auth_registry: Optional[AuthRegistry] = None):
        self.zone_id = zone_id
        self.validators = validators
        self.epoch_manager = epoch_manager
        self.auth_registry = auth_registry or AuthRegistry()

        # Zone mempool (shared across zone validators)
        self.zone_mempool = Mempool()

        # Zone UTXO set
        self.zone_utxo = UTXOSet()

        # Producer per validator
        self.producers: Dict[bytes, BlockProducer] = {}

        # Current epoch state
        self.current_epoch = 0
        self.current_proposer: Optional[bytes] = None
    
    def select_proposer(self, epoch: int, entropy: bytes) -> bytes:
        """
        Select block proposer for epoch using VRF-like selection
        Weighted by stake
        """
        # Get active validators in zone
        zone_validators = [
            (vid, v) for vid, v in self.validators.items()
            if v.config.zone_id == self.zone_id
        ]
        
        if not zone_validators:
            return b''
        
        # Compute selection score for each validator
        scores = []
        for vid, validator in zone_validators:
            # Score = hash(entropy || validator_id || epoch)
            score_input = entropy + vid + epoch.to_bytes(8, 'big')
            score = int.from_bytes(sha3_256(score_input)[:8], 'big')
            
            # Weight by stake
            stake = validator.stake
            weighted_score = score * stake
            scores.append((weighted_score, vid))
        
        # Highest weighted score wins
        scores.sort(reverse=True)
        self.current_proposer = scores[0][1]
        
        return self.current_proposer
    
    def produce_block(self, epoch: int, entropy: bytes,
                     measurements: Dict[bytes, bytes]) -> Optional[ConsensusProposal]:
        """
        Produce block for epoch
        
        Args:
            epoch: Current epoch number
            entropy: Epoch entropy for proposer selection
            measurements: RTT measurement roots per validator
        """
        # Select proposer
        proposer_id = self.select_proposer(epoch, entropy)
        if not proposer_id:
            return None
        
        # Get or create producer for proposer
        if proposer_id not in self.producers:
            self.producers[proposer_id] = BlockProducer(
                validator_id=proposer_id,
                utxo_set=self.zone_utxo,
                mempool=self.zone_mempool,
                auth_registry=self.auth_registry
            )
        
        producer = self.producers[proposer_id]
        
        # Create and fill template
        template = producer.create_template(epoch)
        tx_count = producer.fill_template(template)
        
        # Get measurement root for proposer
        measurement_root = measurements.get(proposer_id, b'\x00' * 32)
        
        # Get proposer's reward address
        validator = self.validators.get(proposer_id)
        reward_address = validator.address if validator else proposer_id
        
        # Build proposal
        proposal = producer.build_block(template, measurement_root, reward_address)
        
        return proposal
    
    def broadcast_transaction(self, tx: Transaction) -> bool:
        """Add transaction to zone mempool"""
        success, _ = self.zone_mempool.add_transaction(tx)
        return success
    
    def get_zone_stats(self) -> dict:
        """Get zone production statistics"""
        total_produced = sum(p.blocks_produced for p in self.producers.values())
        total_included = sum(p.txs_included for p in self.producers.values())
        total_rejected = sum(p.txs_rejected for p in self.producers.values())
        
        return {
            "zone_id": self.zone_id,
            "validators": len(self.validators),
            "mempool_size": self.zone_mempool.size,
            "mempool_fees": self.zone_mempool.total_fees,
            "blocks_produced": total_produced,
            "txs_included": total_included,
            "txs_rejected": total_rejected,
            "utxo_count": len(self.zone_utxo.utxos)
        }


# =============================================================================
# PARALLEL BLOCK BUILDER
# =============================================================================

class ParallelBlockBuilder:
    """
    Builds blocks in parallel across zones
    Maximizes throughput for 16M TPS target
    """
    
    def __init__(self, num_zones: int, workers_per_zone: int = 4):
        self.num_zones = num_zones
        self.workers_per_zone = workers_per_zone
        
        # Thread pool for parallel processing
        self.executor = ThreadPoolExecutor(
            max_workers=num_zones * workers_per_zone
        )
        
        # Zone coordinators
        self.coordinators: Dict[int, BlockCoordinator] = {}
        
        # Global transaction queue
        self.pending_queue: List[Transaction] = []
        self.queue_lock = threading.Lock()
    
    def add_coordinator(self, zone_id: int, 
                       coordinator: BlockCoordinator) -> None:
        """Register zone coordinator"""
        self.coordinators[zone_id] = coordinator
    
    def submit_transaction(self, tx: Transaction) -> bool:
        """Submit transaction for inclusion"""
        with self.queue_lock:
            self.pending_queue.append(tx)
        return True
    
    def distribute_transactions(self) -> Dict[int, int]:
        """
        Distribute pending transactions to zone mempools
        Uses round-robin for now, could be smarter based on address locality
        """
        with self.queue_lock:
            pending = self.pending_queue
            self.pending_queue = []
        
        distribution = {z: 0 for z in self.coordinators}
        
        for i, tx in enumerate(pending):
            zone_id = i % self.num_zones
            if zone_id in self.coordinators:
                if self.coordinators[zone_id].broadcast_transaction(tx):
                    distribution[zone_id] += 1
        
        return distribution
    
    def produce_blocks_parallel(self, epoch: int, entropy: bytes,
                               measurements: Dict[int, Dict[bytes, bytes]]
                               ) -> List[ConsensusProposal]:
        """
        Produce blocks for all zones in parallel
        
        Args:
            epoch: Current epoch
            entropy: Epoch entropy
            measurements: Zone -> (Validator -> measurement_root)
        """
        # Distribute any pending transactions first
        self.distribute_transactions()
        
        # Submit block production jobs
        futures = {}
        for zone_id, coordinator in self.coordinators.items():
            zone_measurements = measurements.get(zone_id, {})
            future = self.executor.submit(
                coordinator.produce_block,
                epoch, entropy, zone_measurements
            )
            futures[future] = zone_id
        
        # Collect results
        proposals = []
        for future in as_completed(futures):
            zone_id = futures[future]
            try:
                proposal = future.result()
                if proposal:
                    proposals.append(proposal)
            except Exception as e:
                print(f"Zone {zone_id} block production failed: {e}")
        
        return proposals
    
    def get_throughput_stats(self) -> dict:
        """Get aggregate throughput statistics"""
        total_mempool = 0
        total_produced = 0
        total_included = 0
        
        for coord in self.coordinators.values():
            stats = coord.get_zone_stats()
            total_mempool += stats["mempool_size"]
            total_produced += stats["blocks_produced"]
            total_included += stats["txs_included"]
        
        return {
            "zones": self.num_zones,
            "total_mempool": total_mempool,
            "blocks_produced": total_produced,
            "txs_included": total_included,
            "workers": self.num_zones * self.workers_per_zone
        }
    
    def shutdown(self):
        """Shutdown thread pool"""
        self.executor.shutdown(wait=True)


# =============================================================================
# INTEGRATED BLOCK FINALIZATION
# =============================================================================

class BlockFinalizer:
    """
    Handles block finalization and state updates
    """
    
    def __init__(self, storage: StorageManager):
        self.storage = storage
        self.finalized_epochs: Set[int] = set()
        self.pending_blocks: Dict[int, Tuple[ConsensusBlock, List[Transaction]]] = {}
    
    def queue_for_finalization(self, block: ConsensusBlock,
                              transactions: List[Transaction]) -> None:
        """Queue block for finalization"""
        self.pending_blocks[block.epoch] = (block, transactions)
    
    def finalize(self, epoch: int) -> bool:
        """
        Finalize block for epoch
        
        Returns:
            True if successfully finalized
        """
        if epoch in self.finalized_epochs:
            return True
        
        if epoch not in self.pending_blocks:
            return False
        
        block, transactions = self.pending_blocks[epoch]
        
        # Store to persistent storage
        success = self.storage.store_block_with_transactions(block, transactions)
        
        if success:
            self.finalized_epochs.add(epoch)
            del self.pending_blocks[epoch]
            
            # Update chain state
            self.storage.state.set_current_epoch(epoch)
            
            # Store epoch entropy
            if hasattr(block.proposal, 'entropy'):
                self.storage.state.store_entropy(
                    epoch, 
                    block.proposal.entropy,
                    sources_used=4
                )
        
        return success
    
    def get_finalization_status(self) -> dict:
        """Get finalization status"""
        return {
            "finalized_count": len(self.finalized_epochs),
            "pending_count": len(self.pending_blocks),
            "latest_finalized": max(self.finalized_epochs) if self.finalized_epochs else -1,
            "chain_height": self.storage.blocks.get_chain_height()
        }
