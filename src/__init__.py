"""
QRTB Testnet - Quantum-Resistant Temporal Blockchain

A complete implementation of the QRTB featuring:
- WOTS+ signatures (67 chains, 2,144 bytes)
- Temporal key evolution with 4-source entropy
- Physics-bounded consensus via RTT measurements
- Triangle inequality adversary detection
- BFT voting with stake-weighted finalization
- UTXO-based transaction model
- HD wallet with key rotation (no seed export - forward secrecy)
- Persistent SQLite storage
- Block production with parallel processing
- Performance optimization for 16M TPS target
"""

from .crypto import (
    sha3_256, sha3_512, concat, secure_random,
    WOTSPlus, TemporalKey, MerkleTree
)
from .measurement import (
    MeasurementProtocol, PeerInfo, RTTMeasurement,
    MeasurementCommitment, MeasurementReveal,
    haversine_distance_km, theoretical_rtt_ms
)
from .detection import (
    DetectionEngine, DetectionResult, TriangleCheck,
    aggregate_detection_results
)
from .epoch import (
    EpochManager, EntropyWell, EpochEntropy,
    EpochPhase, EpochSynchronizer
)
from .consensus import (
    BFTConsensus, ConsensusProposal, ConsensusVote, ConsensusBlock,
    SlashingManager
)
from .validator import (
    ValidatorNode, ValidatorConfig, ValidatorState, ValidatorStats
)
from .network import (
    QRTBTestnet, NetworkConfig,
    create_testnet, run_quick_test
)
from .transaction import (
    Transaction, TxInput, TxOutput, TxType,
    UTXOSet, UTXO, TransactionValidator, Mempool
)
from .wallet import (
    Wallet, WalletConfig,
    KeyManager, KeyPair
)
from .storage import (
    StorageManager, BlockStore, TransactionStore, StateDB,
    StoredBlock
)
from .block_producer import (
    BlockProducer, BlockTemplate, BlockCoordinator,
    ParallelBlockBuilder, BlockFinalizer
)
from .performance import (
    BatchWOTSVerifier, ShardedUTXOSet, ParallelMerkleTree,
    TransactionPipeline, ThroughputBenchmark, run_benchmark
)

__version__ = "0.3.0"
__author__ = "Andrew Dorman"
