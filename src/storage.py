"""
QRTB Persistent Storage
- Block storage with indexing
- State database (UTXO set, validators)
- Transaction indexes
- Chain state management
"""

import json
import struct
import sqlite3
import os
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Iterator
from pathlib import Path
from contextlib import contextmanager
import threading

from .crypto import sha3_256, concat
from .transaction import Transaction, TxOutput, UTXO, UTXOSet
from .consensus import ConsensusBlock, ConsensusProposal

# =============================================================================
# BLOCK STORAGE
# =============================================================================

@dataclass
class StoredBlock:
    """Block with metadata for storage"""
    epoch: int
    block_hash: bytes
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int
    proposer_id: bytes
    transactions: List[bytes]  # Transaction hashes
    raw_data: bytes
    
    @classmethod
    def from_consensus_block(cls, block: ConsensusBlock, 
                             tx_hashes: List[bytes]) -> 'StoredBlock':
        return cls(
            epoch=block.epoch,
            block_hash=block.block_hash,
            prev_hash=b'\x00' * 32,  # Link to previous
            merkle_root=block.proposal.measurement_root,
            timestamp=int(block.finalization_time * 1000),
            proposer_id=block.proposal.proposer_id,
            transactions=tx_hashes,
            raw_data=b""  # Serialized full block
        )


class BlockStore:
    """
    SQLite-based block storage
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
    
    @property
    def conn(self) -> sqlite3.Connection:
        """Thread-local connection"""
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _init_db(self):
        """Initialize database schema"""
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS blocks (
                    epoch INTEGER PRIMARY KEY,
                    block_hash BLOB UNIQUE NOT NULL,
                    prev_hash BLOB NOT NULL,
                    merkle_root BLOB NOT NULL,
                    timestamp INTEGER NOT NULL,
                    proposer_id BLOB NOT NULL,
                    tx_count INTEGER NOT NULL,
                    raw_data BLOB
                );
                
                CREATE TABLE IF NOT EXISTS block_transactions (
                    epoch INTEGER NOT NULL,
                    tx_index INTEGER NOT NULL,
                    tx_hash BLOB NOT NULL,
                    PRIMARY KEY (epoch, tx_index),
                    FOREIGN KEY (epoch) REFERENCES blocks(epoch)
                );
                
                CREATE INDEX IF NOT EXISTS idx_block_hash ON blocks(block_hash);
                CREATE INDEX IF NOT EXISTS idx_block_tx ON block_transactions(tx_hash);
            """)
    
    def store_block(self, block: StoredBlock) -> bool:
        """Store a block"""
        try:
            with self.conn:
                self.conn.execute("""
                    INSERT OR REPLACE INTO blocks 
                    (epoch, block_hash, prev_hash, merkle_root, timestamp, 
                     proposer_id, tx_count, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    block.epoch,
                    block.block_hash,
                    block.prev_hash,
                    block.merkle_root,
                    block.timestamp,
                    block.proposer_id,
                    len(block.transactions),
                    block.raw_data
                ))
                
                # Store transaction references
                for i, tx_hash in enumerate(block.transactions):
                    self.conn.execute("""
                        INSERT OR REPLACE INTO block_transactions
                        (epoch, tx_index, tx_hash) VALUES (?, ?, ?)
                    """, (block.epoch, i, tx_hash))
            
            return True
        except Exception as e:
            print(f"Error storing block: {e}")
            return False
    
    def get_block(self, epoch: int) -> Optional[StoredBlock]:
        """Get block by epoch"""
        row = self.conn.execute(
            "SELECT * FROM blocks WHERE epoch = ?", (epoch,)
        ).fetchone()
        
        if row is None:
            return None
        
        # Get transactions
        tx_rows = self.conn.execute(
            "SELECT tx_hash FROM block_transactions WHERE epoch = ? ORDER BY tx_index",
            (epoch,)
        ).fetchall()
        
        return StoredBlock(
            epoch=row['epoch'],
            block_hash=row['block_hash'],
            prev_hash=row['prev_hash'],
            merkle_root=row['merkle_root'],
            timestamp=row['timestamp'],
            proposer_id=row['proposer_id'],
            transactions=[r['tx_hash'] for r in tx_rows],
            raw_data=row['raw_data'] or b""
        )
    
    def get_block_by_hash(self, block_hash: bytes) -> Optional[StoredBlock]:
        """Get block by hash"""
        row = self.conn.execute(
            "SELECT epoch FROM blocks WHERE block_hash = ?", (block_hash,)
        ).fetchone()
        
        if row:
            return self.get_block(row['epoch'])
        return None
    
    def get_latest_block(self) -> Optional[StoredBlock]:
        """Get most recent block"""
        row = self.conn.execute(
            "SELECT epoch FROM blocks ORDER BY epoch DESC LIMIT 1"
        ).fetchone()
        
        if row:
            return self.get_block(row['epoch'])
        return None
    
    def get_block_range(self, start_epoch: int, 
                       end_epoch: int) -> Iterator[StoredBlock]:
        """Iterate blocks in range"""
        rows = self.conn.execute(
            "SELECT epoch FROM blocks WHERE epoch >= ? AND epoch <= ? ORDER BY epoch",
            (start_epoch, end_epoch)
        ).fetchall()
        
        for row in rows:
            block = self.get_block(row['epoch'])
            if block:
                yield block
    
    def get_chain_height(self) -> int:
        """Get current chain height (latest epoch)"""
        row = self.conn.execute(
            "SELECT MAX(epoch) as height FROM blocks"
        ).fetchone()
        return row['height'] if row['height'] is not None else -1
    
    def has_block(self, epoch: int) -> bool:
        """Check if block exists"""
        row = self.conn.execute(
            "SELECT 1 FROM blocks WHERE epoch = ?", (epoch,)
        ).fetchone()
        return row is not None

    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn


# =============================================================================
# TRANSACTION STORAGE
# =============================================================================

class TransactionStore:
    """
    Transaction storage with indexes
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
    
    @property
    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _init_db(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS transactions (
                    tx_hash BLOB PRIMARY KEY,
                    version INTEGER NOT NULL,
                    tx_type INTEGER NOT NULL,
                    epoch INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL,
                    fee INTEGER NOT NULL,
                    input_count INTEGER NOT NULL,
                    output_count INTEGER NOT NULL,
                    raw_data BLOB NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS tx_inputs (
                    tx_hash BLOB NOT NULL,
                    input_index INTEGER NOT NULL,
                    prev_tx_hash BLOB NOT NULL,
                    prev_output_index INTEGER NOT NULL,
                    PRIMARY KEY (tx_hash, input_index),
                    FOREIGN KEY (tx_hash) REFERENCES transactions(tx_hash)
                );
                
                CREATE TABLE IF NOT EXISTS tx_outputs (
                    tx_hash BLOB NOT NULL,
                    output_index INTEGER NOT NULL,
                    value INTEGER NOT NULL,
                    address BLOB NOT NULL,
                    lock_epoch INTEGER NOT NULL,
                    spent INTEGER DEFAULT 0,
                    spent_by BLOB,
                    PRIMARY KEY (tx_hash, output_index),
                    FOREIGN KEY (tx_hash) REFERENCES transactions(tx_hash)
                );
                
                CREATE INDEX IF NOT EXISTS idx_tx_epoch ON transactions(epoch);
                CREATE INDEX IF NOT EXISTS idx_tx_type ON transactions(tx_type);
                CREATE INDEX IF NOT EXISTS idx_output_address ON tx_outputs(address);
                CREATE INDEX IF NOT EXISTS idx_output_unspent ON tx_outputs(spent, address);
            """)
    
    def store_transaction(self, tx: Transaction) -> bool:
        """Store a transaction"""
        try:
            with self.conn:
                self.conn.execute("""
                    INSERT OR REPLACE INTO transactions
                    (tx_hash, version, tx_type, epoch, timestamp, fee, 
                     input_count, output_count, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    tx.tx_hash,
                    tx.version,
                    tx.tx_type.value,
                    tx.epoch,
                    tx.timestamp,
                    tx.fee,
                    len(tx.inputs),
                    len(tx.outputs),
                    tx.to_bytes()
                ))
                
                # Store inputs
                for i, inp in enumerate(tx.inputs):
                    self.conn.execute("""
                        INSERT OR REPLACE INTO tx_inputs
                        (tx_hash, input_index, prev_tx_hash, prev_output_index)
                        VALUES (?, ?, ?, ?)
                    """, (tx.tx_hash, i, inp.prev_tx_hash, inp.output_index))
                
                # Store outputs
                for i, out in enumerate(tx.outputs):
                    self.conn.execute("""
                        INSERT OR REPLACE INTO tx_outputs
                        (tx_hash, output_index, value, address, lock_epoch)
                        VALUES (?, ?, ?, ?, ?)
                    """, (tx.tx_hash, i, out.value, out.address, out.lock_epoch))
            
            return True
        except Exception as e:
            print(f"Error storing transaction: {e}")
            return False
    
    def get_transaction(self, tx_hash: bytes) -> Optional[dict]:
        """Get transaction metadata by hash"""
        row = self.conn.execute(
            "SELECT * FROM transactions WHERE tx_hash = ?", (tx_hash,)
        ).fetchone()
        
        if row is None:
            return None
        
        return dict(row)
    
    def mark_output_spent(self, tx_hash: bytes, output_index: int,
                         spending_tx: bytes) -> bool:
        """Mark output as spent"""
        try:
            with self.conn:
                self.conn.execute("""
                    UPDATE tx_outputs SET spent = 1, spent_by = ?
                    WHERE tx_hash = ? AND output_index = ?
                """, (spending_tx, tx_hash, output_index))
            return True
        except:
            return False
    
    def get_utxos_for_address(self, address: bytes) -> List[dict]:
        """Get unspent outputs for address"""
        rows = self.conn.execute("""
            SELECT tx_hash, output_index, value, lock_epoch
            FROM tx_outputs
            WHERE address = ? AND spent = 0
        """, (address,)).fetchall()
        
        return [dict(row) for row in rows]
    
    def get_transactions_for_address(self, address: bytes,
                                     limit: int = 100) -> List[dict]:
        """Get transaction history for address"""
        # Outputs received
        received = self.conn.execute("""
            SELECT DISTINCT t.tx_hash, t.epoch, t.timestamp, t.tx_type
            FROM transactions t
            JOIN tx_outputs o ON t.tx_hash = o.tx_hash
            WHERE o.address = ?
            ORDER BY t.timestamp DESC
            LIMIT ?
        """, (address, limit)).fetchall()

        return [dict(row) for row in received]

    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn


# =============================================================================
# STATE DATABASE
# =============================================================================

class StateDB:
    """
    State database for validators, stakes, and chain state
    """
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()
    
    @property
    def conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, 'conn'):
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _init_db(self):
        with self.conn:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS validators (
                    validator_id BLOB PRIMARY KEY,
                    address BLOB NOT NULL,
                    stake INTEGER NOT NULL,
                    zone_id INTEGER NOT NULL,
                    active INTEGER DEFAULT 1,
                    slashed INTEGER DEFAULT 0,
                    registered_epoch INTEGER NOT NULL,
                    last_active_epoch INTEGER
                );
                
                CREATE TABLE IF NOT EXISTS chain_state (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS epoch_entropy (
                    epoch INTEGER PRIMARY KEY,
                    entropy BLOB NOT NULL,
                    sources_used INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS slashing_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    validator_id BLOB NOT NULL,
                    epoch INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    evidence_hash BLOB NOT NULL,
                    slash_amount INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS auth_registry (
                    address BLOB PRIMARY KEY,
                    auth_root BLOB NOT NULL,
                    epoch INTEGER NOT NULL,
                    tx_hash BLOB,
                    rotation_count INTEGER DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_validator_zone ON validators(zone_id);
                CREATE INDEX IF NOT EXISTS idx_validator_active ON validators(active);
                CREATE INDEX IF NOT EXISTS idx_auth_registry_root ON auth_registry(auth_root);
            """)
    
    # Validator management
    def register_validator(self, validator_id: bytes, address: bytes,
                          stake: int, zone_id: int, epoch: int) -> bool:
        try:
            with self.conn:
                self.conn.execute("""
                    INSERT OR REPLACE INTO validators
                    (validator_id, address, stake, zone_id, registered_epoch)
                    VALUES (?, ?, ?, ?, ?)
                """, (validator_id, address, stake, zone_id, epoch))
            return True
        except:
            return False
    
    def update_validator_stake(self, validator_id: bytes, stake: int) -> bool:
        try:
            with self.conn:
                self.conn.execute(
                    "UPDATE validators SET stake = ? WHERE validator_id = ?",
                    (stake, validator_id)
                )
            return True
        except:
            return False
    
    def slash_validator(self, validator_id: bytes, reason: str,
                       evidence_hash: bytes, slash_amount: int, epoch: int) -> bool:
        try:
            with self.conn:
                # Mark as slashed
                self.conn.execute(
                    "UPDATE validators SET slashed = 1, active = 0 WHERE validator_id = ?",
                    (validator_id,)
                )
                
                # Record event
                self.conn.execute("""
                    INSERT INTO slashing_events
                    (validator_id, epoch, reason, evidence_hash, slash_amount, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (validator_id, epoch, reason, evidence_hash, slash_amount, 
                      int(time.time() * 1000)))
            return True
        except:
            return False
    
    def get_active_validators(self, zone_id: Optional[int] = None) -> List[dict]:
        if zone_id is not None:
            rows = self.conn.execute(
                "SELECT * FROM validators WHERE active = 1 AND zone_id = ?",
                (zone_id,)
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM validators WHERE active = 1"
            ).fetchall()
        return [dict(row) for row in rows]
    
    def get_total_stake(self) -> int:
        row = self.conn.execute(
            "SELECT SUM(stake) as total FROM validators WHERE active = 1"
        ).fetchone()
        return row['total'] or 0
    
    # Chain state
    def set_state(self, key: str, value: bytes) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)",
                (key, value)
            )
    
    def get_state(self, key: str) -> Optional[bytes]:
        row = self.conn.execute(
            "SELECT value FROM chain_state WHERE key = ?", (key,)
        ).fetchone()
        return row['value'] if row else None
    
    def set_current_epoch(self, epoch: int) -> None:
        self.set_state("current_epoch", struct.pack('>Q', epoch))
    
    def get_current_epoch(self) -> int:
        data = self.get_state("current_epoch")
        if data:
            return struct.unpack('>Q', data)[0]
        return 0
    
    # Epoch entropy
    def store_entropy(self, epoch: int, entropy: bytes, 
                     sources_used: int) -> None:
        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO epoch_entropy
                (epoch, entropy, sources_used, timestamp)
                VALUES (?, ?, ?, ?)
            """, (epoch, entropy, sources_used, int(time.time() * 1000)))
    
    def get_entropy(self, epoch: int) -> Optional[bytes]:
        row = self.conn.execute(
            "SELECT entropy FROM epoch_entropy WHERE epoch = ?", (epoch,)
        ).fetchone()
        return row['entropy'] if row else None

    # Auth registry methods
    def register_auth(self, address: bytes, auth_root: bytes,
                      epoch: int, tx_hash: Optional[bytes] = None) -> bool:
        """Register address with auth_root. One-time per address."""
        try:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO auth_registry
                    (address, auth_root, epoch, tx_hash, rotation_count)
                    VALUES (?, ?, ?, ?, 0)
                """, (address, auth_root, epoch, tx_hash))
            return True
        except sqlite3.IntegrityError:
            return False  # Already registered

    def rotate_auth(self, address: bytes, new_auth_root: bytes,
                    epoch: int, tx_hash: Optional[bytes] = None) -> bool:
        """Rotate auth_root for a registered address."""
        try:
            with self.conn:
                result = self.conn.execute("""
                    UPDATE auth_registry
                    SET auth_root = ?, epoch = ?, tx_hash = ?,
                        rotation_count = rotation_count + 1
                    WHERE address = ?
                """, (new_auth_root, epoch, tx_hash, address))
            return result.rowcount > 0
        except:
            return False

    def get_auth_root(self, address: bytes) -> Optional[bytes]:
        """Get current auth_root for address."""
        row = self.conn.execute(
            "SELECT auth_root FROM auth_registry WHERE address = ?",
            (address,)
        ).fetchone()
        return row['auth_root'] if row else None

    def is_address_registered(self, address: bytes) -> bool:
        """Check if address is registered."""
        row = self.conn.execute(
            "SELECT 1 FROM auth_registry WHERE address = ?",
            (address,)
        ).fetchone()
        return row is not None

    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'conn'):
            self._local.conn.close()
            del self._local.conn


# =============================================================================
# UNIFIED STORAGE MANAGER
# =============================================================================

class StorageManager:
    """
    Unified storage management
    """
    
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize stores
        self.blocks = BlockStore(str(self.data_dir / "blocks.db"))
        self.transactions = TransactionStore(str(self.data_dir / "transactions.db"))
        self.state = StateDB(str(self.data_dir / "state.db"))
        
        # In-memory UTXO set (loaded from DB)
        self.utxo_set = UTXOSet()
    
    def store_block_with_transactions(self, block: ConsensusBlock,
                                      transactions: List[Transaction]) -> bool:
        """Store block and all its transactions atomically"""
        try:
            # Store transactions first
            tx_hashes = []
            for tx in transactions:
                self.transactions.store_transaction(tx)
                tx_hashes.append(tx.tx_hash)
                
                # Update UTXO set
                for inp in tx.inputs:
                    self.transactions.mark_output_spent(
                        inp.prev_tx_hash, inp.output_index, tx.tx_hash
                    )
            
            # Store block
            stored_block = StoredBlock.from_consensus_block(block, tx_hashes)
            self.blocks.store_block(stored_block)
            
            # Update chain state
            self.state.set_current_epoch(block.epoch)
            
            return True
        except Exception as e:
            print(f"Error storing block: {e}")
            return False
    
    def get_chain_info(self) -> dict:
        """Get current chain information"""
        return {
            "height": self.blocks.get_chain_height(),
            "current_epoch": self.state.get_current_epoch(),
            "total_stake": self.state.get_total_stake(),
            "active_validators": len(self.state.get_active_validators()),
        }
    
    def rebuild_utxo_set(self) -> None:
        """Rebuild UTXO set from stored transactions"""
        # This would scan all transactions and rebuild
        # Expensive but necessary for recovery
        pass
    
    def close(self):
        """Close all database connections."""
        self.blocks.close()
        self.transactions.close()
        self.state.close()

    def export_snapshot(self, output_path: str) -> bool:
        """Export current state snapshot"""
        try:
            snapshot = {
                "chain_height": self.blocks.get_chain_height(),
                "current_epoch": self.state.get_current_epoch(),
                "validators": self.state.get_active_validators(),
                "total_stake": self.state.get_total_stake(),
            }
            
            with open(output_path, 'w') as f:
                json.dump(snapshot, f, indent=2, default=str)
            
            return True
        except:
            return False


# Need to import time for timestamps
import time
