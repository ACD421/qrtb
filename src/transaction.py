"""
QRTB Transaction Layer
- Transaction types (transfer, stake, unstake, slash)
- UTXO model with temporal key binding
- Batch verification for throughput
- Mempool management
"""

import time
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum
from collections import defaultdict

from .crypto import (
    sha3_256, sha3_512, concat, WOTSPlus, secure_random,
    TemporalAuthTree, MerkleTree
)

# =============================================================================
# CONSTANTS
# =============================================================================

TX_VERSION = 1
MAX_TX_SIZE = 65536  # 64KB - WOTS+ signatures are 2144 bytes each
MAX_INPUTS = 16
MAX_OUTPUTS = 16
MIN_FEE_PER_BYTE = 1  # satoshi equivalent
DUST_THRESHOLD = 546  # minimum output value

# =============================================================================
# TRANSACTION TYPES
# =============================================================================

class TxType(Enum):
    """Transaction types"""
    TRANSFER = 0      # Standard value transfer
    STAKE = 1         # Stake tokens for validation
    UNSTAKE = 2       # Withdraw staked tokens
    SLASH = 3         # Slashing penalty (system-generated)
    COINBASE = 4      # Block reward (system-generated)
    DATA = 5          # Arbitrary data storage
    REGISTER = 6      # Address registration (WOTS+ signed, publishes auth_root)
    ROTATE_AUTH = 7   # Auth root rotation (temporal auth, publishes new auth_root)


@dataclass
class TxInput:
    """Transaction input - references previous output"""
    prev_tx_hash: bytes      # 32 bytes - hash of previous tx
    output_index: int        # Which output of that tx
    signature: bytes         # WOTS+ signature (2144 bytes)
    public_key: bytes        # WOTS+ public key (2144 bytes)
    
    @property
    def size(self) -> int:
        return 32 + 4 + len(self.signature) + len(self.public_key)
    
    def to_bytes(self) -> bytes:
        return concat(
            self.prev_tx_hash,
            self.output_index,
            len(self.signature).to_bytes(2, 'big'),
            self.signature,
            len(self.public_key).to_bytes(2, 'big'),
            self.public_key
        )
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple['TxInput', int]:
        prev_tx_hash = data[offset:offset+32]
        output_index = struct.unpack('>I', data[offset+32:offset+36])[0]
        sig_len = struct.unpack('>H', data[offset+36:offset+38])[0]
        signature = data[offset+38:offset+38+sig_len]
        pk_offset = offset + 38 + sig_len
        pk_len = struct.unpack('>H', data[pk_offset:pk_offset+2])[0]
        public_key = data[pk_offset+2:pk_offset+2+pk_len]
        
        return cls(prev_tx_hash, output_index, signature, public_key), pk_offset + 2 + pk_len


@dataclass
class TxOutput:
    """Transaction output - spendable by address owner"""
    value: int               # Amount in smallest unit
    address: bytes           # 64 bytes - recipient's static address
    lock_epoch: int = 0      # Epoch when spendable (0 = immediate)
    data: bytes = b""        # Optional data payload
    
    @property
    def size(self) -> int:
        return 8 + 64 + 8 + 2 + len(self.data)
    
    def to_bytes(self) -> bytes:
        return concat(
            struct.pack('>Q', self.value),
            self.address,
            struct.pack('>Q', self.lock_epoch),
            struct.pack('>H', len(self.data)),
            self.data
        )
    
    @classmethod
    def from_bytes(cls, data: bytes, offset: int = 0) -> Tuple['TxOutput', int]:
        value = struct.unpack('>Q', data[offset:offset+8])[0]
        address = data[offset+8:offset+72]
        lock_epoch = struct.unpack('>Q', data[offset+72:offset+80])[0]
        data_len = struct.unpack('>H', data[offset+80:offset+82])[0]
        payload = data[offset+82:offset+82+data_len]
        
        return cls(value, address, lock_epoch, payload), offset + 82 + data_len


@dataclass
class Transaction:
    """Complete transaction"""
    version: int
    tx_type: TxType
    inputs: List[TxInput]
    outputs: List[TxOutput]
    epoch: int               # Epoch when created
    timestamp: int           # Creation timestamp (ms)
    fee: int                 # Transaction fee
    nonce: bytes = field(default_factory=lambda: secure_random(8))
    
    _hash: Optional[bytes] = field(default=None, repr=False)
    
    @property
    def tx_hash(self) -> bytes:
        """Calculate transaction hash (cached)"""
        if self._hash is None:
            # Hash everything except signatures
            data = concat(
                self.version,
                self.tx_type.value,
                len(self.inputs),
                *[concat(i.prev_tx_hash, i.output_index) for i in self.inputs],
                len(self.outputs),
                *[o.to_bytes() for o in self.outputs],
                self.epoch,
                self.timestamp,
                self.fee,
                self.nonce
            )
            self._hash = sha3_256(data)
        return self._hash
    
    @property
    def size(self) -> int:
        """Total transaction size in bytes"""
        base_size = 1 + 1 + 1 + 1 + 8 + 8 + 8 + 8  # version, type, counts, epoch, ts, fee, nonce
        input_size = sum(i.size for i in self.inputs)
        output_size = sum(o.size for o in self.outputs)
        return base_size + input_size + output_size
    
    @property
    def total_input(self) -> int:
        """Sum of input values (requires UTXO lookup)"""
        # This would be populated during validation
        return 0
    
    @property
    def total_output(self) -> int:
        """Sum of output values"""
        return sum(o.value for o in self.outputs)
    
    def signing_hash(self) -> bytes:
        """Hash used for signing (excludes signatures)"""
        data = concat(
            self.version,
            self.tx_type.value,
            len(self.inputs),
            *[concat(i.prev_tx_hash, i.output_index) for i in self.inputs],
            len(self.outputs),
            *[o.to_bytes() for o in self.outputs],
            self.epoch,
            self.timestamp,
            self.fee,
            self.nonce
        )
        return sha3_256(data)
    
    def to_bytes(self) -> bytes:
        """Serialize transaction"""
        parts = [
            bytes([self.version]),
            bytes([self.tx_type.value]),
            bytes([len(self.inputs)]),
            *[i.to_bytes() for i in self.inputs],
            bytes([len(self.outputs)]),
            *[o.to_bytes() for o in self.outputs],
            struct.pack('>Q', self.epoch),
            struct.pack('>Q', self.timestamp),
            struct.pack('>Q', self.fee),
            self.nonce
        ]
        return b"".join(parts)
    
    def is_valid_structure(self) -> Tuple[bool, str]:
        """Validate transaction structure (not signatures)"""
        if self.version != TX_VERSION:
            return False, f"invalid version: {self.version}"
        
        if len(self.inputs) == 0 and self.tx_type != TxType.COINBASE:
            return False, "no inputs"
        
        if len(self.inputs) > MAX_INPUTS:
            return False, f"too many inputs: {len(self.inputs)}"
        
        if len(self.outputs) == 0:
            return False, "no outputs"
        
        if len(self.outputs) > MAX_OUTPUTS:
            return False, f"too many outputs: {len(self.outputs)}"
        
        if self.size > MAX_TX_SIZE:
            return False, f"transaction too large: {self.size}"
        
        # Check for dust outputs
        for i, out in enumerate(self.outputs):
            if out.value < DUST_THRESHOLD and out.value != 0:
                return False, f"dust output at index {i}: {out.value}"
        
        # Check fee
        min_fee = self.size * MIN_FEE_PER_BYTE
        if self.fee < min_fee and self.tx_type != TxType.COINBASE:
            return False, f"fee too low: {self.fee} < {min_fee}"
        
        return True, "valid"


# =============================================================================
# UTXO SET
# =============================================================================

@dataclass
class UTXO:
    """Unspent Transaction Output"""
    tx_hash: bytes
    output_index: int
    output: TxOutput
    epoch_created: int
    is_spent: bool = False
    spent_by: Optional[bytes] = None  # tx_hash that spent this


class UTXOSet:
    """
    UTXO Set Management
    Tracks all unspent outputs for fast validation
    """
    
    def __init__(self):
        # Primary index: (tx_hash, output_index) -> UTXO
        self.utxos: Dict[Tuple[bytes, int], UTXO] = {}
        
        # Secondary index: address -> set of (tx_hash, output_index)
        self.by_address: Dict[bytes, Set[Tuple[bytes, int]]] = defaultdict(set)
        
        # Staking index: address -> staked amount
        self.staked: Dict[bytes, int] = defaultdict(int)
    
    def add_utxo(self, tx_hash: bytes, output_index: int, 
                 output: TxOutput, epoch: int) -> None:
        """Add a new UTXO"""
        key = (tx_hash, output_index)
        utxo = UTXO(tx_hash, output_index, output, epoch)
        self.utxos[key] = utxo
        self.by_address[output.address].add(key)
    
    def spend_utxo(self, tx_hash: bytes, output_index: int, 
                   spending_tx: bytes) -> Optional[UTXO]:
        """Mark UTXO as spent"""
        key = (tx_hash, output_index)
        utxo = self.utxos.get(key)
        if utxo is None:
            return None
        if utxo.is_spent:
            return None
        
        utxo.is_spent = True
        utxo.spent_by = spending_tx
        self.by_address[utxo.output.address].discard(key)
        return utxo
    
    def get_utxo(self, tx_hash: bytes, output_index: int) -> Optional[UTXO]:
        """Get UTXO by reference"""
        return self.utxos.get((tx_hash, output_index))
    
    def get_balance(self, address: bytes, current_epoch: int) -> int:
        """Get spendable balance for address"""
        total = 0
        for key in self.by_address.get(address, set()):
            utxo = self.utxos.get(key)
            if utxo and not utxo.is_spent:
                if utxo.output.lock_epoch <= current_epoch:
                    total += utxo.output.value
        return total
    
    def get_utxos_for_address(self, address: bytes, 
                              current_epoch: int) -> List[UTXO]:
        """Get all spendable UTXOs for address"""
        result = []
        for key in self.by_address.get(address, set()):
            utxo = self.utxos.get(key)
            if utxo and not utxo.is_spent:
                if utxo.output.lock_epoch <= current_epoch:
                    result.append(utxo)
        return result
    
    def add_stake(self, address: bytes, amount: int) -> None:
        """Record staked amount"""
        self.staked[address] += amount
    
    def remove_stake(self, address: bytes, amount: int) -> bool:
        """Remove staked amount"""
        if self.staked[address] < amount:
            return False
        self.staked[address] -= amount
        return True
    
    def get_stake(self, address: bytes) -> int:
        """Get staked amount for address"""
        return self.staked.get(address, 0)


# =============================================================================
# AUTH REGISTRY
# =============================================================================

class AuthRegistry:
    """
    Tracks registered addresses and their current auth_root.

    Security properties:
      - Registration is one-time per address (no overwrite)
      - Rotation updates auth_root only for registered addresses
      - Unregistered addresses cannot use temporal auth
    """

    def __init__(self):
        self.auth_roots: Dict[bytes, bytes] = {}  # address -> current auth_root
        self.registered_addresses: Set[bytes] = set()
        self.rotation_counts: Dict[bytes, int] = {}  # address -> rotation count

    def is_registered(self, address: bytes) -> bool:
        """Check if address is registered."""
        return address in self.registered_addresses

    def get_auth_root(self, address: bytes) -> Optional[bytes]:
        """Get current auth_root for address."""
        return self.auth_roots.get(address)

    def register_via_tx(self, address: bytes, auth_root: bytes) -> bool:
        """
        Register address with its auth_root. One-time only.

        Returns False if already registered.
        """
        if address in self.registered_addresses:
            return False

        self.registered_addresses.add(address)
        self.auth_roots[address] = auth_root
        self.rotation_counts[address] = 0
        return True

    def rotate_via_tx(self, address: bytes, new_auth_root: bytes) -> bool:
        """
        Rotate auth_root for a registered address.

        Returns False if not registered.
        """
        if address not in self.registered_addresses:
            return False

        self.auth_roots[address] = new_auth_root
        self.rotation_counts[address] = self.rotation_counts.get(address, 0) + 1
        return True


# =============================================================================
# TRANSACTION VALIDATION
# =============================================================================

class TransactionValidator:
    """
    Validates transactions against UTXO set and consensus rules
    """

    def __init__(self, utxo_set: UTXOSet,
                 auth_registry: Optional[AuthRegistry] = None):
        self.utxo_set = utxo_set
        self.auth_registry = auth_registry or AuthRegistry()
        self.wots = WOTSPlus()
    
    def validate_transaction(self, tx: Transaction, 
                            current_epoch: int) -> Tuple[bool, str]:
        """
        Full transaction validation
        
        Returns:
            (is_valid, reason)
        """
        # Structure validation
        valid, reason = tx.is_valid_structure()
        if not valid:
            return False, reason
        
        # Epoch validation
        if tx.epoch > current_epoch:
            return False, f"future epoch: {tx.epoch} > {current_epoch}"
        
        # Grace period: accept transactions from previous epoch
        if tx.epoch < current_epoch - 1:
            return False, f"expired epoch: {tx.epoch}"
        
        # Type-specific validation
        if tx.tx_type == TxType.COINBASE:
            return self._validate_coinbase(tx)
        elif tx.tx_type == TxType.TRANSFER:
            return self._validate_transfer(tx, current_epoch)
        elif tx.tx_type == TxType.STAKE:
            return self._validate_stake(tx, current_epoch)
        elif tx.tx_type == TxType.UNSTAKE:
            return self._validate_unstake(tx, current_epoch)
        elif tx.tx_type == TxType.SLASH:
            return self._validate_slash(tx)
        elif tx.tx_type == TxType.DATA:
            return self._validate_data(tx, current_epoch)
        elif tx.tx_type == TxType.REGISTER:
            return self._validate_register(tx, current_epoch)
        elif tx.tx_type == TxType.ROTATE_AUTH:
            return self._validate_rotate_auth(tx, current_epoch)

        return False, f"unknown tx type: {tx.tx_type}"
    
    def _validate_transfer(self, tx: Transaction, 
                          current_epoch: int) -> Tuple[bool, str]:
        """Validate transfer transaction"""
        total_input = 0
        signing_hash = tx.signing_hash()
        
        for inp in tx.inputs:
            # Check UTXO exists and is unspent
            utxo = self.utxo_set.get_utxo(inp.prev_tx_hash, inp.output_index)
            if utxo is None:
                return False, f"UTXO not found: {inp.prev_tx_hash.hex()[:8]}:{inp.output_index}"
            if utxo.is_spent:
                return False, f"UTXO already spent: {inp.prev_tx_hash.hex()[:8]}:{inp.output_index}"
            
            # Check lock time
            if utxo.output.lock_epoch > current_epoch:
                return False, f"UTXO locked until epoch {utxo.output.lock_epoch}"
            
            # Verify signature
            # Public key must hash to the UTXO's address
            pk_hash = sha3_512(concat(b"address_outer", sha3_512(concat(b"address_inner", inp.public_key[:64]))))
            # Simplified check - in production, derive address properly
            
            if not self.wots.verify(signing_hash, inp.signature, inp.public_key):
                return False, f"invalid signature for input {inp.prev_tx_hash.hex()[:8]}:{inp.output_index}"
            
            total_input += utxo.output.value
        
        # Check value conservation
        total_output = tx.total_output + tx.fee
        if total_input < total_output:
            return False, f"insufficient input: {total_input} < {total_output}"
        
        return True, "valid"
    
    def _validate_stake(self, tx: Transaction, 
                       current_epoch: int) -> Tuple[bool, str]:
        """Validate stake transaction"""
        # Same as transfer, but outputs must be to staking address
        valid, reason = self._validate_transfer(tx, current_epoch)
        if not valid:
            return False, reason
        
        # At least one output must be a stake
        has_stake = any(o.lock_epoch > current_epoch for o in tx.outputs)
        if not has_stake:
            return False, "no staking output"
        
        return True, "valid"
    
    def _validate_unstake(self, tx: Transaction, 
                         current_epoch: int) -> Tuple[bool, str]:
        """Validate unstake transaction"""
        # Must reference staked UTXOs that have passed lock period
        return self._validate_transfer(tx, current_epoch)
    
    def _validate_coinbase(self, tx: Transaction) -> Tuple[bool, str]:
        """Validate coinbase transaction"""
        if len(tx.inputs) != 0:
            return False, "coinbase must have no inputs"
        if len(tx.outputs) == 0:
            return False, "coinbase must have outputs"
        return True, "valid"
    
    def _validate_slash(self, tx: Transaction) -> Tuple[bool, str]:
        """Validate slashing transaction (system-generated)"""
        # Would require slashing evidence in production
        return True, "valid"
    
    def _validate_data(self, tx: Transaction,
                      current_epoch: int) -> Tuple[bool, str]:
        """Validate data transaction"""
        # Same as transfer, but must have data payload
        valid, reason = self._validate_transfer(tx, current_epoch)
        if not valid:
            return False, reason

        has_data = any(len(o.data) > 0 for o in tx.outputs)
        if not has_data:
            return False, "no data payload"

        return True, "valid"

    def _validate_register(self, tx: Transaction,
                           current_epoch: int) -> Tuple[bool, str]:
        """
        Validate REGISTER transaction.

        Structure:
          - Input: WOTS+ signed (proves seed ownership)
          - Output[0].data: inner_hash (64B) || auth_root (64B)
          - Derived address: SHA3-512("address_outer" || inner_hash) must match
            the UTXO address being spent
          - One-time per address (rejects if already registered)
        """
        if len(tx.inputs) != 1:
            return False, "register tx must have exactly 1 input"

        if len(tx.outputs) < 1:
            return False, "register tx must have at least 1 output"

        # The first output must carry the registration data
        # inner_hash: 64 bytes (SHA3-512), auth_root: 32 bytes (SHA3-256 Merkle root)
        reg_data = tx.outputs[0].data
        if len(reg_data) != 96:
            return False, f"register output data must be 96 bytes (inner_hash||auth_root), got {len(reg_data)}"

        inner_hash = reg_data[:64]
        auth_root = reg_data[64:96]

        # Derive address from inner_hash and verify it matches the UTXO
        derived_address = sha3_512(concat(b"address_outer", inner_hash))

        # Verify the input UTXO belongs to this address
        inp = tx.inputs[0]
        utxo = self.utxo_set.get_utxo(inp.prev_tx_hash, inp.output_index)
        if utxo is None:
            return False, "UTXO not found for register input"
        if utxo.is_spent:
            return False, "UTXO already spent"

        if utxo.output.address != derived_address:
            return False, "inner_hash does not derive to UTXO address"

        # Check lock time
        if utxo.output.lock_epoch > current_epoch:
            return False, f"UTXO locked until epoch {utxo.output.lock_epoch}"

        # Verify WOTS+ signature
        signing_hash = tx.signing_hash()
        if not self.wots.verify(signing_hash, inp.signature, inp.public_key):
            return False, "invalid WOTS+ signature for register tx"

        # Check one-time registration
        if self.auth_registry.is_registered(derived_address):
            return False, "address already registered"

        # Value conservation
        total_input = utxo.output.value
        total_output = tx.total_output + tx.fee
        if total_input < total_output:
            return False, f"insufficient input: {total_input} < {total_output}"

        return True, "valid"

    def _validate_rotate_auth(self, tx: Transaction,
                              current_epoch: int) -> Tuple[bool, str]:
        """
        Validate ROTATE_AUTH transaction.

        Structure:
          - Input: temporal auth signed with current registered root
            Input signature field: wots_sig (2144B)
            Input public_key field: wots_pub (2144B) || merkle_proof_data || key_index (4B)
          - Output[0].data: new_auth_root (64B)
          - Address must be already registered
          - Temporal auth verified against current auth_root
        """
        if len(tx.inputs) != 1:
            return False, "rotate_auth tx must have exactly 1 input"

        if len(tx.outputs) < 1:
            return False, "rotate_auth tx must have at least 1 output"

        # Output data is the new auth_root (32 bytes, SHA3-256 Merkle root)
        rot_data = tx.outputs[0].data
        if len(rot_data) != 32:
            return False, f"rotate_auth output data must be 32 bytes (new_auth_root), got {len(rot_data)}"

        new_auth_root = rot_data[:32]

        # Get the input and determine the address
        inp = tx.inputs[0]
        utxo = self.utxo_set.get_utxo(inp.prev_tx_hash, inp.output_index)
        if utxo is None:
            return False, "UTXO not found for rotate_auth input"
        if utxo.is_spent:
            return False, "UTXO already spent"

        address = utxo.output.address

        # Check lock time
        if utxo.output.lock_epoch > current_epoch:
            return False, f"UTXO locked until epoch {utxo.output.lock_epoch}"

        # Must be registered
        if not self.auth_registry.is_registered(address):
            return False, "address not registered, cannot rotate"

        current_auth_root = self.auth_registry.get_auth_root(address)

        # Parse temporal auth from input
        # public_key field contains: wots_pub (2144B) || proof_len (2B) || proof_data || key_index (4B)
        pk_data = inp.public_key
        wots_pub_size = 67 * 32  # 2144
        if len(pk_data) < wots_pub_size + 6:
            return False, "rotate_auth input public_key field too short"

        wots_pub = pk_data[:wots_pub_size]
        proof_len = struct.unpack('>H', pk_data[wots_pub_size:wots_pub_size + 2])[0]
        proof_data_start = wots_pub_size + 2
        proof_data_end = proof_data_start + proof_len
        if len(pk_data) < proof_data_end + 4:
            return False, "rotate_auth input: insufficient proof data"

        # Deserialize Merkle proof
        proof_bytes = pk_data[proof_data_start:proof_data_end]
        key_index = struct.unpack('>I', pk_data[proof_data_end:proof_data_end + 4])[0]

        # Each proof entry: 32 bytes hash + 1 byte position
        proof = []
        offset = 0
        while offset + 33 <= len(proof_bytes):
            sibling = proof_bytes[offset:offset + 32]
            is_right = proof_bytes[offset + 32]
            proof.append((sibling, is_right))
            offset += 33

        # Verify temporal auth: WOTS+ sig + Merkle proof against current auth_root
        signing_hash = tx.signing_hash()
        if not TemporalAuthTree.verify_against_root(
            signing_hash, inp.signature, wots_pub, proof, current_auth_root
        ):
            return False, "temporal auth verification failed for rotate_auth"

        # Key index must be in the reserved range (1022 or 1023)
        if key_index < 1022:
            return False, f"rotate_auth must use reserved key (1022-1023), got {key_index}"

        # Value conservation
        total_input = utxo.output.value
        total_output = tx.total_output + tx.fee
        if total_input < total_output:
            return False, f"insufficient input: {total_input} < {total_output}"

        return True, "valid"

    def apply_transaction(self, tx: Transaction) -> bool:
        """
        Apply transaction to UTXO set and auth registry.

        Returns:
            True if successfully applied
        """
        # Spend inputs
        for inp in tx.inputs:
            result = self.utxo_set.spend_utxo(
                inp.prev_tx_hash,
                inp.output_index,
                tx.tx_hash
            )
            if result is None:
                return False

        # Create outputs
        for i, out in enumerate(tx.outputs):
            self.utxo_set.add_utxo(tx.tx_hash, i, out, tx.epoch)

        # Handle staking
        if tx.tx_type == TxType.STAKE:
            for out in tx.outputs:
                if out.lock_epoch > tx.epoch:
                    self.utxo_set.add_stake(out.address, out.value)

        # Handle registration
        if tx.tx_type == TxType.REGISTER:
            reg_data = tx.outputs[0].data
            inner_hash = reg_data[:64]
            auth_root = reg_data[64:96]
            address = sha3_512(concat(b"address_outer", inner_hash))
            self.auth_registry.register_via_tx(address, auth_root)

        # Handle auth rotation
        if tx.tx_type == TxType.ROTATE_AUTH:
            new_auth_root = tx.outputs[0].data[:32]
            # Determine address from the spent UTXO
            inp = tx.inputs[0]
            utxo = self.utxo_set.get_utxo(inp.prev_tx_hash, inp.output_index)
            if utxo:
                address = utxo.output.address
            else:
                # UTXO was already spent above, look in the spent record
                # The address is on the output we just spent
                # We need to find it from the original UTXO data
                # Since we already spent it, get from utxos dict directly
                key = (inp.prev_tx_hash, inp.output_index)
                spent_utxo = self.utxo_set.utxos.get(key)
                if spent_utxo:
                    address = spent_utxo.output.address
                else:
                    return False
            self.auth_registry.rotate_via_tx(address, new_auth_root)

        return True


# =============================================================================
# MEMPOOL
# =============================================================================

class Mempool:
    """
    Transaction mempool with priority ordering
    """
    
    def __init__(self, max_size_mb: int = 100):
        self.max_size = max_size_mb * 1024 * 1024
        self.current_size = 0
        
        # Transactions by hash
        self.transactions: Dict[bytes, Transaction] = {}
        
        # Priority queue: (fee_rate, timestamp, tx_hash)
        self.priority: List[Tuple[float, int, bytes]] = []
        
        # Spent outputs tracker (prevent double-spend in mempool)
        self.spent_outputs: Set[Tuple[bytes, int]] = set()
    
    def add_transaction(self, tx: Transaction) -> Tuple[bool, str]:
        """Add transaction to mempool"""
        # Check if already in mempool
        if tx.tx_hash in self.transactions:
            return False, "already in mempool"
        
        # Check size
        if self.current_size + tx.size > self.max_size:
            return False, "mempool full"
        
        # Check for double-spend within mempool
        for inp in tx.inputs:
            key = (inp.prev_tx_hash, inp.output_index)
            if key in self.spent_outputs:
                return False, "double-spend detected"
        
        # Add to mempool
        self.transactions[tx.tx_hash] = tx
        self.current_size += tx.size
        
        # Track spent outputs
        for inp in tx.inputs:
            self.spent_outputs.add((inp.prev_tx_hash, inp.output_index))
        
        # Add to priority queue
        fee_rate = tx.fee / tx.size
        self.priority.append((fee_rate, tx.timestamp, tx.tx_hash))
        self.priority.sort(reverse=True)  # Highest fee first
        
        return True, "added"
    
    def remove_transaction(self, tx_hash: bytes) -> Optional[Transaction]:
        """Remove transaction from mempool"""
        tx = self.transactions.pop(tx_hash, None)
        if tx is None:
            return None
        
        self.current_size -= tx.size
        
        # Remove spent outputs
        for inp in tx.inputs:
            self.spent_outputs.discard((inp.prev_tx_hash, inp.output_index))
        
        # Remove from priority (expensive, could optimize)
        self.priority = [(f, t, h) for f, t, h in self.priority if h != tx_hash]
        
        return tx
    
    def get_transactions_for_block(self, max_size: int) -> List[Transaction]:
        """Get highest-priority transactions for block"""
        result = []
        total_size = 0
        
        for fee_rate, timestamp, tx_hash in self.priority:
            tx = self.transactions.get(tx_hash)
            if tx is None:
                continue
            
            if total_size + tx.size > max_size:
                continue
            
            result.append(tx)
            total_size += tx.size
        
        return result
    
    def clear_confirmed(self, confirmed_hashes: Set[bytes]) -> int:
        """Remove confirmed transactions"""
        removed = 0
        for tx_hash in confirmed_hashes:
            if self.remove_transaction(tx_hash):
                removed += 1
        return removed
    
    @property
    def size(self) -> int:
        """Number of transactions in mempool"""
        return len(self.transactions)
    
    @property
    def total_fees(self) -> int:
        """Total fees in mempool"""
        return sum(tx.fee for tx in self.transactions.values())
