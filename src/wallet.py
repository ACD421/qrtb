"""
QRTB Wallet Implementation
- Hierarchical deterministic key derivation
- Transaction building and signing
- Balance tracking
- Key rotation per epoch
"""

import time
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from .crypto import (
    sha3_256, sha3_512, concat, secure_random,
    WOTSPlus, TemporalKey, MerkleTree,
    TemporalAuthTree, derive_initial_batch_seed, derive_next_batch_seed,
    USABLE_KEYS, RESERVED_ROTATION
)
from .transaction import (
    Transaction, TxInput, TxOutput, TxType,
    UTXOSet, UTXO, DUST_THRESHOLD, AuthRegistry
)
import struct

# =============================================================================
# CONSTANTS
# =============================================================================

WALLET_VERSION = 1
DEFAULT_FEE_RATE = 10  # satoshi per byte
STAKING_LOCK_EPOCHS = 100  # Stake locked for 100 epochs (~25 hours)

# =============================================================================
# KEY MANAGEMENT
# =============================================================================

@dataclass
class KeyPair:
    """WOTS+ key pair for a specific epoch"""
    epoch: int
    private_key: bytes
    public_key: bytes
    address: bytes
    used: bool = False  # WOTS+ keys are one-time use
    
    def to_dict(self) -> dict:
        return {
            "epoch": self.epoch,
            "public_key": self.public_key.hex(),
            "address": self.address.hex(),
            "used": self.used
        }


class KeyManager:
    """
    Manages temporal auth trees with batch-based forward secrecy.

    Architecture:
      - master_seed -> batch_0_seed (one-way derivation)
      - batch_N_seed -> batch_{N+1}_seed (one-way chain)
      - Each batch has 1024 WOTS+ keys: 1022 usable + 2 reserved for rotation
      - Forward secrecy: old batch seeds are destroyed after rotation
    """

    def __init__(self, master_seed: Optional[bytes] = None):
        self.master_seed = master_seed or secure_random(64)
        self.wots = WOTSPlus()

        # Derive address: H(H(seed))
        self._inner_hash = sha3_512(concat(b"address_inner", self.master_seed))
        self._address = sha3_512(concat(b"address_outer", self._inner_hash))

        # Initialize batch 0
        self._current_batch_seed = derive_initial_batch_seed(self.master_seed)
        self._auth_tree = TemporalAuthTree(self._current_batch_seed)
        self._batch_number = 0

        # Rotation state
        self._next_batch_seed: Optional[bytes] = None
        self._next_auth_tree: Optional[TemporalAuthTree] = None
        self._next_auth_root: Optional[bytes] = None

        # Registration state
        self._is_registered = False

        # Key usage tracking (for compatibility with existing wallet code)
        self.key_cache: Dict[int, List[KeyPair]] = {}
        self.current_epoch = 0
        self.key_index = 0

    @property
    def address(self) -> bytes:
        """Static wallet address: SHA3-512('address_outer' || inner_hash)"""
        return self._address

    @property
    def inner_hash(self) -> bytes:
        """Inner hash for registration proof."""
        return self._inner_hash

    @property
    def auth_root(self) -> bytes:
        """Current auth tree Merkle root."""
        return self._auth_tree.auth_root

    @property
    def remaining_keys(self) -> int:
        """Usable keys remaining in current batch."""
        return self._auth_tree.remaining_keys

    @property
    def should_rotate(self) -> bool:
        """True when remaining usable keys are below threshold."""
        return self._auth_tree.remaining_keys <= 10

    @property
    def is_registered(self) -> bool:
        return self._is_registered

    def mark_registered(self) -> None:
        """Mark this address as registered on-chain."""
        self._is_registered = True

    def temporal_sign(self, message: bytes) -> Tuple[bytes, bytes, list, int]:
        """
        Sign using the next available usable key (0..1021).
        Raises ValueError if keys are exhausted — wallet must rotate first.
        """
        if not self._is_registered:
            raise ValueError("Address not registered. Must register before temporal signing.")
        return self._auth_tree.sign(message)

    def temporal_sign_rotation(self, message: bytes) -> Tuple[bytes, bytes, list, int]:
        """
        Sign using a reserved rotation key (1022 or 1023).
        Used to authorize the ROTATE_AUTH transaction.
        """
        if not self._is_registered:
            raise ValueError("Address not registered. Cannot rotate unregistered address.")
        return self._auth_tree.sign_rotation(message)

    def prepare_rotation(self) -> bytes:
        """
        Derive next batch seed and compute next auth_root.
        Does NOT destroy current batch yet.

        Returns the next auth_root to publish on-chain.
        """
        self._next_batch_seed = derive_next_batch_seed(self._current_batch_seed)
        self._next_auth_tree = TemporalAuthTree(self._next_batch_seed)
        self._next_auth_root = self._next_auth_tree.auth_root
        return self._next_auth_root

    def execute_rotation(self) -> None:
        """
        Destroy current batch and activate next.
        Call AFTER on-chain confirmation of ROTATE_AUTH tx.
        Provides forward secrecy — old batch cannot sign.
        """
        if self._next_auth_tree is None:
            raise ValueError("Must call prepare_rotation() first")

        # Destroy current batch (forward secrecy)
        self._auth_tree.destroy()

        # Activate next batch
        self._current_batch_seed = self._next_batch_seed
        self._auth_tree = self._next_auth_tree
        self._batch_number += 1

        # Clear next state
        self._next_batch_seed = None
        self._next_auth_tree = None
        self._next_auth_root = None

    def get_wots_keypair_for_registration(self) -> Tuple[bytes, bytes]:
        """
        Generate a WOTS+ keypair from master_seed for registration signing.
        This is separate from the temporal auth tree keys.
        """
        reg_seed = sha3_512(concat(self.master_seed, b"registration_key"))
        priv, pub = self.wots.keygen(reg_seed)
        return priv, pub

    # Legacy compatibility methods for existing wallet code
    def evolve_to_epoch(self, target_epoch: int, entropy: bytes) -> None:
        """Legacy: epoch evolution (no-op in batch model)."""
        self.current_epoch = target_epoch

    def generate_keypair(self, epoch: int) -> KeyPair:
        """Legacy: generate a WOTS+ keypair for epoch-based code."""
        key_seed = sha3_512(concat(
            self._current_batch_seed,
            b"legacy_keypair",
            epoch,
            self.key_index
        ))
        self.key_index += 1

        private_key, public_key = self.wots.keygen(key_seed)
        address = sha3_512(concat(b"address", public_key[:64]))

        keypair = KeyPair(
            epoch=epoch,
            private_key=private_key,
            public_key=public_key,
            address=address
        )

        if epoch not in self.key_cache:
            self.key_cache[epoch] = []
        self.key_cache[epoch].append(keypair)

        return keypair

    def get_unused_keypair(self, epoch: int) -> KeyPair:
        """Legacy: get an unused keypair for signing."""
        if epoch in self.key_cache:
            for kp in self.key_cache[epoch]:
                if not kp.used:
                    return kp
        return self.generate_keypair(epoch)

    def sign(self, message: bytes, keypair: KeyPair) -> bytes:
        """Legacy: sign message with WOTS+."""
        if keypair.used:
            raise ValueError("Cannot reuse WOTS+ key")
        signature = self.wots.sign(message, keypair.private_key)
        keypair.used = True
        return signature


# =============================================================================
# WALLET
# =============================================================================

@dataclass
class WalletConfig:
    """Wallet configuration"""
    name: str = "default"
    network: str = "testnet"
    fee_rate: int = DEFAULT_FEE_RATE
    auto_consolidate: bool = True  # Consolidate UTXOs when too many


class Wallet:
    """
    Full QRTB wallet implementation
    """
    
    def __init__(self, config: Optional[WalletConfig] = None,
                 master_seed: Optional[bytes] = None):
        self.config = config or WalletConfig()
        self.key_manager = KeyManager(master_seed)
        self.wots = WOTSPlus()
        
        # Local UTXO tracking
        self.utxos: Dict[Tuple[bytes, int], UTXO] = {}
        
        # Pending transactions (not yet confirmed)
        self.pending_txs: Dict[bytes, Transaction] = {}
        
        # Transaction history
        self.tx_history: List[bytes] = []
        
        # Current epoch (synced from network)
        self.current_epoch = 0
        
        # Staking info
        self.staked_amount = 0
        self.stake_unlock_epoch = 0
    
    @property
    def address(self) -> bytes:
        """Primary wallet address"""
        return self.key_manager.address
    
    @property
    def balance(self) -> int:
        """Spendable balance"""
        total = 0
        for utxo in self.utxos.values():
            if not utxo.is_spent:
                if utxo.output.lock_epoch <= self.current_epoch:
                    total += utxo.output.value
        return total
    
    @property
    def pending_balance(self) -> int:
        """Balance in pending transactions"""
        total = 0
        for tx in self.pending_txs.values():
            for out in tx.outputs:
                if out.address == self.address:
                    total += out.value
        return total
    
    @property
    def total_balance(self) -> int:
        """Total balance including pending"""
        return self.balance + self.pending_balance
    
    # =========================================================================
    # UTXO MANAGEMENT
    # =========================================================================
    
    def add_utxo(self, tx_hash: bytes, output_index: int, 
                output: TxOutput, epoch: int) -> None:
        """Add UTXO to wallet"""
        key = (tx_hash, output_index)
        self.utxos[key] = UTXO(tx_hash, output_index, output, epoch)
    
    def spend_utxo(self, tx_hash: bytes, output_index: int,
                   spending_tx: bytes) -> bool:
        """Mark UTXO as spent"""
        key = (tx_hash, output_index)
        utxo = self.utxos.get(key)
        if utxo is None or utxo.is_spent:
            return False
        utxo.is_spent = True
        utxo.spent_by = spending_tx
        return True
    
    def get_spendable_utxos(self) -> List[UTXO]:
        """Get list of spendable UTXOs"""
        result = []
        for utxo in self.utxos.values():
            if not utxo.is_spent:
                if utxo.output.lock_epoch <= self.current_epoch:
                    result.append(utxo)
        return result
    
    def select_utxos(self, target_amount: int, 
                    fee_estimate: int) -> Tuple[List[UTXO], int]:
        """
        Select UTXOs to cover target amount plus fees
        Uses simple largest-first selection
        
        Returns:
            (selected_utxos, total_value)
        """
        spendable = self.get_spendable_utxos()
        spendable.sort(key=lambda u: u.output.value, reverse=True)
        
        selected = []
        total = 0
        needed = target_amount + fee_estimate
        
        for utxo in spendable:
            selected.append(utxo)
            total += utxo.output.value
            if total >= needed:
                break
        
        return selected, total
    
    # =========================================================================
    # TRANSACTION BUILDING
    # =========================================================================
    
    def create_transfer(self, recipient: bytes, amount: int,
                       fee: Optional[int] = None) -> Optional[Transaction]:
        """
        Create a transfer transaction
        
        Args:
            recipient: Recipient address (64 bytes)
            amount: Amount to send
            fee: Optional fee (calculated if not provided)
        """
        if amount < DUST_THRESHOLD:
            return None
        
        # Estimate fee from full temporal-auth input size if not provided
        if fee is None:
            # Per input with temporal auth: sig(2144) + pub(2144) + proof(~320) + overhead(40)
            input_size = 2144 + 2144 + 320 + 40
            estimated_size = 50 + input_size + 2 * 80
            fee = estimated_size * self.config.fee_rate
        
        # Select UTXOs
        utxos, total_input = self.select_utxos(amount, fee)
        if total_input < amount + fee:
            return None  # Insufficient funds
        
        # Build outputs first (needed for signing hash)
        outputs = [
            TxOutput(value=amount, address=recipient)
        ]

        # Change goes back to our static wallet address (not a legacy derived address)
        change = total_input - amount - fee
        if change >= DUST_THRESHOLD:
            outputs.append(TxOutput(value=change, address=self.address))

        inputs = [TxInput(prev_tx_hash=u.tx_hash, output_index=u.output_index,
                          signature=b"", public_key=b"") for u in utxos]

        tx = Transaction(version=1, tx_type=TxType.TRANSFER, inputs=inputs,
                         outputs=outputs, epoch=self.current_epoch,
                         timestamp=int(time.time() * 1000), fee=fee)
        self._sign_inputs(tx)
        return tx
    
    def _sign_inputs(self, tx: Transaction) -> None:
        """Sign all inputs using temporal auth (registered) or legacy keypairs."""
        signing_hash = tx.signing_hash()
        if self.key_manager.is_registered:
            for inp in tx.inputs:
                sig, pub, proof, idx = self.key_manager.temporal_sign(signing_hash)
                inp.signature = sig
                inp.public_key = pub
                inp.auth_proof = proof
                inp.auth_key_index = idx
        else:
            for inp in tx.inputs:
                keypair = self.key_manager.get_unused_keypair(self.current_epoch)
                inp.public_key = keypair.public_key
                inp.signature = self.key_manager.sign(signing_hash, keypair)

    def _estimate_fee(self, num_inputs: int, num_outputs: int) -> int:
        """Estimate fee based on full temporal-auth input size."""
        input_size = 2144 + 2144 + 320 + 40  # sig + pub + proof + overhead
        return (50 + num_inputs * input_size + num_outputs * 80) * self.config.fee_rate

    def create_stake(self, amount: int,
                    lock_epochs: int = STAKING_LOCK_EPOCHS) -> Optional[Transaction]:
        """Create a staking transaction"""
        if amount < DUST_THRESHOLD:
            return None

        fee = self._estimate_fee(1, 2)
        utxos, total_input = self.select_utxos(amount, fee)
        if total_input < amount + fee:
            return None

        inputs = [TxInput(prev_tx_hash=u.tx_hash, output_index=u.output_index,
                          signature=b"", public_key=b"") for u in utxos]

        lock_epoch = self.current_epoch + lock_epochs
        outputs = [TxOutput(value=amount, address=self.address, lock_epoch=lock_epoch)]
        change = total_input - amount - fee
        if change >= DUST_THRESHOLD:
            outputs.append(TxOutput(value=change, address=self.address))

        tx = Transaction(version=1, tx_type=TxType.STAKE, inputs=inputs,
                         outputs=outputs, epoch=self.current_epoch,
                         timestamp=int(time.time() * 1000), fee=fee)
        self._sign_inputs(tx)
        return tx
    
    def create_unstake(self) -> Optional[Transaction]:
        """Create unstaking transaction for all mature stakes"""
        staked_utxos = []
        total_staked = 0

        for utxo in self.utxos.values():
            if not utxo.is_spent and utxo.output.lock_epoch > 0:
                if utxo.output.lock_epoch <= self.current_epoch:
                    staked_utxos.append(utxo)
                    total_staked += utxo.output.value

        if not staked_utxos:
            return None

        fee = self._estimate_fee(len(staked_utxos), 1)
        inputs = [TxInput(prev_tx_hash=u.tx_hash, output_index=u.output_index,
                          signature=b"", public_key=b"") for u in staked_utxos]
        outputs = [TxOutput(value=total_staked - fee, address=self.address)]

        tx = Transaction(version=1, tx_type=TxType.UNSTAKE, inputs=inputs,
                         outputs=outputs, epoch=self.current_epoch,
                         timestamp=int(time.time() * 1000), fee=fee)
        self._sign_inputs(tx)
        return tx
    
    def create_data_tx(self, data: bytes,
                      fee: Optional[int] = None) -> Optional[Transaction]:
        """Create a data storage transaction"""
        if len(data) > 1000:
            return None

        if fee is None:
            fee = self._estimate_fee(1, 2)

        utxos, total_input = self.select_utxos(0, fee)
        if total_input < fee:
            return None

        inputs = [TxInput(prev_tx_hash=u.tx_hash, output_index=u.output_index,
                          signature=b"", public_key=b"") for u in utxos]
        outputs = [TxOutput(value=0, address=self.address, data=data)]
        change = total_input - fee
        if change >= DUST_THRESHOLD:
            outputs.append(TxOutput(value=change, address=self.address))
        
        tx = Transaction(version=1, tx_type=TxType.DATA, inputs=inputs,
                         outputs=outputs, epoch=self.current_epoch,
                         timestamp=int(time.time() * 1000), fee=fee)
        self._sign_inputs(tx)
        return tx
    
    # =========================================================================
    # REGISTRATION AND ROTATION
    # =========================================================================

    def create_registration_tx(self, fee: Optional[int] = None) -> Optional[Transaction]:
        """
        Create a REGISTER transaction.

        This WOTS+-signed tx proves seed ownership and publishes the auth_root.
        Output[0].data = inner_hash (64B) || auth_root (64B)
        """
        if self.key_manager.is_registered:
            return None  # Already registered

        # Need a UTXO at our address to spend
        if fee is None:
            estimated_size = 50 + 4400 + 80 + 128  # base + input + output + data
            fee = estimated_size * self.config.fee_rate

        utxos, total_input = self.select_utxos(0, fee)
        if total_input < fee:
            return None  # Insufficient funds

        # Registration data: inner_hash || auth_root
        inner_hash = self.key_manager.inner_hash
        auth_root = self.key_manager.auth_root
        reg_data = inner_hash + auth_root

        # Use the registration WOTS+ keypair (separate from temporal tree)
        reg_priv, reg_pub = self.key_manager.get_wots_keypair_for_registration()

        # Build input (spend first UTXO)
        utxo = utxos[0]
        inp = TxInput(
            prev_tx_hash=utxo.tx_hash,
            output_index=utxo.output_index,
            signature=b"",  # Will sign
            public_key=reg_pub
        )

        # Build outputs
        outputs = [
            TxOutput(value=0, address=self.address, data=reg_data)
        ]

        # Change
        change = total_input - fee
        if change >= DUST_THRESHOLD:
            outputs.append(TxOutput(value=change, address=self.address))

        tx = Transaction(
            version=1,
            tx_type=TxType.REGISTER,
            inputs=[inp],
            outputs=outputs,
            epoch=self.current_epoch,
            timestamp=int(time.time() * 1000),
            fee=fee
        )

        # Sign with WOTS+
        signing_hash = tx.signing_hash()
        tx.inputs[0].signature = self.wots.sign(signing_hash, reg_priv)

        return tx

    def create_rotation_tx(self, fee: Optional[int] = None) -> Optional[Transaction]:
        """
        Create a ROTATE_AUTH transaction.

        Uses a reserved temporal key (1022/1023) to authorize publishing
        the next batch's auth_root on-chain.
        """
        if not self.key_manager.is_registered:
            return None  # Must be registered first

        # Prepare the next batch (derives seed, builds tree)
        new_auth_root = self.key_manager.prepare_rotation()

        if fee is None:
            estimated_size = 50 + 4400 + 80 + 64  # base + input + output + data
            fee = estimated_size * self.config.fee_rate

        utxos, total_input = self.select_utxos(0, fee)
        if total_input < fee:
            return None

        utxo = utxos[0]

        # Build the transaction first (need signing_hash before temporal sign)
        outputs = [
            TxOutput(value=0, address=self.address, data=new_auth_root)
        ]

        change = total_input - fee
        if change >= DUST_THRESHOLD:
            outputs.append(TxOutput(value=change, address=self.address))

        tx = Transaction(
            version=1,
            tx_type=TxType.ROTATE_AUTH,
            inputs=[TxInput(
                prev_tx_hash=utxo.tx_hash,
                output_index=utxo.output_index,
                signature=b"",  # Placeholder
                public_key=b""  # Placeholder
            )],
            outputs=outputs,
            epoch=self.current_epoch,
            timestamp=int(time.time() * 1000),
            fee=fee
        )

        # Sign with reserved rotation key
        signing_hash = tx.signing_hash()
        sig, pub, proof, key_index = self.key_manager.temporal_sign_rotation(signing_hash)

        # Serialize proof into public_key field:
        # wots_pub (2144B) || proof_len (2B) || proof_data || key_index (4B)
        proof_bytes = b""
        for sibling, is_right in proof:
            proof_bytes += sibling + bytes([is_right])

        pk_field = (
            pub +
            struct.pack('>H', len(proof_bytes)) +
            proof_bytes +
            struct.pack('>I', key_index)
        )

        tx.inputs[0].signature = sig
        tx.inputs[0].public_key = pk_field

        # Invalidate cached hash since we changed inputs
        tx._hash = None

        return tx

    def confirm_rotation(self) -> None:
        """
        Called after ROTATE_AUTH tx is confirmed on-chain.
        Destroys current batch and activates the next (forward secrecy).
        """
        self.key_manager.execute_rotation()

    # =========================================================================
    # TRANSACTION TRACKING
    # =========================================================================
    
    def submit_transaction(self, tx: Transaction) -> None:
        """Track submitted transaction"""
        self.pending_txs[tx.tx_hash] = tx
        
        # Mark UTXOs as spent
        for inp in tx.inputs:
            self.spend_utxo(inp.prev_tx_hash, inp.output_index, tx.tx_hash)
    
    def confirm_transaction(self, tx_hash: bytes) -> None:
        """Mark transaction as confirmed"""
        tx = self.pending_txs.pop(tx_hash, None)
        if tx:
            self.tx_history.append(tx_hash)
            
            # Add outputs that belong to us
            for i, out in enumerate(tx.outputs):
                if out.address == self.address or self._is_our_address(out.address):
                    self.add_utxo(tx.tx_hash, i, out, tx.epoch)
    
    def _is_our_address(self, address: bytes) -> bool:
        """Check if address belongs to this wallet"""
        # Check key cache for matching addresses
        for epoch_keys in self.key_manager.key_cache.values():
            for kp in epoch_keys:
                if kp.address == address:
                    return True
        return False
    
    # =========================================================================
    # EPOCH SYNC
    # =========================================================================
    
    def sync_epoch(self, epoch: int, entropy: bytes) -> None:
        """Sync wallet to current epoch"""
        if epoch > self.current_epoch:
            self.key_manager.evolve_to_epoch(epoch, entropy)
            self.current_epoch = epoch
    
    # =========================================================================
    # PERSISTENCE (State only - NO seed export for forward secrecy)
    # =========================================================================
    
    def to_dict(self) -> dict:
        """Export wallet state (public info only)"""
        return {
            "version": WALLET_VERSION,
            "config": {
                "name": self.config.name,
                "network": self.config.network,
                "fee_rate": self.config.fee_rate
            },
            "address": self.address.hex(),
            "current_epoch": self.current_epoch,
            "balance": self.balance,
            "staked_amount": self.staked_amount,
            "utxo_count": len(self.utxos),
            "pending_count": len(self.pending_txs),
            "tx_history_count": len(self.tx_history)
        }
    
    # NOTE: No seed export methods - exporting the master seed would
    # destroy forward secrecy by allowing derivation of all past keys.
    # Wallet recovery requires keeping the device secure, not backups.
    # This is a security feature, not a limitation.
    
    @classmethod
    def create_new(cls, config: Optional[WalletConfig] = None) -> 'Wallet':
        """Create new wallet with random seed"""
        return cls(config)


    # WalletManager removed -- wallet persistence requires encrypted storage
    # implementation. Forward secrecy by design: no seed export.
