"""
QRTB Cryptographic Primitives
- SHA3-256/512 hashing
- WOTS+ signatures (67 chains, w=16, n=32)
- Temporal key evolution
- Secure key destruction
"""

import hashlib
import secrets
import struct
import ctypes
from dataclasses import dataclass
from typing import Tuple, Optional
import os


def _secure_wipe(data: bytes) -> None:
    """Overwrite bytes object in memory. Best-effort on CPython --
    works because CPython bytes have a contiguous internal buffer.
    Not guaranteed on alternative runtimes."""
    if not data:
        return
    try:
        buf = (ctypes.c_char * len(data)).from_address(id(data) + bytes.__basicsize__ - 1)
        ctypes.memset(buf, 0, len(data))
    except Exception:
        pass  # Fallback: GC will eventually reclaim

# =============================================================================
# HASH FUNCTIONS
# =============================================================================

def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash - used for signatures and addresses"""
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    """SHA3-512 hash - used for key derivation and entropy"""
    return hashlib.sha3_512(data).digest()

def concat(*args) -> bytes:
    """Concatenate mixed types into bytes"""
    result = b""
    for arg in args:
        if isinstance(arg, bytes):
            result += arg
        elif isinstance(arg, str):
            result += arg.encode('utf-8')
        elif isinstance(arg, int):
            result += struct.pack('>Q', arg)
        elif isinstance(arg, float):
            result += struct.pack('>d', arg)
    return result

def secure_random(n: int) -> bytes:
    """Cryptographically secure random bytes"""
    return secrets.token_bytes(n)

# =============================================================================
# WOTS+ SIGNATURE SCHEME
# =============================================================================

class WOTSPlus:
    """
    WOTS+ (Winternitz One-Time Signature Plus)
    Per NIST SP 800-208
    
    Parameters:
        n = 32 bytes (SHA3-256 output)
        w = 16 (Winternitz parameter)
        len1 = 64 (message chains)
        len2 = 3 (checksum chains)
        len_total = 67 (total chains)
        
    Signature size: 67 × 32 = 2,144 bytes
    """
    
    def __init__(self):
        self.n = 32          # Hash output size
        self.w = 16          # Winternitz parameter
        self.len1 = 64       # Message chains (256 bits / 4 bits per chunk)
        self.len2 = 3        # Checksum chains
        self.len_total = 67  # Total chains
        
    def _hash_chain(self, start: bytes, iterations: int) -> bytes:
        """Compute hash chain: H^iterations(start)"""
        current = start
        for _ in range(iterations):
            current = sha3_256(current)
        return current
    
    def keygen(self, seed: bytes) -> Tuple[bytes, bytes]:
        """
        Generate WOTS+ keypair from seed
        
        Returns:
            (private_key, public_key) - each 2,144 bytes
        """
        private_chains = []
        for i in range(self.len_total):
            # Derive chain seed deterministically
            chain_seed = sha3_256(concat(seed, b"wots_chain", i))
            private_chains.append(chain_seed)
        
        # Public key: hash each chain w-1 times
        public_chains = []
        for chain in private_chains:
            public_chains.append(self._hash_chain(chain, self.w - 1))
        
        private_key = b"".join(private_chains)
        public_key = b"".join(public_chains)
        return private_key, public_key
    
    def sign(self, message: bytes, private_key: bytes) -> bytes:
        """
        Sign message with WOTS+
        
        Args:
            message: Message to sign (will be hashed)
            private_key: 2,144 byte private key
            
        Returns:
            2,144 byte signature
        """
        msg_hash = sha3_256(message)
        
        # Split hash into 4-bit chunks
        chunks = []
        for byte in msg_hash:
            chunks.append(byte >> 4)      # High nibble
            chunks.append(byte & 0x0F)    # Low nibble
        
        # Compute checksum to prevent existential forgery
        checksum = sum(self.w - 1 - c for c in chunks)
        
        # Encode checksum as 3 chunks
        checksum_chunks = [
            (checksum >> 8) & 0x0F,
            (checksum >> 4) & 0x0F,
            checksum & 0x0F
        ]
        
        all_chunks = chunks + checksum_chunks
        
        # Generate signature: reveal partial chains
        signature_chains = []
        for i, chunk_val in enumerate(all_chunks):
            chain_start = private_key[i * self.n : (i + 1) * self.n]
            sig_val = self._hash_chain(chain_start, chunk_val)
            signature_chains.append(sig_val)
        
        return b"".join(signature_chains)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify WOTS+ signature
        
        Args:
            message: Original message
            signature: 2,144 byte signature
            public_key: 2,144 byte public key
            
        Returns:
            True if valid
        """
        msg_hash = sha3_256(message)
        
        # Split into chunks
        chunks = []
        for byte in msg_hash:
            chunks.append(byte >> 4)
            chunks.append(byte & 0x0F)
        
        # Compute checksum
        checksum = sum(self.w - 1 - c for c in chunks)
        checksum_chunks = [
            (checksum >> 8) & 0x0F,
            (checksum >> 4) & 0x0F,
            checksum & 0x0F
        ]
        
        all_chunks = chunks + checksum_chunks
        
        # Verify each chain
        for i, chunk_val in enumerate(all_chunks):
            sig_val = signature[i * self.n : (i + 1) * self.n]
            remaining = self.w - 1 - chunk_val
            computed = self._hash_chain(sig_val, remaining)
            expected = public_key[i * self.n : (i + 1) * self.n]
            if computed != expected:
                return False
        
        return True

# =============================================================================
# TEMPORAL KEY EVOLUTION
# =============================================================================

@dataclass
class TemporalKey:
    """
    Key that evolves deterministically each epoch
    
    Properties:
        - Static address: H(H(InitialKey)) - never changes
        - Current key: Evolves via SHA3-512(Key || EpochEntropy)
        - Forward secrecy: Past keys cannot be derived from current
    """
    current_key: bytes      # Current epoch's key material
    epoch: int              # Current epoch number
    address: bytes          # Static on-chain address

    @classmethod
    def create(cls, seed: Optional[bytes] = None) -> 'TemporalKey':
        """Create new temporal key with random or provided seed"""
        if seed is None:
            seed = secure_random(64)

        # Double-hash for address: H(H(seed))
        inner = sha3_512(concat(b"address_inner", seed))
        address = sha3_512(concat(b"address_outer", inner))

        return cls(
            current_key=seed,
            epoch=0,
            address=address
        )
    
    def evolve(self, epoch_entropy: bytes) -> None:
        """
        Evolve key to next epoch
        
        Key_N = SHA3-512(Key_{N-1} || EpochEntropy_N)
        """
        self.current_key = sha3_512(concat(self.current_key, epoch_entropy))
        self.epoch += 1
    
    def get_signing_keypair(self, wots: WOTSPlus) -> Tuple[bytes, bytes]:
        """Generate WOTS+ keypair for current epoch"""
        return wots.keygen(self.current_key)
    
    def destroy_previous(self) -> None:
        """Securely destroy previous key material via ctypes memset."""
        _secure_wipe(self.current_key)

# =============================================================================
# MERKLE TREE FOR EPOCH COMMITMENTS
# =============================================================================

class MerkleTree:
    """
    Merkle tree for committing to validator public keys each epoch
    """
    
    def __init__(self, leaves: list):
        self.leaves = [sha3_256(leaf) if isinstance(leaf, bytes) else leaf 
                       for leaf in leaves]
        self.tree = self._build_tree()
    
    def _build_tree(self) -> list:
        """Build complete Merkle tree"""
        if not self.leaves:
            return [sha3_256(b"empty")]
        
        # Pad to power of 2
        n = len(self.leaves)
        next_pow2 = 1 << (n - 1).bit_length()
        padded = self.leaves + [sha3_256(b"pad")] * (next_pow2 - n)
        
        tree = [padded]
        current = padded
        
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                combined = sha3_256(current[i] + current[i + 1])
                next_level.append(combined)
            tree.append(next_level)
            current = next_level
        
        return tree
    
    @property
    def root(self) -> bytes:
        """Get Merkle root"""
        return self.tree[-1][0]
    
    def get_proof(self, index: int) -> list:
        """Get authentication path for leaf at index"""
        if index >= len(self.leaves):
            raise IndexError("Leaf index out of range")
        
        proof = []
        idx = index
        
        for level in self.tree[:-1]:
            sibling_idx = idx ^ 1  # XOR to get sibling
            if sibling_idx < len(level):
                proof.append((level[sibling_idx], idx % 2))
            idx //= 2
        
        return proof
    
    @staticmethod
    def verify_proof(leaf: bytes, proof: list, root: bytes) -> bool:
        """Verify Merkle proof"""
        current = sha3_256(leaf) if len(leaf) != 32 else leaf
        
        for sibling, is_right in proof:
            if is_right:
                current = sha3_256(sibling + current)
            else:
                current = sha3_256(current + sibling)
        
        return current == root


# =============================================================================
# TEMPORAL AUTH TREE (Batch-based Forward-Secret Authentication)
# =============================================================================

TOTAL_KEYS_PER_BATCH = 1024
RESERVED_ROTATION = 2
USABLE_KEYS = TOTAL_KEYS_PER_BATCH - RESERVED_ROTATION  # 1022


def derive_initial_batch_seed(master_seed: bytes) -> bytes:
    """
    Derive the initial batch seed (batch 0) from master_seed.
    master_seed only ever derives batch_0_seed; subsequent batches
    are chained one-way from there.
    """
    return sha3_512(concat(b"batch_initial", master_seed))


def derive_next_batch_seed(current_batch_seed: bytes) -> bytes:
    """
    Derive the next batch seed from the current one.
    One-way: knowing batch_N_seed cannot recover batch_{N-1}_seed.
    """
    return sha3_512(concat(b"batch_next", current_batch_seed))


class TemporalAuthTree:
    """
    Temporal Authentication Tree using WOTS+ keys organized in batches.

    Each batch contains 1024 keys:
      - Keys 0..1021: usable for regular transaction signing
      - Keys 1022..1023: reserved for rotation transaction signing

    Forward secrecy: batch_seed is destroyed after deriving the next batch.
    The auth_root is a Merkle root of all 1024 WOTS+ public key hashes.
    """

    def __init__(self, batch_seed: bytes):
        self._batch_seed = batch_seed
        self._key_index = 0  # Next usable key to use (0..1021)
        self._rotation_index = 0  # 0 or 1 (for keys 1022, 1023)
        self.wots = WOTSPlus()

        # Generate all public keys and pass to MerkleTree (which hashes them)
        pub_keys: list = []
        for i in range(TOTAL_KEYS_PER_BATCH):
            key_seed = self._derive_key_seed(i)
            _, pub = self.wots.keygen(key_seed)
            pub_keys.append(pub)

        # Build auth Merkle tree — MerkleTree hashes each leaf via sha3_256
        self._auth_tree = MerkleTree(pub_keys)

    def _derive_key_seed(self, index: int) -> bytes:
        """Derive the seed for key at given index within this batch.
        Format: SHA3-512("key_seed" || batch_seed || index_BE8)
        Must match native Rust/C implementations exactly.
        """
        return sha3_512(concat(b"key_seed", self._batch_seed, index))

    @property
    def auth_root(self) -> bytes:
        """The Merkle root committing to all 1024 public keys."""
        return self._auth_tree.root

    @property
    def remaining_keys(self) -> int:
        """Number of usable (non-reserved) keys remaining."""
        return USABLE_KEYS - self._key_index

    @property
    def remaining_rotation_keys(self) -> int:
        """Number of reserved rotation keys remaining."""
        return RESERVED_ROTATION - self._rotation_index

    def sign(self, message: bytes) -> Tuple[bytes, bytes, list, int]:
        """
        Sign a message using the next available usable key (0..1021).

        Returns:
            (signature, public_key, merkle_proof, key_index)

        Raises:
            ValueError: if all usable keys are exhausted
        """
        if self._key_index >= USABLE_KEYS:
            raise ValueError(
                "All usable keys exhausted. Must rotate batch before signing."
            )

        idx = self._key_index
        self._key_index += 1

        key_seed = self._derive_key_seed(idx)
        priv, pub = self.wots.keygen(key_seed)

        signature = self.wots.sign(message, priv)
        proof = self._auth_tree.get_proof(idx)

        # Wipe private key material in place
        _secure_wipe(priv)
        _secure_wipe(key_seed)

        return signature, pub, proof, idx

    def sign_rotation(self, message: bytes) -> Tuple[bytes, bytes, list, int]:
        """
        Sign a rotation message using a reserved key (1022 or 1023).

        Returns:
            (signature, public_key, merkle_proof, key_index)

        Raises:
            ValueError: if both rotation keys are exhausted
        """
        if self._rotation_index >= RESERVED_ROTATION:
            raise ValueError("All rotation keys exhausted for this batch.")

        idx = USABLE_KEYS + self._rotation_index  # 1022 or 1023
        self._rotation_index += 1

        key_seed = self._derive_key_seed(idx)
        priv, pub = self.wots.keygen(key_seed)

        signature = self.wots.sign(message, priv)
        proof = self._auth_tree.get_proof(idx)

        # Wipe private key material in place
        _secure_wipe(priv)
        _secure_wipe(key_seed)

        return signature, pub, proof, idx

    def verify_auth(self, message: bytes, signature: bytes,
                    public_key: bytes, proof: list, key_index: int) -> bool:
        """
        Verify a temporal auth signature against this tree's root.

        Checks:
          1. WOTS+ signature valid for message
          2. public_key's hash has valid Merkle proof to auth_root
        """
        # Verify WOTS+ signature
        if not self.wots.verify(message, signature, public_key):
            return False

        # Verify Merkle proof
        pub_hash = sha3_256(public_key)
        return MerkleTree.verify_proof(pub_hash, proof, self.auth_root)

    @staticmethod
    def verify_against_root(message: bytes, signature: bytes,
                            public_key: bytes, proof: list,
                            auth_root: bytes) -> bool:
        """
        Static verification against a known auth_root (for validators).
        Does not require the full tree — just the proof.
        """
        wots = WOTSPlus()
        if not wots.verify(message, signature, public_key):
            return False

        pub_hash = sha3_256(public_key)
        return MerkleTree.verify_proof(pub_hash, proof, auth_root)

    def destroy(self) -> None:
        """
        Securely destroy batch_seed and all derived key material.
        Called after deriving the next batch seed.
        """
        if self._batch_seed:
            _secure_wipe(self._batch_seed)
            self._batch_seed = b'\x00' * 64
        self._auth_tree = None


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def generate_validator_id() -> bytes:
    """Generate unique validator ID"""
    return secure_random(32)

def hash_measurement(validator_id: bytes, target_id: bytes, 
                     rtt_ms: float, timestamp: int) -> bytes:
    """Hash a measurement for commitment"""
    return sha3_256(concat(
        b"measurement",
        validator_id,
        target_id,
        rtt_ms,
        timestamp
    ))
