use crate::sha3::{sha3_256, sha3_512, HASH_SIZE_512};
use crate::wots::{wots_keygen, wots_sign, wots_verify};
use crate::merkle::{merkle_build_with_proof, merkle_verify_proof, MerkleProof, MERKLE_HASH_SIZE};
use zeroize::Zeroize;

pub const TOTAL_KEYS_PER_BATCH: usize = 1024;
pub const RESERVED_ROTATION: usize = 2;
pub const USABLE_KEYS: usize = TOTAL_KEYS_PER_BATCH - RESERVED_ROTATION; // 1022

/// Derive initial batch seed from master seed
pub fn derive_initial_batch_seed(master_seed: &[u8]) -> [u8; HASH_SIZE_512] {
    let mut buf = Vec::with_capacity(14 + master_seed.len());
    buf.extend_from_slice(b"batch_initial");
    buf.extend_from_slice(master_seed);
    sha3_512(&buf)
}

/// Derive next batch seed (forward secrecy chain)
pub fn derive_next_batch_seed(current_batch_seed: &[u8; HASH_SIZE_512]) -> [u8; HASH_SIZE_512] {
    let mut buf = Vec::with_capacity(10 + 64);
    buf.extend_from_slice(b"batch_next");
    buf.extend_from_slice(current_batch_seed);
    sha3_512(&buf)
}

/// Derive key seed for a specific index within a batch
fn derive_key_seed(batch_seed: &[u8; HASH_SIZE_512], index: usize) -> [u8; HASH_SIZE_512] {
    let mut buf = Vec::with_capacity(8 + 64 + 8);
    buf.extend_from_slice(b"key_seed");
    buf.extend_from_slice(batch_seed);
    buf.extend_from_slice(&(index as u64).to_be_bytes());
    sha3_512(&buf)
}

/// Temporal authentication signature result
pub struct TemporalSignature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub proof: MerkleProof,
    pub key_index: usize,
}

/// Temporal Auth Tree: manages a batch of 1024 WOTS+ keys
pub struct TemporalAuthTree {
    batch_seed: [u8; HASH_SIZE_512],
    auth_root: [u8; MERKLE_HASH_SIZE],
    key_index: usize,
    rotation_index: usize,
    /// Cached public keys
    pub_keys: Vec<Vec<u8>>,
    /// Pre-computed Merkle proofs for all keys
    proofs: Vec<MerkleProof>,
}

impl TemporalAuthTree {
    /// Create a new TemporalAuthTree from a batch seed
    pub fn new(batch_seed: [u8; HASH_SIZE_512]) -> Self {
        // Generate all public keys
        let mut pub_keys = Vec::with_capacity(TOTAL_KEYS_PER_BATCH);
        for i in 0..TOTAL_KEYS_PER_BATCH {
            let key_seed = derive_key_seed(&batch_seed, i);
            let (_, pk) = wots_keygen(&key_seed);
            pub_keys.push(pk);
        }

        // Build all proofs at once
        let leaves: Vec<&[u8]> = pub_keys.iter().map(|k| k.as_slice()).collect();
        let mut proofs = Vec::with_capacity(TOTAL_KEYS_PER_BATCH);
        let mut root = [0u8; MERKLE_HASH_SIZE];
        for i in 0..TOTAL_KEYS_PER_BATCH {
            let (r, proof) = merkle_build_with_proof(&leaves, i);
            if i == 0 { root = r; }
            proofs.push(proof);
        }

        TemporalAuthTree {
            batch_seed,
            auth_root: root,
            key_index: 0,
            rotation_index: 0,
            pub_keys,
            proofs,
        }
    }

    /// Get the auth root (Merkle root of all public keys)
    pub fn auth_root(&self) -> &[u8; MERKLE_HASH_SIZE] {
        &self.auth_root
    }

    /// Get remaining usable keys
    pub fn remaining_keys(&self) -> usize {
        USABLE_KEYS - self.key_index
    }

    /// Sign a message using the next available key (keys 0..1021)
    pub fn sign(&mut self, message: &[u8]) -> Option<TemporalSignature> {
        if self.key_index >= USABLE_KEYS {
            return None; // Exhausted
        }

        let idx = self.key_index;
        self.key_index += 1;

        let key_seed = derive_key_seed(&self.batch_seed, idx);
        let (sk, pk) = wots_keygen(&key_seed);
        let sig = wots_sign(message, &sk);

        Some(TemporalSignature {
            signature: sig,
            public_key: pk,
            proof: self.proofs[idx].clone(),
            key_index: idx,
        })
    }

    /// Sign with a reserved rotation key (keys 1022..1023)
    pub fn sign_rotation(&mut self, message: &[u8]) -> Option<TemporalSignature> {
        if self.rotation_index >= RESERVED_ROTATION {
            return None;
        }

        let idx = USABLE_KEYS + self.rotation_index;
        self.rotation_index += 1;

        let key_seed = derive_key_seed(&self.batch_seed, idx);
        let (sk, pk) = wots_keygen(&key_seed);
        let sig = wots_sign(message, &sk);

        Some(TemporalSignature {
            signature: sig,
            public_key: pk,
            proof: self.proofs[idx].clone(),
            key_index: idx,
        })
    }

    /// Verify a temporal auth signature against this tree's root
    pub fn verify(&self, message: &[u8], sig: &TemporalSignature) -> bool {
        Self::verify_against_root(message, sig, &self.auth_root)
    }

    /// Verify against an arbitrary auth root
    pub fn verify_against_root(
        message: &[u8],
        sig: &TemporalSignature,
        auth_root: &[u8; MERKLE_HASH_SIZE],
    ) -> bool {
        // Verify WOTS+ signature
        if !wots_verify(message, &sig.signature, &sig.public_key) {
            return false;
        }

        // Verify Merkle proof
        let leaf_hash = sha3_256(&sig.public_key);
        merkle_verify_proof(&leaf_hash, &sig.proof, auth_root)
    }

    /// Destroy the batch seed (forward secrecy)
    pub fn destroy(&mut self) {
        self.batch_seed.zeroize();
        self.pub_keys.clear();
        self.proofs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_batch_seed_derivation() {
        let master = sha3_512(b"master_seed");
        let batch0 = derive_initial_batch_seed(&master);
        let batch1 = derive_next_batch_seed(&batch0);
        let batch2 = derive_next_batch_seed(&batch1);

        // All different
        assert_ne!(batch0, batch1);
        assert_ne!(batch1, batch2);

        // Deterministic
        let batch0_again = derive_initial_batch_seed(&master);
        assert_eq!(batch0, batch0_again);
    }

    #[test]
    fn test_sign_verify() {
        let seed = derive_initial_batch_seed(b"test_temporal");
        let mut tree = TemporalAuthTree::new(seed);

        let msg = b"test message";
        let sig = tree.sign(msg).unwrap();
        assert!(tree.verify(msg, &sig));
    }

    #[test]
    fn test_wrong_message_fails() {
        let seed = derive_initial_batch_seed(b"test_temporal_2");
        let mut tree = TemporalAuthTree::new(seed);

        let sig = tree.sign(b"message A").unwrap();
        assert!(!tree.verify(b"message B", &sig));
    }

    #[test]
    fn test_key_exhaustion() {
        let seed = derive_initial_batch_seed(b"exhaust_test");
        let mut tree = TemporalAuthTree::new(seed);

        // Use a few keys
        for _ in 0..5 {
            assert!(tree.sign(b"msg").is_some());
        }
        assert_eq!(tree.remaining_keys(), USABLE_KEYS - 5);
    }

    #[test]
    fn test_rotation_keys() {
        let seed = derive_initial_batch_seed(b"rotation_test");
        let mut tree = TemporalAuthTree::new(seed);

        let rot1 = tree.sign_rotation(b"rotate1").unwrap();
        assert!(tree.verify(b"rotate1", &rot1));

        let rot2 = tree.sign_rotation(b"rotate2").unwrap();
        assert!(tree.verify(b"rotate2", &rot2));

        // Third rotation should fail
        assert!(tree.sign_rotation(b"rotate3").is_none());
    }

    #[test]
    fn test_destroy_zeroes_seed() {
        let seed = derive_initial_batch_seed(b"destroy_test");
        let mut tree = TemporalAuthTree::new(seed);
        tree.destroy();
        assert_eq!(tree.batch_seed, [0u8; 64]);
        assert!(tree.pub_keys.is_empty());
    }

    #[test]
    fn test_verify_against_root() {
        let seed = derive_initial_batch_seed(b"root_verify");
        let mut tree = TemporalAuthTree::new(seed);
        let root = *tree.auth_root();

        let sig = tree.sign(b"check_root").unwrap();
        assert!(TemporalAuthTree::verify_against_root(b"check_root", &sig, &root));
    }
}
