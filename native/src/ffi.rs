//! FFI bindings to call C implementations for benchmarking comparison

use crate::sha3::HASH_SIZE_256;
use crate::wots::WOTS_SIG_SIZE;
use crate::merkle::MERKLE_HASH_SIZE;

/// C TemporalAuthTree (opaque-ish struct for FFI)
#[repr(C)]
pub struct CTemporalAuthTree {
    pub batch_seed: [u8; 64],
    pub auth_root: [u8; MERKLE_HASH_SIZE],
    pub pub_keys: *mut u8,
    pub proofs: *mut CMerkleProof,
    pub key_index: usize,
    pub rotation_index: usize,
}

/// C MerkleProof for FFI
#[repr(C)]
pub struct CMerkleProofEntry {
    pub sibling: [u8; MERKLE_HASH_SIZE],
    pub is_right: u8,
}

#[repr(C)]
pub struct CMerkleProof {
    pub entries: [CMerkleProofEntry; 11], // MERKLE_MAX_DEPTH
    pub depth: i32,
}

// C function declarations
extern "C" {
    pub fn sha3_256(input: *const u8, input_len: usize, output: *mut u8);
    pub fn sha3_512(input: *const u8, input_len: usize, output: *mut u8);

    pub fn wots_keygen(seed: *const u8, private_key: *mut u8, public_key: *mut u8);
    pub fn wots_sign(message: *const u8, msg_len: usize,
                     private_key: *const u8, signature: *mut u8);
    pub fn wots_verify(message: *const u8, msg_len: usize,
                       signature: *const u8, public_key: *const u8) -> i32;

    pub fn merkle_build_root(leaves: *const u8, num_leaves: usize,
                             leaf_size: usize, root_out: *mut u8);

    pub fn tat_derive_initial_batch_seed(master_seed: *const u8, seed_len: usize,
                                         out: *mut u8);
    pub fn tat_derive_next_batch_seed(current: *const u8, out: *mut u8);
    pub fn tat_init(tree: *mut CTemporalAuthTree, batch_seed: *const u8);
    pub fn tat_sign(tree: *mut CTemporalAuthTree, message: *const u8, msg_len: usize,
                    signature: *mut u8, pub_key: *mut u8,
                    proof: *mut CMerkleProof, key_index_out: *mut usize) -> i32;
    pub fn tat_verify(message: *const u8, msg_len: usize,
                      signature: *const u8, pub_key: *const u8,
                      proof: *const CMerkleProof,
                      auth_root: *const u8) -> i32;
    pub fn tat_destroy(tree: *mut CTemporalAuthTree);
}

/// Safe wrapper for C SHA3-256
pub fn c_sha3_256(input: &[u8]) -> [u8; HASH_SIZE_256] {
    let mut output = [0u8; HASH_SIZE_256];
    unsafe {
        sha3_256(input.as_ptr(), input.len(), output.as_mut_ptr());
    }
    output
}

/// Safe wrapper for C SHA3-512
pub fn c_sha3_512(input: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    unsafe {
        sha3_512(input.as_ptr(), input.len(), output.as_mut_ptr());
    }
    output
}

/// Safe wrapper for C WOTS+ keygen
pub fn c_wots_keygen(seed: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
    let mut sk = vec![0u8; WOTS_SIG_SIZE];
    let mut pk = vec![0u8; WOTS_SIG_SIZE];
    unsafe {
        wots_keygen(seed.as_ptr(), sk.as_mut_ptr(), pk.as_mut_ptr());
    }
    (sk, pk)
}

/// Safe wrapper for C WOTS+ sign
pub fn c_wots_sign(message: &[u8], private_key: &[u8]) -> Vec<u8> {
    let mut sig = vec![0u8; WOTS_SIG_SIZE];
    unsafe {
        wots_sign(message.as_ptr(), message.len(),
                  private_key.as_ptr(), sig.as_mut_ptr());
    }
    sig
}

/// Safe wrapper for C WOTS+ verify
pub fn c_wots_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    unsafe {
        wots_verify(message.as_ptr(), message.len(),
                    signature.as_ptr(), public_key.as_ptr()) == 1
    }
}

/// Safe wrapper for C Merkle build_root (flat leaf array)
pub fn c_merkle_build_root(leaves: &[u8], num_leaves: usize, leaf_size: usize) -> [u8; MERKLE_HASH_SIZE] {
    let mut root = [0u8; MERKLE_HASH_SIZE];
    unsafe {
        merkle_build_root(leaves.as_ptr(), num_leaves, leaf_size, root.as_mut_ptr());
    }
    root
}

/// Safe wrapper for C batch seed derivation
pub fn c_derive_initial_batch_seed(master_seed: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe {
        tat_derive_initial_batch_seed(master_seed.as_ptr(), master_seed.len(), out.as_mut_ptr());
    }
    out
}

pub fn c_derive_next_batch_seed(current: &[u8; 64]) -> [u8; 64] {
    let mut out = [0u8; 64];
    unsafe {
        tat_derive_next_batch_seed(current.as_ptr(), out.as_mut_ptr());
    }
    out
}

/// Safe wrapper for C TemporalAuthTree init
pub fn c_tat_init(batch_seed: &[u8; 64]) -> CTemporalAuthTree {
    let mut tree = CTemporalAuthTree {
        batch_seed: [0u8; 64],
        auth_root: [0u8; MERKLE_HASH_SIZE],
        pub_keys: std::ptr::null_mut(),
        proofs: std::ptr::null_mut(),
        key_index: 0,
        rotation_index: 0,
    };
    unsafe {
        tat_init(&mut tree, batch_seed.as_ptr());
    }
    tree
}

/// Safe wrapper for C TemporalAuthTree sign
pub fn c_tat_sign(tree: &mut CTemporalAuthTree, message: &[u8])
    -> Option<(Vec<u8>, Vec<u8>, CMerkleProof, usize)> {
    let mut sig = vec![0u8; WOTS_SIG_SIZE];
    let mut pk = vec![0u8; WOTS_SIG_SIZE];
    let mut proof = CMerkleProof {
        entries: unsafe { std::mem::zeroed() },
        depth: 0,
    };
    let mut key_idx: usize = 0;
    let ret = unsafe {
        tat_sign(tree, message.as_ptr(), message.len(),
                 sig.as_mut_ptr(), pk.as_mut_ptr(),
                 &mut proof, &mut key_idx)
    };
    if ret == 0 { Some((sig, pk, proof, key_idx)) } else { None }
}

/// Safe wrapper for C TemporalAuthTree verify
pub fn c_tat_verify(message: &[u8], sig: &[u8], pk: &[u8],
                    proof: &CMerkleProof, auth_root: &[u8; MERKLE_HASH_SIZE]) -> bool {
    unsafe {
        tat_verify(message.as_ptr(), message.len(),
                   sig.as_ptr(), pk.as_ptr(),
                   proof, auth_root.as_ptr()) == 1
    }
}

/// Safe wrapper for C TemporalAuthTree destroy
pub fn c_tat_destroy(tree: &mut CTemporalAuthTree) {
    unsafe { tat_destroy(tree); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_sha3_256_matches_rust() {
        let input = b"test data for cross-validation";
        let c_hash = c_sha3_256(input);
        let rust_hash = crate::sha3::sha3_256(input);
        assert_eq!(c_hash, rust_hash, "C and Rust SHA3-256 outputs differ!");
    }

    #[test]
    fn test_c_sha3_512_matches_rust() {
        let input = b"sha512 cross-validation input";
        let c_hash = c_sha3_512(input);
        let rust_hash = crate::sha3::sha3_512(input);
        assert_eq!(c_hash, rust_hash, "C and Rust SHA3-512 outputs differ!");
    }

    #[test]
    fn test_c_wots_keygen_matches_rust() {
        let seed = crate::sha3::sha3_512(b"cross_val_seed");
        let (c_sk, c_pk) = c_wots_keygen(&seed);
        let (r_sk, r_pk) = crate::wots::wots_keygen(&seed);
        assert_eq!(c_sk, r_sk, "C and Rust WOTS+ private keys differ!");
        assert_eq!(c_pk, r_pk, "C and Rust WOTS+ public keys differ!");
    }

    #[test]
    fn test_c_wots_sign_verify() {
        let seed = crate::sha3::sha3_512(b"c_sign_test");
        let (sk, pk) = c_wots_keygen(&seed);
        let msg = b"message to sign";
        let sig = c_wots_sign(msg, &sk);
        assert!(c_wots_verify(msg, &sig, &pk));
    }

    #[test]
    fn test_c_wots_cross_verify() {
        // Sign with C, verify with Rust (and vice versa)
        let seed = crate::sha3::sha3_512(b"cross_sign");
        let (c_sk, c_pk) = c_wots_keygen(&seed);
        let msg = b"cross verification test";

        let c_sig = c_wots_sign(msg, &c_sk);
        assert!(crate::wots::wots_verify(msg, &c_sig, &c_pk),
                "Rust failed to verify C signature");

        let (r_sk, r_pk) = crate::wots::wots_keygen(&seed);
        let r_sig = crate::wots::wots_sign(msg, &r_sk);
        assert!(c_wots_verify(msg, &r_sig, &r_pk),
                "C failed to verify Rust signature");
    }

    #[test]
    fn test_c_merkle_root() {
        // Build flat leaf array
        let leaf_size = 32usize;
        let num_leaves = 4usize;
        let mut flat_leaves = vec![0u8; num_leaves * leaf_size];
        for i in 0..num_leaves {
            let data = crate::sha3::sha3_256(&(i as u32).to_le_bytes());
            flat_leaves[i * leaf_size..(i + 1) * leaf_size].copy_from_slice(&data);
        }

        let c_root = c_merkle_build_root(&flat_leaves, num_leaves, leaf_size);

        // Rust equivalent
        let leaves: Vec<&[u8]> = (0..num_leaves)
            .map(|i| &flat_leaves[i * leaf_size..(i + 1) * leaf_size])
            .collect();
        let r_root = crate::merkle::merkle_build_root(&leaves);

        assert_eq!(c_root, r_root, "C and Rust Merkle roots differ!");
    }

    #[test]
    fn test_c_batch_seed_matches_rust() {
        let master = b"batch_seed_crossval";
        let c_seed = c_derive_initial_batch_seed(master);
        let r_seed = crate::temporal_auth::derive_initial_batch_seed(master);
        assert_eq!(c_seed, r_seed, "C and Rust initial batch seeds differ!");

        let c_next = c_derive_next_batch_seed(&c_seed);
        let r_next = crate::temporal_auth::derive_next_batch_seed(&r_seed);
        assert_eq!(c_next, r_next, "C and Rust next batch seeds differ!");
    }

    #[test]
    fn test_c_tat_sign_verify() {
        let seed = c_derive_initial_batch_seed(b"c_tat_test");
        let mut tree = c_tat_init(&seed);

        let msg = b"temporal auth test message";
        let (sig, pk, proof, _idx) = c_tat_sign(&mut tree, msg).unwrap();
        assert!(c_tat_verify(msg, &sig, &pk, &proof, &tree.auth_root));

        c_tat_destroy(&mut tree);
    }

    #[test]
    fn test_c_tat_auth_root_matches_rust() {
        let seed = c_derive_initial_batch_seed(b"root_crossval");
        let c_tree = c_tat_init(&seed);
        let r_tree = crate::temporal_auth::TemporalAuthTree::new(seed);

        assert_eq!(c_tree.auth_root, *r_tree.auth_root(),
                   "C and Rust TemporalAuth roots differ!");

        let mut c_tree = c_tree;
        c_tat_destroy(&mut c_tree);
    }
}
