use crate::sha3::{sha3_256, HASH_SIZE_256};

pub const MERKLE_HASH_SIZE: usize = HASH_SIZE_256;
pub const MERKLE_MAX_DEPTH: usize = 11; // log2(1024) + 1

#[derive(Clone, Debug)]
pub struct MerkleProofEntry {
    pub sibling: [u8; MERKLE_HASH_SIZE],
    pub is_right: bool, // true if current node is on the right
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub entries: Vec<MerkleProofEntry>,
}

/// Next power of 2
fn next_pow2(n: usize) -> usize {
    let mut p = 1;
    while p < n {
        p <<= 1;
    }
    p
}

/// Hash two nodes together
fn hash_nodes(left: &[u8; MERKLE_HASH_SIZE], right: &[u8; MERKLE_HASH_SIZE]) -> [u8; MERKLE_HASH_SIZE] {
    let mut combined = [0u8; MERKLE_HASH_SIZE * 2];
    combined[..MERKLE_HASH_SIZE].copy_from_slice(left);
    combined[MERKLE_HASH_SIZE..].copy_from_slice(right);
    sha3_256(&combined)
}

/// Pad hash for unused leaves
fn pad_hash() -> [u8; MERKLE_HASH_SIZE] {
    sha3_256(b"pad")
}

/// Build Merkle root from raw leaves (each leaf is hashed first)
pub fn merkle_build_root(leaves: &[&[u8]]) -> [u8; MERKLE_HASH_SIZE] {
    if leaves.is_empty() {
        return sha3_256(b"empty");
    }

    let padded_size = next_pow2(leaves.len());
    let pad = pad_hash();

    // Hash each leaf
    let mut hashes: Vec<[u8; MERKLE_HASH_SIZE]> = leaves
        .iter()
        .map(|leaf| sha3_256(leaf))
        .collect();

    // Pad remaining
    while hashes.len() < padded_size {
        hashes.push(pad);
    }

    // Build tree bottom-up
    let mut level_size = padded_size;
    while level_size > 1 {
        for i in 0..level_size / 2 {
            hashes[i] = hash_nodes(&hashes[2 * i], &hashes[2 * i + 1]);
        }
        level_size /= 2;
    }

    hashes[0]
}

/// Build Merkle root and proof for a specific leaf
pub fn merkle_build_with_proof(leaves: &[&[u8]], leaf_index: usize) -> ([u8; MERKLE_HASH_SIZE], MerkleProof) {
    assert!(!leaves.is_empty());
    assert!(leaf_index < leaves.len());

    let padded_size = next_pow2(leaves.len());
    let pad = pad_hash();

    // Hash each leaf
    let mut level: Vec<[u8; MERKLE_HASH_SIZE]> = leaves
        .iter()
        .map(|leaf| sha3_256(leaf))
        .collect();

    // Pad remaining
    while level.len() < padded_size {
        level.push(pad);
    }

    // Build tree and collect proof
    let mut entries = Vec::new();
    let mut idx = leaf_index;
    let mut level_size = padded_size;

    while level_size > 1 {
        let sibling = idx ^ 1;
        if sibling < level_size {
            entries.push(MerkleProofEntry {
                sibling: level[sibling],
                is_right: (idx % 2) == 1,
            });
        }

        // Compute next level
        let mut next_level = Vec::with_capacity(level_size / 2);
        for i in 0..level_size / 2 {
            next_level.push(hash_nodes(&level[2 * i], &level[2 * i + 1]));
        }

        level = next_level;
        level_size /= 2;
        idx /= 2;
    }

    (level[0], MerkleProof { entries })
}

/// Verify a Merkle proof
pub fn merkle_verify_proof(
    leaf_hash: &[u8; MERKLE_HASH_SIZE],
    proof: &MerkleProof,
    root: &[u8; MERKLE_HASH_SIZE],
) -> bool {
    let mut current = *leaf_hash;

    for entry in &proof.entries {
        if entry.is_right {
            // current is on the right, sibling on the left
            current = hash_nodes(&entry.sibling, &current);
        } else {
            // current is on the left, sibling on the right
            current = hash_nodes(&current, &entry.sibling);
        }
    }

    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let leaf = b"single leaf";
        let root = merkle_build_root(&[leaf.as_slice()]);
        // Single leaf: next_pow2(1)=1, root = sha3_256(leaf)
        let expected = sha3_256(leaf);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_leaves() {
        let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1"];
        let root = merkle_build_root(&leaves);
        let h0 = sha3_256(b"leaf0");
        let h1 = sha3_256(b"leaf1");
        let expected = hash_nodes(&h0, &h1);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_proof_verification() {
        let leaves: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        for i in 0..4 {
            let (root, proof) = merkle_build_with_proof(&leaves, i);
            let leaf_hash = sha3_256(leaves[i]);
            assert!(merkle_verify_proof(&leaf_hash, &proof, &root));
        }
    }

    #[test]
    fn test_proof_wrong_leaf_fails() {
        let leaves: Vec<&[u8]> = vec![b"x", b"y", b"z", b"w"];
        let (root, proof) = merkle_build_with_proof(&leaves, 0);
        let wrong_hash = sha3_256(b"wrong");
        assert!(!merkle_verify_proof(&wrong_hash, &proof, &root));
    }

    #[test]
    fn test_1024_leaves() {
        let data: Vec<Vec<u8>> = (0..1024u32)
            .map(|i| i.to_le_bytes().to_vec())
            .collect();
        let leaves: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
        let root = merkle_build_root(&leaves);

        // Verify proof for a few indices
        for &idx in &[0, 511, 1023, 500] {
            let (proof_root, proof) = merkle_build_with_proof(&leaves, idx);
            assert_eq!(root, proof_root);
            let leaf_hash = sha3_256(leaves[idx]);
            assert!(merkle_verify_proof(&leaf_hash, &proof, &root));
        }
    }
}
