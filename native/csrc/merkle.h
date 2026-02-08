#ifndef QRTB_MERKLE_H
#define QRTB_MERKLE_H

#include <stdint.h>
#include <stddef.h>

#define MERKLE_HASH_SIZE 32
#define MERKLE_MAX_DEPTH 11  /* log2(1024) + 1 */

/* Proof entry: sibling hash + position (0=left, 1=right) */
typedef struct {
    uint8_t sibling[MERKLE_HASH_SIZE];
    uint8_t is_right;
} MerkleProofEntry;

typedef struct {
    MerkleProofEntry entries[MERKLE_MAX_DEPTH];
    int depth;
} MerkleProof;

/*
 * Build Merkle tree and return root.
 * leaves: array of raw leaves (each leaf_size bytes, will be hashed to 32B)
 * num_leaves: number of leaves
 * leaf_size: size of each leaf in bytes
 * root_out: 32-byte output for the Merkle root
 */
void merkle_build_root(const uint8_t *leaves, size_t num_leaves,
                       size_t leaf_size, uint8_t root_out[MERKLE_HASH_SIZE]);

/*
 * Build Merkle tree and get proof for a specific leaf.
 * Returns the root in root_out and proof in proof_out.
 */
void merkle_build_with_proof(const uint8_t *leaves, size_t num_leaves,
                             size_t leaf_size, size_t leaf_index,
                             uint8_t root_out[MERKLE_HASH_SIZE],
                             MerkleProof *proof_out);

/*
 * Verify a Merkle proof.
 * leaf_hash: SHA3-256 hash of the leaf
 * Returns 1 if valid, 0 if invalid.
 */
int merkle_verify_proof(const uint8_t leaf_hash[MERKLE_HASH_SIZE],
                        const MerkleProof *proof,
                        const uint8_t root[MERKLE_HASH_SIZE]);

#endif /* QRTB_MERKLE_H */
