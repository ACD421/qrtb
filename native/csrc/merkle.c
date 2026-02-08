/*
 * Merkle tree implementation for QRTB
 */

#include "merkle.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>

/* Hash two nodes together */
static void hash_nodes(const uint8_t left[MERKLE_HASH_SIZE],
                       const uint8_t right[MERKLE_HASH_SIZE],
                       uint8_t out[MERKLE_HASH_SIZE]) {
    uint8_t combined[MERKLE_HASH_SIZE * 2];
    memcpy(combined, left, MERKLE_HASH_SIZE);
    memcpy(combined + MERKLE_HASH_SIZE, right, MERKLE_HASH_SIZE);
    sha3_256(combined, MERKLE_HASH_SIZE * 2, out);
}

/* Next power of 2 */
static size_t next_pow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

/* Pad hash for unused leaves */
static void pad_hash(uint8_t out[MERKLE_HASH_SIZE]) {
    const uint8_t pad_input[] = "pad";
    sha3_256(pad_input, 3, out);
}

void merkle_build_root(const uint8_t *leaves, size_t num_leaves,
                       size_t leaf_size, uint8_t root_out[MERKLE_HASH_SIZE]) {
    if (num_leaves == 0) {
        const uint8_t empty[] = "empty";
        sha3_256(empty, 5, root_out);
        return;
    }

    size_t padded_size = next_pow2(num_leaves);
    uint8_t *hashes = (uint8_t *)malloc(padded_size * MERKLE_HASH_SIZE);

    /* Hash each leaf */
    for (size_t i = 0; i < num_leaves; i++) {
        sha3_256(leaves + i * leaf_size, leaf_size,
                 hashes + i * MERKLE_HASH_SIZE);
    }
    /* Pad remaining */
    for (size_t i = num_leaves; i < padded_size; i++) {
        pad_hash(hashes + i * MERKLE_HASH_SIZE);
    }

    /* Build tree bottom-up */
    size_t level_size = padded_size;
    while (level_size > 1) {
        for (size_t i = 0; i < level_size / 2; i++) {
            hash_nodes(hashes + (2 * i) * MERKLE_HASH_SIZE,
                       hashes + (2 * i + 1) * MERKLE_HASH_SIZE,
                       hashes + i * MERKLE_HASH_SIZE);
        }
        level_size /= 2;
    }

    memcpy(root_out, hashes, MERKLE_HASH_SIZE);
    free(hashes);
}

void merkle_build_with_proof(const uint8_t *leaves, size_t num_leaves,
                             size_t leaf_size, size_t leaf_index,
                             uint8_t root_out[MERKLE_HASH_SIZE],
                             MerkleProof *proof_out) {
    size_t padded_size = next_pow2(num_leaves);

    /* Allocate full tree storage: all levels */
    /* Level 0: padded_size nodes, Level 1: padded_size/2, ... */
    /* Total nodes = 2*padded_size - 1, but we store level by level */
    uint8_t *level = (uint8_t *)malloc(padded_size * MERKLE_HASH_SIZE);
    uint8_t *next_level = (uint8_t *)malloc((padded_size / 2 + 1) * MERKLE_HASH_SIZE);

    /* Hash leaves */
    for (size_t i = 0; i < num_leaves; i++) {
        sha3_256(leaves + i * leaf_size, leaf_size,
                 level + i * MERKLE_HASH_SIZE);
    }
    for (size_t i = num_leaves; i < padded_size; i++) {
        pad_hash(level + i * MERKLE_HASH_SIZE);
    }

    /* Build tree and collect proof */
    proof_out->depth = 0;
    size_t level_size = padded_size;
    size_t idx = leaf_index;

    while (level_size > 1) {
        /* Get sibling */
        size_t sibling = idx ^ 1;
        if (sibling < level_size) {
            memcpy(proof_out->entries[proof_out->depth].sibling,
                   level + sibling * MERKLE_HASH_SIZE, MERKLE_HASH_SIZE);
            proof_out->entries[proof_out->depth].is_right = (uint8_t)(idx % 2);
            proof_out->depth++;
        }

        /* Compute next level */
        for (size_t i = 0; i < level_size / 2; i++) {
            hash_nodes(level + (2 * i) * MERKLE_HASH_SIZE,
                       level + (2 * i + 1) * MERKLE_HASH_SIZE,
                       next_level + i * MERKLE_HASH_SIZE);
        }

        /* Swap buffers */
        uint8_t *tmp = level;
        level = next_level;
        next_level = tmp;

        level_size /= 2;
        idx /= 2;
    }

    memcpy(root_out, level, MERKLE_HASH_SIZE);
    free(level);
    free(next_level);
}

int merkle_verify_proof(const uint8_t leaf_hash[MERKLE_HASH_SIZE],
                        const MerkleProof *proof,
                        const uint8_t root[MERKLE_HASH_SIZE]) {
    uint8_t current[MERKLE_HASH_SIZE];
    memcpy(current, leaf_hash, MERKLE_HASH_SIZE);

    for (int i = 0; i < proof->depth; i++) {
        if (proof->entries[i].is_right) {
            /* current is on the right, sibling on the left */
            hash_nodes(proof->entries[i].sibling, current, current);
        } else {
            /* current is on the left, sibling on the right */
            hash_nodes(current, proof->entries[i].sibling, current);
        }
    }

    return memcmp(current, root, MERKLE_HASH_SIZE) == 0;
}
