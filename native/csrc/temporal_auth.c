/*
 * Temporal Auth Tree implementation for QRTB
 */

#include "temporal_auth.h"
#include "sha3.h"
#include <string.h>
#include <stdlib.h>

/* Derive key seed for index within batch */
static void derive_key_seed(const uint8_t batch_seed[64], size_t index,
                            uint8_t out[64]) {
    uint8_t buf[8 + 64 + 8]; /* "key_seed" + batch_seed + index_be64 */
    memcpy(buf, "key_seed", 8);
    memcpy(buf + 8, batch_seed, 64);
    buf[72] = (uint8_t)((index >> 56) & 0xFF);
    buf[73] = (uint8_t)((index >> 48) & 0xFF);
    buf[74] = (uint8_t)((index >> 40) & 0xFF);
    buf[75] = (uint8_t)((index >> 32) & 0xFF);
    buf[76] = (uint8_t)((index >> 24) & 0xFF);
    buf[77] = (uint8_t)((index >> 16) & 0xFF);
    buf[78] = (uint8_t)((index >> 8) & 0xFF);
    buf[79] = (uint8_t)(index & 0xFF);
    sha3_512(buf, 80, out);
}

void tat_derive_initial_batch_seed(const uint8_t *master_seed, size_t seed_len,
                                   uint8_t out[64]) {
    /* SHA3-512("batch_initial" || master_seed) */
    size_t buf_len = 13 + seed_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    memcpy(buf, "batch_initial", 13);
    memcpy(buf + 13, master_seed, seed_len);
    sha3_512(buf, buf_len, out);
    free(buf);
}

void tat_derive_next_batch_seed(const uint8_t current[64], uint8_t out[64]) {
    /* SHA3-512("batch_next" || current) */
    uint8_t buf[10 + 64];
    memcpy(buf, "batch_next", 10);
    memcpy(buf + 10, current, 64);
    sha3_512(buf, 74, out);
}

void tat_init(TemporalAuthTree *tree, const uint8_t batch_seed[64]) {
    memcpy(tree->batch_seed, batch_seed, 64);
    tree->key_index = 0;
    tree->rotation_index = 0;

    /* Allocate and generate all public keys */
    tree->pub_keys = (uint8_t *)malloc(TAT_TOTAL_KEYS * WOTS_SIG_SIZE);
    uint8_t private_key[WOTS_SIG_SIZE];

    for (int i = 0; i < TAT_TOTAL_KEYS; i++) {
        uint8_t key_seed[64];
        derive_key_seed(batch_seed, i, key_seed);
        wots_keygen(key_seed, private_key,
                    tree->pub_keys + i * WOTS_SIG_SIZE);
    }

    /* Pre-compute all Merkle proofs */
    tree->proofs = (MerkleProof *)malloc(TAT_TOTAL_KEYS * sizeof(MerkleProof));
    for (int i = 0; i < TAT_TOTAL_KEYS; i++) {
        uint8_t root_tmp[MERKLE_HASH_SIZE];
        merkle_build_with_proof(tree->pub_keys, TAT_TOTAL_KEYS, WOTS_SIG_SIZE,
                                i, root_tmp, &tree->proofs[i]);
        if (i == 0) {
            memcpy(tree->auth_root, root_tmp, MERKLE_HASH_SIZE);
        }
    }

    /* Clear private key from stack */
    memset(private_key, 0, WOTS_SIG_SIZE);
}

int tat_sign(TemporalAuthTree *tree, const uint8_t *message, size_t msg_len,
             uint8_t signature[WOTS_SIG_SIZE], uint8_t pub_key[WOTS_SIG_SIZE],
             MerkleProof *proof, size_t *key_index_out) {
    if (tree->key_index >= TAT_USABLE_KEYS)
        return -1;

    size_t idx = tree->key_index++;
    *key_index_out = idx;

    /* Derive key and sign */
    uint8_t key_seed[64];
    derive_key_seed(tree->batch_seed, idx, key_seed);
    uint8_t private_key[WOTS_SIG_SIZE];
    wots_keygen(key_seed, private_key, pub_key);
    wots_sign(message, msg_len, private_key, signature);

    /* Use pre-cached proof */
    memcpy(proof, &tree->proofs[idx], sizeof(MerkleProof));

    /* Clear sensitive data */
    memset(private_key, 0, WOTS_SIG_SIZE);
    memset(key_seed, 0, 64);

    return 0;
}

int tat_sign_rotation(TemporalAuthTree *tree, const uint8_t *message, size_t msg_len,
                      uint8_t signature[WOTS_SIG_SIZE], uint8_t pub_key[WOTS_SIG_SIZE],
                      MerkleProof *proof, size_t *key_index_out) {
    if (tree->rotation_index >= TAT_RESERVED)
        return -1;

    size_t idx = TAT_USABLE_KEYS + tree->rotation_index++;
    *key_index_out = idx;

    uint8_t key_seed[64];
    derive_key_seed(tree->batch_seed, idx, key_seed);
    uint8_t private_key[WOTS_SIG_SIZE];
    wots_keygen(key_seed, private_key, pub_key);
    wots_sign(message, msg_len, private_key, signature);

    /* Use pre-cached proof */
    memcpy(proof, &tree->proofs[idx], sizeof(MerkleProof));

    memset(private_key, 0, WOTS_SIG_SIZE);
    memset(key_seed, 0, 64);

    return 0;
}

int tat_verify(const uint8_t *message, size_t msg_len,
               const uint8_t signature[WOTS_SIG_SIZE],
               const uint8_t pub_key[WOTS_SIG_SIZE],
               const MerkleProof *proof,
               const uint8_t auth_root[MERKLE_HASH_SIZE]) {
    /* Verify WOTS+ signature */
    if (!wots_verify(message, msg_len, signature, pub_key))
        return 0;

    /* Verify Merkle proof: hash the pub_key to get leaf hash */
    uint8_t leaf_hash[MERKLE_HASH_SIZE];
    sha3_256(pub_key, WOTS_SIG_SIZE, leaf_hash);

    return merkle_verify_proof(leaf_hash, proof, auth_root);
}

void tat_destroy(TemporalAuthTree *tree) {
    memset(tree->batch_seed, 0, 64);
    if (tree->pub_keys) {
        free(tree->pub_keys);
        tree->pub_keys = NULL;
    }
    if (tree->proofs) {
        free(tree->proofs);
        tree->proofs = NULL;
    }
    tree->key_index = 0;
    tree->rotation_index = 0;
}
