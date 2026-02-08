#ifndef QRTB_TEMPORAL_AUTH_H
#define QRTB_TEMPORAL_AUTH_H

#include <stdint.h>
#include <stddef.h>
#include "merkle.h"
#include "wots.h"

#define TAT_TOTAL_KEYS    1024
#define TAT_RESERVED      2
#define TAT_USABLE_KEYS   1022

typedef struct {
    uint8_t batch_seed[64];
    uint8_t auth_root[MERKLE_HASH_SIZE];
    uint8_t *pub_keys;        /* TAT_TOTAL_KEYS * WOTS_SIG_SIZE bytes */
    MerkleProof *proofs;      /* TAT_TOTAL_KEYS pre-computed proofs */
    size_t key_index;
    size_t rotation_index;
} TemporalAuthTree;

/* Derive initial batch seed from master seed */
void tat_derive_initial_batch_seed(const uint8_t *master_seed, size_t seed_len,
                                   uint8_t out[64]);

/* Derive next batch seed (forward secrecy chain) */
void tat_derive_next_batch_seed(const uint8_t current[64], uint8_t out[64]);

/* Initialize a TemporalAuthTree. Caller must call tat_destroy when done. */
void tat_init(TemporalAuthTree *tree, const uint8_t batch_seed[64]);

/* Sign with next usable key (0..1021). Returns 0 on success, -1 if exhausted. */
int tat_sign(TemporalAuthTree *tree, const uint8_t *message, size_t msg_len,
             uint8_t signature[WOTS_SIG_SIZE], uint8_t pub_key[WOTS_SIG_SIZE],
             MerkleProof *proof, size_t *key_index_out);

/* Sign with reserved rotation key (1022..1023). Returns 0 on success, -1 if exhausted. */
int tat_sign_rotation(TemporalAuthTree *tree, const uint8_t *message, size_t msg_len,
                      uint8_t signature[WOTS_SIG_SIZE], uint8_t pub_key[WOTS_SIG_SIZE],
                      MerkleProof *proof, size_t *key_index_out);

/* Verify a temporal auth signature against a root */
int tat_verify(const uint8_t *message, size_t msg_len,
               const uint8_t signature[WOTS_SIG_SIZE],
               const uint8_t pub_key[WOTS_SIG_SIZE],
               const MerkleProof *proof,
               const uint8_t auth_root[MERKLE_HASH_SIZE]);

/* Destroy tree, zeroing batch_seed */
void tat_destroy(TemporalAuthTree *tree);

#endif /* QRTB_TEMPORAL_AUTH_H */
