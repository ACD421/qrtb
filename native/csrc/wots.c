/*
 * WOTS+ (Winternitz One-Time Signature Plus) for QRTB
 * Parameters: n=32, w=16, len1=64, len2=3, len_total=67
 */

#include "wots.h"
#include "sha3.h"
#include <string.h>

/* Hash chain: compute H^iterations(start) */
static void hash_chain(const uint8_t start[WOTS_N], int iterations,
                        uint8_t out[WOTS_N]) {
    memcpy(out, start, WOTS_N);
    for (int i = 0; i < iterations; i++) {
        uint8_t tmp[WOTS_N];
        sha3_256(out, WOTS_N, tmp);
        memcpy(out, tmp, WOTS_N);
    }
}

/* Derive chain seed: SHA3-256(seed || "wots_chain" || index) */
static void derive_chain_seed(const uint8_t seed[64], int index,
                               uint8_t out[WOTS_N]) {
    uint8_t buf[64 + 10 + 8]; /* seed + "wots_chain" + index(8 bytes big-endian) */
    memcpy(buf, seed, 64);
    memcpy(buf + 64, "wots_chain", 10);
    /* Big-endian uint64 index */
    buf[74] = 0; buf[75] = 0; buf[76] = 0; buf[77] = 0;
    buf[78] = (uint8_t)((index >> 24) & 0xFF);
    buf[79] = (uint8_t)((index >> 16) & 0xFF);
    buf[80] = (uint8_t)((index >> 8) & 0xFF);
    buf[81] = (uint8_t)(index & 0xFF);
    sha3_256(buf, 82, out);
}

void wots_keygen(const uint8_t seed[64], uint8_t private_key[WOTS_SIG_SIZE],
                 uint8_t public_key[WOTS_SIG_SIZE]) {
    for (int i = 0; i < WOTS_LEN_TOTAL; i++) {
        /* Derive private chain */
        derive_chain_seed(seed, i, private_key + i * WOTS_N);
        /* Public key: hash chain w-1 times */
        hash_chain(private_key + i * WOTS_N, WOTS_W - 1,
                   public_key + i * WOTS_N);
    }
}

/* Compute message chunks + checksum */
static void compute_chunks(const uint8_t *message, size_t msg_len,
                            uint8_t chunks[WOTS_LEN_TOTAL]) {
    uint8_t msg_hash[32];
    sha3_256(message, msg_len, msg_hash);

    /* Split into 4-bit chunks */
    for (int i = 0; i < 32; i++) {
        chunks[i * 2]     = (msg_hash[i] >> 4) & 0x0F;
        chunks[i * 2 + 1] = msg_hash[i] & 0x0F;
    }

    /* Compute checksum */
    int checksum = 0;
    for (int i = 0; i < WOTS_LEN1; i++)
        checksum += WOTS_W - 1 - chunks[i];

    /* Encode checksum as 3 chunks */
    chunks[64] = (checksum >> 8) & 0x0F;
    chunks[65] = (checksum >> 4) & 0x0F;
    chunks[66] = checksum & 0x0F;
}

void wots_sign(const uint8_t *message, size_t msg_len,
               const uint8_t private_key[WOTS_SIG_SIZE],
               uint8_t signature[WOTS_SIG_SIZE]) {
    uint8_t chunks[WOTS_LEN_TOTAL];
    compute_chunks(message, msg_len, chunks);

    for (int i = 0; i < WOTS_LEN_TOTAL; i++) {
        hash_chain(private_key + i * WOTS_N, chunks[i],
                   signature + i * WOTS_N);
    }
}

int wots_verify(const uint8_t *message, size_t msg_len,
                const uint8_t signature[WOTS_SIG_SIZE],
                const uint8_t public_key[WOTS_SIG_SIZE]) {
    uint8_t chunks[WOTS_LEN_TOTAL];
    compute_chunks(message, msg_len, chunks);

    uint8_t computed[WOTS_N];
    for (int i = 0; i < WOTS_LEN_TOTAL; i++) {
        int remaining = WOTS_W - 1 - chunks[i];
        hash_chain(signature + i * WOTS_N, remaining, computed);
        if (memcmp(computed, public_key + i * WOTS_N, WOTS_N) != 0)
            return 0;
    }
    return 1;
}
