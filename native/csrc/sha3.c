/*
 * SHA3 (Keccak) implementation for QRTB
 * Based on the Keccak-f[1600] permutation
 */

#include "sha3.h"
#include <string.h>

/* Keccak round constants */
static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808AULL, 0x8000000080008000ULL,
    0x000000000000808BULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008AULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000AULL,
    0x000000008000808BULL, 0x800000000000008BULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800AULL, 0x800000008000000AULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

/* Rotation offsets: indexed as [x][y] */
static const int ROTATIONS[5][5] = {
    { 0, 36,  3, 41, 18},
    { 1, 44, 10, 45,  2},
    {62,  6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39,  8, 14}
};

static inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

/* Keccak-f[1600] permutation */
static void keccak_f1600(uint64_t state[25]) {
    uint64_t C[5], D[5], B[5][5];

    for (int round = 0; round < 24; round++) {
        /* Theta */
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 5; y++)
                state[x + 5 * y] ^= D[x];
        }

        /* Rho and Pi */
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                B[y][(2 * x + 3 * y) % 5] = rotl64(state[x + 5 * y], ROTATIONS[x][y]);

        /* Chi */
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                state[x + 5 * y] = B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]);

        /* Iota */
        state[0] ^= RC[round];
    }
}

/* Keccak sponge absorb + squeeze */
static void keccak(const uint8_t *input, size_t input_len,
                   uint8_t *output, size_t output_len,
                   size_t rate, uint8_t domain_sep) {
    uint64_t state[25];
    memset(state, 0, sizeof(state));

    size_t rate_bytes = rate / 8;

    /* Absorb */
    size_t offset = 0;
    while (offset + rate_bytes <= input_len) {
        for (size_t i = 0; i < rate_bytes / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++)
                lane |= (uint64_t)input[offset + i * 8 + j] << (8 * j);
            state[i] ^= lane;
        }
        keccak_f1600(state);
        offset += rate_bytes;
    }

    /* Absorb remaining + padding */
    uint8_t pad_block[200];
    memset(pad_block, 0, sizeof(pad_block));
    size_t remaining = input_len - offset;
    if (remaining > 0)
        memcpy(pad_block, input + offset, remaining);

    pad_block[remaining] = domain_sep;    /* SHA3 domain separation: 0x06 */
    pad_block[rate_bytes - 1] |= 0x80;   /* Final bit */

    for (size_t i = 0; i < rate_bytes / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++)
            lane |= (uint64_t)pad_block[i * 8 + j] << (8 * j);
        state[i] ^= lane;
    }
    keccak_f1600(state);

    /* Squeeze */
    size_t out_offset = 0;
    while (out_offset < output_len) {
        size_t block_size = output_len - out_offset;
        if (block_size > rate_bytes)
            block_size = rate_bytes;

        for (size_t i = 0; i < block_size; i++)
            output[out_offset + i] = (uint8_t)(state[i / 8] >> (8 * (i % 8)));

        out_offset += block_size;
        if (out_offset < output_len)
            keccak_f1600(state);
    }
}

void sha3_256(const uint8_t *input, size_t input_len, uint8_t output[32]) {
    /* SHA3-256: rate = 1088, capacity = 512 */
    keccak(input, input_len, output, 32, 1088, 0x06);
}

void sha3_512(const uint8_t *input, size_t input_len, uint8_t output[64]) {
    /* SHA3-512: rate = 576, capacity = 1024 */
    keccak(input, input_len, output, 64, 576, 0x06);
}
