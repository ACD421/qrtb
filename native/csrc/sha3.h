#ifndef QRTB_SHA3_H
#define QRTB_SHA3_H

#include <stdint.h>
#include <stddef.h>

/* SHA3-256: 32-byte output */
void sha3_256(const uint8_t *input, size_t input_len, uint8_t output[32]);

/* SHA3-512: 64-byte output */
void sha3_512(const uint8_t *input, size_t input_len, uint8_t output[64]);

#endif /* QRTB_SHA3_H */
