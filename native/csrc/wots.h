#ifndef QRTB_WOTS_H
#define QRTB_WOTS_H

#include <stdint.h>
#include <stddef.h>

/* WOTS+ parameters: n=32, w=16, len1=64, len2=3, len_total=67 */
#define WOTS_N          32
#define WOTS_W          16
#define WOTS_LEN1       64
#define WOTS_LEN2       3
#define WOTS_LEN_TOTAL  67
#define WOTS_SIG_SIZE   (WOTS_LEN_TOTAL * WOTS_N)  /* 2144 bytes */

/* Generate WOTS+ keypair from seed */
void wots_keygen(const uint8_t seed[64], uint8_t private_key[WOTS_SIG_SIZE],
                 uint8_t public_key[WOTS_SIG_SIZE]);

/* Sign message (will be hashed internally) */
void wots_sign(const uint8_t *message, size_t msg_len,
               const uint8_t private_key[WOTS_SIG_SIZE],
               uint8_t signature[WOTS_SIG_SIZE]);

/* Verify signature. Returns 1 if valid, 0 if invalid */
int wots_verify(const uint8_t *message, size_t msg_len,
                const uint8_t signature[WOTS_SIG_SIZE],
                const uint8_t public_key[WOTS_SIG_SIZE]);

#endif /* QRTB_WOTS_H */
