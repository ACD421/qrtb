// Quick cross-validation: CPU vs GPU SHA3-256 and WOTS+ verify
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// ============================================================================
// Paste the same Keccak/SHA3 and WOTS CPU functions from wots_verify.cu
// (just the CPU versions + GPU kernel for SHA3 comparison)
// ============================================================================

static const uint64_t cpu_keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
static inline uint64_t cpu_rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

void cpu_keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ cpu_rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5)
                state[y + x] ^= D[x];
        }
        uint64_t temp[25];
        temp[0] = state[0];
        static const int rho[25] = {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
        static const int pi[25] = {0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4};
        for (int i = 0; i < 25; i++)
            temp[pi[i]] = cpu_rotl64(state[i], rho[i]);
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                state[y + x] = temp[y + x] ^ ((~temp[y + (x + 1) % 5]) & temp[y + (x + 2) % 5]);
        state[0] ^= cpu_keccak_rc[round];
    }
}

void cpu_sha3_256(const uint8_t *input, int input_len, uint8_t output[32]) {
    uint64_t state[25]; memset(state, 0, sizeof(state));
    const int rate = 136;
    int offset = 0;
    while (offset + rate <= input_len) {
        for (int i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) lane |= ((uint64_t)input[offset + i*8+j]) << (j*8);
            state[i] ^= lane;
        }
        cpu_keccak_f1600(state);
        offset += rate;
    }
    uint8_t pad[136]; memset(pad, 0, rate);
    int remaining = input_len - offset;
    if (remaining > 0) memcpy(pad, input + offset, remaining);
    pad[remaining] = 0x06;
    pad[rate - 1] |= 0x80;
    for (int i = 0; i < rate / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++) lane |= ((uint64_t)pad[i*8+j]) << (j*8);
        state[i] ^= lane;
    }
    cpu_keccak_f1600(state);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            output[i*8+j] = (uint8_t)(state[i] >> (j*8));
}

// GPU SHA3
__device__ __constant__ uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};
__device__ __forceinline__ uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

__device__ __constant__ int d_rho[25] = {0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14};
__device__ __constant__ int d_pi[25] = {0,10,20,5,15,16,1,11,21,6,7,17,2,12,22,23,8,18,3,13,14,24,9,19,4};

__device__ void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x+4)%5] ^ rotl64(C[(x+1)%5], 1);
            for (int y = 0; y < 25; y += 5) state[y+x] ^= D[x];
        }
        uint64_t temp[25];
        for (int i = 0; i < 25; i++)
            temp[d_pi[i]] = rotl64(state[i], d_rho[i]);
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                state[y+x] = temp[y+x] ^ ((~temp[y+(x+1)%5]) & temp[y+(x+2)%5]);
        state[0] ^= keccak_rc[round];
    }
}

__device__ void gpu_sha3_256(const uint8_t *input, int input_len, uint8_t output[32]) {
    uint64_t state[25]; memset(state, 0, sizeof(state));
    const int rate = 136;
    int offset = 0;
    while (offset + rate <= input_len) {
        for (int i = 0; i < rate/8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++) lane |= ((uint64_t)input[offset+i*8+j]) << (j*8);
            state[i] ^= lane;
        }
        keccak_f1600(state);
        offset += rate;
    }
    uint8_t pad[136]; memset(pad, 0, rate);
    int remaining = input_len - offset;
    if (remaining > 0) memcpy(pad, input + offset, remaining);
    pad[remaining] = 0x06;
    pad[rate-1] |= 0x80;
    for (int i = 0; i < rate/8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++) lane |= ((uint64_t)pad[i*8+j]) << (j*8);
        state[i] ^= lane;
    }
    keccak_f1600(state);
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            output[i*8+j] = (uint8_t)(state[i] >> (j*8));
}

// Kernel: hash one input, store result
__global__ void hash_test_kernel(const uint8_t *input, int input_len, uint8_t *output) {
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        gpu_sha3_256(input, input_len, output);
    }
}

// Test: single WOTS verify on GPU
#define WOTS_N 32
#define WOTS_W 16
#define WOTS_LEN1 64
#define WOTS_LEN2 3
#define WOTS_LEN 67
#define WOTS_SIG_SIZE (WOTS_LEN * WOTS_N)

__global__ void verify_one_chain(
    const uint8_t *sig_chunk,   // 32 bytes
    const uint8_t *pk_chunk,    // 32 bytes
    int remaining,              // iterations needed
    uint8_t *result,            // 1 byte: 1 if match
    uint8_t *computed_out       // 32 bytes: what we computed
) {
    if (threadIdx.x != 0 || blockIdx.x != 0) return;

    uint8_t current[32];
    memcpy(current, sig_chunk, 32);

    for (int i = 0; i < remaining; i++) {
        uint8_t next[32];
        gpu_sha3_256(current, 32, next);
        memcpy(current, next, 32);
    }

    memcpy(computed_out, current, 32);

    *result = 1;
    for (int i = 0; i < 32; i++) {
        if (current[i] != pk_chunk[i]) {
            *result = 0;
            break;
        }
    }
}

int main() {
    printf("=== CPU vs GPU SHA3-256 Cross-Validation ===\n\n");

    // Test 1: SHA3-256 of known input
    {
        uint8_t input[] = {0, 0, 0, 0, 0, 0, 0, 0};  // 8 zero bytes
        uint8_t cpu_out[32], gpu_out[32];
        cpu_sha3_256(input, 8, cpu_out);

        uint8_t *d_in, *d_out;
        cudaMalloc(&d_in, 8);
        cudaMalloc(&d_out, 32);
        cudaMemcpy(d_in, input, 8, cudaMemcpyHostToDevice);
        hash_test_kernel<<<1, 1>>>(d_in, 8, d_out);
        cudaMemcpy(gpu_out, d_out, 32, cudaMemcpyDeviceToHost);

        printf("Input: 8 zero bytes\n");
        printf("CPU: "); for (int i = 0; i < 32; i++) printf("%02x", cpu_out[i]); printf("\n");
        printf("GPU: "); for (int i = 0; i < 32; i++) printf("%02x", gpu_out[i]); printf("\n");
        printf("Match: %s\n\n", memcmp(cpu_out, gpu_out, 32) == 0 ? "YES" : "NO");

        cudaFree(d_in);
        cudaFree(d_out);
    }

    // Test 2: SHA3-256 of 32-byte input (hash chain step)
    {
        uint8_t input[32];
        for (int i = 0; i < 32; i++) input[i] = (uint8_t)i;
        uint8_t cpu_out[32], gpu_out[32];
        cpu_sha3_256(input, 32, cpu_out);

        uint8_t *d_in, *d_out;
        cudaMalloc(&d_in, 32);
        cudaMalloc(&d_out, 32);
        cudaMemcpy(d_in, input, 32, cudaMemcpyHostToDevice);
        hash_test_kernel<<<1, 1>>>(d_in, 32, d_out);
        cudaMemcpy(gpu_out, d_out, 32, cudaMemcpyDeviceToHost);

        printf("Input: 0x00..0x1f (32 bytes)\n");
        printf("CPU: "); for (int i = 0; i < 32; i++) printf("%02x", cpu_out[i]); printf("\n");
        printf("GPU: "); for (int i = 0; i < 32; i++) printf("%02x", gpu_out[i]); printf("\n");
        printf("Match: %s\n\n", memcmp(cpu_out, gpu_out, 32) == 0 ? "YES" : "NO");

        // Test 2b: chain of 5 hashes
        uint8_t cpu_chain[32], gpu_chain[32];
        memcpy(cpu_chain, input, 32);
        for (int i = 0; i < 5; i++) {
            uint8_t tmp[32];
            cpu_sha3_256(cpu_chain, 32, tmp);
            memcpy(cpu_chain, tmp, 32);
        }

        // GPU: do 5-step chain
        cudaMemcpy(d_in, input, 32, cudaMemcpyHostToDevice);
        // Just run hash 5 times sequentially on GPU using a single thread kernel
        for (int i = 0; i < 5; i++) {
            hash_test_kernel<<<1, 1>>>(d_in, 32, d_out);
            cudaMemcpy(d_in, d_out, 32, cudaMemcpyDeviceToDevice);
        }
        cudaMemcpy(gpu_chain, d_in, 32, cudaMemcpyDeviceToHost);

        printf("5-step hash chain:\n");
        printf("CPU: "); for (int i = 0; i < 32; i++) printf("%02x", cpu_chain[i]); printf("\n");
        printf("GPU: "); for (int i = 0; i < 32; i++) printf("%02x", gpu_chain[i]); printf("\n");
        printf("Match: %s\n\n", memcmp(cpu_chain, gpu_chain, 32) == 0 ? "YES" : "NO");

        cudaFree(d_in);
        cudaFree(d_out);
    }

    // Test 3: known SHA3-256("") = a7ffc6f8...
    {
        uint8_t cpu_out[32];
        cpu_sha3_256((const uint8_t*)"", 0, cpu_out);
        printf("SHA3-256(''): ");
        for (int i = 0; i < 32; i++) printf("%02x", cpu_out[i]);
        printf("\n");
        printf("Expected:     a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a\n\n");
    }

    printf("=== Done ===\n");
    return 0;
}
