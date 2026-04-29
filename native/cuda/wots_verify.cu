/**
 * QRTB GPU-Accelerated WOTS+ Batch Verification
 *
 * Each CUDA thread verifies one chain of one signature.
 * For N transactions: N * 67 threads = N * 67 independent hash chains.
 * RTX 4070: 4608 CUDA cores, 36 SMs.
 *
 * Keccak/SHA3-256 implemented inline for maximum throughput.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

// WOTS+ parameters
#define WOTS_N        32
#define WOTS_W        16
#define WOTS_LEN1     64
#define WOTS_LEN2     3
#define WOTS_LEN      67
#define WOTS_SIG_SIZE (WOTS_LEN * WOTS_N)  // 2144 bytes

// ============================================================================
// Keccak / SHA3-256 (GPU implementation)
// ============================================================================

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

__device__ __forceinline__ uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

// Rho offsets and Pi permutation in constant memory for GPU
__device__ __constant__ int d_rho_offsets[25] = {
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
    3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
};
__device__ __constant__ int d_pi_lanes[25] = {
    0, 10, 20, 5, 15, 16, 1, 11, 21, 6,
    7, 17, 2, 12, 22, 23, 8, 18, 3, 13,
    14, 24, 9, 19, 4
};

__device__ void keccak_f1600(uint64_t state[25]) {
    for (int round = 0; round < 24; round++) {
        // Theta
        uint64_t C[5], D[5];
        for (int x = 0; x < 5; x++)
            C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5)
                state[y + x] ^= D[x];
        }

        // Rho + Pi
        uint64_t temp[25];
        for (int i = 0; i < 25; i++)
            temp[d_pi_lanes[i]] = rotl64(state[i], d_rho_offsets[i]);

        // Chi
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                state[y + x] = temp[y + x] ^ ((~temp[y + (x + 1) % 5]) & temp[y + (x + 2) % 5]);

        // Iota
        state[0] ^= keccak_rc[round];
    }
}

__device__ void gpu_sha3_256(const uint8_t *input, int input_len, uint8_t output[32]) {
    uint64_t state[25];
    memset(state, 0, sizeof(state));

    // Absorb (rate = 136 bytes for SHA3-256)
    const int rate = 136;
    int offset = 0;

    while (offset + rate <= input_len) {
        for (int i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++)
                lane |= ((uint64_t)input[offset + i * 8 + j]) << (j * 8);
            state[i] ^= lane;
        }
        keccak_f1600(state);
        offset += rate;
    }

    // Pad and absorb final block
    uint8_t pad[136];
    memset(pad, 0, rate);
    int remaining = input_len - offset;
    if (remaining > 0)
        memcpy(pad, input + offset, remaining);

    pad[remaining] = 0x06;      // SHA3 domain separator
    pad[rate - 1] |= 0x80;     // Final bit

    for (int i = 0; i < rate / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++)
            lane |= ((uint64_t)pad[i * 8 + j]) << (j * 8);
        state[i] ^= lane;
    }
    keccak_f1600(state);

    // Squeeze (32 bytes)
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++)
            output[i * 8 + j] = (uint8_t)(state[i] >> (j * 8));
    }
}

// ============================================================================
// WOTS+ GPU Verification Kernel
// ============================================================================

/**
 * Each thread verifies one chain (one of 67) for one transaction.
 * Thread ID = tx_index * WOTS_LEN + chain_index
 *
 * For each chain:
 *   remaining = (W-1) - chunk[chain_index]
 *   computed = hash_chain(sig_chunk, remaining)
 *   valid = (computed == pub_chunk)
 */
__global__ void wots_verify_kernel(
    const uint8_t *signatures,     // [N * WOTS_SIG_SIZE]
    const uint8_t *public_keys,    // [N * WOTS_SIG_SIZE]
    const uint8_t *msg_hashes,     // [N * 32] -- pre-hashed messages
    uint8_t *chain_results,        // [N * WOTS_LEN] -- 1 if chain valid, 0 if not
    int num_txs
) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    int total_chains = num_txs * WOTS_LEN;
    if (tid >= total_chains) return;

    int tx_idx = tid / WOTS_LEN;
    int chain_idx = tid % WOTS_LEN;

    const uint8_t *msg_hash = &msg_hashes[tx_idx * 32];
    const uint8_t *sig = &signatures[tx_idx * WOTS_SIG_SIZE + chain_idx * WOTS_N];
    const uint8_t *pub_chain = &public_keys[tx_idx * WOTS_SIG_SIZE + chain_idx * WOTS_N];

    // Compute chunks (same as CPU: 4-bit nibbles + checksum)
    uint8_t chunks[WOTS_LEN];
    for (int i = 0; i < 32; i++) {
        chunks[i * 2]     = (msg_hash[i] >> 4) & 0x0F;
        chunks[i * 2 + 1] = msg_hash[i] & 0x0F;
    }
    uint32_t checksum = 0;
    for (int i = 0; i < WOTS_LEN1; i++)
        checksum += (WOTS_W - 1) - chunks[i];
    chunks[64] = (checksum >> 8) & 0x0F;
    chunks[65] = (checksum >> 4) & 0x0F;
    chunks[66] = checksum & 0x0F;

    int remaining = (WOTS_W - 1) - chunks[chain_idx];

    // Hash chain: H^remaining(sig_chunk)
    uint8_t current[32];
    memcpy(current, sig, 32);

    for (int i = 0; i < remaining; i++) {
        uint8_t next[32];
        gpu_sha3_256(current, 32, next);
        memcpy(current, next, 32);
    }

    // Compare with public key chain
    uint8_t valid = 1;
    for (int i = 0; i < 32; i++) {
        if (current[i] != pub_chain[i]) {
            valid = 0;
            break;
        }
    }

    chain_results[tid] = valid;
}

/**
 * Reduce chain results to per-transaction results.
 * tx is valid iff all 67 chains are valid.
 */
__global__ void reduce_chains_kernel(
    const uint8_t *chain_results,  // [N * WOTS_LEN]
    uint8_t *tx_results,           // [N]
    int num_txs
) {
    int tx_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (tx_idx >= num_txs) return;

    uint8_t valid = 1;
    const uint8_t *chains = &chain_results[tx_idx * WOTS_LEN];
    for (int i = 0; i < WOTS_LEN; i++) {
        if (!chains[i]) {
            valid = 0;
            break;
        }
    }
    tx_results[tx_idx] = valid;
}

// ============================================================================
// CPU-side WOTS+ (for generating test data)
// ============================================================================

// CPU Keccak constants
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

static inline uint64_t cpu_rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

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
        static const int rho[25] = {
            0, 1, 62, 28, 27, 36, 44, 6, 55, 20,
            3, 10, 43, 25, 39, 41, 45, 15, 21, 8,
            18, 2, 61, 56, 14
        };
        static const int pi[25] = {
            0, 10, 20, 5, 15, 16, 1, 11, 21, 6,
            7, 17, 2, 12, 22, 23, 8, 18, 3, 13,
            14, 24, 9, 19, 4
        };
        for (int i = 0; i < 25; i++)
            temp[pi[i]] = cpu_rotl64(state[i], rho[i]);
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                state[y + x] = temp[y + x] ^ ((~temp[y + (x + 1) % 5]) & temp[y + (x + 2) % 5]);
        state[0] ^= cpu_keccak_rc[round];
    }
}

void cpu_sha3_256(const uint8_t *input, int input_len, uint8_t output[32]) {
    uint64_t state[25];
    memset(state, 0, sizeof(state));
    const int rate = 136;
    int offset = 0;

    while (offset + rate <= input_len) {
        for (int i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++)
                lane |= ((uint64_t)input[offset + i * 8 + j]) << (j * 8);
            state[i] ^= lane;
        }
        cpu_keccak_f1600(state);
        offset += rate;
    }

    uint8_t pad[136];
    memset(pad, 0, rate);
    int remaining = input_len - offset;
    if (remaining > 0) memcpy(pad, input + offset, remaining);
    pad[remaining] = 0x06;
    pad[rate - 1] |= 0x80;

    for (int i = 0; i < rate / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++)
            lane |= ((uint64_t)pad[i * 8 + j]) << (j * 8);
        state[i] ^= lane;
    }
    cpu_keccak_f1600(state);

    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++)
            output[i * 8 + j] = (uint8_t)(state[i] >> (j * 8));
}

void cpu_sha3_512(const uint8_t *input, int input_len, uint8_t output[64]) {
    uint64_t state[25];
    memset(state, 0, sizeof(state));
    const int rate = 72;
    int offset = 0;

    while (offset + rate <= input_len) {
        for (int i = 0; i < rate / 8; i++) {
            uint64_t lane = 0;
            for (int j = 0; j < 8; j++)
                lane |= ((uint64_t)input[offset + i * 8 + j]) << (j * 8);
            state[i] ^= lane;
        }
        cpu_keccak_f1600(state);
        offset += rate;
    }

    uint8_t pad[72];
    memset(pad, 0, rate);
    int remaining = input_len - offset;
    if (remaining > 0) memcpy(pad, input + offset, remaining);
    pad[remaining] = 0x06;
    pad[rate - 1] |= 0x80;

    for (int i = 0; i < rate / 8; i++) {
        uint64_t lane = 0;
        for (int j = 0; j < 8; j++)
            lane |= ((uint64_t)pad[i * 8 + j]) << (j * 8);
        state[i] ^= lane;
    }
    cpu_keccak_f1600(state);

    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++)
            output[i * 8 + j] = (uint8_t)(state[i] >> (j * 8));
}

void cpu_hash_chain(const uint8_t start[32], int iterations, uint8_t out[32]) {
    memcpy(out, start, 32);
    for (int i = 0; i < iterations; i++) {
        uint8_t next[32];
        cpu_sha3_256(out, 32, next);
        memcpy(out, next, 32);
    }
}

void cpu_wots_keygen(const uint8_t seed[64], uint8_t *sk, uint8_t *pk) {
    for (int i = 0; i < WOTS_LEN; i++) {
        // derive chain seed
        uint8_t buf[82];
        memcpy(buf, seed, 64);
        memcpy(buf + 64, "wots_chain", 10);
        uint64_t val = (uint64_t)i;
        uint64_t idx_be = ((val & 0xFF) << 56) | ((val & 0xFF00) << 40) |
                          ((val & 0xFF0000) << 24) | ((val & 0xFF000000ULL) << 8) |
                          ((val >> 8) & 0xFF000000ULL) | ((val >> 24) & 0xFF0000) |
                          ((val >> 40) & 0xFF00) | ((val >> 56) & 0xFF);
        memcpy(buf + 74, &idx_be, 8);
        uint8_t chain_seed[32];
        cpu_sha3_256(buf, 82, chain_seed);
        memcpy(sk + i * WOTS_N, chain_seed, 32);
        cpu_hash_chain(chain_seed, WOTS_W - 1, pk + i * WOTS_N);
    }
}

void cpu_wots_sign(const uint8_t *msg, int msg_len, const uint8_t *sk, uint8_t *sig) {
    uint8_t msg_hash[32];
    cpu_sha3_256(msg, msg_len, msg_hash);

    uint8_t chunks[WOTS_LEN];
    for (int i = 0; i < 32; i++) {
        chunks[i * 2]     = (msg_hash[i] >> 4) & 0x0F;
        chunks[i * 2 + 1] = msg_hash[i] & 0x0F;
    }
    uint32_t checksum = 0;
    for (int i = 0; i < WOTS_LEN1; i++)
        checksum += (WOTS_W - 1) - chunks[i];
    chunks[64] = (checksum >> 8) & 0x0F;
    chunks[65] = (checksum >> 4) & 0x0F;
    chunks[66] = checksum & 0x0F;

    for (int i = 0; i < WOTS_LEN; i++) {
        uint8_t start[32];
        memcpy(start, sk + i * WOTS_N, 32);
        cpu_hash_chain(start, chunks[i], sig + i * WOTS_N);
    }
}

// ============================================================================
// Benchmark Harness
// ============================================================================

typedef struct {
    float verify_ms;
    float reduce_ms;
    float total_ms;
    int num_valid;
} BenchResult;

BenchResult run_gpu_benchmark(int num_txs,
    uint8_t *h_sigs, uint8_t *h_pks, uint8_t *h_msg_hashes)
{
    BenchResult result;

    // Device memory
    uint8_t *d_sigs, *d_pks, *d_msg_hashes, *d_chain_results, *d_tx_results;
    size_t sig_bytes = (size_t)num_txs * WOTS_SIG_SIZE;
    size_t hash_bytes = (size_t)num_txs * 32;
    size_t chain_bytes = (size_t)num_txs * WOTS_LEN;

    cudaMalloc(&d_sigs, sig_bytes);
    cudaMalloc(&d_pks, sig_bytes);
    cudaMalloc(&d_msg_hashes, hash_bytes);
    cudaMalloc(&d_chain_results, chain_bytes);
    cudaMalloc(&d_tx_results, num_txs);

    // H2D transfer
    cudaMemcpy(d_sigs, h_sigs, sig_bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_pks, h_pks, sig_bytes, cudaMemcpyHostToDevice);
    cudaMemcpy(d_msg_hashes, h_msg_hashes, hash_bytes, cudaMemcpyHostToDevice);

    cudaDeviceSynchronize();

    // Launch verification kernel
    int total_chains = num_txs * WOTS_LEN;
    int block_size = 256;
    int grid_size = (total_chains + block_size - 1) / block_size;

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    cudaEventRecord(start);
    wots_verify_kernel<<<grid_size, block_size>>>(
        d_sigs, d_pks, d_msg_hashes, d_chain_results, num_txs);
    cudaEventRecord(stop);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&result.verify_ms, start, stop);

    // Launch reduce kernel
    int reduce_blocks = (num_txs + 255) / 256;
    cudaEvent_t rstart, rstop;
    cudaEventCreate(&rstart);
    cudaEventCreate(&rstop);

    cudaEventRecord(rstart);
    reduce_chains_kernel<<<reduce_blocks, 256>>>(
        d_chain_results, d_tx_results, num_txs);
    cudaEventRecord(rstop);
    cudaEventSynchronize(rstop);
    cudaEventElapsedTime(&result.reduce_ms, rstart, rstop);

    result.total_ms = result.verify_ms + result.reduce_ms;
    // Ensure no negative from timing jitter
    if (result.total_ms < 0.001f) result.total_ms = 0.001f;

    // Read back results
    uint8_t *h_results = (uint8_t*)malloc(num_txs);
    cudaMemcpy(h_results, d_tx_results, num_txs, cudaMemcpyDeviceToHost);

    result.num_valid = 0;
    for (int i = 0; i < num_txs; i++)
        if (h_results[i]) result.num_valid++;

    free(h_results);
    cudaFree(d_sigs);
    cudaFree(d_pks);
    cudaFree(d_msg_hashes);
    cudaFree(d_chain_results);
    cudaFree(d_tx_results);
    cudaEventDestroy(start);
    cudaEventDestroy(stop);
    cudaEventDestroy(rstart);
    cudaEventDestroy(rstop);

    return result;
}

int main() {
    printf("======================================================================\n");
    printf("  QRTB GPU WOTS+ Batch Verification Benchmark\n");
    printf("  RTX 4070 Laptop GPU -- 4608 CUDA cores, 36 SMs\n");
    printf("======================================================================\n");

    // Get GPU info
    cudaDeviceProp prop;
    cudaGetDeviceProperties(&prop, 0);
    printf("  GPU: %s\n", prop.name);
    printf("  SMs: %d  CUDA cores: ~%d\n", prop.multiProcessorCount,
           prop.multiProcessorCount * 128);
    printf("  VRAM: %.2f GB\n", prop.totalGlobalMem / (1024.0 * 1024.0 * 1024.0));
    printf("  WOTS+ params: w=%d, chains=%d, sig_size=%d bytes\n",
           WOTS_W, WOTS_LEN, WOTS_SIG_SIZE);

    // Per-tx GPU memory: 2*2144 (sig+pk) + 32 (hash) + 67 (chains) + 1 (result) = 4388 bytes
    // 100K txs = ~419 MB -- fits in 8.59 GB VRAM
    // 500K txs = ~2.09 GB -- fits
    // 1M txs = ~4.19 GB -- fits

    int test_sizes[] = {1000, 10000, 50000, 100000, 500000};
    int num_tests = 5;

    // Find max size that fits in VRAM (leave 1 GB headroom)
    size_t max_vram = prop.totalGlobalMem - (size_t)(1024 * 1024 * 1024);
    size_t per_tx = 2 * WOTS_SIG_SIZE + 32 + WOTS_LEN + 1;

    for (int t = 0; t < num_tests; t++) {
        int n = test_sizes[t];
        size_t needed = (size_t)n * per_tx;
        if (needed > max_vram) {
            printf("\n  Skipping %d txs (needs %.1f GB, have %.1f GB free)\n",
                   n, needed / (1024.0*1024.0*1024.0), max_vram / (1024.0*1024.0*1024.0));
            continue;
        }

        printf("\n=== %d Transactions ===\n", n);

        // Generate test data on CPU
        printf("  Generating test data...\n");
        uint8_t *sigs = (uint8_t*)malloc((size_t)n * WOTS_SIG_SIZE);
        uint8_t *pks  = (uint8_t*)malloc((size_t)n * WOTS_SIG_SIZE);
        uint8_t *msg_hashes = (uint8_t*)malloc((size_t)n * 32);

        clock_t gen_start = clock();
        for (int i = 0; i < n; i++) {
            // Deterministic seed
            uint8_t seed_in[16];
            memset(seed_in, 0, 16);
            uint64_t idx = (uint64_t)i;
            memcpy(seed_in, &idx, 8);
            memcpy(seed_in + 8, "qrtb_gpu", 8);
            uint8_t seed[64];
            cpu_sha3_512(seed_in, 16, seed);

            // Keygen into separate sk buffer, pk into pks
            uint8_t *sk = (uint8_t*)malloc(WOTS_SIG_SIZE);
            cpu_wots_keygen(seed, sk, pks + (size_t)i * WOTS_SIG_SIZE);

            // Message hash
            uint8_t msg[8];
            memcpy(msg, &idx, 8);
            uint8_t msg_hash[32];
            cpu_sha3_256(msg, 8, msg_hash);
            memcpy(msg_hashes + (size_t)i * 32, msg_hash, 32);

            // Sign with sk, output to sigs
            cpu_wots_sign(msg, 8, sk, sigs + (size_t)i * WOTS_SIG_SIZE);
            free(sk);

            if (i > 0 && i % 10000 == 0)
                printf("    Generated %d/%d\n", i, n);
        }
        double gen_time = (double)(clock() - gen_start) / CLOCKS_PER_SEC;
        printf("  Generated in %.2fs (%.0f tx/s)\n", gen_time, n / gen_time);

        // Warmup
        if (n <= 10000) {
            BenchResult warmup = run_gpu_benchmark(n, sigs, pks, msg_hashes);
            (void)warmup;
        }

        // Benchmark (best of 3)
        BenchResult best;
        best.total_ms = 1e9f;
        for (int run = 0; run < 3; run++) {
            BenchResult r = run_gpu_benchmark(n, sigs, pks, msg_hashes);
            if (r.total_ms < best.total_ms) best = r;
        }

        double verify_tps = n / ((double)best.verify_ms / 1000.0);
        double total_tps = n / ((double)best.total_ms / 1000.0);

        printf("  GPU verify:  %.3f ms  %12.0f verify/s\n", best.verify_ms, verify_tps);
        printf("  GPU reduce:  %.3f ms\n", best.reduce_ms);
        printf("  GPU total:   %.3f ms  %12.0f TPS (single zone)\n", best.total_ms, total_tps);
        printf("  6-zone:                %12.0f TPS\n", total_tps * 6.0);
        printf("  Valid: %d/%d\n", best.num_valid, n);

        free(sigs);
        free(pks);
        free(msg_hashes);
    }

    printf("\n======================================================================\n");
    printf("  DONE\n");
    printf("======================================================================\n");
    return 0;
}
