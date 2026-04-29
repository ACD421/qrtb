# QRTB: Quantum-Resistant Temporal Blockchain

**Consensus of Measurement | 16M TPS | SHA3-256 Only | Quantum Irrelevant**

**Author:** Andrew Dorman ([ACD421](https://github.com/ACD421))

---

## Overview

QRTB is a blockchain built from scratch on one cryptographic primitive: **SHA3-256**. No elliptic curves. No RSA. No lattices. Quantum computers are structurally irrelevant -- Shor's algorithm has nothing to attack, and Grover's 2^128 brute force requires 790 trillion universe lifetimes.

The protocol introduces **Consensus of Measurement**, a new consensus family where validators collectively measure physical network round-trip times and reach consensus through that collective act. The measurement process IS the consensus process. The only strategy indistinguishable from honest behavior is honest behavior.

## Key Properties

- **16M TPS** on consumer hardware (6 zones x 15 shards x 177,243 TPS/shard measured on RTX 4070)
- **SHA3-256 only**: One primitive. FIPS 202 standardized. No algebraic structure to break.
- **Quantum irrelevant**: No algebraic structure for Shor. Grover gives 2^128 -- physically impossible.
- **1022+2 key design**: Unlimited wallet lifetime with forward secrecy. 1022 transaction keys + 2 reserved rotation keys per batch. No key exhaustion.
- **Anti-centralization**: RTT measurement detects co-located validators. Datacenter concentration is slashable.
- **Epoch-atomic finality**: Nothing committed until end-of-epoch BFT consensus. Eliminates quantum observation windows.
- **DoD forward secrecy**: Meets CNSA 2.0, NIST SP 800-208, FIPS 202.

## Architecture

### Python Implementation (`src/`)

| Module | Lines | Description |
|--------|-------|-------------|
| `crypto.py` | 514 | SHA3-256/512, WOTS+ (67 chains, w=16, n=32), Merkle trees, TemporalAuthTree (1022+2), secure key wipe via ctypes |
| `transaction.py` | 895 | 8 transaction types (TRANSFER, STAKE, UNSTAKE, SLASH, COINBASE, DATA, REGISTER, ROTATE_AUTH), UTXO model, AuthRegistry, TransactionValidator |
| `wallet.py` | 895 | KeyManager with batch-based temporal auth, registration/rotation lifecycle, transaction building |
| `consensus.py` | 530 | BFT three-phase voting, deterministic proposer selection, equivocation detection, registered-stake enforcement |
| `measurement.py` | 401 | RTT measurement protocol, commit-reveal scheme, 6 geographic zones with 30 cities |
| `detection.py` | 353 | Four-signal adversary detection: ratio analysis, triangle inequality, variance, path consistency |
| `epoch.py` | 428 | 15-minute epoch lifecycle, four-source entropy well (network, blockchain, external beacons, historical) |
| `block_producer.py` | 552 | Block templates, coinbase, parallel zone production, block finalization |
| `validator.py` | 405 | Complete validator node coordinating all subsystems |
| `network.py` | 493 | Multi-validator testnet simulation with zone-based message routing |
| `storage.py` | 688 | SQLite-backed persistence: blocks, transactions, state, auth registry |
| `performance.py` | 777 | Batch WOTS+ verification, sharded UTXO (256 shards), parallel Merkle, transaction pipeline |

### Native Implementation (`native/`)

- **Rust** (`native/src/`): WOTS+, SHA3, Merkle trees, TemporalAuthTree with `zeroize`, end-to-end TPS benchmark with rayon
- **C** (`native/csrc/`): SHA3 (Keccak-f[1600]), WOTS+, Merkle tree, TemporalAuthTree -- portable C99
- **CUDA** (`native/cuda/`): GPU-parallel WOTS+ batch verification, custom Keccak kernel
- **Cross-validation**: Rust, C, and Python produce bit-identical output for all operations (verified via FFI test harness)

## Benchmarks

All measured on a single laptop (16-core CPU, RTX 4070 GPU, 8 GB VRAM).

### Throughput

| Platform | Verify/s | Per-Shard TPS | 90-Shard TPS |
|---|---|---|---|
| Python (1 core) | 2,721 | 2,715 | 244,350 |
| Python (8 cores) | 13,673 | 13,541 | 1,218,690 |
| Rust (16 cores, rayon) | 53,472 | 51,160 | 4,604,400 |
| **CUDA RTX 4070** | **177,260** | **177,243** | **15,951,870** |

### Native Cryptographic Primitives (Rust, Criterion-verified)

| Operation | Time | Throughput |
|---|---|---|
| SHA3-256 (32B) | 273 ns | 3.7M ops/s |
| WOTS+ Keygen | 285 us | 3,500/s |
| WOTS+ Sign | 147 us | 6,800/s |
| WOTS+ Verify | 119 us | 8,400/s |
| Merkle Build (1024 leaves) | 527 us | 1,900/s |
| Merkle Proof Verify | 2.6 us | 385K/s |

### Network Simulation

| Validators | Adversary % | Finalization | Detection | False Positive |
|---|---|---|---|---|
| 15 (3 zones) | 20% | 100% | 100% | 0.00% |
| 90 (6 zones) | 10% | 100% | 100% | 0.25% |
| 300 (6 zones) | 25% | 100% | 99.4% | 0.19% |
| 300 (12 zones) | 33% | 100% | 96.9% | 0.20% |

## Security Properties

- **Quantum irrelevant**: Forging one WOTS+ signature via Grover requires 2^128 operations = 790 trillion universe lifetimes on hardware that requires 10--400 million physical qubits (currently ~1,000 exist)
- **Forward secrecy**: One-way batch seed chain (SHA3-512). Past keys irrecoverable after rotation. Secure destruction via ctypes.memset (Python) / zeroize (Rust) / memset (C)
- **Epoch-atomic finality**: All state tentative until BFT consensus at epoch end
- **Self-correcting punishment**: Detection -> slashing -> stake erosion -> honest convergence
- **Geometric hardness**: Triangle inequality creates O(N^2) constraints from O(N) measurements. Measurement forgery is geometrically infeasible.

## Quick Start

```bash
# Clone
git clone https://github.com/ACD421/qrtb.git
cd qrtb

# Run the live demo (registration -> transfer -> rotation)
python run_live.py

# Run the testnet simulation (6 zones, 90 validators, 10% adversary)
python run_testnet.py --full

# Run integration tests
python test_integration.py

# Run security unit tests
python tests/test_basic.py

# Python TPS benchmark (multiprocessing)
python bench_tps.py
```

### Building Native (Rust + C)

```bash
cd native
cargo build --release
cargo run --release                    # Cross-validation + primitive benchmarks
cargo run --release --bin bench_tps    # End-to-end TPS with rayon parallel verification
cargo bench                            # Criterion benchmarks
```

### GPU Benchmark (CUDA)

```bash
cd native/cuda
nvcc -O3 -arch=sm_89 -o wots_verify.exe wots_verify.cu
./wots_verify.exe
```

## Whitepaper

See [WHITEPAPER.md](WHITEPAPER.md) for the full technical paper including Consensus of Measurement, the 1022+2 design, security analysis, and complete benchmark data.

## License

Proprietary License. See [LICENSE](LICENSE).
