# QRTB: Quantum-Resistant Temporal Blockchain

**Author:** Andrew Dorman ([Hollow Point Labs](https://github.com/ACD421))

## Overview

QRTB is a blockchain designed from scratch to resist quantum computing attacks. It replaces ECDSA with **WOTS+ (Winternitz One-Time Signature Plus)** signatures built on **SHA3-256**, uses **Merkle authentication trees** for key management, and introduces **temporal authentication** -- a mechanism that binds transaction validity to time-evolving keys with automatic rotation and forward secrecy.

No elliptic curves. No RSA. No lattice assumptions. The only hardness assumption is the pre-image resistance of SHA3-256.

## Architecture

### Python Implementation (`src/`)

| Module | Description |
|--------|-------------|
| `crypto.py` | Cryptographic primitives: SHA3-256/512, WOTS+ signatures (67 chains, w=16, n=32), temporal key evolution, Merkle trees, temporal auth trees, secure key destruction |
| `transaction.py` | Transaction types (transfer, stake, unstake, slash), UTXO model with temporal key binding, batch verification, mempool management |
| `wallet.py` | Hierarchical deterministic key derivation, transaction building/signing, balance tracking, key rotation per epoch |
| `block_producer.py` | Block production pipeline: mempool collection, UTXO validation, Merkle tree construction, consensus proposal, 2/3+ stake finalization |
| `consensus.py` | BFT consensus: measurement-based proposal generation, three-phase voting (pre-vote, pre-commit, commit), stake-weighted finalization, physics-bounded timing |
| `validator.py` | Complete validator node: coordinates crypto, measurement, detection, consensus; epoch lifecycle management |
| `network.py` | Multi-validator testnet simulation, message routing, epoch coordination, adversary simulation |
| `storage.py` | Persistent storage: SQLite-backed block storage with indexing, UTXO set state, transaction indexes, chain state management |
| `epoch.py` | Epoch and entropy management: four-source entropy generation, epoch lifecycle, key evolution coordination |
| `measurement.py` | RTT measurement protocol between peers, commit-reveal scheme, physics bounds validation, measurement aggregation |
| `detection.py` | Detection system: triangle inequality validation, RTT ratio analysis, variance detection, path integral consistency, adversary scoring |
| `performance.py` | Performance optimization targeting 16M TPS: batch WOTS+ verification, transaction pipelining, sharded UTXO lookups, parallel Merkle construction |

### Native Implementation (`native/`)

High-performance Rust and C implementations of the core cryptographic primitives:

- **Rust** (`native/src/`): WOTS+ signatures, SHA3, Merkle trees, temporal auth, FFI bindings
- **C** (`native/csrc/`): SHA3, WOTS+, Merkle tree, temporal auth -- portable C99
- **Benchmarks** (`native/benches/`): Criterion-based crypto benchmarks

## Security Properties

- **Quantum resistance**: WOTS+ signatures rely only on hash function pre-image resistance (SHA3-256). No algebraic structure for quantum algorithms to exploit.
- **Address registration**: Addresses must be registered with an auth root before spending, preventing signature forgery from address observation alone.
- **Temporal authentication**: Keys evolve each epoch. A compromised key from epoch N cannot sign transactions in epoch N+1.
- **Forward secrecy**: Key rotation derives new keys from the previous epoch's seed, then securely destroys the old material. Past keys are unrecoverable.
- **No silent rotation**: Key rotation transactions are visible on-chain. Validators and peers can audit rotation history.
- **Reserved rotation keys**: A portion of each Merkle batch is reserved exclusively for rotation transactions, ensuring key evolution cannot be blocked by UTXO exhaustion.
- **Auth root rotation**: The Merkle auth root can be rotated to a fresh key batch, extending wallet lifetime indefinitely.

## Quick Start

```bash
# Clone
git clone https://github.com/ACD421/qrtb.git
cd qrtb

# Run the live demo (creates wallets, sends transactions, runs consensus)
python run_live.py

# Run the testnet simulation
python run_testnet.py

# Run integration tests
python test_integration.py

# Run unit tests
python -m pytest tests/
```

### Building the Native Library (Optional)

```bash
cd native
cargo build --release
```

## License

MIT License. See [LICENSE](LICENSE) for details.
