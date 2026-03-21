<div align="center">

# QRTB

### Quantum-Resistant Temporal Blockchain

**Post-quantum cryptography | WOTS+ on SHA3-256 | Temporal authentication | Forward secrecy**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-native-orange.svg)](https://rust-lang.org)

</div>

## Overview

QRTB is a production-grade blockchain implementation designed to resist quantum computing attacks. It replaces ECDSA (vulnerable to Shor's algorithm) with **WOTS+ (Winternitz One-Time Signature)** built on SHA3-256, combined with Merkle tree state management and temporal authentication for automatic key rotation.

## Why Post-Quantum?

Current blockchain cryptography (ECDSA on secp256k1) will be broken by sufficiently powerful quantum computers running Shor's algorithm. QRTB addresses this by:

- **WOTS+ signatures**: Hash-based, no algebraic structure to attack
- **SHA3-256 foundation**: Quantum-resistant hash function (Grover's gives only sqrt speedup)
- **Automatic key rotation**: Temporal authentication ensures forward secrecy
- **Merkle tree state**: Efficient verification without exposing signing keys

## Architecture

```
+------------------+     +------------------+     +------------------+
|  Transaction     |     |  Block           |     |  Chain           |
|  Layer           |---->|  Assembly        |---->|  Consensus       |
|                  |     |                  |     |                  |
|  WOTS+ signing   |     |  Merkle roots    |     |  BFT protocol    |
|  Temporal auth   |     |  State proofs    |     |  Fork resolution |
+------------------+     +------------------+     +------------------+
        |                         |                        |
        v                         v                        v
+------------------+     +------------------+     +------------------+
|  Crypto          |     |  Storage         |     |  Network         |
|                  |     |                  |     |                  |
|  SHA3-256        |     |  Block store     |     |  P2P gossip      |
|  WOTS+ keygen    |     |  UTXO index      |     |  Peer discovery  |
|  Key rotation    |     |  Merkle trees    |     |  Sync protocol   |
+------------------+     +------------------+     +------------------+
```

## Components

### Python Implementation

| Module | Description |
|--------|-------------|
| `src/crypto.py` | WOTS+ signature scheme on SHA3-256 |
| `src/temporal_auth.py` | Time-based key rotation with forward secrecy |
| `src/merkle.py` | Merkle tree construction and proof generation |
| `src/block.py` | Block structure with quantum-resistant signatures |
| `src/chain.py` | Chain management and fork resolution |
| `src/consensus.py` | BFT consensus protocol |
| `src/transaction.py` | Transaction creation and validation |
| `src/network.py` | P2P networking layer |
| `src/storage.py` | Persistent block and state storage |
| `src/performance.py` | Benchmarking and optimization (16M TPS target) |

### Native Implementations

- **Rust**: High-performance crypto primitives
- **C**: SHA3-256 and WOTS+ for embedded targets

## Key Properties

| Property | Guarantee |
|----------|-----------|
| Quantum resistance | WOTS+ -- no algebraic structure to attack |
| Forward secrecy | Temporal key rotation, old keys cannot sign future |
| Signature size | ~2.5 KB per WOTS+ signature |
| Verification speed | O(1) per signature, O(log n) Merkle proof |
| TPS target | 16M (with native crypto) |

## Quick Start

```bash
# Run testnet
python run_testnet.py

# Run live node
python run_live.py

# Integration tests
python test_integration.py
```

## Security Model

**Threat model**: Adversary with access to a cryptographically relevant quantum computer (CRQC).

- **ECDSA**: Broken by Shor's algorithm in polynomial time
- **RSA**: Broken by Shor's algorithm in polynomial time
- **WOTS+ on SHA3-256**: Requires Grover's algorithm, which only provides sqrt speedup. Effective security remains at 128-bit equivalent.

Temporal authentication adds defense in depth: even if a signing key is compromised, it cannot be used outside its validity window.

## Related Work

- [secp256k1-geometric-analysis](https://github.com/ACD421/secp256k1-geometric-analysis) -- Research on the curve QRTB is designed to replace
- [SGM-Substrate](https://github.com/ACD421/sgm-substrate) -- Same author, different domain (AI architecture)

## Author

**Andrew C. Dorman** -- [Hollow Point Labs](https://github.com/ACD421)

## License

MIT
