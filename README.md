<div align="center">

# QRTB

### Quantum-Resistant Temporal Blockchain

**WOTS+ on SHA3-256 | Temporal key rotation | BFT consensus | Forward secrecy**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-Native%20Crypto-orange.svg)](https://rust-lang.org)

</div>

## Overview

A blockchain built for the post-quantum era. Uses **WOTS+ (Winternitz One-Time Signatures)** on **SHA3-256** instead of ECDSA, with temporal key evolution that provides forward secrecy by design. Keys rotate automatically -- compromising a future key reveals nothing about past signatures.

## Architecture

### Python Layer -- Protocol Logic

```
src/
|-- crypto.py           # SHA3-256/512, WOTS+ signatures, Merkle trees, temporal keys
|-- block_producer.py   # Transaction collection, Merkle root, consensus integration
|-- consensus.py        # BFT consensus with 2/3+ stake threshold
|-- transaction.py      # UTXO model, transaction validation, mempool
|-- wallet.py           # Key management, signing, address derivation
|-- validator.py        # Block and transaction validation rules
|-- epoch.py            # Epoch management, key rotation scheduling
|-- measurement.py      # Network measurement protocol for consensus
|-- detection.py        # Anomaly and attack detection
|-- network.py          # P2P networking layer
|-- storage.py          # Persistent block and UTXO storage
+-- performance.py      # Benchmarking and performance metrics
```

### Rust/C Layer -- Performance-Critical Crypto

```
native/
|-- src/
|   |-- wots.rs         # WOTS+ signature generation/verification
|   |-- sha3.rs         # SHA3-256/512 implementation
|   |-- merkle.rs       # Merkle tree construction
|   +-- temporal_auth.rs # Temporal authentication chains
|-- csrc/
|   |-- wots.c          # C fallback: WOTS+ signatures
|   |-- sha3.c          # C fallback: SHA3 hashing
|   |-- merkle.c        # C fallback: Merkle trees
|   +-- temporal_auth.c # C fallback: temporal auth
+-- Cargo.toml
```

## Why WOTS+

ECDSA (secp256k1, ed25519) breaks under Shor's algorithm. WOTS+ is a hash-based signature scheme -- its security reduces to the preimage resistance of SHA3-256, which is quantum-resistant.

| Property | ECDSA | WOTS+ |
|----------|-------|-------|
| Quantum resistance | No | Yes |
| Security assumption | ECDLP hardness | SHA3 preimage resistance |
| Signature size | 64 bytes | ~2 KB |
| Key reuse | Unlimited | One-time (managed by temporal rotation) |

The one-time limitation of WOTS+ is handled by **temporal key evolution** -- automatic key rotation with forward secrecy guarantees.

## Quick Start

```bash
# Run testnet
python run_testnet.py

# Run integration tests
python test_integration.py

# Benchmark native crypto
cd native && cargo bench
```

## Related

- [secp256k1-geometric-analysis](https://github.com/ACD421/secp256k1-geometric-analysis) -- Why secp256k1 needs replacing
- [SGM-Substrate](https://github.com/ACD421/sgm-substrate) -- Same geometric thinking applied to AI

## Author

**Andrew C. Dorman** -- [Hollow Point Labs](https://github.com/ACD421)

## License

MIT