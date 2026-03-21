<div align="center">

# QRTB

### Quantum-Resistant Temporal Blockchain

**WOTS+ on SHA3-256 | Temporal key rotation | BFT consensus | Forward secrecy**

[![Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)
[![Rust](https://img.shields.io/badge/Rust-Native%20Crypto-orange.svg)](https://rust-lang.org)

</div>

## Overview

Post-quantum blockchain. WOTS+ on SHA3-256 instead of ECDSA. Temporal key evolution with forward secrecy.

## Architecture

```
src/  crypto.py, block_producer.py, consensus.py, transaction.py, wallet.py,
      validator.py, epoch.py, measurement.py, detection.py, network.py,
      storage.py, performance.py

native/src/   wots.rs, sha3.rs, merkle.rs, temporal_auth.rs  (Rust)
native/csrc/  wots.c, sha3.c, merkle.c, temporal_auth.c      (C fallback)
```

## Quick Start

```bash
python run_testnet.py
cd native && cargo bench
```

## Author

**Andrew C. Dorman**

## License

Proprietary License. See [LICENSE](LICENSE).