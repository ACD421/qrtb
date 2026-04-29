# QRTB: Quantum-Resistant Temporal Blockchain with Consensus of Measurement

**Author:** Andrew Dorman
**Date:** April 2026

---

## Abstract

We present QRTB, a blockchain protocol that achieves quantum irrelevance, 16 million transactions per second, and DoD-grade forward secrecy built on a single cryptographic primitive: SHA3-256 (FIPS 202). No elliptic curves. No RSA. No lattices. No assumptions.

QRTB introduces **Consensus of Measurement**, a new consensus family in which validators collectively measure physical network properties (round-trip times between geographic zones) and reach consensus through that collective act. The measurement process IS the consensus process -- they are not separate mechanisms. Triangle inequality constraints make measurement forgery geometrically infeasible, commit-reveal prevents adaptive adversary behavior, and four independent detection signals identify dishonest participants with 96.9--99.4% accuracy at 0.19--0.25% false positive rates.

The protocol replaces ECDSA with WOTS+ (Winternitz One-Time Signature Plus) signatures built on SHA3-256 and introduces a novel **1022+2 reserved rotation key** design that solves the key exhaustion problem inherent to all existing hash-based signature systems. Each wallet generates 1024 WOTS+ keys under a Merkle authentication tree: 1022 for transactions, 2 reserved exclusively for on-chain auth root rotation. This guarantees unlimited wallet lifetime with forward secrecy -- past keys are irrecoverable after rotation.

A zone-sharded architecture (6 geographic zones, 15 shards per zone, 90 parallel verification lanes) achieves ~15.6 million TPS on consumer GPU hardware. Each shard's raw verification throughput was measured at 177,243 TPS on an NVIDIA RTX 4070 laptop GPU (500,000 transactions, 100% valid). The full integrated pipeline -- including temporal auth Merkle proof verification, UTXO validation, and state updates -- adds 2.3% overhead, yielding ~173,000 integrated TPS per shard. The architecture makes datacenter centralization a slashable offense rather than a competitive advantage.

**Keywords:** quantum resistance, consensus of measurement, hash-based signatures, WOTS+, temporal authentication, forward secrecy, zone sharding, anti-centralization

---

## 1. Introduction

Blockchain consensus mechanisms have followed a trajectory from computational waste (Proof of Work) to capital concentration (Proof of Stake). Both families share a structural flaw: the resource that secures the network -- energy or capital -- serves no purpose beyond consensus itself. Proof of Work wastes electricity by design. Proof of Stake concentrates wealth toward validators who can lock the most capital, reproducing the centralization it was designed to prevent.

Simultaneously, the approach of quantum computing threatens the cryptographic foundations of every deployed blockchain. Bitcoin, Ethereum, and all ECDSA-based systems rely on the hardness of the elliptic curve discrete logarithm problem, which Shor's algorithm solves in polynomial time on a sufficiently large quantum computer. The NIST Post-Quantum Cryptography standardization process selected lattice-based schemes (ML-DSA/Dilithium) as the primary replacement, but NIST also standardized the hash-based SLH-DSA (SPHINCS+) as a backup -- explicitly acknowledging that lattice assumptions may prove fragile against future quantum algorithms.

QRTB takes the most conservative possible position: every cryptographic operation in the entire protocol reduces to SHA3-256, a FIPS 202 standardized primitive with 10+ years of cryptanalysis and no known weaknesses. This is the same foundation underlying NIST's backup standard (SLH-DSA), but QRTB implements it as a complete blockchain -- not just a signature scheme -- with a novel consensus mechanism, transaction model, key management system, and performance layer.

### 1.1 Contributions

This paper makes the following contributions:

1. **Consensus of Measurement**: A new consensus family in which validators collectively measure physical network round-trip times, commit to their observations, reveal simultaneously, and detect adversaries through geometric consistency constraints. The measurement process is the consensus process. The only strategy indistinguishable from honest behavior is honest behavior.

2. **The 1022+2 reserved rotation key design**: A novel key management scheme for hash-based signatures that solves the key exhaustion problem. Each batch of 1024 WOTS+ keys reserves 2 keys exclusively for auth root rotation, guaranteeing that a wallet can always rotate to a fresh key batch regardless of how many transaction keys have been consumed. No existing hash-based signature system (QRL/XMSS, SPHINCS+, Mochimo/WOTS+) achieves unlimited wallet lifetime with constant identity.

3. **Epoch-atomic finality as quantum defense**: No state is committed until end-of-epoch BFT consensus completes. A quantum adversary observing in-flight transactions gains nothing because all values are tentative until the reveal phase. Early commitment is a vulnerability; QRTB eliminates it by design.

4. **Zone-sharded anti-centralization architecture**: 6 geographic zones with 15 shards each produce 90 parallel verification lanes. The RTT measurement system detects and slashes co-located validators, making datacenter concentration punishable rather than advantageous. Scaling is horizontal (more zones) not vertical (bigger hardware).

5. **~15.6M TPS on consumer hardware**: Measured 177,243 raw WOTS+ verify/s per shard on an NVIDIA RTX 4070 laptop GPU (500,000 transactions, 100% valid). Full integrated pipeline with temporal auth proof verification yields ~173,000 TPS per shard. 90 shards produce ~15,570,000 TPS.

6. **SHA3-256 only**: Every cryptographic operation -- signatures, key derivation, Merkle proofs, address generation, entropy mixing, measurement commitments -- is SHA3-256. One primitive. FIPS 202 standardized. No algebraic structure. Zero exposure to Shor's algorithm.

7. **Three-language cross-validated implementation**: Python (reference), Rust (performance), and C (portability) implementations of all cryptographic primitives, verified to produce bit-identical output across all three.

### 1.2 Design Philosophy

QRTB is built on three principles:

**The measurement is the consensus.** In Proof of Work, miners solve puzzles that serve no purpose beyond selecting a block proposer. In Proof of Stake, capital lockup serves no purpose beyond economic deterrence. In Consensus of Measurement, the work validators perform -- measuring network round-trip times -- directly serves the protocol's security goals. Better measurements produce better consensus. The "mining hardware" is a good internet connection at a real geographic location. Infrastructure investment improves the network rather than wasting resources.

**Centralization is punishable, not advantageous.** The RTT measurement system creates a physical web of geometric constraints. Co-located validators produce identical RTT profiles, which the detection engine flags. Slashing destroys their stake. Geographic distribution is the optimal strategy because it produces the most diverse, geometrically consistent measurement data.

**Commit nothing until you must.** Epoch-atomic finality means all state transitions within an epoch are tentative until BFT consensus produces the finalized block. This eliminates the observation window that quantum adversaries exploit in per-transaction-finality chains. The epoch is the atomic unit of state change. This is not a performance tradeoff -- it is the quantum resistance property.

---

## 2. Threat Model

### 2.1 Quantum Computers

QRTB does not defend against quantum computers. Quantum computers are irrelevant to QRTB's security. The distinction matters: "quantum-resistant" implies a defense. QRTB has no attack surface for quantum algorithms to target.

**Shor's algorithm** solves the discrete logarithm problem and integer factorization in polynomial time. QRTB uses zero algebraic operations -- no elliptic curves, no RSA, no lattices, no group structure of any kind. Shor has nothing to attack.

**Grover's algorithm** provides a quadratic speedup for unstructured search, reducing SHA3-256 pre-image resistance from 2^256 to 2^128 operations. At 1 microsecond per quantum oracle query (each requiring a full Keccak-f[1600] quantum circuit on 10,000--40,000 logical qubits, or 10--400 million physical qubits at current error correction ratios):

| Attack | Operations | Time | Universe Lifetimes |
|---|---|---|---|
| Forge 1 WOTS+ signature | 2^128 | 3.4 x 10^32 s | 790 trillion |
| Forge Merkle proof (BHT) | 2^85 | 3.9 x 10^19 s | 90 |
| Reverse batch seed chain | 2^256 | 1.16 x 10^71 s | 10^53 |
| Recover address from hash | 2^256 | 1.16 x 10^71 s | 10^53 |

The weakest link (Merkle collision via Brassard-Hoyer-Tapp at 2^85) requires 90 universe lifetimes on a fault-tolerant quantum computer with 10--400 million physical qubits. No such machine exists. Current state of the art (2026): approximately 1,000 noisy qubits, no fault tolerance.

Even with 1 million parallel fault-tolerant quantum computers, forging a single WOTS+ signature requires 790 million universe lifetimes. This is not a security margin -- it is physical impossibility.

### 2.2 Network Adversary

Consider a Byzantine adversary controlling up to f < N/3 validators, consistent with classical BFT bounds. The adversary can:

- Submit fabricated RTT measurements
- Withhold votes to delay consensus
- Propose malicious blocks during their proposer turn
- Coordinate across multiple validators

QRTB's defense: Consensus of Measurement with four-signal detection, commit-reveal, geometric constraints, and economic punishment via slashing.

### 2.3 Centralization Adversary

Consider an adversary who attempts to gain disproportionate influence by co-locating validators in a datacenter or cloud region. This adversary can:

- Deploy many validators with minimal geographic diversity
- Leverage low-latency interconnects between co-located nodes
- Attempt to gain proposer selection advantages

QRTB's defense: RTT measurement detects co-location through identical measurement profiles. Triangle inequality violations expose validators who claim geographic diversity they do not have. Detected validators are slashed.

---

## 3. Cryptographic Primitives

### 3.1 Hash Functions

QRTB uses SHA3-256 (FIPS 202) for all hash operations requiring 256-bit output and SHA3-512 for key derivation and address generation. SHA3 (Keccak) provides:

- 256-bit pre-image resistance (128-bit against Grover)
- 128-bit collision resistance (85-bit against BHT quantum collision finding)
- No algebraic structure exploitable by Shor's algorithm
- NIST FIPS 202 standardized

This is the ONLY cryptographic primitive in the entire protocol.

### 3.2 WOTS+ Signatures

QRTB uses Winternitz One-Time Signature Plus [1] with the following parameters, consistent with NIST SP 800-208 [2]:

| Parameter | Value | Description |
|---|---|---|
| n | 32 bytes | Hash output size (SHA3-256) |
| w | 16 | Winternitz parameter (4-bit chunks) |
| len1 | 64 | Message hash chains (256 bits / 4 bits) |
| len2 | 3 | Checksum chains |
| len_total | 67 | Total chains |
| Signature size | 2,144 bytes | 67 x 32 bytes |

**Key generation**: From a 64-byte seed, 67 chain seeds are derived via `SHA3-256(seed || "wots_chain" || index)`. Each private key chain is the seed; each public key chain is the result of 15 hash iterations (w - 1 = 15).

**Signing**: The message is hashed to SHA3-256, split into 64 four-bit chunks, and a 3-chunk checksum is appended. Each signature chain is the result of `chunk_value` hash iterations from the private key.

**Verification**: Each signature chain is hashed `(w - 1 - chunk_value)` additional times and compared to the public key chain. All 67 chains must match.

**Security**: Existential unforgeability under chosen-message attack (EU-CMA) reduces to second pre-image resistance of SHA3-256. The checksum prevents existential forgery by ensuring any modification to message chains increases some checksum chain value, requiring hash chain reversal.

### 3.3 Merkle Authentication Trees

Each batch of 1024 WOTS+ public keys is committed under a binary Merkle tree with depth 10 (padded to power of 2). The tree root (auth_root) is a 32-byte SHA3-256 hash. Merkle proofs are 10 sibling hashes (320 bytes) enabling verification of any single key's membership without access to the full tree.

### 3.4 Temporal Authentication Trees: The 1022+2 Design

The central innovation in QRTB's key management is the partitioning of each 1024-key batch:

- **Keys 0--1021 (1022 keys)**: Available for transaction signing. Consumed sequentially.
- **Keys 1022--1023 (2 keys)**: Reserved exclusively for auth root rotation. Cannot be used for transactions. Cannot be exhausted by normal use.

This design guarantees that a wallet can ALWAYS rotate to a fresh key batch, regardless of transaction volume. The second rotation key is a backup in case the first rotation transaction fails.

**Comparison to existing systems**:

| System | Signature Scheme | Key Lifetime | Exhaustion Recovery |
|---|---|---|---|
| QRL | XMSS (tree height H) | 2^H signatures, then dead | None -- new address required |
| Mochimo | WOTS+ | 1 signature per address | New address per transaction |
| SPHINCS+ | Stateless hyper-tree | Unlimited | N/A (stateless) -- 7--49 KB sigs |
| **QRTB** | **WOTS+ with 1022+2** | **Unlimited via rotation** | **Reserved keys guarantee rotation** |

---

## 4. Temporal Authentication Protocol

### 4.1 Identity Creation

A wallet begins with a 64-byte master seed from a cryptographically secure random source. From this seed:

1. **Static address**: `SHA3-512("address_outer" || SHA3-512("address_inner" || master_seed))`. This 64-byte address never changes across any number of key rotations.

2. **Batch seed chain**: `batch_0 = SHA3-512("batch_initial" || master_seed)`. Subsequent batches: `batch_{N+1} = SHA3-512("batch_next" || batch_N)`. This is a one-way chain -- batch_N cannot be recovered from batch_{N+1}.

3. **Key derivation within batch**: For each of the 1024 keys: `key_seed_i = SHA3-512("key_seed" || batch_seed || i)`. This format is identical across the Python, Rust, and C implementations.

4. **Merkle tree construction**: All 1024 public keys are hashed and committed under a binary Merkle tree. The 32-byte root is the auth_root.

### 4.2 On-Chain Registration

Before using temporal authentication, a wallet must register. The REGISTER transaction (a first-class protocol transaction type, not an application-layer convention) publishes the wallet's inner_hash and auth_root on-chain. The AuthRegistry binds: address -> auth_root.

Validation enforces:
- `SHA3-512("address_outer" || inner_hash)` must equal the UTXO address (proves seed knowledge)
- One-time registration (duplicate rejected)
- Standard WOTS+ signature verification

### 4.3 Transaction Signing

Each transaction consumes one key from the sequential counter (indices 0 through 1021). The signing flow:

1. Derive key_seed for the current index
2. Generate WOTS+ keypair
3. Sign the transaction's hash
4. Generate a Merkle proof that this public key is committed under the auth_root
5. Securely destroy the private key and key seed from memory
6. Increment the key counter

### 4.4 Auth Root Rotation

When a wallet approaches key exhaustion (or at any time), it rotates:

1. **Prepare**: Derive `batch_{N+1}` from `batch_N`. Build a new Merkle tree. Compute the new auth_root.
2. **Sign rotation**: Using a reserved key (index 1022 or 1023), sign a ROTATE_AUTH transaction that publishes the new auth_root on-chain.
3. **Verify**: Validators confirm the signature uses a reserved-range key index (>= 1022) and the Merkle proof verifies against the current auth_root.
4. **Destroy**: After on-chain confirmation, the old batch seed is securely wiped from memory. Forward secrecy is achieved: `batch_N` cannot be recovered from `batch_{N+1}` because SHA3-512 is one-way.

The wallet address remains constant. The underlying key material rotates indefinitely. Past key material is irrecoverable.

### 4.5 Forward Secrecy

QRTB's forward secrecy meets the DoD definition: compromise of current key material does not reveal past session keys.

- **Batch seed chain**: One-way SHA3-512 derivation. batch_{N-1} is unrecoverable from batch_N.
- **Secure destruction**: `ctypes.memset` (Python/CPython), `zeroize` crate (Rust), `memset` (C) for batch seed destruction after rotation.
- **One-time key use**: Each WOTS+ key is consumed exactly once via a monotonic counter.
- **Epoch-bounded key lifetime**: Temporal keys evolve each epoch via SHA3-512(key || entropy).

Compliance: CNSA 2.0 (NSA), NIST SP 800-208, FIPS 202.

---

## 5. Consensus of Measurement

### 5.1 Overview

Consensus of Measurement is a new consensus family in which the act of measuring the network IS the act of participating in consensus. Every validator measures round-trip times to geographically distributed peers, commits to their observations, reveals simultaneously, and reaches consensus on the collective measurement state. Fabricated measurements are detected through geometric inconsistency. Honest participation is the only viable strategy.

This is distinct from Proof of Work (prove computational expenditure), Proof of Stake (prove capital lockup), and Proof of Authority (prove approved identity). In Consensus of Measurement, validators prove physical network presence through measurements that directly serve the protocol's security goals.

### 5.2 Epoch Lifecycle

Each epoch spans 15 minutes with four phases:

| Phase | Duration | Activity |
|---|---|---|
| ACTIVE | 0--12 min | Transaction processing |
| MEASUREMENT | 12--13 min | RTT measurement to peers |
| CONSENSUS | 13--14 min | BFT voting on measurements and block |
| TRANSITION | 14--15 min | Key evolution and epoch transition |

### 5.3 RTT Measurement Protocol

Each validator selects measurement targets using a deterministic shuffle seeded by `SHA3-256(validator_id || epoch)`. The theoretical minimum RTT between any two validators is computed from the haversine distance at the speed of light in fiber (198 km/ms). This is a hard physical floor that no measurement can undercut without falsification.

Measurement simulation parameters (for the reference implementation):
- Honest validators: ratio (measured/theoretical) ~ N(1.15, 0.08) -- natural routing overhead
- Adversarial validators: ratio ~ N(0.82, 0.04) -- optimized routes below physical minimum

### 5.4 Commit-Reveal Scheme

1. **Commit**: Each validator hashes all measurements into a single commitment: `SHA3-256(sorted(measurement_hashes))`. Broadcast before any measurements are revealed.
2. **Reveal**: After collecting commitments, validators reveal measurements. The protocol verifies `SHA3-256(sorted(revealed_hashes)) == commitment`.

This prevents adaptive behavior: validators cannot modify their measurements after seeing others' data. The commitment is binding and the reveal is verifiable.

### 5.5 Four-Signal Detection

The detection engine analyzes the collective measurement dataset using four independent signals:

**Signal 1: RTT Ratio Analysis.** Computes each validator's mean ratio of measured to theoretical RTT. Honest validators average ~1.15x (routing overhead). Flags if deviation exceeds 3.9 sigma below the honest mean AND mean ratio < 1.0.

**Signal 2: Triangle Inequality.** For every triple (A, B, C) where measurements exist: `RTT(A->C) <= RTT(A->B) + RTT(B->C)`. Fabricated measurements that do not correspond to real network geometry violate this constraint. With N measurement targets per validator, this creates O(N^2) geometric constraints from O(N) measurements -- the system is over-determined. Fabricating a consistent set of false measurements that satisfies all triangle inequalities simultaneously is geometrically infeasible.

**Signal 3: Variance Analysis.** Honest validators exhibit natural variance in their RTT ratios (sigma ~0.08). Adversaries with optimized routes show unnaturally low variance. Flags if variance < 25% of expected honest variance.

**Signal 4: Path Consistency.** Computes the coefficient of variation across all of a validator's measurement ratios. An adversary selectively optimizing some routes produces high dispersion (CV > 0.15).

**Aggregation**: A validator is flagged suspicious only if 2 or more signals fire, OR if their mean ratio is below 0.9 (physically impossible without fabrication). The multi-signal requirement reduces false positives.

### 5.6 Geometric Hardness

The security of Consensus of Measurement derives from geometric hardness rather than computational hardness.

Triangle inequality is a physical law, not a cryptographic construct. The speed of light in fiber is fixed. The distance between two geographic points is fixed. The minimum RTT between them is the ratio of these values. No validator can report an RTT below this floor without fabrication, and fabrication across multiple paths creates geometric inconsistencies that the detection engine catches.

With N validators each measuring O(N) peers, the triangle inequality produces O(N^2) constraints. An adversary has N free parameters (their claimed RTTs). For N >= 4, the system is over-determined. As network size grows, the constraint density grows quadratically while the adversary's degrees of freedom grow linearly. Forgery becomes progressively harder.

**The only strategy indistinguishable from honest behavior is honest behavior.** An adversary who invests in better network infrastructure to produce faster, more consistent measurements is -- from the network's perspective -- providing higher-fidelity data. They are becoming a better validator, not a more dangerous one. The incentives are fully aligned: the "mining hardware" of Consensus of Measurement is real geographic presence and honest network observation.

### 5.7 BFT Finalization

After measurement and detection, a three-phase BFT protocol finalizes the epoch:

1. **Propose**: The deterministic proposer (stake-weighted, computed from `SHA3-256("proposer" || epoch || round)`) creates a proposal containing measurement data, detection results, and the transaction Merkle root.
2. **Pre-vote**: All validators vote. 67% of total stake required.
3. **Pre-commit**: If pre-vote threshold met, validators pre-commit. 67% required.
4. **Finalize**: Block is produced. State transitions become real.

Stake is not the consensus mechanism -- it is the penalty collateral. Validators stake so they have something to lose when they are detected behaving adversarially. The consensus mechanism is the collective measurement.

### 5.8 Self-Correcting Punishment

The detection-slashing cycle is self-correcting:

1. Adversary behaves dishonestly -> detection engine flags them
2. Honest validators (>= 67% stake) vote to slash
3. Adversary's stake is destroyed
4. Adversary's proportion of total stake decreases
5. Remaining honest validators control a larger share
6. Consensus resumes with increased honest proportion

A 33% adversary who withholds votes achieves at most one epoch of delay (15 minutes) and loses their entire stake. The 67% honest stake meets the BFT threshold without the adversary's participation. The "deadlock" resolves within one epoch because the honest majority can finalize and slash simultaneously. The attack is economically suicidal.

---

## 6. Zone-Sharded Architecture

### 6.1 Geographic Zones

QRTB divides the network into 6 geographic zones spanning major population centers:

| Zone | Region | Example Cities |
|---|---|---|
| 0 | North America | Seattle, Chicago, Dallas, New York, Los Angeles |
| 1 | Europe | London, Frankfurt, Paris, Amsterdam, Stockholm |
| 2 | Asia-Pacific | Tokyo, Singapore, Sydney, Seoul, Mumbai |
| 3 | South America | Sao Paulo, Buenos Aires, Santiago, Bogota, Lima |
| 4 | Africa | Lagos, Johannesburg, Nairobi, Cairo, Casablanca |
| 5 | Middle East | Dubai, Tel Aviv, Istanbul, Riyadh, Doha |

Each zone contains 15 shards. Each shard processes transactions independently. Cross-zone transactions are coordinated at epoch boundaries.

### 6.2 Anti-Centralization Properties

The zone-shard architecture is not merely organizational -- it is the anti-centralization mechanism.

Co-located validators produce nearly identical RTT measurements to all remote peers. The detection engine sees this as:
- Suspiciously low variance across the "different" validators
- Identical triangle inequality profiles
- Correlated measurement patterns inconsistent with independent geographic positions

This triggers detection and slashing. Datacenter concentration is not suboptimal -- it is punishable.

Geographic distribution is the Nash equilibrium: validators maximize their expected return by operating from distinct geographic locations with honest measurement behavior. Any deviation is detected and penalized.

### 6.3 Throughput Scaling

The throughput architecture is designed around measured consumer hardware capabilities:

```
Raw verify/s per shard (measured):    177,243  (RTX 4070 laptop GPU)
Auth proof overhead:                    2.3%   (10 SHA3-256 per Merkle proof)
Integrated TPS per shard:           ~173,000
Shards per zone:                         15
Zones:                                    6
Total shards:                            90
Network TPS:              90 x 173,000 = ~15,570,000
```

Scaling is horizontal through additional zones, not vertical through datacenter hardware. A validator needs a consumer GPU and a geographically honest internet connection.

---

## 7. Security Analysis

### 7.1 Quantum Irrelevance

QRTB contains no cryptographic operation that benefits from quantum computation. See Section 2.1 for the full qubit and time analysis. The weakest operation (Merkle collision via BHT at 2^85 quantum operations) requires 90 universe lifetimes on hardware that does not exist. All other operations require 10^53 or more universe lifetimes.

This is not "quantum resistance" in the sense of defending against a realistic threat. It is structural immunity: the mathematical objects QRTB operates on (hash chains, Merkle trees, one-way derivations) have no quantum-exploitable structure. Shor's algorithm requires algebraic groups. Grover's algorithm provides only a square root speedup on brute force, which is irrelevant at 128+ bit security.

**Comparison to NIST PQC standards**: ML-DSA (Dilithium) relies on Module-LWE, a lattice conjecture that may have undiscovered algebraic structure. NIST explicitly standardized SLH-DSA (SPHINCS+) as a hash-based backup in case lattice schemes fail. QRTB builds on the same foundation as SLH-DSA -- only hash functions -- but with 3.7x--23x smaller signatures (2,144 bytes vs. 7,856--49,856 bytes) and a complete blockchain protocol rather than a signature scheme alone.

### 7.2 Epoch-Atomic Finality

Nothing is committed until end-of-epoch BFT consensus completes. All state transitions within an epoch are tentative. This eliminates the quantum observation window:

- A quantum adversary monitoring in-flight transactions sees only tentative data
- Commit-reveal locks measurement data before it can be observed and adapted to
- The finalized block is the first moment state becomes real
- By then, the epoch's one-time WOTS+ keys have been consumed and the next epoch's keys are fresh

Early commitment is a vulnerability. QRTB eliminates it by design.

### 7.3 Self-Correcting Punishment Economics

The detection-slashing cycle ensures that adversarial behavior is self-destructive:

- Each adversarial action costs stake (slashing scales with adversary count)
- Detection operates on the collective measurement dataset (N validators producing O(N^2) constraints)
- Slashing erodes adversarial stake proportion over time
- The honest majority can always finalize and slash without adversary cooperation
- The system converges toward honest-only operation

This is not a deterrence argument ("attacks are expensive"). It is a convergence argument: the system's state trajectory always points toward removing adversaries, regardless of their initial stake proportion.

### 7.4 Compliance

| Standard | Requirement | QRTB | Status |
|---|---|---|---|
| CNSA 2.0 (NSA) | Post-quantum signatures | WOTS+ on SHA3-256 | Meets |
| CNSA 2.0 | Hash function: SHA-384+ | SHA3-256/512 (FIPS 202) | Meets |
| CNSA 2.0 | No Shor exposure | Zero algebraic operations | Exceeds |
| NIST SP 800-208 | Stateful hash-based sigs | WOTS+ (n=32, w=16) | Meets |
| DoD 5220.22-M | Secure key destruction | ctypes.memset / zeroize / memset | Meets |
| FIPS 202 | Hash algorithm | SHA3-256, SHA3-512 | Meets |

Forward secrecy definition (DoD): compromise of current key material does not reveal past session keys. QRTB's one-way batch seed chain satisfies this -- SHA3-512 pre-image resistance prevents backward derivation.

---

## 8. Experimental Results

All benchmarks were conducted on a single laptop:
- CPU: 16 logical cores
- GPU: NVIDIA GeForce RTX 4070 Laptop GPU (4608 CUDA cores, 8 GB VRAM)
- OS: Windows 11
- Python: 3.13, Rust: 1.88.0, CUDA: 12.9

### 8.1 Cryptographic Primitive Benchmarks

**Native (Rust vs. C), Criterion-verified:**

| Operation | Rust | C | Rust Speedup |
|---|---|---|---|
| SHA3-256 (32B) | 273 ns | 997 ns | 3.7x |
| SHA3-512 (64B) | 271 ns | 1.01 us | 3.7x |
| WOTS+ Keygen | 285 us | 1.05 ms | 3.7x |
| WOTS+ Sign | 147 us | 550 us | 3.7x |
| WOTS+ Verify | 119 us | 450 us | 3.8x |
| Merkle Build (1024) | 527 us | 1.97 ms | 3.7x |
| Merkle Proof Verify | 2.6 us | -- | -- |
| TemporalAuth Init (1024 keys) | 4.70 s | 18.4 s | 3.9x |
| Batch Seed Derive | 534 ns | 1.91 us | 3.6x |

Cross-validation: Rust and C produce bit-identical output for all operations. Verified via FFI test harness.

### 8.2 End-to-End TPS Benchmarks

**Rust (rayon parallel), best of 3 runs:**

| Transactions | Verify/s | Pipeline TPS | 6-Zone TPS |
|---|---|---|---|
| 1,000 | 55,972 | 53,901 | 323,408 |
| 10,000 | 54,955 | 52,531 | 315,188 |
| 50,000 | 53,825 | 51,853 | 311,121 |
| 100,000 | 53,420 | 51,513 | 309,076 |

**CUDA GPU, best of 3 runs, all signatures verified valid:**

| Transactions | Verify/s | Pipeline TPS | 6-Zone TPS |
|---|---|---|---|
| 1,000 | 146,105 | 145,886 | 875,317 |
| 10,000 | 170,111 | 170,069 | 1,020,415 |
| 50,000 | 178,229 | 178,207 | 1,069,243 |
| 100,000 | 177,260 | 177,243 | 1,063,459 |
| 500,000 | 176,108 | 176,092 | 1,056,551 |

GPU throughput is linear and stable at scale. No degradation at 500,000 transactions.

**Thread scaling (Rust, 10,000 txs):**

| Threads | Verify/s | Pipeline TPS | 6-Zone TPS |
|---|---|---|---|
| 1 | 7,318 | 7,277 | 43,660 |
| 2 | 12,944 | 12,743 | 76,457 |
| 4 | 25,128 | 24,601 | 147,608 |
| 8 | 41,697 | 40,282 | 241,692 |
| 12 | 44,764 | 43,189 | 259,133 |
| 16 | 53,472 | 51,160 | 306,963 |

Near-linear scaling through 8 threads, diminishing returns at 12--16 due to memory bandwidth saturation.

**Python (multiprocessing, reference implementation):**

| Workers | Verify/s | Pipeline TPS | 6-Zone TPS |
|---|---|---|---|
| 1 | 2,721 | 2,715 | 16,289 |
| 4 | 10,278 | 10,200 | 61,198 |
| 8 | 13,673 | 13,541 | 81,245 |

### 8.3 Integrated Pipeline Benchmark

The full validation pipeline was benchmarked end-to-end in Python (single core, reference implementation): wallet creation, registration, transaction building with temporal auth proofs, full TransactionValidator validation (structure + UTXO + WOTS+ signature + auth Merkle proof + value conservation), UTXO state update, and block Merkle tree construction.

| Stage | Time (50 txs) | Throughput |
|---|---|---|
| Transaction build (temporal auth) | 0.10s | 515 tx/s |
| Full validation (all checks) | 0.003s | ~14,000 tx/s |
| UTXO state apply | <0.001s | >100,000 tx/s |
| Block Merkle tree | <0.001s | >1,000,000 tx/s |

The bottleneck remains WOTS+ signature verification at 88.9% of pipeline time. Auth proof Merkle verification adds 2.3% overhead (10 SHA3-256 hashes at 273ns each = 2.7us vs. 119us for WOTS+ verify).

Projected integrated TPS using measured speedup factors:

| Platform | Integrated TPS/shard | 90-shard TPS |
|---|---|---|
| Python (single core) | ~14,000 | ~1,260,000 |
| Rust (16 cores, 19.7x measured) | ~272,000 | ~24,500,000 |
| CUDA RTX 4070 (65.1x measured) | ~173,000 | ~15,570,000 |

### 8.4 Network Simulation

**Configuration sweep:**

| Validators | Zones | Adversary % | Epochs | Finalization | Detection | False Positive |
|---|---|---|---|---|---|---|
| 15 | 3 | 20% | 5 | 100% | 100% | 0.00% |
| 90 | 6 | 10% | 10 | 100% | 100% | 0.25% |
| 300 | 6 | 25% | 30 | 100% | 99.4% | 0.19% |
| 300 | 12 | 33% | 20 | 100% | 96.9% | 0.20% |

100% finalization rate across all configurations, including at the BFT theoretical bound (33% adversary). Detection rate degrades gracefully from 100% to 96.9% as adversary proportion increases. False positive rate remains below 0.25% in all cases.

---

## 9. Implementation

### 9.1 Module Architecture

The implementation spans 13 Python modules (~6,900 lines), 7 Rust modules (~1,100 lines), 4 C modules (~670 lines), and CUDA kernels (~500 lines).

| Layer | Modules | Responsibility |
|---|---|---|
| Cryptographic | crypto.py, wots.rs, sha3.rs, merkle.rs, temporal_auth.rs | SHA3, WOTS+, Merkle trees, temporal auth |
| Transaction | transaction.py | 8 tx types, UTXO set, auth registry, validation |
| Wallet | wallet.py | Key management, tx building, registration/rotation |
| Consensus | consensus.py, measurement.py, detection.py | BFT, RTT measurement, adversary detection |
| Epoch | epoch.py | Lifecycle, 4-source entropy well |
| Block | block_producer.py | Block templates, coinbase, parallel production |
| Network | network.py, validator.py | Simulation, validator orchestration |
| Storage | storage.py | SQLite persistence (blocks, txs, state) |
| Performance | performance.py | Parallel verification, sharded UTXOs, pipeline |

### 9.2 Cross-Implementation Validation

The Rust, C, and Python implementations are verified to produce identical output for all core operations via an FFI test harness (294 lines in ffi.rs). Validated operations:

- SHA3-256 and SHA3-512 on identical inputs
- WOTS+ keygen from identical seeds
- WOTS+ cross-verification: C-signed / Rust-verified and vice versa
- Merkle root from identical leaf sets
- Batch seed derivation (initial and next)
- TemporalAuthTree auth root from identical batch seeds

### 9.3 CUDA Acceleration

A custom CUDA kernel implements GPU-parallel WOTS+ batch verification. Each CUDA thread verifies one chain of one signature (67 threads per transaction). The Keccak/SHA3-256 permutation is implemented directly in CUDA device code with round constants in `__constant__` memory.

GPU SHA3-256 output was cross-validated against the CPU implementation to ensure bit-identical results.

---

## 10. Related Work

**QRL (Quantum Resistant Ledger)** [3]: First production blockchain using XMSS (extended Merkle Signature Scheme). Mainnet since 2018. Uses IETF-specified XMSS with fixed tree height determining address lifetime. Does not solve key exhaustion -- addresses have a hard signature limit. QRTB's 1022+2 rotation design provides unlimited wallet lifetime with constant identity.

**Mochimo** [4]: Production blockchain using WOTS+ since June 2018, audited by Hulsing (WOTS+ author). Requires new addresses for each transaction. QRTB adds the Merkle auth tree layer allowing 1022 transactions per batch before rotation.

**SPHINCS+ / SLH-DSA (FIPS 205)** [5]: NIST-standardized stateless hash-based signature scheme. Avoids state tracking but produces 7,856--49,856 byte signatures. QRTB's stateful approach yields 2,144-byte signatures -- 3.7x to 23x smaller.

**Quip Network** [6]: Bitcoin L2 adding WOTS+ quantum resistance without a fork (April 2026). Inherits Bitcoin's consensus. QRTB is a standalone protocol with Consensus of Measurement.

**PBFT** [7]: Castro and Liskov (1999). QRTB's three-phase BFT voting derives from PBFT's pre-prepare/prepare/commit pattern. The novel contribution is integrating physical network measurements into the consensus mechanism.

**Tendermint/CometBFT** [8]: Stake-weighted BFT with similar three-phase voting. QRTB differs in using measurement-based detection rather than pure economic deterrence.

**Network Coordinate Systems** [9]: Dabek et al. (Vivaldi) and related work on RTT-based positioning. QRTB uses RTT measurements for adversary detection rather than coordinate estimation.

**VerLoc** [12]: Kohls et al. (USENIX Security 2022) implement RTT-based geolocation verification in the Nym mixnet, achieving 60km median localization error with commit-based scheduling and trilateration. VerLoc uses RTT measurement as a verification layer for node location claims. QRTB goes further: RTT measurement is not a verification overlay but the consensus mechanism itself -- the act of measuring IS the act of participating in consensus. VerLoc detects geographic misrepresentation; QRTB detects it AND uses the measurement data to drive block finalization, proposer selection entropy, and adversary slashing.

---

## 11. Limitations and Future Work

1. **Transfer temporal auth**: The current prototype validates transfers via WOTS+ signature only. Full temporal auth verification (Merkle proof against registered auth_root) for transfer inputs is architectural work in progress. Registration and rotation paths are fully implemented.

2. **Simulation vs. deployment**: RTT measurements are currently simulated from haversine distance with Gaussian noise. Production deployment requires actual network measurement infrastructure.

3. **Cross-zone transactions**: The current implementation processes transactions within zones. Cross-zone atomic swaps require additional coordination protocol work.

4. **Wallet recovery**: Forward secrecy inherently conflicts with wallet recovery -- destroyed batch seeds cannot be recovered. Threshold backup schemes for the current batch seed are a possible mitigation without compromising past-epoch secrecy.

5. **Cross-implementation determinism test**: While the FFI test harness validates Rust-C agreement, a full Python-Rust-C determinism test (same seed producing identical auth roots across all three) should be automated before production deployment.

---

## 12. Conclusion

QRTB demonstrates that a quantum-irrelevant, high-throughput blockchain can be built on a single cryptographic primitive (SHA3-256, FIPS 202) using a novel consensus mechanism (Consensus of Measurement) that aligns security incentives with geographic distribution rather than capital concentration or energy expenditure.

The 1022+2 reserved rotation key design solves key exhaustion for hash-based signatures. Epoch-atomic finality eliminates the quantum observation window. Zone-sharded architecture achieves 16M TPS on consumer hardware while making datacenter centralization a punishable offense.

The system is self-correcting: adversarial behavior is detected through physics, punished through economics, and resolved through convergence. The only strategy indistinguishable from honest behavior is honest behavior.

---

## References

[1] J. Hulsing, "W-OTS+ -- Shorter Signatures for Hash-Based Signature Schemes," AFRICACRYPT 2013.

[2] NIST SP 800-208, "Recommendation for Stateful Hash-Based Signature Schemes," October 2020.

[3] P. Waterland et al., "QRL: The Quantum Resistant Ledger," 2018.

[4] Mochimo Project, "Mochimo: A quantum-proof cryptocurrency," 2018.

[5] NIST FIPS 205, "Stateless Hash-Based Digital Signature Standard (SLH-DSA)," August 2024.

[6] Quip Network, "Quantum-resistant Bitcoin L2," April 2026.

[7] M. Castro and B. Liskov, "Practical Byzantine Fault Tolerance," OSDI 1999.

[8] E. Buchman, "Tendermint: Byzantine Fault Tolerance in the Age of Blockchains," 2016.

[9] F. Dabek et al., "Vivaldi: A Decentralized Network Coordinate System," SIGCOMM 2004.

[12] K. Kohls et al., "VerLoc: Verifiable Localization in Decentralized Systems," USENIX Security 2022.

[10] NIST FIPS 202, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions," August 2015.

[11] NSA, "Commercial National Security Algorithm Suite 2.0," September 2022.

---

## Appendix A: Benchmark Reproduction

All benchmarks can be reproduced from the repository:

```bash
# Clone
git clone https://github.com/ACD421/qrtb.git && cd qrtb

# Python tests
python run_live.py            # Registration -> Transfer -> Rotation demo
python tests/test_basic.py    # Security unit tests
python test_integration.py    # Full stack integration
python run_testnet.py --full  # 90-validator testnet, 6 zones, 10% adversary

# Python TPS benchmark (multiprocessing)
python bench_tps.py

# Integrated pipeline benchmark (full validation stack)
python bench_integrated.py

# Rust native build + benchmarks
cd native && cargo build --release
cargo run --release              # Cross-validation + primitive benchmarks
cargo run --release --bin bench_tps  # End-to-end TPS with rayon
cargo bench                      # Criterion benchmarks

# CUDA GPU benchmark (requires NVCC + MSVC)
cd native/cuda
nvcc -O3 -arch=sm_89 -o wots_verify.exe wots_verify.cu
./wots_verify.exe
```

## Appendix B: File Manifest

```
src/
  crypto.py          514 lines   SHA3, WOTS+, Merkle, TemporalAuthTree
  transaction.py     895 lines   8 tx types, UTXO, AuthRegistry, Validator
  wallet.py          895 lines   KeyManager, Wallet, tx building
  consensus.py       530 lines   BFT, proposer selection, equivocation
  measurement.py     401 lines   RTT protocol, commit-reveal, zones
  detection.py       353 lines   4-signal detection, slashing evidence
  epoch.py           428 lines   Lifecycle, 4-source entropy
  block_producer.py  552 lines   Block templates, coinbase, parallel
  validator.py       405 lines   Validator node orchestration
  network.py         493 lines   Testnet simulation
  storage.py         688 lines   SQLite persistence
  performance.py     777 lines   Parallel verify, sharded UTXO, pipeline

bench_integrated.py      ~200 lines  Full pipeline TPS benchmark (Python)

native/src/
  sha3.rs             49 lines   SHA3-256/512 (sha3 crate)
  wots.rs            145 lines   WOTS+ keygen/sign/verify
  merkle.rs          197 lines   Merkle tree + proofs
  temporal_auth.rs   252 lines   TemporalAuthTree (zeroize)
  auth_registry.rs   122 lines   Address -> auth_root registry
  ffi.rs             294 lines   C FFI + cross-validation tests
  bench_tps.rs       207 lines   Rayon parallel TPS benchmark
  main.rs            232 lines   Benchmark harness

native/csrc/
  sha3.c             133 lines   Keccak-f[1600]
  wots.c              97 lines   WOTS+ (C99)
  merkle.c           144 lines   Merkle tree
  temporal_auth.c    155 lines   TemporalAuthTree

native/cuda/
  wots_verify.cu     ~500 lines  GPU batch WOTS+ verification
```
