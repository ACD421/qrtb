use std::time::Instant;

use qrtb_native::sha3::{sha3_256 as rust_sha3_256, sha3_512 as rust_sha3_512};
use qrtb_native::wots::{wots_keygen as rust_wots_keygen, wots_sign as rust_wots_sign, wots_verify as rust_wots_verify};
use qrtb_native::merkle::{self, merkle_build_root as rust_merkle_build_root};
use qrtb_native::temporal_auth::{TemporalAuthTree, derive_initial_batch_seed, derive_next_batch_seed};
use qrtb_native::ffi::{c_sha3_256, c_sha3_512, c_wots_keygen, c_wots_sign, c_wots_verify, c_merkle_build_root,
    c_derive_initial_batch_seed, c_derive_next_batch_seed, c_tat_init, c_tat_sign, c_tat_destroy};

fn bench<F: FnMut()>(name: &str, iterations: u64, mut f: F) {
    // Warmup
    for _ in 0..std::cmp::min(10, iterations) {
        f();
    }

    let start = Instant::now();
    for _ in 0..iterations {
        f();
    }
    let elapsed = start.elapsed();
    let ns_per_op = elapsed.as_nanos() as f64 / iterations as f64;

    if ns_per_op < 1_000.0 {
        println!("  {:<35} {:>8.1} ns/op    ({:.1} M ops/sec)",
                 name, ns_per_op, 1_000.0 / ns_per_op);
    } else if ns_per_op < 1_000_000.0 {
        println!("  {:<35} {:>8.2} us/op    ({:.1} K ops/sec)",
                 name, ns_per_op / 1_000.0, 1_000_000.0 / ns_per_op);
    } else {
        println!("  {:<35} {:>8.3} ms/op    ({:.1} ops/sec)",
                 name, ns_per_op / 1_000_000.0, 1_000_000_000.0 / ns_per_op);
    }
}

fn run_cross_validation() {
    println!("\n=== Cross-Validation: C vs Rust ===\n");

    // SHA3-256
    let input = b"cross validation test input data";
    let c_hash = c_sha3_256(input);
    let r_hash = rust_sha3_256(input);
    assert_eq!(c_hash, r_hash, "SHA3-256 mismatch!");
    println!("  SHA3-256:      PASS (C == Rust)");

    // SHA3-512
    let c_hash512 = c_sha3_512(input);
    let r_hash512 = rust_sha3_512(input);
    assert_eq!(c_hash512, r_hash512, "SHA3-512 mismatch!");
    println!("  SHA3-512:      PASS (C == Rust)");

    // WOTS+ keygen
    let seed = rust_sha3_512(b"crossval_keygen_seed");
    let (c_sk, c_pk) = c_wots_keygen(&seed);
    let (r_sk, r_pk) = rust_wots_keygen(&seed);
    assert_eq!(c_sk, r_sk, "WOTS+ private key mismatch!");
    assert_eq!(c_pk, r_pk, "WOTS+ public key mismatch!");
    println!("  WOTS+ keygen:  PASS (C == Rust)");

    // WOTS+ sign (C sign, Rust verify and vice versa)
    let msg = b"signature cross-validation message";
    let c_sig = c_wots_sign(msg, &c_sk);
    let r_sig = rust_wots_sign(msg, &r_sk);
    assert_eq!(c_sig, r_sig, "WOTS+ signature mismatch!");
    assert!(rust_wots_verify(msg, &c_sig, &c_pk), "Rust failed to verify C sig");
    assert!(c_wots_verify(msg, &r_sig, &r_pk), "C failed to verify Rust sig");
    println!("  WOTS+ sign:    PASS (C == Rust, cross-verify OK)");

    // Merkle root
    let leaf_size = 32usize;
    let num_leaves = 8usize;
    let mut flat_leaves = vec![0u8; num_leaves * leaf_size];
    for i in 0..num_leaves {
        let h = rust_sha3_256(&(i as u32).to_le_bytes());
        flat_leaves[i * leaf_size..(i + 1) * leaf_size].copy_from_slice(&h);
    }
    let c_root = c_merkle_build_root(&flat_leaves, num_leaves, leaf_size);
    let leaves: Vec<&[u8]> = (0..num_leaves)
        .map(|i| &flat_leaves[i * leaf_size..(i + 1) * leaf_size])
        .collect();
    let r_root = rust_merkle_build_root(&leaves);
    assert_eq!(c_root, r_root, "Merkle root mismatch!");
    println!("  Merkle root:   PASS (C == Rust)");

    // Batch seed derivation
    let c_bseed = c_derive_initial_batch_seed(b"crossval_batch");
    let r_bseed = derive_initial_batch_seed(b"crossval_batch");
    assert_eq!(c_bseed, r_bseed, "Initial batch seed mismatch!");
    let c_next = c_derive_next_batch_seed(&c_bseed);
    let r_next = derive_next_batch_seed(&r_bseed);
    assert_eq!(c_next, r_next, "Next batch seed mismatch!");
    println!("  Batch seeds:   PASS (C == Rust)");

    // TemporalAuthTree auth root
    let c_tree = c_tat_init(&c_bseed);
    let r_tree = TemporalAuthTree::new(r_bseed);
    assert_eq!(c_tree.auth_root, *r_tree.auth_root(), "Auth root mismatch!");
    println!("  Auth root:     PASS (C == Rust)");
    let mut c_tree = c_tree;
    c_tat_destroy(&mut c_tree);

    println!("\n  All cross-validation checks passed!");
}

fn run_benchmarks() {
    println!("\n=== QRTB Native Baseline Benchmarks ===\n");

    let input_32 = [0x42u8; 32];
    let input_64 = [0x42u8; 64];

    // SHA3-256
    println!("--- SHA3-256 (32B input) ---");
    bench("Rust (sha3 crate)", 100_000, || {
        std::hint::black_box(rust_sha3_256(&input_32));
    });
    bench("C (custom Keccak)", 100_000, || {
        std::hint::black_box(c_sha3_256(&input_32));
    });

    // SHA3-512
    println!("\n--- SHA3-512 (64B input) ---");
    bench("Rust (sha3 crate)", 100_000, || {
        std::hint::black_box(rust_sha3_512(&input_64));
    });
    bench("C (custom Keccak)", 100_000, || {
        std::hint::black_box(c_sha3_512(&input_64));
    });

    // WOTS+ keygen
    println!("\n--- WOTS+ Keygen ---");
    let seed = rust_sha3_512(b"bench_keygen_seed");
    bench("Rust", 10, || {
        std::hint::black_box(rust_wots_keygen(&seed));
    });
    bench("C", 10, || {
        std::hint::black_box(c_wots_keygen(&seed));
    });

    // WOTS+ sign
    println!("\n--- WOTS+ Sign ---");
    let (r_sk, _r_pk) = rust_wots_keygen(&seed);
    let (c_sk, _c_pk) = c_wots_keygen(&seed);
    let msg = b"benchmark message for signing";
    bench("Rust", 10, || {
        std::hint::black_box(rust_wots_sign(msg, &r_sk));
    });
    bench("C", 10, || {
        std::hint::black_box(c_wots_sign(msg, &c_sk));
    });

    // WOTS+ verify
    println!("\n--- WOTS+ Verify ---");
    let r_sig = rust_wots_sign(msg, &r_sk);
    let c_sig = c_wots_sign(msg, &c_sk);
    bench("Rust", 10, || {
        std::hint::black_box(rust_wots_verify(msg, &r_sig, &_r_pk));
    });
    bench("C", 10, || {
        std::hint::black_box(c_wots_verify(msg, &c_sig, &_c_pk));
    });

    // Merkle tree build (1024 leaves)
    println!("\n--- Merkle Tree Build (1024 leaves, 32B each) ---");
    let leaf_data: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| rust_sha3_256(&i.to_le_bytes()).to_vec())
        .collect();
    let leaf_refs: Vec<&[u8]> = leaf_data.iter().map(|v| v.as_slice()).collect();
    let flat_leaves: Vec<u8> = leaf_data.iter().flatten().copied().collect();

    bench("Rust", 5, || {
        std::hint::black_box(rust_merkle_build_root(&leaf_refs));
    });
    bench("C", 5, || {
        std::hint::black_box(c_merkle_build_root(&flat_leaves, 1024, 32));
    });

    // Merkle proof verify
    println!("\n--- Merkle Proof Verify ---");
    let (root, proof) = merkle::merkle_build_with_proof(&leaf_refs, 500);
    let leaf_hash = rust_sha3_256(leaf_refs[500]);
    bench("Rust", 1_000, || {
        std::hint::black_box(merkle::merkle_verify_proof(&leaf_hash, &proof, &root));
    });

    // TemporalAuthTree init
    println!("\n--- TemporalAuthTree Init (1024 keys) ---");
    let batch_seed = derive_initial_batch_seed(b"bench_temporal");
    bench("Rust", 2, || {
        std::hint::black_box(TemporalAuthTree::new(batch_seed));
    });
    bench("C", 2, || {
        let mut t = c_tat_init(&batch_seed);
        std::hint::black_box(&t);
        c_tat_destroy(&mut t);
    });

    // TemporalAuthTree sign
    println!("\n--- TemporalAuthTree Sign ---");
    let mut tree = TemporalAuthTree::new(batch_seed);
    bench("Rust", 5, || {
        std::hint::black_box(tree.sign(b"bench sign message"));
    });
    let mut c_tree = c_tat_init(&batch_seed);
    bench("C", 5, || {
        std::hint::black_box(c_tat_sign(&mut c_tree, b"bench sign message"));
    });
    c_tat_destroy(&mut c_tree);

    // Batch seed derivation
    println!("\n--- Batch Seed Derivation ---");
    let mut current_seed = derive_initial_batch_seed(b"bench_chain");
    bench("Rust", 10_000, || {
        current_seed = derive_next_batch_seed(&current_seed);
        std::hint::black_box(&current_seed);
    });
    let mut c_seed = c_derive_initial_batch_seed(b"bench_chain_c");
    bench("C", 10_000, || {
        c_seed = c_derive_next_batch_seed(&c_seed);
        std::hint::black_box(&c_seed);
    });
}

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║       QRTB Native Performance Baseline          ║");
    println!("╚══════════════════════════════════════════════════╝");

    run_cross_validation();
    run_benchmarks();

    println!("\n=== Done ===");
}
