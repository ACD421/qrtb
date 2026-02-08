use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use qrtb_native::sha3::{sha3_256 as rust_sha3_256, sha3_512 as rust_sha3_512};
use qrtb_native::wots::{wots_keygen as rust_wots_keygen, wots_sign as rust_wots_sign, wots_verify as rust_wots_verify};
use qrtb_native::merkle::{merkle_build_root, merkle_build_with_proof, merkle_verify_proof};
use qrtb_native::temporal_auth::{TemporalAuthTree, derive_initial_batch_seed, derive_next_batch_seed};
use qrtb_native::ffi::{c_sha3_256, c_sha3_512, c_wots_keygen, c_wots_sign, c_wots_verify, c_merkle_build_root};

fn bench_sha3_256(c: &mut Criterion) {
    let input = [0x42u8; 32];
    let mut group = c.benchmark_group("SHA3-256 (32B)");

    group.bench_function("Rust", |b| {
        b.iter(|| rust_sha3_256(&input))
    });
    group.bench_function("C", |b| {
        b.iter(|| c_sha3_256(&input))
    });

    group.finish();
}

fn bench_sha3_512(c: &mut Criterion) {
    let input = [0x42u8; 64];
    let mut group = c.benchmark_group("SHA3-512 (64B)");

    group.bench_function("Rust", |b| {
        b.iter(|| rust_sha3_512(&input))
    });
    group.bench_function("C", |b| {
        b.iter(|| c_sha3_512(&input))
    });

    group.finish();
}

fn bench_wots_keygen(c: &mut Criterion) {
    let seed = rust_sha3_512(b"bench_keygen");
    let mut group = c.benchmark_group("WOTS+ Keygen");

    group.sample_size(10);
    group.bench_function("Rust", |b| {
        b.iter(|| rust_wots_keygen(&seed))
    });
    group.bench_function("C", |b| {
        b.iter(|| c_wots_keygen(&seed))
    });

    group.finish();
}

fn bench_wots_sign(c: &mut Criterion) {
    let seed = rust_sha3_512(b"bench_sign");
    let (r_sk, _) = rust_wots_keygen(&seed);
    let (c_sk, _) = c_wots_keygen(&seed);
    let msg = b"benchmark signing message";

    let mut group = c.benchmark_group("WOTS+ Sign");
    group.sample_size(10);

    group.bench_function("Rust", |b| {
        b.iter(|| rust_wots_sign(msg, &r_sk))
    });
    group.bench_function("C", |b| {
        b.iter(|| c_wots_sign(msg, &c_sk))
    });

    group.finish();
}

fn bench_wots_verify(c: &mut Criterion) {
    let seed = rust_sha3_512(b"bench_verify");
    let (r_sk, r_pk) = rust_wots_keygen(&seed);
    let (c_sk, c_pk) = c_wots_keygen(&seed);
    let msg = b"benchmark verify message";
    let r_sig = rust_wots_sign(msg, &r_sk);
    let c_sig = c_wots_sign(msg, &c_sk);

    let mut group = c.benchmark_group("WOTS+ Verify");
    group.sample_size(10);

    group.bench_function("Rust", |b| {
        b.iter(|| rust_wots_verify(msg, &r_sig, &r_pk))
    });
    group.bench_function("C", |b| {
        b.iter(|| c_wots_verify(msg, &c_sig, &c_pk))
    });

    group.finish();
}

fn bench_merkle_build(c: &mut Criterion) {
    let leaf_data: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| rust_sha3_256(&i.to_le_bytes()).to_vec())
        .collect();
    let leaf_refs: Vec<&[u8]> = leaf_data.iter().map(|v| v.as_slice()).collect();
    let flat_leaves: Vec<u8> = leaf_data.iter().flatten().copied().collect();

    let mut group = c.benchmark_group("Merkle Build (1024 leaves)");
    group.sample_size(10);

    group.bench_function("Rust", |b| {
        b.iter(|| merkle_build_root(&leaf_refs))
    });
    group.bench_function("C", |b| {
        b.iter(|| c_merkle_build_root(&flat_leaves, 1024, 32))
    });

    group.finish();
}

fn bench_merkle_verify(c: &mut Criterion) {
    let leaf_data: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| rust_sha3_256(&i.to_le_bytes()).to_vec())
        .collect();
    let leaf_refs: Vec<&[u8]> = leaf_data.iter().map(|v| v.as_slice()).collect();
    let (root, proof) = merkle_build_with_proof(&leaf_refs, 500);
    let leaf_hash = rust_sha3_256(leaf_refs[500]);

    c.bench_function("Merkle Proof Verify (Rust)", |b| {
        b.iter(|| merkle_verify_proof(&leaf_hash, &proof, &root))
    });
}

fn bench_temporal_auth_init(c: &mut Criterion) {
    let batch_seed = derive_initial_batch_seed(b"bench_init");

    let mut group = c.benchmark_group("TemporalAuth Init");
    group.sample_size(10);

    group.bench_function("1024 keys", |b| {
        b.iter(|| TemporalAuthTree::new(batch_seed))
    });

    group.finish();
}

fn bench_batch_seed(c: &mut Criterion) {
    let mut seed = derive_initial_batch_seed(b"bench_chain");

    c.bench_function("Batch Seed Derivation", |b| {
        b.iter(|| {
            seed = derive_next_batch_seed(&seed);
            seed
        })
    });
}

criterion_group!(
    benches,
    bench_sha3_256,
    bench_sha3_512,
    bench_wots_keygen,
    bench_wots_sign,
    bench_wots_verify,
    bench_merkle_build,
    bench_merkle_verify,
    bench_temporal_auth_init,
    bench_batch_seed,
);
criterion_main!(benches);
