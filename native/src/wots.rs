use crate::sha3::sha3_256;

pub const WOTS_N: usize = 32;
pub const WOTS_W: usize = 16;
pub const WOTS_LEN1: usize = 64;
pub const WOTS_LEN2: usize = 3;
pub const WOTS_LEN_TOTAL: usize = 67;
pub const WOTS_SIG_SIZE: usize = WOTS_LEN_TOTAL * WOTS_N; // 2144 bytes

/// Hash chain: compute H^iterations(start)
fn hash_chain(start: &[u8; WOTS_N], iterations: usize) -> [u8; WOTS_N] {
    let mut out = *start;
    for _ in 0..iterations {
        out = sha3_256(&out);
    }
    out
}

/// Derive chain seed: SHA3-256(seed || "wots_chain" || index_be64)
fn derive_chain_seed(seed: &[u8; 64], index: usize) -> [u8; WOTS_N] {
    let mut buf = Vec::with_capacity(82);
    buf.extend_from_slice(seed);
    buf.extend_from_slice(b"wots_chain");
    buf.extend_from_slice(&(index as u64).to_be_bytes());
    sha3_256(&buf)
}

/// WOTS+ key generation from 64-byte seed
pub fn wots_keygen(seed: &[u8; 64]) -> (Vec<u8>, Vec<u8>) {
    let mut private_key = vec![0u8; WOTS_SIG_SIZE];
    let mut public_key = vec![0u8; WOTS_SIG_SIZE];

    for i in 0..WOTS_LEN_TOTAL {
        let chain_seed = derive_chain_seed(seed, i);
        private_key[i * WOTS_N..(i + 1) * WOTS_N].copy_from_slice(&chain_seed);
        let pub_chain = hash_chain(&chain_seed, WOTS_W - 1);
        public_key[i * WOTS_N..(i + 1) * WOTS_N].copy_from_slice(&pub_chain);
    }

    (private_key, public_key)
}

/// Compute message chunks + checksum
fn compute_chunks(message: &[u8]) -> [u8; WOTS_LEN_TOTAL] {
    let msg_hash = sha3_256(message);
    let mut chunks = [0u8; WOTS_LEN_TOTAL];

    // Split into 4-bit chunks
    for i in 0..32 {
        chunks[i * 2] = (msg_hash[i] >> 4) & 0x0F;
        chunks[i * 2 + 1] = msg_hash[i] & 0x0F;
    }

    // Compute checksum
    let mut checksum: u32 = 0;
    for i in 0..WOTS_LEN1 {
        checksum += (WOTS_W as u32) - 1 - (chunks[i] as u32);
    }

    // Encode checksum as 3 chunks
    chunks[64] = ((checksum >> 8) & 0x0F) as u8;
    chunks[65] = ((checksum >> 4) & 0x0F) as u8;
    chunks[66] = (checksum & 0x0F) as u8;

    chunks
}

/// Sign a message with WOTS+
pub fn wots_sign(message: &[u8], private_key: &[u8]) -> Vec<u8> {
    assert_eq!(private_key.len(), WOTS_SIG_SIZE);
    let chunks = compute_chunks(message);
    let mut signature = vec![0u8; WOTS_SIG_SIZE];

    for i in 0..WOTS_LEN_TOTAL {
        let mut start = [0u8; WOTS_N];
        start.copy_from_slice(&private_key[i * WOTS_N..(i + 1) * WOTS_N]);
        let chain = hash_chain(&start, chunks[i] as usize);
        signature[i * WOTS_N..(i + 1) * WOTS_N].copy_from_slice(&chain);
    }

    signature
}

/// Verify a WOTS+ signature. Returns true if valid.
pub fn wots_verify(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    assert_eq!(signature.len(), WOTS_SIG_SIZE);
    assert_eq!(public_key.len(), WOTS_SIG_SIZE);

    let chunks = compute_chunks(message);

    for i in 0..WOTS_LEN_TOTAL {
        let remaining = (WOTS_W - 1) - chunks[i] as usize;
        let mut sig_chunk = [0u8; WOTS_N];
        sig_chunk.copy_from_slice(&signature[i * WOTS_N..(i + 1) * WOTS_N]);
        let computed = hash_chain(&sig_chunk, remaining);
        if computed != public_key[i * WOTS_N..(i + 1) * WOTS_N] {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::sha3_512;

    #[test]
    fn test_keygen_deterministic() {
        let seed = sha3_512(b"test_seed");
        let (sk1, pk1) = wots_keygen(&seed);
        let (sk2, pk2) = wots_keygen(&seed);
        assert_eq!(sk1, sk2);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_sign_verify() {
        let seed = sha3_512(b"wots_test_seed");
        let (sk, pk) = wots_keygen(&seed);
        let msg = b"hello world";
        let sig = wots_sign(msg, &sk);
        assert!(wots_verify(msg, &sig, &pk));
    }

    #[test]
    fn test_wrong_message_fails() {
        let seed = sha3_512(b"wots_test_seed_2");
        let (sk, pk) = wots_keygen(&seed);
        let sig = wots_sign(b"message A", &sk);
        assert!(!wots_verify(b"message B", &sig, &pk));
    }

    #[test]
    fn test_signature_size() {
        let seed = sha3_512(b"size_test");
        let (sk, pk) = wots_keygen(&seed);
        assert_eq!(sk.len(), WOTS_SIG_SIZE);
        assert_eq!(pk.len(), WOTS_SIG_SIZE);
        let sig = wots_sign(b"data", &sk);
        assert_eq!(sig.len(), WOTS_SIG_SIZE);
    }
}
