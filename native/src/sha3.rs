use sha3::{Sha3_256, Sha3_512, Digest};

pub const HASH_SIZE_256: usize = 32;
pub const HASH_SIZE_512: usize = 64;

pub fn sha3_256(input: &[u8]) -> [u8; HASH_SIZE_256] {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize().into()
}

pub fn sha3_512(input: &[u8]) -> [u8; HASH_SIZE_512] {
    let mut hasher = Sha3_512::new();
    hasher.update(input);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let hash = sha3_256(b"");
        // Known SHA3-256 of empty string
        assert_eq!(
            hex::encode(hash),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn test_sha3_512_empty() {
        let hash = sha3_512(b"");
        let hex_str = hex::encode(hash);
        assert_eq!(
            &hex_str[..32],
            "a69f73cca23a9ac5c8b567dc185a756e"
        );
    }

    #[test]
    fn test_sha3_256_deterministic() {
        let h1 = sha3_256(b"test input");
        let h2 = sha3_256(b"test input");
        assert_eq!(h1, h2);
    }
}
