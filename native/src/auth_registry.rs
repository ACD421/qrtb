use std::collections::HashMap;
use crate::merkle::MERKLE_HASH_SIZE;

/// Authentication registry: tracks registered addresses and their current auth_root
pub struct AuthRegistry {
    entries: HashMap<Vec<u8>, AuthEntry>,
}

struct AuthEntry {
    auth_root: [u8; MERKLE_HASH_SIZE],
    rotation_count: u32,
}

impl AuthRegistry {
    pub fn new() -> Self {
        AuthRegistry {
            entries: HashMap::new(),
        }
    }

    /// Register an address with its initial auth_root. Returns false if already registered.
    pub fn register(&mut self, address: &[u8], auth_root: [u8; MERKLE_HASH_SIZE]) -> bool {
        if self.entries.contains_key(address) {
            return false; // Already registered
        }
        self.entries.insert(address.to_vec(), AuthEntry {
            auth_root,
            rotation_count: 0,
        });
        true
    }

    /// Rotate the auth_root for a registered address. Returns false if not registered.
    pub fn rotate(&mut self, address: &[u8], new_auth_root: [u8; MERKLE_HASH_SIZE]) -> bool {
        if let Some(entry) = self.entries.get_mut(address) {
            entry.auth_root = new_auth_root;
            entry.rotation_count += 1;
            true
        } else {
            false
        }
    }

    /// Check if an address is registered
    pub fn is_registered(&self, address: &[u8]) -> bool {
        self.entries.contains_key(address)
    }

    /// Get the current auth_root for an address
    pub fn get_auth_root(&self, address: &[u8]) -> Option<&[u8; MERKLE_HASH_SIZE]> {
        self.entries.get(address).map(|e| &e.auth_root)
    }

    /// Get the rotation count for an address
    pub fn get_rotation_count(&self, address: &[u8]) -> Option<u32> {
        self.entries.get(address).map(|e| e.rotation_count)
    }

    /// Number of registered addresses
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AuthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha3::sha3_256;

    #[test]
    fn test_register_and_lookup() {
        let mut reg = AuthRegistry::new();
        let addr = sha3_256(b"address1");
        let root = sha3_256(b"auth_root1");

        assert!(reg.register(&addr, root));
        assert!(reg.is_registered(&addr));
        assert_eq!(reg.get_auth_root(&addr), Some(&root));
    }

    #[test]
    fn test_double_register_fails() {
        let mut reg = AuthRegistry::new();
        let addr = sha3_256(b"address2");
        let root = sha3_256(b"root2");

        assert!(reg.register(&addr, root));
        assert!(!reg.register(&addr, root)); // Already registered
    }

    #[test]
    fn test_rotate() {
        let mut reg = AuthRegistry::new();
        let addr = sha3_256(b"address3");
        let root1 = sha3_256(b"root_v1");
        let root2 = sha3_256(b"root_v2");

        reg.register(&addr, root1);
        assert!(reg.rotate(&addr, root2));
        assert_eq!(reg.get_auth_root(&addr), Some(&root2));
        assert_eq!(reg.get_rotation_count(&addr), Some(1));
    }

    #[test]
    fn test_rotate_unregistered_fails() {
        let mut reg = AuthRegistry::new();
        let addr = sha3_256(b"unknown");
        let root = sha3_256(b"root");
        assert!(!reg.rotate(&addr, root));
    }
}
