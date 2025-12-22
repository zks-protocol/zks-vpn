//! Kyber768 Hybrid Key Exchange - Post-Quantum Safe
//!
//! Implements hybrid key exchange:
//!   K_Local = X25519_shared ⊕ Kyber768_shared
//!
//! This provides:
//! - Classical security from X25519
//! - Quantum resistance from Kyber768 (NIST PQC winner)
//! - If either is broken, the other still protects

#[cfg(feature = "swarm")]
use pqcrypto_kyber::kyber768::{self, Ciphertext, PublicKey, SecretKey, SharedSecret};

/// Size of the final derived key
pub const KEY_SIZE: usize = 32;

/// Kyber768 keypair for key encapsulation
#[cfg(feature = "swarm")]
pub struct KyberKeypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[cfg(feature = "swarm")]
impl KyberKeypair {
    /// Generate a new Kyber768 keypair
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        Self {
            public_key: pk,
            secret_key: sk,
        }
    }

    /// Get public key bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        pqcrypto_traits::kem::PublicKey::as_bytes(&self.public_key).to_vec()
    }

    /// Decapsulate to get shared secret
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Option<[u8; KEY_SIZE]> {
        use pqcrypto_traits::kem::Ciphertext as CiphertextTrait;

        let ct = Ciphertext::from_bytes(ciphertext).ok()?;
        let shared = kyber768::decapsulate(&ct, &self.secret_key);

        let bytes = pqcrypto_traits::kem::SharedSecret::as_bytes(&shared);
        if bytes.len() < KEY_SIZE {
            return None;
        }

        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(&bytes[..KEY_SIZE]);
        Some(key)
    }
}

/// Encapsulate for a peer's public key
#[cfg(feature = "swarm")]
pub fn encapsulate(peer_public_key: &[u8]) -> Option<(Vec<u8>, [u8; KEY_SIZE])> {
    use pqcrypto_traits::kem::{
        Ciphertext as CtTrait, PublicKey as PkTrait, SharedSecret as SsTrait,
    };

    let pk = PublicKey::from_bytes(peer_public_key).ok()?;
    let (shared, ct) = kyber768::encapsulate(&pk);

    let shared_bytes = shared.as_bytes();
    if shared_bytes.len() < KEY_SIZE {
        return None;
    }

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&shared_bytes[..KEY_SIZE]);

    Some((ct.as_bytes().to_vec(), key))
}

/// Combine X25519 and Kyber768 keys into a hybrid key
#[cfg(feature = "swarm")]
pub fn hybrid_xor(x25519_key: &[u8; KEY_SIZE], kyber_key: &[u8; KEY_SIZE]) -> [u8; KEY_SIZE] {
    let mut hybrid = [0u8; KEY_SIZE];
    for i in 0..KEY_SIZE {
        hybrid[i] = x25519_key[i] ^ kyber_key[i];
    }
    hybrid
}

/// Hybrid key exchange result
#[cfg(feature = "swarm")]
pub struct HybridKeyExchange {
    /// X25519 component
    pub x25519_key: [u8; KEY_SIZE],
    /// Kyber768 component
    pub kyber_key: [u8; KEY_SIZE],
    /// Combined hybrid key: X25519 ⊕ Kyber768
    pub hybrid_key: [u8; KEY_SIZE],
}

#[cfg(feature = "swarm")]
impl HybridKeyExchange {
    /// Create a new hybrid key from X25519 and Kyber components
    pub fn new(x25519_key: [u8; KEY_SIZE], kyber_key: [u8; KEY_SIZE]) -> Self {
        let hybrid_key = hybrid_xor(&x25519_key, &kyber_key);
        Self {
            x25519_key,
            kyber_key,
            hybrid_key,
        }
    }

    /// Get the final K_Local for Wasif-Vernam cipher
    pub fn get_k_local(&self) -> [u8; KEY_SIZE] {
        self.hybrid_key
    }
}

#[cfg(all(test, feature = "swarm"))]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_keypair() {
        let keypair = KyberKeypair::generate();
        let pk_bytes = keypair.public_key_bytes();

        // Encapsulate
        let (ct, shared_a) = encapsulate(&pk_bytes).unwrap();

        // Decapsulate
        let shared_b = keypair.decapsulate(&ct).unwrap();

        // Both should have the same shared secret
        assert_eq!(shared_a, shared_b);
    }

    #[test]
    fn test_hybrid_xor() {
        let x25519 = [0x42u8; KEY_SIZE];
        let kyber = [0x13u8; KEY_SIZE];

        let hybrid = hybrid_xor(&x25519, &kyber);

        // XOR result
        assert_eq!(hybrid[0], 0x42 ^ 0x13);

        // XOR is reversible
        let recovered = hybrid_xor(&hybrid, &kyber);
        assert_eq!(recovered, x25519);
    }

    #[test]
    fn test_hybrid_key_exchange() {
        let x25519 = [0xAAu8; KEY_SIZE];
        let kyber = [0x55u8; KEY_SIZE];

        let exchange = HybridKeyExchange::new(x25519, kyber);

        // K_Local should be hybrid
        assert_eq!(exchange.get_k_local()[0], 0xAA ^ 0x55);
    }
}
