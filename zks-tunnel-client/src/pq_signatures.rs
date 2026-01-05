//! Post-Quantum Signatures using ML-DSA-65 (Dilithium)
//!
//! Provides quantum-resistant digital signatures for key exchange authentication.
//! ML-DSA-65 (formerly Dilithium3) is a NIST-approved post-quantum signature scheme.
//!
//! # Security Level
//! - ML-DSA-65 provides NIST Level 3 security (equivalent to AES-192)
//! - Resistant to attacks from both classical and quantum computers
//!
//! # Key Sizes
//! - Public key: 1952 bytes
//! - Secret key: 4032 bytes  
//! - Signature: 3309 bytes

use zeroize::Zeroizing;

/// ML-DSA-65 public key size
pub const PUBLIC_KEY_SIZE: usize = 1952;

/// ML-DSA-65 secret key size
pub const SECRET_KEY_SIZE: usize = 4032;

/// ML-DSA-65 signature size
pub const SIGNATURE_SIZE: usize = 3309;

/// Post-quantum signature keypair
pub struct PQSignatureKeypair {
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// Secret key for signing (zeroized on drop)
    secret_key: Zeroizing<Vec<u8>>,
}

impl PQSignatureKeypair {
    /// Generate a new ML-DSA-65 keypair
    pub fn generate() -> Result<Self, &'static str> {
        use ml_dsa::{KeyGen, MlDsa65};
        use rand_core::OsRng;

        // Generate keypair using OS random number generator
        let keypair = MlDsa65::key_gen(&mut OsRng);

        // Extract keys as bytes
        let public_key = keypair.verifying_key().encode().as_slice().to_vec();
        let secret_key = Zeroizing::new(keypair.signing_key().encode().as_slice().to_vec());

        tracing::info!(
            "🔐 Generated ML-DSA-65 keypair (pk: {} bytes, sk: {} bytes)",
            public_key.len(),
            secret_key.len()
        );

        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Sign a message using the secret key
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, &'static str> {
        use ml_dsa::{EncodedSigningKey, MlDsa65, SigningKey};
        use ml_dsa::signature::Signer;

        // Decode our secret key with explicit type parameter
        let encoded_sk = EncodedSigningKey::<MlDsa65>::try_from(self.secret_key.as_slice())
            .map_err(|_| "Failed to decode secret key")?;
        let signing_key: SigningKey<MlDsa65> = SigningKey::decode(&encoded_sk);

        // Sign the message
        let signature = signing_key.sign(message);
        let sig_bytes = signature.encode().as_slice().to_vec();

        tracing::debug!(
            "🖊️ Signed {} byte message, signature: {} bytes",
            message.len(),
            sig_bytes.len()
        );

        Ok(sig_bytes)
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Verify a signature using a public key
///
/// # Arguments
/// * `public_key` - ML-DSA-65 public key bytes
/// * `message` - The original message that was signed
/// * `signature` - The signature to verify
///
/// # Returns
/// * `Ok(())` if signature is valid
/// * `Err(...)` if signature is invalid or verification failed
pub fn verify_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};
    use ml_dsa::signature::Verifier;

    // Decode public key
    let encoded_pk = EncodedVerifyingKey::<MlDsa65>::try_from(public_key)
        .map_err(|_| "Failed to decode public key")?;
    let verifying_key = VerifyingKey::<MlDsa65>::decode(&encoded_pk);

    // Decode signature
    let encoded_sig = EncodedSignature::<MlDsa65>::try_from(signature)
        .map_err(|_| "Failed to decode signature")?;
    let sig = Signature::decode(&encoded_sig)
        .ok_or("Failed to parse signature")?;

    // Verify
    verifying_key
        .verify(message, &sig)
        .map_err(|_| "Signature verification failed")
}

/// Sign for key exchange: Signs the ephemeral public key + Kyber public key
/// This binds the signature to the specific key exchange session
pub fn sign_key_exchange(
    keypair: &PQSignatureKeypair,
    ephemeral_pk: &[u8; 32],
    kyber_pk: &[u8],
) -> Result<Vec<u8>, &'static str> {
    // Construct message to sign: ephemeral_pk || kyber_pk
    let mut message = Vec::with_capacity(32 + kyber_pk.len());
    message.extend_from_slice(ephemeral_pk);
    message.extend_from_slice(kyber_pk);

    keypair.sign(&message)
}

/// Verify a key exchange signature
pub fn verify_key_exchange_signature(
    sig_pk: &[u8],
    ephemeral_pk: &[u8; 32],
    kyber_pk: &[u8],
    signature: &[u8],
) -> Result<(), &'static str> {
    // Reconstruct the signed message
    let mut message = Vec::with_capacity(32 + kyber_pk.len());
    message.extend_from_slice(ephemeral_pk);
    message.extend_from_slice(kyber_pk);

    verify_signature(sig_pk, &message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = PQSignatureKeypair::generate().unwrap();
        assert_eq!(keypair.public_key.len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = PQSignatureKeypair::generate().unwrap();
        let message = b"Test message for signing";

        let signature = keypair.sign(message).unwrap();
        assert_eq!(signature.len(), SIGNATURE_SIZE);

        // Verify should succeed
        let result = verify_signature(&keypair.public_key, message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_signature_rejected() {
        let keypair = PQSignatureKeypair::generate().unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message).unwrap();

        // Verifying with wrong message should fail
        let result = verify_signature(&keypair.public_key, wrong_message, &signature);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_exchange_signature() {
        let keypair = PQSignatureKeypair::generate().unwrap();
        let ephemeral_pk = [0x42u8; 32];
        let kyber_pk = vec![0xABu8; 1184]; // ML-KEM-768 public key size

        let signature = sign_key_exchange(&keypair, &ephemeral_pk, &kyber_pk).unwrap();

        // Verify should succeed
        let result = verify_key_exchange_signature(
            &keypair.public_key,
            &ephemeral_pk,
            &kyber_pk,
            &signature,
        );
        assert!(result.is_ok());
    }
}
