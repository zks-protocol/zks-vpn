//! ZKS Key Exchange - X25519 Ephemeral Key Agreement
//!
//! Implements secure key exchange between Client and Exit Peer:
//! 1. Both generate ephemeral X25519 keypairs
//! 2. Exchange public keys via relay
//! 3. Compute shared secret using X25519
//! 4. Derive encryption keys using HKDF-SHA256
//!
//! The relay CANNOT decrypt traffic because it never sees the private keys.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Key exchange state machine
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchangeState {
    /// Initial state - no keys generated
    Init,
    /// Local keypair generated, waiting for peer's public key
    WaitingForPeer,
    /// Key exchange complete, shared secret derived
    Complete,
    /// Key exchange failed
    Failed,
}

/// Ephemeral key pair for X25519 key exchange
pub struct KeyExchange {
    /// Our ephemeral secret (private key)
    secret: Option<EphemeralSecret>,
    /// Our public key
    pub public_key: Option<PublicKey>,
    /// Peer's public key
    peer_public_key: Option<PublicKey>,
    /// Derived shared secret (after exchange)
    shared_secret: Option<SharedSecret>,
    /// Derived encryption key (from HKDF)
    encryption_key: Option<Vec<u8>>,
    /// Current state
    pub state: KeyExchangeState,
    /// Room ID (used as HKDF salt)
    room_id: String,
}

#[allow(dead_code)]
impl KeyExchange {
    /// Create a new key exchange context
    pub fn new(room_id: &str) -> Self {
        Self {
            secret: None,
            public_key: None,
            peer_public_key: None,
            shared_secret: None,
            encryption_key: None,
            state: KeyExchangeState::Init,
            room_id: room_id.to_string(),
        }
    }

    /// Generate our ephemeral keypair
    pub fn generate_keypair(&mut self) {
        let secret = EphemeralSecret::random_from_rng(rand_core::OsRng);
        let public_key = PublicKey::from(&secret);

        self.secret = Some(secret);
        self.public_key = Some(public_key);
        self.state = KeyExchangeState::WaitingForPeer;
    }

    /// Get our public key as bytes (for sending to peer)
    pub fn get_public_key_bytes(&self) -> Option<[u8; 32]> {
        self.public_key.map(|pk| pk.to_bytes())
    }

    /// Receive peer's public key and complete the exchange
    pub fn receive_peer_public_key(&mut self, peer_pk_bytes: &[u8]) -> Result<(), &'static str> {
        if peer_pk_bytes.len() != 32 {
            self.state = KeyExchangeState::Failed;
            return Err("Invalid public key length");
        }

        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(peer_pk_bytes);
        let peer_public_key = PublicKey::from(pk_array);
        self.peer_public_key = Some(peer_public_key);

        // Compute shared secret
        if let Some(secret) = self.secret.take() {
            let shared_secret = secret.diffie_hellman(&peer_public_key);
            self.shared_secret = Some(shared_secret);

            // Derive encryption key using HKDF
            self.derive_encryption_key();
            self.state = KeyExchangeState::Complete;
            Ok(())
        } else {
            self.state = KeyExchangeState::Failed;
            Err("No local secret key")
        }
    }

    /// Derive encryption key from shared secret using HKDF-SHA256
    fn derive_encryption_key(&mut self) {
        if let Some(ref shared_secret) = self.shared_secret {
            // Use room_id as salt for domain separation
            let salt = self.room_id.as_bytes();
            let info = b"ZKS-VPN v1.0 encryption key";

            let hk = Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());

            // 1. Derive 32-byte seed using HKDF (max output is 255*32 bytes, so we can't derive 1MB directly)
            let mut seed = [0u8; 32];
            hk.expand(info, &mut seed).expect("HKDF expansion failed");

            // 2. Expand to 1MB using SHA256 counter mode
            // This creates a cryptographically secure stream from the seed
            let target_size = 1024 * 1024;
            let mut key_material = Vec::with_capacity(target_size);
            let mut counter = 0u64;
            let mut hasher = Sha256::new();

            while key_material.len() < target_size {
                hasher.update(seed);
                hasher.update(counter.to_le_bytes());
                let result = hasher.finalize_reset();
                key_material.extend_from_slice(&result);
                counter += 1;
            }

            // Truncate to exact size
            key_material.truncate(target_size);

            self.encryption_key = Some(key_material);
        }
    }

    /// Get the derived encryption key (only available after exchange complete)
    pub fn get_encryption_key(&self) -> Option<&[u8]> {
        self.encryption_key.as_deref()
    }

    /// Check if key exchange is complete
    pub fn is_complete(&self) -> bool {
        self.state == KeyExchangeState::Complete
    }
}

/// Key exchange message format (JSON)
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum KeyExchangeMessage {
    /// Send our public key to peer
    #[serde(rename = "key_exchange")]
    PublicKey {
        /// Hex-encoded X25519 public key (32 bytes)
        public_key: String,
    },
    /// Acknowledge key exchange complete
    #[serde(rename = "key_exchange_ack")]
    Ack {
        /// Indicates successful key derivation
        success: bool,
    },
}

impl KeyExchangeMessage {
    /// Create a public key message
    pub fn new_public_key(pk_bytes: &[u8; 32]) -> Self {
        Self::PublicKey {
            public_key: hex::encode(pk_bytes),
        }
    }

    /// Parse public key from message
    pub fn parse_public_key(&self) -> Option<Vec<u8>> {
        match self {
            Self::PublicKey { public_key } => hex::decode(public_key).ok(),
            _ => None,
        }
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_exchange() {
        // Simulate Client and Exit Peer
        let mut client = KeyExchange::new("test-room");
        let mut exit_peer = KeyExchange::new("test-room");

        // Both generate keypairs
        client.generate_keypair();
        exit_peer.generate_keypair();

        // Exchange public keys
        let client_pk = client.get_public_key_bytes().unwrap();
        let exit_pk = exit_peer.get_public_key_bytes().unwrap();

        // Receive each other's public keys
        client.receive_peer_public_key(&exit_pk).unwrap();
        exit_peer.receive_peer_public_key(&client_pk).unwrap();

        // Both should have the same encryption key
        assert!(client.is_complete());
        assert!(exit_peer.is_complete());

        let client_key = client.get_encryption_key().unwrap();
        let exit_key = exit_peer.get_encryption_key().unwrap();

        assert_eq!(client_key.len(), 1024 * 1024);
        assert_eq!(client_key, exit_key);
    }

    #[test]
    fn test_key_exchange_message() {
        let pk = [0x42u8; 32];
        let msg = KeyExchangeMessage::new_public_key(&pk);
        let json = msg.to_json();

        let parsed = KeyExchangeMessage::from_json(&json).unwrap();
        let recovered = parsed.parse_public_key().unwrap();

        assert_eq!(recovered, pk.to_vec());
    }
}
