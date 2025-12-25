//! Onion Routing - Multi-Layer Wasif-Vernam Encryption for Triple-Blind Privacy
//!
//! Implements onion-style encryption where each hop can only decrypt its layer:
//! - Layer 2 (outer): Encrypted with Relay Peer key
//! - Layer 1 (inner): Encrypted with Exit Peer key
//!
//! This ensures:
//! - Relay knows Client IP, but cannot see destination (encrypted)
//! - Exit knows destination, but cannot see Client IP (only sees Relay)

#![allow(dead_code)]

use tracing::{debug, info};

/// Onion-encrypted packet with two layers
#[derive(Debug, Clone)]
pub struct OnionPacket {
    /// The encrypted payload (layers applied from inside out)
    pub data: Vec<u8>,
    /// Number of encryption layers remaining
    pub layers: u8,
}

/// Onion encryption keys for a route
#[derive(Clone)]
pub struct OnionKeys {
    /// Key for Layer 1 (Exit Peer) - innermost
    pub exit_key: [u8; 32],
    /// Key for Layer 2 (Relay Peer) - outermost
    pub relay_key: [u8; 32],
    /// Swarm entropy (K_Remote) - XOR'd with both layers
    pub k_remote: [u8; 32],
}

impl OnionKeys {
    /// Create new onion keys from key exchange results
    pub fn new(exit_key: [u8; 32], relay_key: [u8; 32], k_remote: [u8; 32]) -> Self {
        Self {
            exit_key,
            relay_key,
            k_remote,
        }
    }
}

/// Encrypt data with onion layers (client-side)
///
/// Wraps plaintext in two layers:
/// 1. First encrypt with exit_key ⊕ k_remote (Exit Peer will decrypt this)
/// 2. Then encrypt with relay_key ⊕ k_remote (Relay Peer will decrypt this)
pub fn encrypt_onion(plaintext: &[u8], keys: &OnionKeys) -> OnionPacket {
    debug!(
        "Encrypting onion packet ({} bytes, 2 layers)",
        plaintext.len()
    );

    // Layer 1: Encrypt for Exit Peer
    let layer1 = xor_encrypt(plaintext, &keys.exit_key, &keys.k_remote);

    // Layer 2: Encrypt for Relay Peer
    let layer2 = xor_encrypt(&layer1, &keys.relay_key, &keys.k_remote);

    OnionPacket {
        data: layer2,
        layers: 2,
    }
}

/// Decrypt one onion layer (relay or exit side)
///
/// Each node decrypts with its key ⊕ k_remote, then passes to next hop
pub fn decrypt_onion_layer(
    packet: &OnionPacket,
    key: &[u8; 32],
    k_remote: &[u8; 32],
) -> OnionPacket {
    debug!(
        "Decrypting onion layer ({} bytes, {} layers remaining)",
        packet.data.len(),
        packet.layers
    );

    let decrypted = xor_decrypt(&packet.data, key, k_remote);

    OnionPacket {
        data: decrypted,
        layers: packet.layers.saturating_sub(1),
    }
}

/// Wasif-Vernam XOR encryption: P ⊕ K_Local ⊕ K_Remote
fn xor_encrypt(plaintext: &[u8], k_local: &[u8; 32], k_remote: &[u8; 32]) -> Vec<u8> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());

    for (i, &byte) in plaintext.iter().enumerate() {
        let key_byte = k_local[i % 32] ^ k_remote[i % 32];
        ciphertext.push(byte ^ key_byte);
    }

    ciphertext
}

/// Wasif-Vernam XOR decryption (same as encryption - symmetric)
fn xor_decrypt(ciphertext: &[u8], k_local: &[u8; 32], k_remote: &[u8; 32]) -> Vec<u8> {
    xor_encrypt(ciphertext, k_local, k_remote) // XOR is symmetric
}

/// Route through the onion network
#[derive(Debug, Clone)]
pub struct OnionRoute {
    /// Relay peer info (first hop)
    pub relay_peer_id: String,
    pub relay_addr: String,
    /// Exit peer info (final hop)
    pub exit_peer_id: String,
    pub exit_addr: String,
}

impl OnionRoute {
    /// Create a new 2-hop onion route
    pub fn new(
        relay_peer_id: impl Into<String>,
        relay_addr: impl Into<String>,
        exit_peer_id: impl Into<String>,
        exit_addr: impl Into<String>,
    ) -> Self {
        Self {
            relay_peer_id: relay_peer_id.into(),
            relay_addr: relay_addr.into(),
            exit_peer_id: exit_peer_id.into(),
            exit_addr: exit_addr.into(),
        }
    }

    /// Log the route for debugging
    pub fn log_route(&self) {
        info!("🧅 Onion Route:");
        info!("   1. Relay: {} @ {}", self.relay_peer_id, self.relay_addr);
        info!("   2. Exit:  {} @ {}", self.exit_peer_id, self.exit_addr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_encryption() {
        let plaintext = b"Hello, Triple-Blind World!";
        let keys = OnionKeys {
            exit_key: [0x42; 32],
            relay_key: [0x13; 32],
            k_remote: [0x37; 32],
        };

        // Client encrypts
        let onion = encrypt_onion(plaintext, &keys);
        assert_eq!(onion.layers, 2);
        assert_ne!(&onion.data, plaintext); // Should be encrypted

        // Relay decrypts layer 2
        let after_relay = decrypt_onion_layer(&onion, &keys.relay_key, &keys.k_remote);
        assert_eq!(after_relay.layers, 1);

        // Exit decrypts layer 1
        let final_data = decrypt_onion_layer(&after_relay, &keys.exit_key, &keys.k_remote);
        assert_eq!(final_data.layers, 0);
        assert_eq!(&final_data.data, plaintext); // Should be decrypted
    }
}
