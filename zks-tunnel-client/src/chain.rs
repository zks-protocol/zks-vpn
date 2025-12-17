//! Multi-Hop Chain Builder for ZKS-over-ZKS Encryption
//!
//! Creates encrypted onion layers for multi-hop routing through multiple relays.
//! Each layer is encrypted with the ZKS keys of the corresponding hop.
//!
//! Architecture (3-hop example):
//! ```text
//! Client encrypts layers in reverse order:
//!   Layer 3 (innermost): For Exit Peer - contains actual destination
//!   Layer 2: For VPS-2 - contains Layer 3 + routing info to Exit Peer
//!   Layer 1 (outermost): For VPS-1 - contains Layer 2 + routing to VPS-2
//!
//! On the wire:
//!   [Client] → VPS-1 → VPS-2 → Exit Peer → Internet
//!
//! Each hop:
//!   1. Receives encrypted blob
//!   2. Decrypts with its ZKS keys
//!   3. Sees next_room and inner encrypted payload
//!   4. Forwards to next_room
//! ```

use bytes::Bytes;
use std::sync::atomic::{AtomicU32, Ordering};

/// Global chain ID counter
static CHAIN_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Configuration for a single hop in the chain
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct HopConfig {
    /// Relay URL for this hop (e.g., wss://relay.workers.dev)
    pub relay_url: String,
    /// Room ID at this relay
    pub room_id: String,
    /// Vernam key URL for this hop
    pub vernam_url: String,
}

/// Multi-hop chain configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ChainConfig {
    /// Ordered list of hops (first = entry, last = exit)
    pub hops: Vec<HopConfig>,
}

#[allow(dead_code)]
impl ChainConfig {
    /// Create a new chain config
    pub fn new() -> Self {
        Self { hops: Vec::new() }
    }

    /// Add a hop to the chain
    pub fn add_hop(&mut self, relay_url: &str, room_id: &str, vernam_url: &str) {
        self.hops.push(HopConfig {
            relay_url: relay_url.to_string(),
            room_id: room_id.to_string(),
            vernam_url: vernam_url.to_string(),
        });
    }

    /// Number of hops in the chain
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Check if chain is empty
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

impl Default for ChainConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Encryption context for a single hop
#[allow(dead_code)]
pub struct HopContext {
    /// Local key (CSPRNG)
    pub local_key: Vec<u8>,
    /// Remote key (from Vernam server)
    pub remote_key: Vec<u8>,
    /// Current key position
    pub key_pos: usize,
}

impl HopContext {
    /// Create a new hop context with generated local key
    pub fn new(key_size: usize) -> Self {
        let mut local_key = vec![0u8; key_size];
        getrandom::getrandom(&mut local_key).unwrap_or_default();

        Self {
            local_key,
            remote_key: Vec::new(),
            key_pos: 0,
        }
    }

    /// Set the remote key (fetched from Vernam server)
    pub fn set_remote_key(&mut self, key: Vec<u8>) {
        self.remote_key = key;
    }

    /// Encrypt/decrypt data using double-key Vernam
    /// Ciphertext = Plaintext XOR LocalKey XOR RemoteKey
    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());

        for byte in data {
            let local_byte = self.local_key[self.key_pos % self.local_key.len()];
            let remote_byte = if !self.remote_key.is_empty() {
                self.remote_key[self.key_pos % self.remote_key.len()]
            } else {
                0
            };

            result.push(byte ^ local_byte ^ remote_byte);
            self.key_pos += 1;
        }

        result
    }
}

/// Chain builder for multi-hop encryption
#[allow(dead_code)]
pub struct ChainBuilder {
    /// Chain configuration
    config: ChainConfig,
    /// Encryption contexts for each hop
    hop_contexts: Vec<HopContext>,
    /// Current chain ID
    chain_id: u32,
}

#[allow(dead_code)]
impl ChainBuilder {
    /// Create a new chain builder
    pub fn new(config: ChainConfig) -> Self {
        let mut hop_contexts = Vec::with_capacity(config.hops.len());

        // Create encryption context for each hop
        // Key size = 64KB (enough for most messages, will cycle if needed)
        for _ in &config.hops {
            hop_contexts.push(HopContext::new(65536));
        }

        Self {
            config,
            hop_contexts,
            chain_id: CHAIN_ID_COUNTER.fetch_add(1, Ordering::SeqCst),
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    /// Get the chain configuration
    pub fn config(&self) -> &ChainConfig {
        &self.config
    }

    /// Set remote key for a specific hop
    pub fn set_hop_remote_key(&mut self, hop_index: usize, key: Vec<u8>) {
        if hop_index < self.hop_contexts.len() {
            self.hop_contexts[hop_index].set_remote_key(key);
        }
    }

    /// Encrypt payload for the chain (apply layers in reverse order)
    ///
    /// For a 3-hop chain (A → B → C → Exit):
    /// 1. Encrypt for C (innermost)
    /// 2. Encrypt for B
    /// 3. Encrypt for A (outermost)
    ///
    /// Each layer includes routing info to the next hop.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        if self.hop_contexts.is_empty() {
            return plaintext.to_vec();
        }

        let mut current = plaintext.to_vec();

        // Apply encryption in reverse order (innermost first)
        for i in (0..self.hop_contexts.len()).rev() {
            // Add routing header for next hop (except for innermost layer)
            if i < self.hop_contexts.len() - 1 {
                // Format: [next_room_len:2][next_room:N][payload_len:4][payload:N]
                let next_room = &self.config.hops[i + 1].room_id;
                let mut with_header = Vec::new();
                with_header.extend_from_slice(&(next_room.len() as u16).to_be_bytes());
                with_header.extend_from_slice(next_room.as_bytes());
                with_header.extend_from_slice(&(current.len() as u32).to_be_bytes());
                with_header.extend_from_slice(&current);
                current = with_header;
            }

            // Encrypt with this hop's keys
            current = self.hop_contexts[i].apply(&current);
        }

        current
    }

    /// Decrypt a layer (called by intermediate hops)
    /// Returns (next_room, inner_payload) or None if this is the final hop
    pub fn decrypt_layer(&mut self, hop_index: usize, data: &[u8]) -> Option<(String, Bytes)> {
        if hop_index >= self.hop_contexts.len() {
            return None;
        }

        // Decrypt with this hop's keys
        let decrypted = self.hop_contexts[hop_index].apply(data);

        // If this is the last hop, return the payload directly
        if hop_index == self.hop_contexts.len() - 1 {
            return None; // Final destination
        }

        // Parse routing header
        if decrypted.len() < 6 {
            return None;
        }

        let room_len = u16::from_be_bytes([decrypted[0], decrypted[1]]) as usize;
        if decrypted.len() < 2 + room_len + 4 {
            return None;
        }

        let next_room = String::from_utf8(decrypted[2..2 + room_len].to_vec()).ok()?;

        let payload_len_start = 2 + room_len;
        let payload_len = u32::from_be_bytes([
            decrypted[payload_len_start],
            decrypted[payload_len_start + 1],
            decrypted[payload_len_start + 2],
            decrypted[payload_len_start + 3],
        ]) as usize;

        let payload_start = payload_len_start + 4;
        if decrypted.len() < payload_start + payload_len {
            return None;
        }

        let payload =
            Bytes::copy_from_slice(&decrypted[payload_start..payload_start + payload_len]);

        Some((next_room, payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_config() {
        let mut config = ChainConfig::new();
        config.add_hop(
            "wss://relay1.workers.dev",
            "room-1",
            "https://vernam1.workers.dev",
        );
        config.add_hop(
            "wss://relay2.workers.dev",
            "room-2",
            "https://vernam2.workers.dev",
        );

        assert_eq!(config.len(), 2);
        assert!(!config.is_empty());
    }

    #[test]
    fn test_hop_context_encryption() {
        let mut ctx = HopContext::new(32);
        ctx.set_remote_key(vec![0x55; 32]);

        let plaintext = b"Hello, World!";
        let encrypted = ctx.apply(plaintext);

        // Reset position for decryption
        ctx.key_pos = 0;
        let decrypted = ctx.apply(&encrypted);

        assert_eq!(decrypted, plaintext);
    }
}
