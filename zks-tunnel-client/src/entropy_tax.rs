//! Entropy Tax - P2P Swarm Entropy for Wasif-Vernam Cipher
//!
//! Implements the K_Remote component of the Wasif-Vernam cipher:
//!   Ciphertext = Plaintext ⊕ K_Local ⊕ K_Remote
//!
//! K_Remote = XOR of entropy contributions from N random peers
//! This ensures that even if one peer is compromised, the key remains secure.

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Size of entropy contribution in bytes
pub const ENTROPY_SIZE: usize = 32;

/// How often to broadcast new entropy (seconds)
pub const ENTROPY_REFRESH_INTERVAL: u64 = 10;

/// Maximum number of peers to send entropy to
pub const ENTROPY_BROADCAST_PEERS: usize = 5;

/// Shared entropy pool for a swarm
#[derive(Default)]
pub struct EntropyPool {
    /// Current accumulated K_Remote (XOR of all received entropy)
    k_remote: [u8; ENTROPY_SIZE],
    /// Number of entropy contributions received
    contribution_count: u64,
    /// Our own entropy contribution (for broadcasting)
    our_contribution: [u8; ENTROPY_SIZE],
}

impl EntropyPool {
    /// Create a new entropy pool
    pub fn new() -> Self {
        let mut pool = Self::default();
        pool.refresh_our_contribution();
        pool
    }

    /// Generate new random entropy for our contribution
    pub fn refresh_our_contribution(&mut self) {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut self.our_contribution);
        debug!("Generated new entropy contribution");
    }

    /// Get our current entropy contribution (for broadcasting)
    pub fn get_our_contribution(&self) -> [u8; ENTROPY_SIZE] {
        self.our_contribution
    }

    /// Receive and accumulate entropy from a peer
    pub fn receive_entropy(&mut self, entropy: &[u8; ENTROPY_SIZE]) {
        // XOR into K_Remote
        for i in 0..ENTROPY_SIZE {
            self.k_remote[i] ^= entropy[i];
        }
        self.contribution_count += 1;
        debug!(
            "Received entropy #{}, K_Remote updated",
            self.contribution_count
        );
    }

    /// Get the current K_Remote value
    pub fn get_k_remote(&self) -> [u8; ENTROPY_SIZE] {
        self.k_remote
    }

    /// Get the number of contributions received
    pub fn contribution_count(&self) -> u64 {
        self.contribution_count
    }
}

/// Entropy Tax Payer - handles broadcasting and receiving entropy
pub struct EntropyTaxPayer {
    pool: Arc<RwLock<EntropyPool>>,
}

impl EntropyTaxPayer {
    /// Create a new entropy tax payer
    pub fn new() -> Self {
        Self {
            pool: Arc::new(RwLock::new(EntropyPool::new())),
        }
    }

    /// Get a clone of the pool for sharing
    pub fn pool(&self) -> Arc<RwLock<EntropyPool>> {
        self.pool.clone()
    }

    /// Get current K_Remote
    pub async fn get_k_remote(&self) -> [u8; ENTROPY_SIZE] {
        self.pool.read().await.get_k_remote()
    }

    /// Receive entropy from a peer
    pub async fn receive_entropy(&self, entropy: &[u8; ENTROPY_SIZE]) {
        self.pool.write().await.receive_entropy(entropy);
    }

    /// Get our contribution for broadcasting
    pub async fn get_our_contribution(&self) -> [u8; ENTROPY_SIZE] {
        self.pool.read().await.get_our_contribution()
    }

    /// Refresh our entropy contribution
    pub async fn refresh_contribution(&self) {
        self.pool.write().await.refresh_our_contribution();
    }
}

impl Default for EntropyTaxPayer {
    fn default() -> Self {
        Self::new()
    }
}

/// Entropy Tax message for P2P broadcasting
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EntropyTaxMessage {
    /// Hex-encoded 32-byte entropy
    pub entropy: String,
    /// Unix timestamp (ms) when generated
    pub timestamp_ms: u64,
}

impl EntropyTaxMessage {
    /// Create a new entropy tax message
    pub fn new(entropy: &[u8; ENTROPY_SIZE]) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Self {
            entropy: hex::encode(entropy),
            timestamp_ms,
        }
    }

    /// Parse entropy bytes from message
    pub fn parse_entropy(&self) -> Option<[u8; ENTROPY_SIZE]> {
        let bytes = hex::decode(&self.entropy).ok()?;
        if bytes.len() != ENTROPY_SIZE {
            return None;
        }
        let mut arr = [0u8; ENTROPY_SIZE];
        arr.copy_from_slice(&bytes);
        Some(arr)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Option<Self> {
        serde_json::from_str(json).ok()
    }
}

/// Run the entropy tax broadcasting loop
pub async fn run_entropy_tax_loop(
    tax_payer: Arc<EntropyTaxPayer>,
    broadcast_fn: impl Fn(EntropyTaxMessage) + Send + Sync + 'static,
) {
    info!(
        "🎲 Starting Entropy Tax loop (refresh every {}s)",
        ENTROPY_REFRESH_INTERVAL
    );

    let mut interval = tokio::time::interval(Duration::from_secs(ENTROPY_REFRESH_INTERVAL));

    loop {
        interval.tick().await;

        // Refresh our contribution
        tax_payer.refresh_contribution().await;

        // Get our new contribution
        let contribution = tax_payer.get_our_contribution().await;

        // Create and broadcast message
        let msg = EntropyTaxMessage::new(&contribution);
        broadcast_fn(msg);

        let count = tax_payer.pool.read().await.contribution_count();
        debug!("Broadcast entropy, received {} contributions so far", count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_pool() {
        let mut pool = EntropyPool::new();

        // Initial K_Remote should be zero
        assert_eq!(pool.contribution_count(), 0);

        // Add entropy
        let entropy1 = [0x42u8; ENTROPY_SIZE];
        pool.receive_entropy(&entropy1);

        assert_eq!(pool.contribution_count(), 1);
        assert_eq!(pool.get_k_remote(), entropy1);

        // Add more entropy (XOR)
        let entropy2 = [0x13u8; ENTROPY_SIZE];
        pool.receive_entropy(&entropy2);

        assert_eq!(pool.contribution_count(), 2);

        // K_Remote should be XOR of both
        let expected: [u8; ENTROPY_SIZE] = core::array::from_fn(|i| entropy1[i] ^ entropy2[i]);
        assert_eq!(pool.get_k_remote(), expected);
    }

    #[test]
    fn test_entropy_message() {
        let entropy = [0xABu8; ENTROPY_SIZE];
        let msg = EntropyTaxMessage::new(&entropy);

        let json = msg.to_json();
        let parsed = EntropyTaxMessage::from_json(&json).unwrap();

        assert_eq!(parsed.parse_entropy().unwrap(), entropy);
    }
}
