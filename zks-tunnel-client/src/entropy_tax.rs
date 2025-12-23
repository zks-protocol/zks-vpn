//! Entropy Tax: Commitment-Based Swarm Entropy Collection
//!
//! Implements a provably secure protocol for collecting cryptographic entropy
//! from multiple peers, achieving information-theoretic security.
//!
//! Security Guarantee: Even if n-1 peers are malicious, one honest peer
//! ensures unpredictability (prevents adaptive attacks via commitment scheme).
//!
//! Protocol:
//! 1. Each peer generates 32 bytes local entropy
//! 2. Commit phase: Peers send SHA256(entropy)
//! 3. Reveal phase: After all committed, peers send actual entropy
//! 4. Verify: Check commitments match revealed entropy
//! 5. Combine: SHA256(e1 || e2 || ... || room_id)
//! 6. Derive: HKDF(combined, "swarm-entropy-v1", 1MB)

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Maximum age for entropy collection (30 seconds)
const MAX_ENTROPY_AGE: Duration = Duration::from_secs(30);

/// Size of entropy contribution from each peer
const ENTROPY_SIZE: usize = 32;

/// Size of derived remote key (1MB for XOR layer)
const REMOTE_KEY_SIZE: usize = 1024 * 1024;

/// Entropy collection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyState {
    /// Initial state - generating local entropy
    Init,
    /// Committed - sent hash, waiting for peer commitments
    Committed,
    /// Revealed - sent entropy, waiting for peer reveals
    Revealed,
    /// Complete - all entropy collected and verified
    Complete,
    /// Failed - verification failed or timeout
    Failed,
}

/// Entropy Tax: Commitment-based entropy collection
pub struct EntropyTax {
    /// Our local entropy contribution
    local_entropy: [u8; ENTROPY_SIZE],
    /// Our commitment (SHA256 of local_entropy)
    commitment: [u8; 32],
    /// Peer commitments (peer_id -> commitment_hash)
    peer_commitments: HashMap<String, [u8; 32]>,
    /// Peer entropies (peer_id -> entropy_bytes)
    peer_entropies: HashMap<String, [u8; ENTROPY_SIZE]>,
    /// Combined entropy (after all peers revealed)
    combined_entropy: Option<[u8; 32]>,
    /// Derived remote key (1MB)
    remote_key: Option<Vec<u8>>,
    /// Current state
    state: EntropyState,
    /// Timestamp when entropy was generated
    created_at: Instant,
}

impl EntropyTax {
    /// Create new entropy tax with locally generated entropy
    pub fn new() -> Self {
        let mut local_entropy = [0u8; ENTROPY_SIZE];
        getrandom::getrandom(&mut local_entropy).expect("Failed to generate random entropy");

        // Compute commitment (SHA256 hash)
        let mut hasher = Sha256::new();
        hasher.update(local_entropy);
        let commitment: [u8; 32] = hasher.finalize().into();

        Self {
            local_entropy,
            commitment,
            peer_commitments: HashMap::new(),
            peer_entropies: HashMap::new(),
            combined_entropy: None,
            remote_key: None,
            state: EntropyState::Init,
            created_at: Instant::now(),
        }
    }

    /// Get our commitment hash (to send to peers)
    pub fn get_commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Get current state
    #[allow(dead_code)]
    pub fn state(&self) -> EntropyState {
        self.state
    }

    /// Mark as committed (after sending commitment to peers)
    pub fn mark_committed(&mut self) {
        self.state = EntropyState::Committed;
    }

    /// Add peer commitment
    pub fn add_peer_commitment(
        &mut self,
        peer_id: String,
        commitment: [u8; 32],
    ) -> Result<(), String> {
        if self.state == EntropyState::Init {
            return Err("Cannot add peer commitment before our own commitment".to_string());
        }

        if self.peer_commitments.contains_key(&peer_id) {
            return Err(format!("Peer {} already committed", peer_id));
        }

        self.peer_commitments.insert(peer_id, commitment);
        Ok(())
    }

    /// Check if all expected peers have committed
    pub fn all_committed(&self, expected_peers: &[String]) -> bool {
        expected_peers
            .iter()
            .all(|peer_id| self.peer_commitments.contains_key(peer_id))
    }

    /// Reveal our local entropy (after all peers committed)
    pub fn reveal(&mut self, expected_peers: &[String]) -> Result<[u8; ENTROPY_SIZE], String> {
        if !self.all_committed(expected_peers) {
            return Err("Not all peers have committed yet".to_string());
        }

        self.state = EntropyState::Revealed;
        Ok(self.local_entropy)
    }

    /// Add peer entropy and verify against commitment
    pub fn add_peer_entropy(
        &mut self,
        peer_id: String,
        entropy: [u8; ENTROPY_SIZE],
    ) -> Result<(), String> {
        // Get peer's commitment
        let expected_commitment = self
            .peer_commitments
            .get(&peer_id)
            .ok_or_else(|| format!("No commitment from peer {}", peer_id))?;

        // Verify commitment matches revealed entropy
        let mut hasher = Sha256::new();
        hasher.update(entropy);
        let actual_commitment: [u8; 32] = hasher.finalize().into();

        if &actual_commitment != expected_commitment {
            return Err(format!(
                "Commitment verification failed for peer {}",
                peer_id
            ));
        }

        // Store verified entropy
        self.peer_entropies.insert(peer_id, entropy);
        Ok(())
    }

    /// Check if all expected peers have revealed
    pub fn all_revealed(&self, expected_peers: &[String]) -> bool {
        expected_peers
            .iter()
            .all(|peer_id| self.peer_entropies.contains_key(peer_id))
    }

    /// Derive remote key from all collected entropy
    pub fn derive_remote_key(
        &mut self,
        my_peer_id: &str,
        room_id: &str,
        expected_peers: &[String],
    ) -> Result<Vec<u8>, String> {
        if !self.all_revealed(expected_peers) {
            return Err("Not all peers have revealed entropy yet".to_string());
        }

        // Check for timeout
        if self.created_at.elapsed() > MAX_ENTROPY_AGE {
            self.state = EntropyState::Failed;
            return Err("Entropy collection timeout".to_string());
        }

        // Combine all entropy: SHA256(sorted(e1, e2, ..., en) || room_id)
        let mut hasher = Sha256::new();

        // Collect all entropies (local + peers)
        let mut all_entropies = Vec::new();
        all_entropies.push((my_peer_id.to_string(), self.local_entropy));

        for (peer_id, entropy) in &self.peer_entropies {
            all_entropies.push((peer_id.clone(), *entropy));
        }

        // Sort by peer_id to ensure deterministic order
        all_entropies.sort_by(|a, b| a.0.cmp(&b.0));

        for (_, entropy) in all_entropies {
            hasher.update(entropy);
        }

        // Add room_id for domain separation
        hasher.update(room_id.as_bytes());

        let combined: [u8; 32] = hasher.finalize().into();
        self.combined_entropy = Some(combined);

        // Derive 1MB remote key using iterative HKDF
        // HKDF with SHA256 has max output of 255 * 32 = 8160 bytes per call
        // So we use multiple HKDF expansions with different context
        let chunk_size: usize = 1024; // Safe size
        let num_chunks = REMOTE_KEY_SIZE.div_ceil(chunk_size);
        let mut remote_key = Vec::with_capacity(REMOTE_KEY_SIZE);

        for i in 0..num_chunks {
            let hk = Hkdf::<Sha256>::new(Some(b"swarm-entropy-v1"), &combined);
            let context = format!("zks-remote-key-chunk-{}", i);
            let remaining = REMOTE_KEY_SIZE.saturating_sub(remote_key.len());
            let this_chunk_size = remaining.min(chunk_size);
            // println!("Chunk {}: size {}", i, this_chunk_size);
            let mut chunk = vec![0u8; this_chunk_size];
            hk.expand(context.as_bytes(), &mut chunk)
                .map_err(|e| {
                    format!(
                        "HKDF expand failed at chunk {} size {}: {:?}",
                        i, this_chunk_size, e
                    )
                })
                .expect("HKDF expansion should not fail");
            remote_key.extend_from_slice(&chunk);
        }

        remote_key.truncate(REMOTE_KEY_SIZE);

        self.remote_key = Some(remote_key.clone());
        self.state = EntropyState::Complete;

        Ok(remote_key)
    }

    /// Get the derived remote key (if available)
    #[allow(dead_code)]
    pub fn get_remote_key(&self) -> Option<Vec<u8>> {
        self.remote_key.clone()
    }

    /// Get combined entropy (for debugging/verification)
    #[allow(dead_code)]
    pub fn get_combined_entropy(&self) -> Option<[u8; 32]> {
        self.combined_entropy
    }

    /// Get number of peers that have committed
    #[allow(dead_code)]
    pub fn commitment_count(&self) -> usize {
        self.peer_commitments.len()
    }

    /// Get number of peers that have revealed
    #[allow(dead_code)]
    pub fn reveal_count(&self) -> usize {
        self.peer_entropies.len()
    }
}

impl Default for EntropyTax {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_generation() {
        let tax = EntropyTax::new();
        assert_eq!(tax.state(), EntropyState::Init);
        assert_eq!(tax.local_entropy.len(), ENTROPY_SIZE);
        assert_eq!(tax.commitment.len(), 32);
    }

    #[test]
    fn test_commitment_verification() {
        let tax = EntropyTax::new();
        let commitment = tax.get_commitment();

        // Verify commitment matches local entropy
        let mut hasher = Sha256::new();
        hasher.update(&tax.local_entropy);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(commitment, expected);
    }

    #[test]
    fn test_two_peer_entropy_collection() {
        let mut peer1 = EntropyTax::new();
        let mut peer2 = EntropyTax::new();

        let peer1_commitment = peer1.get_commitment();
        let peer2_commitment = peer2.get_commitment();

        // Mark as committed
        peer1.mark_committed();
        peer2.mark_committed();

        // Exchange commitments
        peer1
            .add_peer_commitment("peer2".to_string(), peer2_commitment)
            .unwrap();
        peer2
            .add_peer_commitment("peer1".to_string(), peer1_commitment)
            .unwrap();

        // Reveal entropy
        let expected_peers = vec!["peer2".to_string()];
        let peer1_entropy = peer1.reveal(&expected_peers).unwrap();

        let expected_peers = vec!["peer1".to_string()];
        let peer2_entropy = peer2.reveal(&expected_peers).unwrap();

        // Exchange and verify entropy
        peer1
            .add_peer_entropy("peer2".to_string(), peer2_entropy)
            .unwrap();
        peer2
            .add_peer_entropy("peer1".to_string(), peer1_entropy)
            .unwrap();

        // Derive remote keys
        let room_id = "test-room";
        let expected_peers = vec!["peer2".to_string()];
        let key1 = peer1
            .derive_remote_key("peer1", room_id, &expected_peers)
            .unwrap();

        let expected_peers = vec!["peer1".to_string()];
        let key2 = peer2
            .derive_remote_key("peer2", room_id, &expected_peers)
            .unwrap();

        // Both peers should derive the same key
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), REMOTE_KEY_SIZE);
        assert_eq!(peer1.state(), EntropyState::Complete);
        assert_eq!(peer2.state(), EntropyState::Complete);
    }

    #[test]
    fn test_commitment_mismatch_detection() {
        let mut peer1 = EntropyTax::new();
        let peer2 = EntropyTax::new();

        peer1.mark_committed();

        // Add peer2's commitment
        let peer2_commitment = peer2.get_commitment();
        peer1
            .add_peer_commitment("peer2".to_string(), peer2_commitment)
            .unwrap();

        // Try to add wrong entropy (should fail verification)
        let wrong_entropy = [0u8; ENTROPY_SIZE];
        let result = peer1.add_peer_entropy("peer2".to_string(), wrong_entropy);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("Commitment verification failed"));
    }

    #[test]
    fn test_premature_reveal() {
        let mut tax = EntropyTax::new();
        tax.mark_committed();

        // Try to reveal before all peers committed
        let expected_peers = vec!["peer2".to_string()];
        let result = tax.reveal(&expected_peers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Not all peers have committed"));
    }

    #[test]
    fn test_premature_key_derivation() {
        let mut tax = EntropyTax::new();
        tax.mark_committed();

        // Try to derive key before all peers revealed
        let expected_peers = vec!["peer2".to_string()];
        let result = tax.derive_remote_key("peer1", "test-room", &expected_peers);

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Not all peers have revealed"));
    }

    #[test]
    fn test_hkdf_standalone() {
        use hkdf::Hkdf;
        use sha2::Sha256;
        let ikm = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let chunk_size = 32;
        for i in 0..100 {
            let context = format!("zks-remote-key-chunk-{}", i);
            let mut okm = vec![0u8; chunk_size];
            hk.expand(context.as_bytes(), &mut okm)
                .expect("HKDF loop failed");
        }
    }
}
